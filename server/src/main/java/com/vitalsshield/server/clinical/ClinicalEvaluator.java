package com.vitalsshield.server.clinical;

// LOCK ORDER (DECISIONS #82, extends #70), in every transaction: devices -> certificates -> telemetry_records
// -> patient_device_assignments -> clinical_alerts -> audit advisory lock LAST. This class: devices FOR KEY SHARE, the telemetry row FOR UPDATE,
// the assignment row FOR NO KEY UPDATE, then clinical_alerts inserts. It never takes the audit lock.

import com.vitalsshield.server.telemetry.TelemetryMetrics;
import java.sql.Array;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

/**
 * Spec Section 6 steps 2 to 4 (DECISIONS #68 to #73). The ingest service calls {@link #submit} after its CTE
 * committed a new row; evaluation runs later on a dedicated boundedElastic scheduler, so it never delays the HTTP
 * response. Batches of one
 * assignment run one at a time in submission order (an in-memory serial queue per assignment); the assignment row
 * lock serializes them again in the database, so two server threads can never interleave one assignment's streaks.
 *
 * <p>One transaction per batch:
 * <ol>
 *   <li>devices FOR KEY SHARE: stop unless ACTIVE. KEY SHARE does not conflict with the ingest CTE's UPDATE of the
 *       same row, but does conflict with quarantine's FOR UPDATE, so an evaluation either finishes before a
 *       quarantine locks the device or starts after it committed and sees QUARANTINED.</li>
 *   <li>telemetry row FOR UPDATE: stop unless ACCEPTED or SIGNAL_DEGRADED and not yet evaluated.</li>
 *   <li>assignment FOR NO KEY UPDATE; activity; degraded streak, acute, calibration, drift; update the assignment.</li>
 *   <li>insert alerts; mark the telemetry row evaluated.</li>
 * </ol>
 * A failure rolls the transaction back: the batch keeps clinical_evaluated_at NULL and is counted and logged.
 */
@Service
public class ClinicalEvaluator {

    private static final Logger log = LoggerFactory.getLogger(ClinicalEvaluator.class);

    public static final String LOW_PERFUSION_CRITICAL = "LOW_PERFUSION_CRITICAL";
    public static final String DRIFT = "DRIFT";

    /** What one evaluation did; also returned to tests. */
    public enum Outcome {
        EVALUATED,
        SKIPPED_DEVICE_NOT_ACTIVE,
        SKIPPED_NOT_EVALUABLE,
        FAILED
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final ClinicalProperties props;
    private final TelemetryMetrics metrics;
    private final ClinicalHooks hooks;
    private final Clock clock;
    private final ConcurrentHashMap<UUID, CompletableFuture<Void>> tails = new ConcurrentHashMap<>();
    private final AtomicInteger pending = new AtomicInteger();
    /**
     * Its own boundedElastic scheduler (at most 4 threads), not the shared one that the ingest and admin paths use:
     * a slow database makes evaluations queue up here instead of starving request handling. Disposed with the
     * context, which also drops evaluations still queued.
     */
    private final Scheduler scheduler = Schedulers.newBoundedElastic(4, 100_000, "clinical-eval");
    private final Executor executor = r -> scheduler.schedule(r);

    public ClinicalEvaluator(JdbcTemplate jdbc, TransactionTemplate tx, ClinicalProperties props,
                             TelemetryMetrics metrics, ObjectProvider<ClinicalHooks> hooks, Clock clock) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.props = props;
        this.metrics = metrics;
        this.hooks = hooks.getIfAvailable(() -> ClinicalHooks.NONE);
        this.clock = clock;
    }

    public ClinicalProperties properties() {
        return props;
    }

    /**
     * Queues the batch behind earlier batches of the same assignment. Non-blocking. Returns false when the queue is
     * full (DECISIONS #79): the batch stays unevaluated, the overflow is counted, and it is never replayed later.
     */
    public boolean submit(String deviceId, UUID assignmentId, UUID batchId) {
        int cap = props.queueCapacity();
        while (true) {
            int now = pending.get();
            if (now >= cap) {
                metrics.increment("clinical.queue_overflows");
                log.warn("Clinical queue full ({} of {}): {} batch {} stays unevaluated", now, cap, deviceId, batchId);
                return false;
            }
            if (pending.compareAndSet(now, now + 1)) {
                break;
            }
        }
        @SuppressWarnings("unchecked")
        CompletableFuture<Void>[] mine = new CompletableFuture[1];
        tails.compute(assignmentId, (k, tail) -> {
            CompletableFuture<Void> base = tail == null ? CompletableFuture.completedFuture(null) : tail;
            // A rejected schedule (scheduler disposed at shutdown) completes exceptionally; the batch stays unevaluated.
            mine[0] = base.exceptionally(e -> null).thenRunAsync(() -> evaluate(deviceId, batchId), executor);
            return mine[0];
        });
        mine[0].whenComplete((v, e) -> {
            tails.remove(assignmentId, mine[0]);
            pending.decrementAndGet();
        });
        return true;
    }

    @jakarta.annotation.PreDestroy
    void shutdown() {
        scheduler.dispose();
    }

    /** Evaluations queued or running. */
    public int pending() {
        return pending.get();
    }

    /** Test helper: waits until no evaluation is queued or running. */
    public boolean awaitIdle(Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (pending.get() > 0) {
            if (System.nanoTime() > deadline) {
                return false;
            }
            Thread.sleep(10);
        }
        return true;
    }

    /** Blocking; never throws. */
    public Outcome evaluate(String deviceId, UUID batchId) {
        try {
            hooks.beforeEvaluate(deviceId, batchId);
            Outcome o = tx.execute(status -> evaluateInTx(deviceId, batchId));
            if (o == Outcome.EVALUATED) {
                metrics.increment("clinical.evaluations");
            }
            return o;
        } catch (RuntimeException e) {
            metrics.increment("clinical.evaluation_failures");
            log.error("Clinical evaluation failed for {} batch {}; it stays unevaluated", deviceId, batchId, e);
            return Outcome.FAILED;
        }
    }

    private record Row(UUID assignmentId, String trustState, Instant measuredAt, BatchMetrics m) {
    }

    private record Assignment(int birthYear, String baselineState, int baselineVersion, List<UUID> calibrationIds,
                              CalibrationStats.Baseline baseline, Instant restingSince, int degradedStreak,
                              List<UUID> degradedIds, int driftStreak, List<UUID> driftIds, Instant lastMeasuredAt) {
    }

    private record NewAlert(String type, String conditionCode, Integer baselineVersion, List<UUID> batchIds,
                            String explanation) {
    }

    private Outcome evaluateInTx(String deviceId, UUID batchId) {
        // 1. devices FOR KEY SHARE.
        List<String> state = jdbc.queryForList(
                "SELECT trust_state::text FROM devices WHERE device_id = ? FOR KEY SHARE", String.class, deviceId);
        if (state.isEmpty() || !"ACTIVE".equals(state.get(0))) {
            return Outcome.SKIPPED_DEVICE_NOT_ACTIVE;
        }
        // 2. The telemetry row FOR UPDATE.
        List<Row> rows = jdbc.query("""
                SELECT assignment_id, trust_state::text AS ts, measured_at, clinical_evaluated_at, heart_rate_bpm,
                       hrv_rmssd_ms, spo2_pct, perfusion_index, step_cadence_spm, motion_g_rms
                  FROM telemetry_records WHERE device_id = ? AND batch_id = ? FOR UPDATE
                """, (rs, i) -> rs.getTimestamp("clinical_evaluated_at") != null ? null
                : new Row((UUID) rs.getObject("assignment_id"), rs.getString("ts"),
                        rs.getTimestamp("measured_at").toInstant(), metrics(rs)), deviceId, batchId);
        if (rows.isEmpty() || rows.get(0) == null) {
            return Outcome.SKIPPED_NOT_EVALUABLE;
        }
        Row row = rows.get(0);
        boolean accepted = "ACCEPTED".equals(row.trustState());
        if (!accepted && !"SIGNAL_DEGRADED".equals(row.trustState())) {
            return Outcome.SKIPPED_NOT_EVALUABLE;
        }
        // 3. The assignment FOR NO KEY UPDATE (DECISIONS #70).
        Assignment a = jdbc.queryForObject("""
                SELECT patient_birth_year, baseline_state::text AS bs, baseline_version, calibration_batch_ids,
                       ref_hr_mean, ref_hr_sd, ref_hrv_mean, ref_hrv_sd, ref_spo2_mean, ref_spo2_sd, resting_since,
                       degraded_critical_streak, degraded_critical_batch_ids, drift_breach_streak,
                       drift_breach_batch_ids, last_evaluated_measured_at
                  FROM patient_device_assignments WHERE assignment_id = ? FOR NO KEY UPDATE
                """, (rs, i) -> new Assignment(rs.getInt("patient_birth_year"), rs.getString("bs"),
                rs.getInt("baseline_version"), uuids(rs.getArray("calibration_batch_ids")),
                rs.getObject("ref_hr_mean") == null ? null : new CalibrationStats.Baseline(rs.getDouble("ref_hr_mean"),
                        rs.getDouble("ref_hr_sd"), rs.getDouble("ref_hrv_mean"), rs.getDouble("ref_hrv_sd"),
                        rs.getDouble("ref_spo2_mean"), rs.getDouble("ref_spo2_sd")),
                instant(rs.getTimestamp("resting_since")), rs.getInt("degraded_critical_streak"),
                uuids(rs.getArray("degraded_critical_batch_ids")), rs.getInt("drift_breach_streak"),
                uuids(rs.getArray("drift_breach_batch_ids")), instant(rs.getTimestamp("last_evaluated_measured_at"))),
                row.assignmentId());

        // A streak must never carry a batch that is no longer trusted (for example one quarantined while the
        // baseline itself was not tainted): such a streak starts over.
        DegradedCriticalStreak.State degraded = stillTrusted(deviceId, a.degradedIds())
                ? new DegradedCriticalStreak.State(a.degradedStreak(), a.degradedIds()) : DegradedCriticalStreak.State.EMPTY;
        DriftRule.State drift = stillTrusted(deviceId, a.driftIds())
                ? new DriftRule.State(a.driftStreak(), a.driftIds()) : DriftRule.State.EMPTY;

        // 4. Activity.
        ActivityClassifier.Result activity = ActivityClassifier.classify(row.m(), row.measuredAt(), a.restingSince(),
                a.lastMeasuredAt(), props);
        ActivityContext ctx = activity.context();

        List<NewAlert> alerts = new ArrayList<>();
        List<UUID> calibrationIds = a.calibrationIds();
        String baselineState = a.baselineState();
        CalibrationStats.Baseline baseline = a.baseline();

        if (!accepted) {
            // 5. SIGNAL_DEGRADED: only the low-perfusion critical streak.
            DegradedCriticalStreak.Step step = DegradedCriticalStreak.onDegraded(degraded, batchId, row.m(), props);
            degraded = step.next();
            if (step.fire()) {
                alerts.add(new NewAlert("LOW_PERFUSION_CRITICAL_ALERT", LOW_PERFUSION_CRITICAL, null,
                        step.next().batchIds(), DegradedCriticalStreak.explanation(row.m(), step.next().streak(), props)));
            }
        } else {
            degraded = DegradedCriticalStreak.onAccepted();
            // 6. Acute.
            int age = AcuteRules.age(row.measuredAt(), a.birthYear());
            List<AcuteRules.Condition> conditions = AcuteRules.evaluate(row.m(), ctx, age, props);
            boolean acuteTriggering = !conditions.isEmpty();
            if (acuteTriggering) {
                List<AlertDedupe.Prior> priors = openAcutePriors(row.assignmentId());
                for (AcuteRules.Condition c : conditions) {
                    if (AlertDedupe.suppressed(priors, c.code(), row.measuredAt(), props.acuteDedupeWindow())) {
                        metrics.increment("clinical.dedupe_suppressed");
                        continue;
                    }
                    String explanation = c.explanation()
                            + (activity.notYetSustained() ? " (still, but rest not yet sustained)" : "");
                    alerts.add(new NewAlert("ACUTE_PHYSIOLOGICAL_ALERT", c.code(), null, List.of(batchId), explanation));
                }
            }
            // 7. Calibration.
            if ("CALIBRATING".equals(baselineState)
                    && CalibrationStats.eligible(row.trustState(), ctx, acuteTriggering)) {
                List<UUID> ids = new ArrayList<>(calibrationIds);
                ids.add(batchId);
                calibrationIds = List.copyOf(ids);
                if (calibrationIds.size() >= props.calibrationSize()) {
                    baseline = CalibrationStats.compute(metricsOf(deviceId, calibrationIds), props);
                    baselineState = "LOCKED";
                }
            } else if ("LOCKED".equals(baselineState) && ctx == ActivityContext.RESTING && baseline != null) {
                // 8. Drift (only RESTING ACCEPTED batches reach here; EXERTION neither counts nor resets).
                DriftRule.ZScores z = DriftRule.z(row.m(), baseline);
                DriftRule.Step step = DriftRule.onResting(drift, batchId, DriftRule.breach(z, props), props);
                drift = step.next();
                if (step.fire()) {
                    CalibrationStats.Baseline b = baseline;
                    List<DriftRule.ZScores> zs = metricsOf(deviceId, step.trigger()).stream()
                            .map(m -> DriftRule.z(m, b)).toList();
                    alerts.add(new NewAlert("POTENTIAL_PHYSIOLOGICAL_DRIFT", DRIFT, a.baselineVersion(),
                            step.trigger(), DriftRule.explanation(a.baselineVersion(), zs)));
                }
            }
        }

        // Assignment update (still inside its row lock), then alerts, then the telemetry row.
        jdbc.update("""
                UPDATE patient_device_assignments
                   SET resting_since = ?, last_evaluated_measured_at = ?,
                       degraded_critical_streak = ?, degraded_critical_batch_ids = ?::uuid[],
                       drift_breach_streak = ?, drift_breach_batch_ids = ?::uuid[],
                       calibration_batch_ids = ?::uuid[], baseline_state = ?::baseline_lock_state,
                       ref_hr_mean = ?, ref_hr_sd = ?, ref_hrv_mean = ?, ref_hrv_sd = ?, ref_spo2_mean = ?, ref_spo2_sd = ?
                 WHERE assignment_id = ?
                """, ts(activity.restingSince()), Timestamp.from(row.measuredAt()),
                degraded.streak(), literal(degraded.batchIds()), drift.streak(), literal(drift.batchIds()),
                literal(calibrationIds), baselineState,
                baseline == null ? null : baseline.hrMean(), baseline == null ? null : baseline.hrSd(),
                baseline == null ? null : baseline.hrvMean(), baseline == null ? null : baseline.hrvSd(),
                baseline == null ? null : baseline.spo2Mean(), baseline == null ? null : baseline.spo2Sd(),
                row.assignmentId());
        List<UUID> alertIds = new java.util.ArrayList<>();
        for (NewAlert n : alerts) {
            UUID alertId = UUID.randomUUID();
            alertIds.add(alertId);
            jdbc.update("""
                    INSERT INTO clinical_alerts (alert_id, device_id, assignment_id, baseline_version, alert_type,
                                                 alert_status, triggering_batch_ids, explanation_summary, condition_code)
                    VALUES (?, ?, ?, ?, ?::alert_severity_type, 'ACTIVE', ?::uuid[], ?, ?)
                    """, alertId, deviceId, row.assignmentId(), n.baselineVersion(), n.type(),
                    literal(n.batchIds()), n.explanation(), n.conditionCode());
            metrics.increment("clinical.alerts." + n.type());
        }
        if (!alertIds.isEmpty()) {
            hooks.afterAlertsInserted(deviceId, batchId, alertIds);
        }
        jdbc.update("""
                UPDATE telemetry_records SET activity_context = ?, clinical_evaluated_at = ?
                 WHERE device_id = ? AND batch_id = ?
                """, ctx.name(), Timestamp.from(clock.instant()), deviceId, batchId);
        if ("LOCKED".equals(baselineState) && !"LOCKED".equals(a.baselineState())) {
            log.info("Baseline v{} LOCKED for assignment {} after {} resting batches", a.baselineVersion(),
                    row.assignmentId(), calibrationIds.size());
        }
        return Outcome.EVALUATED;
    }

    private boolean stillTrusted(String deviceId, List<UUID> ids) {
        if (ids.isEmpty()) {
            return true;
        }
        Integer n = jdbc.queryForObject("""
                SELECT count(*) FROM telemetry_records
                 WHERE device_id = ? AND batch_id = ANY(?::uuid[]) AND trust_state IN ('ACCEPTED', 'SIGNAL_DEGRADED')
                """, Integer.class, deviceId, literal(ids));
        return n != null && n == ids.size();
    }

    private List<AlertDedupe.Prior> openAcutePriors(UUID assignmentId) {
        return jdbc.query("""
                SELECT ca.condition_code, t.measured_at
                  FROM clinical_alerts ca
                  JOIN telemetry_records t ON t.device_id = ca.device_id AND t.batch_id = ANY(ca.triggering_batch_ids)
                 WHERE ca.assignment_id = ? AND ca.alert_type = 'ACUTE_PHYSIOLOGICAL_ALERT'
                   AND ca.alert_status IN ('ACTIVE', 'ACKNOWLEDGED') AND ca.condition_code IS NOT NULL
                """, (rs, i) -> new AlertDedupe.Prior(rs.getString(1), rs.getTimestamp(2).toInstant()), assignmentId);
    }

    /** Metrics of the given batches, in the order of {@code ids}. */
    private List<BatchMetrics> metricsOf(String deviceId, List<UUID> ids) {
        Map<UUID, BatchMetrics> byId = new java.util.HashMap<>();
        jdbc.query("""
                SELECT batch_id, heart_rate_bpm, hrv_rmssd_ms, spo2_pct, perfusion_index, step_cadence_spm, motion_g_rms
                  FROM telemetry_records WHERE device_id = ? AND batch_id = ANY(?::uuid[])
                """, rs -> {
            byId.put((UUID) rs.getObject("batch_id"), metrics(rs));
        }, deviceId, literal(ids));
        return ids.stream().map(byId::get).toList();
    }

    private static BatchMetrics metrics(java.sql.ResultSet rs) throws SQLException {
        return new BatchMetrics(rs.getInt("heart_rate_bpm"), rs.getDouble("hrv_rmssd_ms"), rs.getDouble("spo2_pct"),
                rs.getDouble("perfusion_index"), rs.getInt("step_cadence_spm"), rs.getDouble("motion_g_rms"));
    }

    static List<UUID> uuids(Array a) throws SQLException {
        if (a == null) {
            return List.of();
        }
        Object[] values = (Object[]) a.getArray();
        return Arrays.stream(values).map(v -> v instanceof UUID u ? u : UUID.fromString(v.toString())).toList();
    }

    /** A Postgres array literal for {@code ?::uuid[]}. */
    static String literal(List<UUID> ids) {
        return ids.stream().map(UUID::toString).collect(Collectors.joining(",", "{", "}"));
    }

    private static Instant instant(Timestamp t) {
        return t == null ? null : t.toInstant();
    }

    private static Timestamp ts(Instant i) {
        return i == null ? null : Timestamp.from(i);
    }
}
