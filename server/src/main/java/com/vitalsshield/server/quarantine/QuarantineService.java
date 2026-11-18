package com.vitalsshield.server.quarantine;

// LOCK ORDER (DECISIONS #82, extends #70), in every transaction: devices -> certificates -> telemetry_records
// -> patient_device_assignments -> clinical_alerts -> audit advisory lock LAST. This class: devices FOR UPDATE first, then (one statement) the
// sanitize CTE updates telemetry_records, patient_device_assignments and clinical_alerts in that order, then the
// audit append. Certificates are revoked afterwards in SignerRevocationService's own transaction.

import com.vitalsshield.server.audit.AuditLog;
import org.springframework.beans.factory.ObjectProvider;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.signer.SignerRevocationService;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Confirm-compromise quarantine (spec Section 4 recovery path 2, Section 6; DECISIONS #1, #42, #45).
 * <ol>
 *   <li>Revoke every live certificate of the device (KEY_COMPROMISE), deny-list first, evict all sockets.</li>
 *   <li>One READ COMMITTED transaction: lock the devices row FOR UPDATE; set QUARANTINED and clear the DEK; revoke
 *       outstanding bootstrap tokens; then, as a separate statement, the spec Section 6 sanitize CTE.</li>
 * </ol>
 * Locking and flipping the state first means any ingest still in flight either committed before the lock (and its
 * row is visible to the sanitize statement, which takes a fresh snapshot) or blocks on the lock and then fails the
 * CTE's {@code trust_state = 'ACTIVE'} check.
 */
@Service
public class QuarantineService {

    private static final Logger log = LoggerFactory.getLogger(QuarantineService.class);
    private static final int RECENT_LIMIT = 50;

    /**
     * Spec Section 6 sanitize statement, unchanged except that the final UPDATE is wrapped as the {@code
     * retracted_alerts} CTE with {@code RETURNING ca.alert_id}, a SELECT returns the three counts, and (Phase 7,
     * DECISIONS #68) the tainted_baselines SET list also zeroes the four V5 streak columns.
     */
    static final String SANITIZE_WITH_COUNTS = """
            WITH quarantined_batches AS (
                UPDATE telemetry_records
                SET trust_state = 'QUARANTINED'
                WHERE device_id = :deviceId
                  AND trust_state IN ('ACCEPTED', 'SIGNAL_DEGRADED')
                  AND (
                      ingested_at >= :quarantineTs - (:lookbackMinutes * INTERVAL '1 minute')
                      OR measured_at >= :quarantineTs - (:lookbackMinutes * INTERVAL '1 minute')
                  )
                RETURNING batch_id, assignment_id
            ),
            tainted_baselines AS (
                UPDATE patient_device_assignments a
                SET baseline_state        = 'CALIBRATING',
                    baseline_version      = a.baseline_version + 1,
                    calibration_batch_ids = '{}',
                    ref_hr_mean           = NULL,
                    ref_hr_sd             = NULL,
                    ref_hrv_mean          = NULL,
                    ref_hrv_sd            = NULL,
                    ref_spo2_mean         = NULL,
                    ref_spo2_sd           = NULL,
                    degraded_critical_streak    = 0,
                    degraded_critical_batch_ids = '{}',
                    drift_breach_streak         = 0,
                    drift_breach_batch_ids      = '{}'
                WHERE a.device_id = :deviceId
                  AND a.calibration_batch_ids && ARRAY(SELECT batch_id FROM quarantined_batches)
                RETURNING a.assignment_id, (a.baseline_version - 1) AS old_baseline_version
            ),
            retracted_alerts AS (
            UPDATE clinical_alerts ca
            SET alert_status = 'RETRACTED_BY_QUARANTINE',
                retracted_at = NOW()
            WHERE ca.device_id = :deviceId
              AND ca.alert_status IN ('ACTIVE', 'ACKNOWLEDGED')
              AND (
                  ca.triggering_batch_ids && ARRAY(SELECT batch_id FROM quarantined_batches)
                  OR (
                      ca.alert_type = 'POTENTIAL_PHYSIOLOGICAL_DRIFT'
                      AND EXISTS (
                          SELECT 1 FROM tainted_baselines tb
                          WHERE tb.assignment_id = ca.assignment_id
                            AND tb.old_baseline_version = ca.baseline_version
                      )
                  )
              )
            RETURNING ca.alert_id
            )
            SELECT (SELECT count(*) FROM quarantined_batches) AS batches_quarantined,
                   (SELECT count(*) FROM tainted_baselines)   AS baselines_reset,
                   (SELECT count(*) FROM retracted_alerts)    AS alerts_retracted
            """;

    public record Result(String deviceId, Instant at, int certsRevoked, int channelsClosed,
                         long revocationLatencyMicros, long batchesQuarantined, long baselinesReset,
                         long alertsRetracted) {
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("device_id", deviceId);
            m.put("at", at.toString());
            m.put("certs_revoked", certsRevoked);
            m.put("channels_closed", channelsClosed);
            m.put("revocation_latency_micros", revocationLatencyMicros);
            m.put("batches_quarantined", batchesQuarantined);
            m.put("baselines_reset", baselinesReset);
            m.put("alerts_retracted", alertsRetracted);
            return m;
        }
    }

    /** 409 for a device in the wrong state. */
    public static final class StateConflict extends RuntimeException {
        private final String code;

        public StateConflict(String code) {
            super(code);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final SignerRevocationService revocations;
    private final CrlService crls;
    private final Clock clock;
    private final Deque<Result> recent = new ConcurrentLinkedDeque<>();
    private final AuditLog audit;
    private final QuarantineHooks hooks;

    /** Who approved the quarantine (webauthn mode), for the audit entry written inside the transaction. */
    public record Approval(String clinicianId, String assertionSha256) {
    }

    public QuarantineService(NamedParameterJdbcTemplate jdbc, TransactionTemplate tx,
                             SignerRevocationService revocations, CrlService crls, Clock clock, AuditLog audit,
                             ObjectProvider<QuarantineHooks> hooks) {
        this.audit = audit;
        this.hooks = hooks.getIfAvailable(() -> QuarantineHooks.NONE);
        this.jdbc = jdbc;
        this.tx = tx;
        this.revocations = revocations;
        this.crls = crls;
        this.clock = clock;
    }

    /** Bearer mode (Phase 4/5): no approval, no audit entry. */
    public Mono<Result> quarantine(String deviceId, int lookbackMinutes, String reason) {
        return quarantine(deviceId, lookbackMinutes, reason, null);
    }

    /**
     * With {@code approval}, the DEVICE_QUARANTINED audit entry is appended inside the same transaction as the lock,
     * state flip, and sanitize (DECISIONS #67): both commit or neither does.
     */
    public Mono<Result> quarantine(String deviceId, int lookbackMinutes, String reason, Approval approval) {
        long t0 = System.nanoTime();
        return Mono.fromCallable(() -> requireQuarantinable(deviceId))
                .subscribeOn(Schedulers.boundedElastic())
                .then(revocations.revokeAllForDevice(deviceId, "KEY_COMPROMISE", t0))
                .flatMap(bulk -> {
                    // DECISIONS #11: t0 (request receipt) to every close future complete, measured once inside the
                    // bulk revocation so the revocation log and this response report the same number.
                    long latencyMicros = bulk.latencyMicros();
                    return Mono.fromCallable(() -> sanitize(deviceId, lookbackMinutes, reason, bulk, latencyMicros,
                                    approval))
                            .subscribeOn(Schedulers.boundedElastic());
                })
                .doOnNext(r -> {
                    recent.addFirst(r);
                    while (recent.size() > RECENT_LIMIT) {
                        recent.pollLast();
                    }
                    log.warn("Quarantined {}: {}", deviceId, r);
                });
    }

    public List<Result> recentResults() {
        return new ArrayList<>(recent);
    }

    private Boolean requireQuarantinable(String deviceId) {
        List<String> states = jdbc.queryForList("SELECT trust_state::text FROM devices WHERE device_id = :d",
                Map.of("d", deviceId), String.class);
        if (states.isEmpty()) {
            throw new StateConflict("DEVICE_NOT_FOUND");
        }
        checkState(states.get(0));
        return Boolean.TRUE;
    }

    private static void checkState(String state) {
        if ("QUARANTINED".equals(state)) {
            throw new StateConflict("ALREADY_QUARANTINED");
        }
        if (!"ACTIVE".equals(state) && !"REAUTH_REQUIRED".equals(state)) {
            throw new StateConflict("INVALID_STATE");
        }
    }

    private Result sanitize(String deviceId, int lookbackMinutes, String reason,
                            SignerRevocationService.BulkRevocation bulk, long latencyMicros, Approval approval) {
        Result result = tx.execute(status -> {
            Map<String, Object> d = Map.of("d", deviceId);
            // a) Lock first (DECISIONS #42), and re-check the state under the lock.
            String state = jdbc.queryForObject(
                    "SELECT trust_state::text FROM devices WHERE device_id = :d FOR UPDATE", d, String.class);
            checkState(state);
            // b) Flip the state so any ingest blocked on this row fails the CTE's trust_state = 'ACTIVE' check.
            jdbc.update("""
                    UPDATE devices SET trust_state = 'QUARANTINED', quarantine_reason = :r,
                           dek_spki_der_b64 = NULL, dek_spki_sha256 = NULL, dek_registry_kms_sig = NULL,
                           updated_at = NOW()
                     WHERE device_id = :d
                    """, Map.of("d", deviceId, "r", reason));
            // c) DECISIONS #45.
            jdbc.update("""
                    UPDATE device_bootstrap_tokens SET status = 'REVOKED'
                     WHERE device_id = :d AND status IN ('ISSUED', 'CLAIMING')
                    """, d);
            // d) Spec Section 6, a separate statement with its own (later) snapshot. :quarantineTs is Postgres now()
            // read in this transaction (DECISIONS #89): the window is compared with ingested_at, which Postgres
            // stamped, so a Docker VM clock behind or ahead of the JVM cannot shift which batches are sanitized.
            Instant quarantineTs = jdbc.queryForObject("SELECT now()", Map.of(), java.sql.Timestamp.class).toInstant();
            Map<String, Object> counts = jdbc.queryForMap(SANITIZE_WITH_COUNTS, new MapSqlParameterSource()
                    .addValue("deviceId", deviceId)
                    // Typed as timestamptz: an untyped Timestamp makes ":quarantineTs - interval" resolve to an interval.
                    .addValue("quarantineTs", new org.springframework.jdbc.core.SqlParameterValue(
                            java.sql.Types.TIMESTAMP_WITH_TIMEZONE,
                            java.time.OffsetDateTime.ofInstant(quarantineTs, java.time.ZoneOffset.UTC)))
                    .addValue("lookbackMinutes", lookbackMinutes));
            Result r = new Result(deviceId, quarantineTs, bulk.keys().size(), bulk.channelsClosed(), latencyMicros,
                    ((Number) counts.get("batches_quarantined")).longValue(),
                    ((Number) counts.get("baselines_reset")).longValue(),
                    ((Number) counts.get("alerts_retracted")).longValue());
            // e) Audit last (DECISIONS #67): its advisory lock is taken after every row lock above.
            if (approval != null) {
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("device_id", deviceId);
                payload.put("lookback_minutes", lookbackMinutes);
                payload.put("reason", reason);
                payload.put("batches_quarantined", r.batchesQuarantined());
                payload.put("certs_revoked", r.certsRevoked());
                payload.put("assertion_sha256", approval.assertionSha256());
                audit.append("DEVICE_QUARANTINED", approval.clinicianId(), payload);
            }
            hooks.beforeCommit(deviceId);
            return r;
        });
        bulk.keys().stream().map(k -> k.issuerKeyHash()).distinct().forEach(crls::revocationCommitted);
        return result;
    }
}
