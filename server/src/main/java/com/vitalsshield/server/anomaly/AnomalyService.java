package com.vitalsshield.server.anomaly;

// LOCK ORDER (DECISIONS #82, extends #70), in every transaction: devices -> certificates -> telemetry_records
// -> patient_device_assignments -> clinical_alerts -> audit advisory lock LAST. This class: devices FOR UPDATE, then
// the device's certificates FOR UPDATE, a plain read of the ACTIVE assignment, the clinical_alerts insert, and the
// audit append last. It never touches telemetry_records.

import com.vitalsshield.server.audit.AuditLog;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import com.vitalsshield.server.signer.EvictionProperties;
import com.vitalsshield.server.telemetry.TelemetryMetrics;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Non-destructive anomaly response (spec Section 4, DECISIONS #92). In one transaction: every ACTIVE,
 * ISSUED_PENDING_USE or RENEWED certificate of the device is deny-listed (before commit) and REVOKED with
 * SUSPECTED_CLONE; trust_state becomes REAUTH_REQUIRED; a SECURITY_ANOMALY_ALERT is inserted with no triggering
 * batches and no baseline version; a SECURITY_ANOMALY audit entry by "system" is appended last. After commit the live
 * sockets are closed and the CRL is republished. Telemetry is never changed: a clinician decides between restore and
 * quarantine.
 *
 * <p>Idempotent: if the device is not ACTIVE (already REAUTH_REQUIRED, QUARANTINED, ...), only an audit entry is
 * appended; nothing is revoked and no second alert is created.
 */
@Service
public class AnomalyService {

    private static final Logger log = LoggerFactory.getLogger(AnomalyService.class);
    public static final String REVOCATION_REASON = "SUSPECTED_CLONE";
    public static final String AUDIT_EVENT = "SECURITY_ANOMALY";
    public static final String ACTOR = "system";

    /** What one raise did. {@code revoked} is empty when the device was not ACTIVE (audit only). */
    public record Raised(String deviceId, String conditionCode, String previousState, UUID alertId,
                         List<CertKey> revoked, Instant at) {
        public boolean auditOnly() {
            return alertId == null;
        }
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final CertificateDenyList denyList;
    private final ActiveSessionRegistry sessions;
    private final CrlService crls;
    private final AuditLog audit;
    private final EvictionProperties eviction;
    private final TelemetryMetrics metrics;
    private final Clock clock;
    private final com.vitalsshield.server.signer.SignerRevocationService revocationLog;

    public AnomalyService(JdbcTemplate jdbc, TransactionTemplate tx, CertificateDenyList denyList,
                          ActiveSessionRegistry sessions, CrlService crls, AuditLog audit,
                          EvictionProperties eviction, TelemetryMetrics metrics, Clock clock,
                          com.vitalsshield.server.signer.SignerRevocationService revocationLog) {
        this.revocationLog = revocationLog;
        this.jdbc = jdbc;
        this.tx = tx;
        this.denyList = denyList;
        this.sessions = sessions;
        this.crls = crls;
        this.audit = audit;
        this.eviction = eviction;
        this.metrics = metrics;
        this.clock = clock;
    }

    /** Blocking: its own transaction, then {@link #afterCommit}. */
    public Raised raise(String deviceId, String conditionCode, String explanation, Map<String, Object> detail) {
        Raised r = tx.execute(s -> raiseInTx(deviceId, conditionCode, explanation, detail));
        afterCommit(r).block();
        return r;
    }

    /** {@link #raise} on boundedElastic; errors are logged, never propagated (traps call this). */
    public Mono<Raised> raiseAsync(String deviceId, String conditionCode, String explanation,
                                   Map<String, Object> detail) {
        return Mono.fromCallable(() -> tx.execute(s -> raiseInTx(deviceId, conditionCode, explanation, detail)))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(r -> afterCommit(r).thenReturn(r))
                .doOnError(e -> log.error("Anomaly {} for {} could not be recorded", conditionCode, deviceId, e))
                .onErrorResume(e -> Mono.empty());
    }

    /**
     * Inside the caller's transaction (Protocol C Tx 1 calls it with the devices row already locked). The audit append
     * is the last statement, so the caller must not take row locks after this returns.
     */
    public Raised raiseInTx(String deviceId, String conditionCode, String explanation, Map<String, Object> detail) {
        List<String> state = jdbc.queryForList("SELECT trust_state::text FROM devices WHERE device_id = ? FOR UPDATE",
                String.class, deviceId);
        if (state.isEmpty()) {
            throw new IllegalArgumentException("unknown device " + deviceId);
        }
        String previous = state.get(0);
        Instant now = clock.instant();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("device_id", deviceId);
        payload.put("condition_code", conditionCode);
        payload.put("previous_state", previous);
        payload.put("detail", stringify(detail));
        if (!"ACTIVE".equals(previous)) {
            payload.put("action", "AUDIT_ONLY");
            audit.append(AUDIT_EVENT, ACTOR, payload);
            return new Raised(deviceId, conditionCode, previous, null, List.of(), now);
        }

        List<CertKey> keys = jdbc.query("""
                SELECT issuer_key_hash, serial_number FROM certificates
                 WHERE device_id = ? AND status IN ('ACTIVE', 'ISSUED_PENDING_USE', 'RENEWED')
                 FOR UPDATE
                """, (rs, i) -> CertKey.of(rs.getString(1), rs.getString(2)), deviceId);
        keys.forEach(k -> denyList.add(k, now, "REVOKED")); // before commit: fail closed
        jdbc.update("""
                UPDATE certificates SET status = 'REVOKED', revocation_reason = ?, revoked_at = ?
                 WHERE device_id = ? AND status IN ('ACTIVE', 'ISSUED_PENDING_USE', 'RENEWED')
                """, REVOCATION_REASON, Timestamp.from(now), deviceId);
        jdbc.update("UPDATE devices SET trust_state = 'REAUTH_REQUIRED', updated_at = NOW() WHERE device_id = ?",
                deviceId);

        List<UUID> assignment = jdbc.queryForList(
                "SELECT assignment_id FROM patient_device_assignments WHERE device_id = ? AND status = 'ACTIVE'",
                UUID.class, deviceId);
        UUID alertId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO clinical_alerts (alert_id, device_id, assignment_id, baseline_version, alert_type,
                                             alert_status, triggering_batch_ids, explanation_summary, condition_code)
                VALUES (?, ?, ?, NULL, 'SECURITY_ANOMALY_ALERT', 'ACTIVE', '{}', ?, ?)
                """, alertId, deviceId, assignment.isEmpty() ? null : assignment.get(0), explanation, conditionCode);

        payload.put("action", "REAUTH_REQUIRED");
        payload.put("alert_id", alertId.toString());
        payload.put("certs_revoked", keys.size());
        audit.append(AUDIT_EVENT, ACTOR, payload); // last (DECISIONS #67, #82)
        return new Raised(deviceId, conditionCode, previous, alertId, keys, now);
    }

    /** After commit: close every live socket of the revoked certificates, then republish the CRLs. */
    public Mono<Void> afterCommit(Raised r) {
        if (r == null) {
            return Mono.empty();
        }
        if (r.auditOnly()) {
            log.info("Anomaly {} for {} recorded (device already {}; audit only)", r.conditionCode(), r.deviceId(),
                    r.previousState());
            return Mono.empty();
        }
        metrics.increment("anomaly." + r.conditionCode());
        long t0 = System.nanoTime();
        return Flux.fromIterable(r.revoked())
                .flatMap(k -> (eviction.enabled() ? sessions.evictByCert(k) : Mono.just(0))
                        .doOnNext(closed -> revocationLog.recordCommitted(new com.vitalsshield.server.signer
                                .RevocationResult(k, r.deviceId(), REVOCATION_REASON, r.at(), closed,
                                (System.nanoTime() - t0) / 1000))))
                .reduce(0, Integer::sum)
                .doOnNext(closed -> {
                    log.warn("SECURITY ANOMALY {} for {}: REAUTH_REQUIRED, {} certificate(s) revoked SUSPECTED_CLONE,"
                                    + " {} socket(s) closed, alert {}", r.conditionCode(), r.deviceId(),
                            r.revoked().size(), closed, r.alertId());
                    r.revoked().stream().map(CertKey::issuerKeyHash).distinct().forEach(crls::revocationCommitted);
                })
                .then();
    }

    /** Audit payload values must be strings, integers, booleans or maps. */
    private static Map<String, Object> stringify(Map<String, Object> detail) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (detail != null) {
            detail.forEach((k, v) -> out.put(k, v instanceof Number n && !(v instanceof Double || v instanceof Float)
                    ? (Object) n.longValue() : v instanceof Boolean b ? b : String.valueOf(v)));
        }
        return out;
    }
}
