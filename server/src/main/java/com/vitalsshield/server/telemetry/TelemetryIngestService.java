package com.vitalsshield.server.telemetry;

import com.vitalsshield.crypto.TelemetryJws;
import com.vitalsshield.server.gateway.ResolvedCert;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * POST /api/v1/telemetry/ingest (spec Section 5). Order: certificate binding (x5t#S256 = TLS leaf = stored thumbprint),
 * JWS verification with the TLS leaf's key only, strict payload validation, assignment check, classification, then
 * the spec's single-CTE window update and insert, unchanged, as one autocommit statement on boundedElastic.
 */
@Service
public class TelemetryIngestService {

    /** Spec Section 5, verbatim. */
    static final String WINDOW_CTE = """
            WITH window_update AS (
                UPDATE devices
                SET
                    replay_bitmap = CASE
                        WHEN (:seq - last_sequence_num) >= 64 THEN 1::BIGINT
                        WHEN (:seq - last_sequence_num) > 0   THEN (replay_bitmap << (:seq - last_sequence_num)::INT) | 1::BIGINT
                        ELSE replay_bitmap | (1::BIGINT << (last_sequence_num - :seq)::INT)
                    END,
                    last_sequence_num = GREATEST(last_sequence_num, :seq),
                    last_ingested_at  = NOW(),
                    updated_at        = NOW()
                WHERE device_id = :deviceId
                  AND trust_state = 'ACTIVE'
                  AND boot_epoch = :bootEpoch
                  AND (
                      :seq > last_sequence_num
                      OR (
                          (last_sequence_num - :seq) BETWEEN 0 AND 63
                          AND ((replay_bitmap >> (last_sequence_num - :seq)::INT) & 1::BIGINT) = 0
                      )
                  )
                RETURNING device_id, boot_epoch
            )
            INSERT INTO telemetry_records (
                batch_id, device_id, assignment_id, issuer_key_hash, serial_number,
                boot_epoch, sequence_number, measured_at, transmitted_at, heart_rate_bpm,
                hrv_rmssd_ms, spo2_pct, perfusion_index, step_cadence_spm,
                motion_g_rms, firmware_hash_meta, payload_sha256, jws_compact, trust_state
            )
            SELECT
                :batchId, w.device_id, :assignmentId, :issuerKeyHash, :serialNumber,
                w.boot_epoch, :seq, :measuredAt, :transmittedAt, :hr,
                :hrv, :spo2, :perfusion, :cadence,
                :motion, :fwHash, :payloadSha256, :jwsCompact, :trustState
            FROM window_update w
            ON CONFLICT DO NOTHING
            RETURNING batch_id;
            """;

    private final NamedParameterJdbcTemplate jdbc;
    private final TelemetryMetrics metrics;
    private final Clock clock;

    public TelemetryIngestService(NamedParameterJdbcTemplate jdbc, TelemetryMetrics metrics, Clock clock) {
        this.jdbc = jdbc;
        this.metrics = metrics;
        this.clock = clock;
    }

    /** Result: HTTP status and body. */
    public record Outcome(int status, Map<String, Object> body) {
    }

    public Mono<Outcome> ingest(String jwsCompact, X509Certificate tlsLeaf, ResolvedCert cert) {
        return Mono.fromCallable(() -> ingestBlocking(jwsCompact, tlsLeaf, cert))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(IngestRejection.class, r -> {
                    metrics.increment("rejected." + r.status() + "." + r.body().get("error"));
                    return Mono.just(new Outcome(r.status(), r.body()));
                });
    }

    Outcome ingestBlocking(String jwsCompact, X509Certificate tlsLeaf, ResolvedCert cert) {
        // 2. Certificate binding: TLS leaf thumbprint == stored thumbprint (== header x5t#S256, checked in step 3).
        String tlsThumb = TelemetryJws.thumbprint(der(tlsLeaf));
        if (!tlsThumb.equals(cert.certThumbprintS256())) {
            throw IngestRejection.of(401, "JWS_CERT_MISMATCH");
        }
        // 3. Verify with the TLS leaf's key; never a key from the JWS.
        byte[] payloadBytes;
        try {
            payloadBytes = TelemetryJws.parseAndVerify(jwsCompact, tlsThumb, tlsLeaf.getPublicKey());
        } catch (TelemetryJws.Rejected r) {
            metrics.increment("jws_rejected." + r.reason());
            if (r.reason() == TelemetryJws.Reason.X5T) {
                throw IngestRejection.of(401, "JWS_CERT_MISMATCH");
            }
            throw IngestRejection.of(401, "JWS_INVALID", r.reason().name());
        }
        metrics.increment("jws_verified");

        // 4. Strict payload.
        TelemetryPayload p = TelemetryPayloadValidator.parse(payloadBytes);
        TelemetryPayloadValidator.validate(p, cert.deviceId(), clock.instant());

        // 5. Assignment must be the device's ACTIVE one.
        List<Map<String, Object>> assignment = jdbc.queryForList("""
                SELECT assignment_id, active_from FROM patient_device_assignments
                 WHERE device_id = :d AND status = 'ACTIVE'
                """, Map.of("d", p.deviceId()));
        if (assignment.isEmpty()) {
            throw IngestRejection.of(409, "DEVICE_UNASSIGNED");
        }
        UUID currentAssignment = (UUID) assignment.get(0).get("assignment_id");
        if (!currentAssignment.equals(p.assignmentId())) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", "ASSIGNMENT_CHANGED");
            body.put("current_assignment_id", currentAssignment.toString());
            body.put("assignment_active_from", ((Timestamp) assignment.get(0).get("active_from")).toInstant().toString());
            throw new IngestRejection(409, body);
        }

        // PHASE 8 HOOK: first-use switchover. If cert.status() is ISSUED_PENDING_USE, this is the first valid batch
        // signed by the renewed certificate: call the Signer RPC to make it ACTIVE and move superseded_serial to RENEWED
        // (grace_expires_at = NOW() + 60 s) before or atomically with the insert below.

        // 6. Classification (DECISIONS #46).
        String trustState = TelemetryClassifier.classify(p.metrics());
        String payloadSha256 = HexFormat.of().formatHex(sha256(payloadBytes));

        // 7. Spec Section 5 CTE, one autocommit statement.
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("seq", p.sequenceNumber())
                .addValue("deviceId", p.deviceId())
                .addValue("bootEpoch", p.bootEpoch())
                .addValue("batchId", p.batchId())
                .addValue("assignmentId", p.assignmentId())
                .addValue("issuerKeyHash", cert.issuerKeyHash())
                .addValue("serialNumber", cert.serial())
                .addValue("measuredAt", Timestamp.from(p.measuredAt()))
                .addValue("transmittedAt", Timestamp.from(p.transmittedAt()))
                .addValue("hr", p.metrics().heartRateBpm())
                .addValue("hrv", p.metrics().hrvRmssdMs())
                .addValue("spo2", p.metrics().spo2Pct())
                .addValue("perfusion", p.metrics().signalPerfusionIndex())
                .addValue("cadence", p.metrics().stepCadenceSpm())
                .addValue("motion", p.metrics().motionGRms())
                .addValue("fwHash", p.firmwareHash())
                .addValue("payloadSha256", payloadSha256)
                .addValue("jwsCompact", jwsCompact)
                // Bound as an untyped literal so Postgres infers the telemetry_trust_state enum without changing the SQL.
                .addValue("trustState", new SqlParameterValue(Types.OTHER, trustState));
        List<UUID> inserted = jdbc.queryForList(WINDOW_CTE, params, UUID.class);

        // 8. Accepted.
        if (!inserted.isEmpty()) {
            metrics.increment("accepted." + trustState);
            return ok(p.batchId(), trustState, false);
        }
        // 9. No row: work out why.
        return classifyNoRow(p, payloadSha256);
    }

    private Outcome classifyNoRow(TelemetryPayload p, String payloadSha256) {
        List<Map<String, Object>> existing = jdbc.queryForList("""
                SELECT payload_sha256, boot_epoch, trust_state::text AS trust_state FROM telemetry_records
                 WHERE device_id = :d AND batch_id = :b
                """, Map.of("d", p.deviceId(), "b", p.batchId()));
        if (!existing.isEmpty()) {
            Map<String, Object> row = existing.get(0);
            if (payloadSha256.equals(row.get("payload_sha256")) && p.bootEpoch().equals(row.get("boot_epoch"))) {
                metrics.increment("idempotent_retries");
                return ok(p.batchId(), (String) row.get("trust_state"), true);
            }
            throw IngestRejection.of(409, "BATCH_ID_REUSED");
        }
        Map<String, Object> device = jdbc.queryForMap("""
                SELECT trust_state::text AS trust_state, boot_epoch, last_sequence_num FROM devices WHERE device_id = :d
                """, Map.of("d", p.deviceId()));
        if (!"ACTIVE".equals(device.get("trust_state"))) {
            throw IngestRejection.of(403, "DEVICE_NOT_ACTIVE");
        }
        if (!p.bootEpoch().equals(device.get("boot_epoch"))) {
            throw IngestRejection.of(409, "BOOT_EPOCH_MISMATCH");
        }
        if ((Long) device.get("last_sequence_num") - p.sequenceNumber() > 63) {
            throw IngestRejection.of(409, "SEQUENCE_TOO_OLD");
        }
        throw IngestRejection.of(409, "DUPLICATE_SEQUENCE_REPLAY");
    }

    private Outcome ok(UUID batchId, String trustState, boolean idempotent) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accepted", true);
        body.put("batch_id", batchId.toString());
        body.put("trust_state", trustState);
        body.put("idempotent_retry", idempotent);
        return new Outcome(200, body);
    }

    static byte[] der(X509Certificate c) {
        try {
            return c.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
