package com.vitalsshield.devtools;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Dev-only stand-in for clinician provisioning until Phase 6 (DECISIONS #32). One transaction upserts a fake
 * clinician passkey, the device, an ACTIVE assignment, and a fresh bootstrap token. Every WebAuthn field is visibly
 * fake. The SQL lives only here: the CLI ({@link SeedDemoDevice}) and the integration tests both call it.
 */
public final class DevSeeder {

    public static final String FAKE_WEBAUTHN = "DEV-SEED-NOT-WEBAUTHN";
    public static final String FAKE_SIGNATURE = "DEV-SEED-NOT-A-SIGNATURE";
    public static final String CREDENTIAL_ID = "dev-seed";
    public static final String CLINICIAN_ID = "dev-seed-clinician";
    public static final String HARDWARE_MODEL = "vitalsshield-sim-v1";

    public record Request(String deviceId, String patientId, int birthYear, Duration tokenTtl) {
        public static Request defaults(String deviceId) {
            return new Request(deviceId, "demo-patient-001", 1985, Duration.ofHours(1));
        }
    }

    public record Result(String token, UUID tokenId, UUID assignmentId) {
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final Clock clock;

    public DevSeeder(JdbcTemplate jdbc, TransactionTemplate tx, Clock clock) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.clock = clock;
    }

    public Result seed(Request req) {
        return tx.execute(status -> {
            Instant now = clock.instant();
            jdbc.update("""
                    INSERT INTO clinician_passkeys (credential_id_b64, clinician_id, public_key_cose_der_b64,
                                                    passkey_registry_kms_sig)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT (credential_id_b64) DO NOTHING
                    """, CREDENTIAL_ID, CLINICIAN_ID, FAKE_WEBAUTHN, FAKE_SIGNATURE);
            jdbc.update("""
                    INSERT INTO devices (device_id, hardware_model) VALUES (?, ?)
                    ON CONFLICT (device_id) DO NOTHING
                    """, req.deviceId(), HARDWARE_MODEL);

            List<UUID> active = jdbc.queryForList(
                    "SELECT assignment_id FROM patient_device_assignments WHERE device_id = ? AND status = 'ACTIVE'",
                    UUID.class, req.deviceId());
            UUID assignmentId;
            if (active.isEmpty()) {
                assignmentId = UUID.randomUUID();
                jdbc.update("""
                        INSERT INTO patient_device_assignments (assignment_id, device_id, patient_id, patient_birth_year,
                                                                active_from, max_renewal_horizon, status)
                        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                        """, assignmentId, req.deviceId(), req.patientId(), req.birthYear(), Timestamp.from(now),
                        Timestamp.from(now.plus(Duration.ofDays(30))));
            } else {
                assignmentId = active.get(0);
            }

            String token = newToken();
            UUID tokenId = UUID.randomUUID();
            jdbc.update("""
                    INSERT INTO device_bootstrap_tokens (token_id, device_id, token_hash, status, issued_by_clinician,
                                                         webauthn_cred_id_b64, webauthn_auth_data, webauthn_client_json,
                                                         webauthn_signature, expires_at)
                    VALUES (?, ?, ?, 'ISSUED', ?, ?, ?, ?, ?, ?)
                    """, tokenId, req.deviceId(), sha256Hex(token), CLINICIAN_ID, CREDENTIAL_ID,
                    FAKE_WEBAUTHN, FAKE_WEBAUTHN, FAKE_WEBAUTHN, Timestamp.from(now.plus(req.tokenTtl())));
            return new Result(token, tokenId, assignmentId);
        });
    }

    /** 32 random bytes, base64url without padding (43 ASCII characters). */
    static String newToken() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static String sha256Hex(String token) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
