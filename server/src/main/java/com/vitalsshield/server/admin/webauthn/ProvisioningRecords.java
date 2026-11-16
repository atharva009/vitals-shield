package com.vitalsshield.server.admin.webauthn;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The provisioning rows, shared by {@link ProvisioningService} and the dev seed tool so both write exactly the same
 * thing. Call inside a transaction. webauthn_* columns hold base64url of the raw bytes the authenticator signed
 * (authenticatorData, clientDataJSON) and of the DER signature, so Protocol A can re-verify them byte for byte.
 */
public final class ProvisioningRecords {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcTemplate jdbc;

    public ProvisioningRecords(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public record Assignment(UUID id, boolean created) {
    }

    /** Creates the device (PROVISIONED) if absent and an ACTIVE assignment if none exists. */
    public Assignment ensureDeviceAndAssignment(String deviceId, String hardwareModel, String patientId, int birthYear,
                                          int maxRenewalDays, Instant now) {
        jdbc.update("INSERT INTO devices (device_id, hardware_model) VALUES (?, ?) ON CONFLICT (device_id) DO NOTHING",
                deviceId, hardwareModel);
        List<UUID> active = jdbc.queryForList(
                "SELECT assignment_id FROM patient_device_assignments WHERE device_id = ? AND status = 'ACTIVE'",
                UUID.class, deviceId);
        if (!active.isEmpty()) {
            return new Assignment(active.get(0), false);
        }
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO patient_device_assignments (assignment_id, device_id, patient_id, patient_birth_year,
                                                        active_from, max_renewal_horizon, status)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
                """, id, deviceId, patientId, birthYear, Timestamp.from(now),
                Timestamp.from(now.plus(Duration.ofDays(maxRenewalDays))));
        return new Assignment(id, true);
    }

    public UUID insertToken(String deviceId, String token, String clinicianId, WebAuthnService.VerifiedAssertion a,
                            Instant expiresAt) {
        UUID tokenId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO device_bootstrap_tokens (token_id, device_id, token_hash, status, issued_by_clinician,
                                                     webauthn_cred_id_b64, webauthn_auth_data, webauthn_client_json,
                                                     webauthn_signature, expires_at)
                VALUES (?, ?, ?, 'ISSUED', ?, ?, ?, ?, ?, ?)
                """, tokenId, deviceId, WebAuthnBytes.sha256Hex(token.getBytes(StandardCharsets.US_ASCII)), clinicianId,
                a.credentialId(), WebAuthnBytes.b64url(a.authenticatorData()), WebAuthnBytes.b64url(a.clientDataJson()),
                WebAuthnBytes.b64url(a.signature()), Timestamp.from(expiresAt));
        return tokenId;
    }

    /** 32 random bytes, base64url without padding (43 ASCII characters). */
    public static String newToken() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return WebAuthnBytes.b64url(b);
    }
}
