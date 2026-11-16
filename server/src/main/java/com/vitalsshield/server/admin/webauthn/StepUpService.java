package com.vitalsshield.server.admin.webauthn;

// LOCK ORDER (DECISIONS #70), in every transaction: devices -> telemetry_records -> patient_device_assignments
// -> clinical_alerts -> audit advisory lock LAST. This class: restore updates devices, then the audit append.

import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import com.vitalsshield.server.audit.AuditLog;
import com.vitalsshield.server.quarantine.QuarantineController;
import com.yubico.webauthn.AssertionRequest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Step-up approvals bound to the action (DECISIONS #58). begin stores the validated parameters and a 16-byte nonce
 * server-side and returns assertion options whose challenge is SHA-256 of the canonical action encoding; finish takes
 * only the assertion and returns the STORED parameters, so a request cannot swap them after the clinician approved.
 * Blocking.
 */
@Service
public class StepUpService {

    public enum Purpose { QUARANTINE, RESTORE_ACTIVE }

    public record Begun(String ceremonyId, String optionsJson) {
    }

    /** What the clinician approved, with the assertion that approved it. */
    public record Approved(Purpose purpose, QuarantineController.Params params, String deviceId,
                           WebAuthnService.VerifiedAssertion assertion) {
    }

    private record Pending(Purpose purpose, String deviceId, QuarantineController.Params params, String clinicianId,
                           AssertionRequest request) {
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final WebAuthnService webauthn;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final AuditLog audit;
    private final CeremonyStore<Pending> ceremonies;

    public StepUpService(WebAuthnService webauthn, JdbcTemplate jdbc, TransactionTemplate tx, AuditLog audit,
                         Clock clock) {
        this.webauthn = webauthn;
        this.jdbc = jdbc;
        this.tx = tx;
        this.audit = audit;
        this.ceremonies = new CeremonyStore<>(clock);
    }

    public Begun beginQuarantine(AdminSessionStore.Session session, QuarantineController.Params p) {
        byte[] nonce = nonce();
        byte[] digest = CanonicalEncodings.quarantineApprovalDigest(p.deviceId(), p.lookbackMinutes(), p.reason(), nonce);
        return begin(new Pending(Purpose.QUARANTINE, p.deviceId(), p, session.clinicianId(),
                webauthn.boundAssertion(digest, session.credentialId(), session.clinicianId())));
    }

    /** Spec Section 4 recovery: only from REAUTH_REQUIRED (checked here and again at commit). */
    public Begun beginRestore(AdminSessionStore.Session session, String deviceId) {
        String state = trustState(deviceId);
        if (state == null) {
            throw new WebAuthnFailure(404, "DEVICE_NOT_FOUND", deviceId);
        }
        if (!"REAUTH_REQUIRED".equals(state)) {
            throw new WebAuthnFailure(409, "INVALID_STATE", state);
        }
        byte[] digest = CanonicalEncodings.restoreApprovalDigest(deviceId, nonce());
        return begin(new Pending(Purpose.RESTORE_ACTIVE, deviceId, null, session.clinicianId(),
                webauthn.boundAssertion(digest, session.credentialId(), session.clinicianId())));
    }

    /**
     * Single use (a second finish is 410), same clinician as begin, purpose and device must match the URL. Any
     * failure means nothing is executed.
     */
    public Approved finish(AdminSessionStore.Session session, Purpose purpose, String deviceId, String ceremonyId,
                           String credentialJson) {
        Pending p = ceremonies.take(ceremonyId).orElseThrow(WebAuthnFailure::gone);
        if (!p.clinicianId().equals(session.clinicianId())) {
            throw new WebAuthnFailure(403, "CLINICIAN_MISMATCH", "ceremony belongs to another clinician");
        }
        if (p.purpose() != purpose || !p.deviceId().equals(deviceId)) {
            throw new WebAuthnFailure(400, "CEREMONY_MISMATCH", "ceremony is for another action or device");
        }
        WebAuthnService.VerifiedAssertion a = webauthn.finishAssertion(p.request(), webauthn.parseAssertion(credentialJson),
                WebAuthnService.Use.STEP_UP);
        if (!a.clinicianId().equals(session.clinicianId())) {
            throw new WebAuthnFailure(403, "CLINICIAN_MISMATCH", "assertion from another clinician's passkey");
        }
        return new Approved(purpose, p.params(), p.deviceId(), a);
    }

    /** REAUTH_REQUIRED to ACTIVE with epoch_resync_allowed, and the audit entry, in one transaction. */
    public Map<String, Object> restore(Approved approved) {
        return tx.execute(s -> {
            int n = jdbc.update("""
                    UPDATE devices SET trust_state = 'ACTIVE', epoch_resync_allowed = TRUE, updated_at = NOW()
                     WHERE device_id = ? AND trust_state = 'REAUTH_REQUIRED'
                    """, approved.deviceId());
            if (n != 1) {
                throw new WebAuthnFailure(409, "INVALID_STATE", "device is no longer REAUTH_REQUIRED");
            }
            audit.append("DEVICE_RESTORED", approved.assertion().clinicianId(), Map.of(
                    "device_id", approved.deviceId(), "assertion_sha256", approved.assertion().sha256Hex()));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("device_id", approved.deviceId());
            out.put("trust_state", "ACTIVE");
            out.put("epoch_resync_allowed", true);
            out.put("approved_by", approved.assertion().clinicianId());
            return out;
        });
    }

    private Begun begin(Pending p) {
        String id = ceremonies.put(p);
        return new Begun(id, WebAuthnService.requestJson(p.request()));
    }

    private String trustState(String deviceId) {
        return jdbc.queryForList("SELECT trust_state::text FROM devices WHERE device_id = ?", String.class, deviceId)
                .stream().findFirst().orElse(null);
    }

    private static byte[] nonce() {
        byte[] n = new byte[CanonicalEncodings.NONCE_LENGTH];
        RANDOM.nextBytes(n);
        return n;
    }
}
