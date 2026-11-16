package com.vitalsshield.server.admin.webauthn;

import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import com.vitalsshield.server.audit.AuditLog;
import com.yubico.webauthn.AssertionRequest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Device provisioning with a clinician approval (DECISIONS #4, #10). begin creates the device and assignment, draws
 * the bootstrap token, and returns assertion options whose challenge is the 32-byte ProvisioningDigest (spec encoding
 * 2). finish verifies the assertion and stores the token hash with the real assertion, so Protocol A can re-verify it
 * (DECISIONS #57). The token is returned once and never again. Blocking.
 */
@Service
public class ProvisioningService {

    public static final Duration TOKEN_TTL = Duration.ofMinutes(15);

    public record BeginRequest(String deviceId, String hardwareModel, String patientId, int birthYear,
                               int maxRenewalDays) {
    }

    public record Begun(String ceremonyId, String optionsJson) {
    }

    public record Provisioned(String deviceId, String bootstrapToken, Instant expiresAt, UUID assignmentId,
                              String approvedBy, String assertionSha256) {
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("device_id", deviceId);
            m.put("bootstrap_token", bootstrapToken);
            m.put("expires_at", expiresAt.toString());
            m.put("assignment_id", assignmentId.toString());
            m.put("approved_by", approvedBy);
            return m;
        }
    }

    private record Pending(String deviceId, String token, Instant expiresAt, UUID assignmentId, String clinicianId,
                           AssertionRequest request, WebAuthnService.Use use) {
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final WebAuthnService webauthn;
    private final AuditLog audit;
    private final Clock clock;
    private final ProvisioningRecords records;
    private final CeremonyStore<Pending> ceremonies;

    public ProvisioningService(JdbcTemplate jdbc, TransactionTemplate tx, WebAuthnService webauthn, AuditLog audit,
                               Clock clock) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.webauthn = webauthn;
        this.audit = audit;
        this.clock = clock;
        this.records = new ProvisioningRecords(jdbc);
        this.ceremonies = new CeremonyStore<>(clock);
    }

    /** From a clinician's session (the HTTP route). */
    public Begun begin(String clinicianId, String credentialId, BeginRequest req) {
        return begin(clinicianId, credentialId, req, WebAuthnService.Use.PROVISION);
    }

    /** The dev seed tool's path: the only one a DEV_SEED credential may finish, in the local profile (#66). */
    public Begun beginForSeedTool(String clinicianId, String credentialId, BeginRequest req) {
        return begin(clinicianId, credentialId, req, WebAuthnService.Use.SEED_PROVISION);
    }

    private Begun begin(String clinicianId, String credentialId, BeginRequest req, WebAuthnService.Use use) {
        Instant now = clock.instant();
        UUID assignmentId = tx.execute(s -> {
            ProvisioningRecords.Assignment a = records.ensureDeviceAndAssignment(req.deviceId(), req.hardwareModel(),
                    req.patientId(), req.birthYear(), req.maxRenewalDays(), now);
            if (a.created()) {
                audit.append("ASSIGNMENT_CREATED", clinicianId, Map.of("device_id", req.deviceId(),
                        "assignment_id", a.id().toString(), "patient_id", req.patientId()));
            }
            return a.id();
        });
        String token = ProvisioningRecords.newToken();
        Instant expiresAt = now.plus(TOKEN_TTL).truncatedTo(ChronoUnit.MILLIS);
        byte[] digest = CanonicalEncodings.provisioningDigest(req.deviceId(), token, expiresAt.toEpochMilli());
        AssertionRequest request = webauthn.boundAssertion(digest, credentialId, clinicianId);
        String ceremonyId = ceremonies.put(new Pending(req.deviceId(), token, expiresAt, assignmentId, clinicianId,
                request, use));
        return new Begun(ceremonyId, WebAuthnService.requestJson(request));
    }

    public Provisioned finish(String clinicianId, String ceremonyId, String credentialJson) {
        Pending p = ceremonies.take(ceremonyId).orElseThrow(WebAuthnFailure::gone);
        if (!p.clinicianId().equals(clinicianId)) {
            throw new WebAuthnFailure(403, "CLINICIAN_MISMATCH", "ceremony belongs to another clinician");
        }
        WebAuthnService.VerifiedAssertion a = webauthn.finishAssertion(p.request(), webauthn.parseAssertion(credentialJson),
                p.use());
        if (!a.clinicianId().equals(clinicianId)) {
            throw new WebAuthnFailure(403, "CLINICIAN_MISMATCH", "assertion from another clinician's passkey");
        }
        tx.executeWithoutResult(s -> {
            records.insertToken(p.deviceId(), p.token(), clinicianId, a, p.expiresAt());
            audit.append("DEVICE_PROVISIONED", clinicianId, Map.of("device_id", p.deviceId(),
                    "assignment_id", p.assignmentId().toString(), "expires_at", p.expiresAt().toString(),
                    "assertion_sha256", a.sha256Hex()));
        });
        return new Provisioned(p.deviceId(), p.token(), p.expiresAt(), p.assignmentId(), clinicianId, a.sha256Hex());
    }

    /** POST /assignments/{id}/close: ACTIVE to CLOSED, active_until = now. False if no ACTIVE row matched. */
    public boolean closeAssignment(String clinicianId, UUID assignmentId) {
        Instant now = clock.instant();
        Boolean done = tx.execute(s -> {
            int n = jdbc.update("""
                    UPDATE patient_device_assignments SET status = 'CLOSED', active_until = GREATEST(?, active_from)
                     WHERE assignment_id = ? AND status = 'ACTIVE'
                    """, java.sql.Timestamp.from(now), assignmentId);
            if (n == 1) {
                audit.append("ASSIGNMENT_CLOSED", clinicianId, Map.of("assignment_id", assignmentId.toString()));
            }
            return n == 1;
        });
        return Boolean.TRUE.equals(done);
    }
}
