package com.vitalsshield.server.enrollment;

// LOCK ORDER (DECISIONS #70), in every transaction: devices -> telemetry_records -> patient_device_assignments
// -> clinical_alerts -> audit advisory lock LAST. This class: devices FOR UPDATE (activation) and plain reads of the
// ACTIVE assignment; it never locks telemetry_records, assignments or alerts, and never appends to the audit log.

import com.vitalsshield.server.admin.AdminProperties;
import com.vitalsshield.server.admin.webauthn.ProvisioningAssertionVerifier;
import com.vitalsshield.crypto.CsrFactory;
import com.vitalsshield.crypto.DerSignatures;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import com.vitalsshield.server.kms.KmsSigner;
import com.vitalsshield.server.pki.ActiveKmsKeys;
import com.vitalsshield.server.pki.CaIssuerRepository;
import com.vitalsshield.server.pki.CertificateIssuer;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.pki.IssuedSerialLedger;
import com.vitalsshield.server.pki.KeyPurpose;
import com.vitalsshield.server.pki.Pems;
import com.vitalsshield.server.pki.PkiProperties;
import com.vitalsshield.server.pki.SerialNumbers;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Protocol A (spec Section 4). Three stages, so no DB lock is ever held across a KMS call:
 * <ol>
 *   <li>Short Tx 1 (claim): lock the token row, ISSUED to CLAIMING; check the device and its ACTIVE assignment.</li>
 *   <li>No transaction: verify the CSR (OLK possession) and the DEK proof, sign the DEK registry anchor with KMS Key #4,
 *       issue the leaf with the Device Intermediate.</li>
 *   <li>Short Tx 2 (activate): supersede prior certificates (deny-list first), update the device, insert the new
 *       certificate, consume the token. After commit: evict old sockets, republish the CRL.</li>
 * </ol>
 * Token semantics (DECISIONS #34): a proof failure burns the token (REVOKED); a transient KMS or DB failure returns it
 * to ISSUED; a CLAIMING token older than 2 minutes can be claimed again.
 *
 * <p>Serial ledger (DECISIONS #38): Tx 1 reserves the leaf serial before any KMS call; Tx 2 records it. Every path
 * that does not activate voids it, and if a leaf was already signed it is stored REVOKED (REPLACED_BEFORE_USE) and
 * deny-listed, so every serial the CA signs is recorded or revocable.
 */
@Service
public class EnrollmentService {

    private static final Logger log = LoggerFactory.getLogger(EnrollmentService.class);
    /** 503 Retry-After is a random integer from 3 to 8 seconds, so retries from many devices spread out. */
    static int retryAfterSeconds() {
        return java.util.concurrent.ThreadLocalRandom.current().nextInt(3, 9);
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final KmsSigner kmsSigner;
    private final ActiveKmsKeys kmsKeys;
    private final CertificateIssuer issuer;
    private final CertificateDenyList denyList;
    private final ActiveSessionRegistry sessions;
    private final CrlService crls;
    private final PkiProperties pki;
    private final Clock clock;
    private final IssuedSerialLedger ledger;
    private final CaIssuerRepository issuers;
    private final EnrollmentHooks hooks;
    private final AdminProperties admin;
    private final ProvisioningAssertionVerifier approvals;

    public EnrollmentService(JdbcTemplate jdbc, TransactionTemplate tx, KmsSigner kmsSigner, ActiveKmsKeys kmsKeys,
                             CertificateIssuer issuer, CertificateDenyList denyList, ActiveSessionRegistry sessions,
                             CrlService crls, PkiProperties pki, Clock clock, IssuedSerialLedger ledger,
                             CaIssuerRepository issuers, ObjectProvider<EnrollmentHooks> hooks,
                             AdminProperties admin, ProvisioningAssertionVerifier approvals) {
        this.admin = admin;
        this.approvals = approvals;
        this.jdbc = jdbc;
        this.tx = tx;
        this.kmsSigner = kmsSigner;
        this.kmsKeys = kmsKeys;
        this.issuer = issuer;
        this.denyList = denyList;
        this.sessions = sessions;
        this.crls = crls;
        this.pki = pki;
        this.clock = clock;
        this.ledger = ledger;
        this.issuers = issuers;
        this.hooks = hooks.getIfAvailable(() -> EnrollmentHooks.NONE);
    }

    /** Runs the blocking flow on boundedElastic, then the after-commit eviction. */
    public Mono<EnrollmentResult> enroll(EnrollRequest req) {
        return Mono.fromCallable(() -> enrollBlocking(req))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(result -> Flux.fromIterable(result.supersededCerts())
                        .concatMap(sessions::evictByCert)
                        .then(Mono.fromRunnable(() -> result.supersededCerts()
                                .forEach(k -> crls.revocationCommitted(k.issuerKeyHash()))))
                        .thenReturn(result));
    }

    record Claim(UUID tokenId, String assignmentId, Instant assignmentActiveFrom, CertKey reserved,
                 BigInteger serial, ProvisioningAssertionVerifier.StoredApproval approval) {
    }

    /** Activation found the token or the reserved serial taken by someone else. */
    static final class ActivationSuperseded extends RuntimeException {
        ActivationSuperseded(String message) {
            super(message);
        }
    }

    EnrollmentResult enrollBlocking(EnrollRequest req) {
        // ---- Short Tx 1: claim ------------------------------------------------------------------------------------
        Object claimed = tx.execute(status -> claim(req));
        if (claimed instanceof EnrollmentResult early) {
            return early;
        }
        Claim claim = (Claim) claimed;

        // ---- Out of transaction: the clinician's provisioning approval (DECISIONS #57), before any KMS call ------
        if (admin.webauthn()) {
            java.util.Optional<String> problem = approvals.verify(req.deviceId(), req.bootstrapToken(), claim.approval());
            if (problem.isPresent()) {
                log.warn("Provisioning approval for {} does not verify; token burned: {}", req.deviceId(),
                        problem.get());
                tx.executeWithoutResult(s -> {
                    setTokenStatusInTx(claim.tokenId(), "REVOKED");
                    ledger.voidSerial(claim.reserved(), req.deviceId(), clock.instant());
                });
                // No CRL republication here: the voided serial was never signed, so this path makes no KMS Sign
                // call at all; the serial joins the CRL at the next republication.
                return EnrollmentResult.error(403, "PROVISIONING_UNVERIFIED");
            }
        }

        // ---- Out of transaction: proofs ---------------------------------------------------------------------------
        SubjectPublicKeyInfo olkSpki;
        try {
            PublicKey dek = EcKeys.publicKeyFromSpki(req.dekSpkiDer());
            olkSpki = CsrFactory.parseAndVerify(req.olkCsrDer());
            if (Arrays.equals(olkSpki.getEncoded(), req.dekSpkiDer())) {
                throw new IllegalArgumentException("DEK and OLK are the same key");
            }
            byte[] proofBytes = CanonicalEncodings.dekEnrollmentProofBytes(
                    req.deviceId(), req.bootstrapToken(), req.olkCsrDer());
            if (!DerSignatures.verify(dek, proofBytes, req.dekProofSig())) {
                throw new IllegalArgumentException("DEK proof signature does not verify");
            }
        } catch (Exception e) {
            log.info("Enrollment proof invalid for {}; token burned: {}", req.deviceId(), e.getMessage());
            tx.executeWithoutResult(s -> {
                setTokenStatusInTx(claim.tokenId(), "REVOKED");
                ledger.voidSerial(claim.reserved(), req.deviceId(), clock.instant());
            });
            return EnrollmentResult.error(400, "PROOF_INVALID");
        }

        // ---- Out of transaction: KMS anchor and leaf issuance -----------------------------------------------------
        Instant provisionedAt = clock.instant().truncatedTo(ChronoUnit.MILLIS);
        String dekAnchorSig;
        X509Certificate cert = null;
        try {
            byte[] anchorBytes = CanonicalEncodings.dekAnchorBytes(
                    req.deviceId(), req.dekSpkiDer(), provisionedAt.toEpochMilli());
            byte[] der = kmsSigner.signDigestBlocking(kmsKeys.requireArn(KeyPurpose.REGISTRY_ANCHOR), sha256(anchorBytes));
            dekAnchorSig = Base64.getEncoder().encodeToString(der);
            cert = issuer.issueDeviceLeaf(req.deviceId(), olkSpki, pki.deviceLeafTtl(), claim.serial());
        } catch (RuntimeException e) {
            log.warn("Enrollment for {} hit a transient failure; token returned: {}", req.deviceId(), e.toString());
            return transientFailure(req, claim, cert);
        }
        // Errors thrown here (test crash simulation) deliberately skip every cleanup path: only the sweep recovers.
        hooks.afterLeafSigned(req.deviceId());

        // ---- Short Tx 2: activate ---------------------------------------------------------------------------------
        X509Certificate signed = cert;
        try {
            return tx.execute(status -> activate(req, claim, signed, dekAnchorSig, provisionedAt));
        } catch (ActivationSuperseded e) {
            log.warn("Enrollment for {} superseded during activation ({}); voiding serial {}", req.deviceId(),
                    e.getMessage(), claim.serial().toString(16));
            abandonSignedLeaf(req.deviceId(), claim, signed, false);
            return EnrollmentResult.error(409, "ENROLLMENT_SUPERSEDED");
        } catch (RuntimeException e) {
            log.warn("Enrollment activation for {} failed; token returned: {}", req.deviceId(), e.toString());
            return transientFailure(req, claim, signed);
        }
    }

    /** KMS or DB trouble: token back to ISSUED, serial VOIDED, and any signed leaf stored REVOKED. */
    private EnrollmentResult transientFailure(EnrollRequest req, Claim claim, X509Certificate signedOrNull) {
        try {
            abandonSignedLeaf(req.deviceId(), claim, signedOrNull, true);
        } catch (RuntimeException cleanup) {
            // The reservation stays RESERVED; the 2-minute sweep voids it and the deny-list/CRL pick it up.
            log.error("Could not void serial {} for {}: {}", claim.serial().toString(16), req.deviceId(),
                    cleanup.toString());
        }
        return EnrollmentResult.unavailable(retryAfterSeconds());
    }

    /**
     * One short transaction: VOID the serial; if a leaf was signed, store it REVOKED (REPLACED_BEFORE_USE) at the same
     * instant and deny-list it (before commit). Optionally returns the token to ISSUED. Then republish the CRL.
     */
    private void abandonSignedLeaf(String deviceId, Claim claim, X509Certificate signedOrNull, boolean returnToken) {
        Instant voidedAt = clock.instant();
        tx.executeWithoutResult(s -> {
            if (returnToken) {
                setTokenStatusInTx(claim.tokenId(), "ISSUED");
            }
            ledger.voidSerial(claim.reserved(), deviceId, voidedAt);
            if (signedOrNull != null) {
                CertKey key = CertKey.from(signedOrNull);
                if (!key.equals(claim.reserved())) {
                    ledger.voidSerial(key, deviceId, voidedAt);
                }
                denyList.add(key, voidedAt, "REVOKED");
                jdbc.update("""
                        INSERT INTO certificates (issuer_key_hash, serial_number, device_id, cert_thumbprint_s256,
                                                  cert_pem, not_before, not_after, status, revocation_reason, revoked_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'REVOKED', 'REPLACED_BEFORE_USE', ?)
                        ON CONFLICT (issuer_key_hash, serial_number) DO NOTHING
                        """, key.issuerKeyHash(), key.serial(), deviceId, x5tS256(encoded(signedOrNull)),
                        Pems.certificate(signedOrNull), Timestamp.from(signedOrNull.getNotBefore().toInstant()),
                        Timestamp.from(signedOrNull.getNotAfter().toInstant()), Timestamp.from(voidedAt));
            }
        });
        crls.revocationCommitted(claim.reserved().issuerKeyHash());
    }

    /** Returns a Claim, or an EnrollmentResult to return immediately. Runs inside Tx 1. */
    private Object claim(EnrollRequest req) {
        List<Map<String, Object>> tokens = jdbc.queryForList("""
                SELECT token_id, status::text AS status, webauthn_cred_id_b64, webauthn_auth_data,
                       webauthn_client_json, webauthn_signature, expires_at
                  FROM device_bootstrap_tokens
                 WHERE device_id = ? AND token_hash = ? AND expires_at > NOW()
                   AND (status = 'ISSUED' OR (status = 'CLAIMING' AND claimed_at < NOW() - INTERVAL '2 minutes'))
                 FOR UPDATE
                """, req.deviceId(), tokenHash(req.bootstrapToken()));
        if (tokens.isEmpty()) {
            return EnrollmentResult.error(401, "INVALID_BOOTSTRAP");
        }
        UUID tokenId = (UUID) tokens.get(0).get("token_id");
        Map<String, Object> t = tokens.get(0);
        ProvisioningAssertionVerifier.StoredApproval approval = new ProvisioningAssertionVerifier.StoredApproval(
                (String) t.get("webauthn_cred_id_b64"), (String) t.get("webauthn_auth_data"),
                (String) t.get("webauthn_client_json"), (String) t.get("webauthn_signature"),
                ((Timestamp) t.get("expires_at")).toInstant());
        if ("CLAIMING".equals(tokens.get(0).get("status"))) {
            // Stale reclaim: whatever the previous claimant reserved more than 2 minutes ago is void (DECISIONS #38).
            for (CertKey voided : ledger.sweepStale()) {
                denyList.add(voided, clock.instant(), "REVOKED");
            }
        }
        jdbc.update("UPDATE device_bootstrap_tokens SET status = 'CLAIMING', claimed_at = NOW() WHERE token_id = ?",
                tokenId);

        String trustState = jdbc.queryForObject("SELECT trust_state::text FROM devices WHERE device_id = ?",
                String.class, req.deviceId());
        if ("DECOMMISSIONED".equals(trustState)) {
            jdbc.update("UPDATE device_bootstrap_tokens SET status = 'REVOKED' WHERE token_id = ?", tokenId);
            return EnrollmentResult.error(403, "DEVICE_DECOMMISSIONED");
        }
        List<Map<String, Object>> assignment = jdbc.queryForList("""
                SELECT assignment_id::text AS id, active_from FROM patient_device_assignments
                 WHERE device_id = ? AND status = 'ACTIVE'
                """, req.deviceId());
        if (assignment.isEmpty()) {
            jdbc.update("UPDATE device_bootstrap_tokens SET status = 'ISSUED', claimed_at = NULL WHERE token_id = ?",
                    tokenId);
            return EnrollmentResult.error(409, "DEVICE_UNASSIGNED");
        }
        String issuerKeyHash = issuers.requireActive(KeyPurpose.DEVICE_INTERMEDIATE).issuerKeyHash();
        BigInteger serial = ledger.reserve(issuerKeyHash, req.deviceId());
        return new Claim(tokenId, (String) assignment.get(0).get("id"),
                ((Timestamp) assignment.get(0).get("active_from")).toInstant(),
                CertKey.of(issuerKeyHash, SerialNumbers.toHex(serial)), serial, approval);
    }

    private EnrollmentResult activate(EnrollRequest req, Claim claim, X509Certificate cert, String dekAnchorSig,
                                      Instant provisionedAt) {
        long storedEpoch = jdbc.queryForObject(
                "SELECT boot_epoch FROM devices WHERE device_id = ? FOR UPDATE", Long.class, req.deviceId());
        String tokenStatus = jdbc.queryForObject(
                "SELECT status::text FROM device_bootstrap_tokens WHERE token_id = ? FOR UPDATE", String.class,
                claim.tokenId());
        if (!"CLAIMING".equals(tokenStatus)) {
            throw new ActivationSuperseded("token is " + tokenStatus);
        }
        CertKey newKey = CertKey.from(cert);
        if (!newKey.equals(claim.reserved()) || !ledger.record(newKey)) {
            throw new ActivationSuperseded("serial reservation no longer RESERVED");
        }

        List<Map<String, Object>> prior = jdbc.queryForList(
                "SELECT issuer_key_hash, serial_number, status::text AS status FROM certificates WHERE device_id = ?",
                req.deviceId());
        List<CertKey> superseded = new ArrayList<>();
        Instant revokedAt = clock.instant();
        for (Map<String, Object> row : prior) {
            if (!"REVOKED".equals(row.get("status"))) {
                CertKey key = CertKey.of((String) row.get("issuer_key_hash"), (String) row.get("serial_number"));
                denyList.add(key, revokedAt, "REVOKED"); // before commit: fail closed
                superseded.add(key);
            }
        }
        jdbc.update("""
                UPDATE certificates
                   SET status = 'REVOKED', revocation_reason = 'SUPERSEDED_BY_REPROVISION', revoked_at = ?
                 WHERE device_id = ? AND status <> 'REVOKED'
                """, Timestamp.from(revokedAt), req.deviceId());

        BootEpochRule.DeviceCounters counters = BootEpochRule.afterEnrollment(storedEpoch, !prior.isEmpty());
        jdbc.update("""
                UPDATE devices
                   SET dek_spki_der_b64 = ?, dek_spki_sha256 = ?, dek_registry_kms_sig = ?, provisioned_at = ?,
                       trust_state = 'ACTIVE', boot_epoch = ?, last_sequence_num = ?, replay_bitmap = ?,
                       epoch_resync_allowed = FALSE, updated_at = NOW()
                 WHERE device_id = ?
                """,
                Base64.getEncoder().encodeToString(req.dekSpkiDer()), HexFormat.of().formatHex(sha256(req.dekSpkiDer())),
                dekAnchorSig, Timestamp.from(provisionedAt), counters.bootEpoch(), counters.lastSequenceNum(),
                counters.replayBitmap(), req.deviceId());

        byte[] der = encoded(cert);
        jdbc.update("""
                INSERT INTO certificates (issuer_key_hash, serial_number, device_id, cert_thumbprint_s256, cert_pem,
                                          not_before, not_after, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
                """, newKey.issuerKeyHash(), newKey.serial(), req.deviceId(), x5tS256(der), Pems.certificate(cert),
                Timestamp.from(cert.getNotBefore().toInstant()), Timestamp.from(cert.getNotAfter().toInstant()));

        int consumed = jdbc.update("""
                UPDATE device_bootstrap_tokens SET status = 'CONSUMED', consumed_at = NOW()
                 WHERE token_id = ? AND status = 'CLAIMING'
                """, claim.tokenId());
        if (consumed != 1) {
            throw new ActivationSuperseded("token was reclaimed during enrollment");
        }
        log.info("Enrolled {}: serial {} boot_epoch {} (superseded {})", req.deviceId(), newKey.serial(),
                counters.bootEpoch(), superseded.size());
        return EnrollmentResult.created(Pems.certificate(cert), counters.bootEpoch(), claim.assignmentId(),
                claim.assignmentActiveFrom().toString(), superseded);
    }

    /** Inside a transaction: CLAIMING to {@code status} (no-op if someone else already moved the token on). */
    private void setTokenStatusInTx(UUID tokenId, String status) {
        jdbc.update("UPDATE device_bootstrap_tokens SET status = ?::token_status, claimed_at = CASE WHEN ? = 'ISSUED' "
                        + "THEN NULL ELSE claimed_at END WHERE token_id = ? AND status = 'CLAIMING'",
                status, status, tokenId);
    }

    /** Lowercase hex SHA-256 of the token's ASCII bytes (the stored token_hash). */
    public static String tokenHash(String token) {
        return HexFormat.of().formatHex(sha256(token.getBytes(StandardCharsets.US_ASCII)));
    }

    /** base64url(SHA-256(cert DER)) without padding: the JWS x5t#S256 value (DECISIONS #35). */
    public static String x5tS256(byte[] certDer) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(certDer));
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] encoded(X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
