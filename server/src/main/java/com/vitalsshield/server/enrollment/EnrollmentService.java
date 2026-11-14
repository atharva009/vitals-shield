package com.vitalsshield.server.enrollment;

import com.vitalsshield.crypto.CsrFactory;
import com.vitalsshield.crypto.DerSignatures;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import com.vitalsshield.server.kms.KmsSigner;
import com.vitalsshield.server.pki.ActiveKmsKeys;
import com.vitalsshield.server.pki.CertificateIssuer;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.pki.KeyPurpose;
import com.vitalsshield.server.pki.Pems;
import com.vitalsshield.server.pki.PkiProperties;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.session.ActiveSessionRegistry;
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
 */
@Service
public class EnrollmentService {

    private static final Logger log = LoggerFactory.getLogger(EnrollmentService.class);
    static final int RETRY_AFTER_SECONDS = 5;

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

    public EnrollmentService(JdbcTemplate jdbc, TransactionTemplate tx, KmsSigner kmsSigner, ActiveKmsKeys kmsKeys,
                             CertificateIssuer issuer, CertificateDenyList denyList, ActiveSessionRegistry sessions,
                             CrlService crls, PkiProperties pki, Clock clock) {
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

    record Claim(UUID tokenId, String assignmentId, Instant assignmentActiveFrom) {
    }

    EnrollmentResult enrollBlocking(EnrollRequest req) {
        // ---- Short Tx 1: claim ------------------------------------------------------------------------------------
        Object claimed = tx.execute(status -> claim(req));
        if (claimed instanceof EnrollmentResult early) {
            return early;
        }
        Claim claim = (Claim) claimed;

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
            setTokenStatus(claim.tokenId(), "REVOKED");
            return EnrollmentResult.error(400, "PROOF_INVALID");
        }

        // ---- Out of transaction: KMS anchor and leaf issuance -----------------------------------------------------
        Instant provisionedAt = clock.instant().truncatedTo(ChronoUnit.MILLIS);
        String dekAnchorSig;
        X509Certificate cert;
        try {
            byte[] anchorBytes = CanonicalEncodings.dekAnchorBytes(
                    req.deviceId(), req.dekSpkiDer(), provisionedAt.toEpochMilli());
            byte[] der = kmsSigner.signDigestBlocking(kmsKeys.requireArn(KeyPurpose.REGISTRY_ANCHOR), sha256(anchorBytes));
            dekAnchorSig = Base64.getEncoder().encodeToString(der);
            cert = issuer.issueDeviceLeaf(req.deviceId(), olkSpki, pki.deviceLeafTtl());
        } catch (RuntimeException e) {
            log.warn("Enrollment for {} hit a transient failure; token returned: {}", req.deviceId(), e.toString());
            setTokenStatus(claim.tokenId(), "ISSUED");
            return EnrollmentResult.unavailable(RETRY_AFTER_SECONDS);
        }

        // ---- Short Tx 2: activate ---------------------------------------------------------------------------------
        try {
            return tx.execute(status -> activate(req, claim, cert, dekAnchorSig, provisionedAt));
        } catch (RuntimeException e) {
            log.warn("Enrollment activation for {} failed; token returned: {}", req.deviceId(), e.toString());
            setTokenStatus(claim.tokenId(), "ISSUED");
            return EnrollmentResult.unavailable(RETRY_AFTER_SECONDS);
        }
    }

    /** Returns a Claim, or an EnrollmentResult to return immediately. Runs inside Tx 1. */
    private Object claim(EnrollRequest req) {
        List<UUID> tokens = jdbc.queryForList("""
                SELECT token_id FROM device_bootstrap_tokens
                 WHERE device_id = ? AND token_hash = ? AND expires_at > NOW()
                   AND (status = 'ISSUED' OR (status = 'CLAIMING' AND claimed_at < NOW() - INTERVAL '2 minutes'))
                 FOR UPDATE
                """, UUID.class, req.deviceId(), tokenHash(req.bootstrapToken()));
        if (tokens.isEmpty()) {
            return EnrollmentResult.error(401, "INVALID_BOOTSTRAP");
        }
        UUID tokenId = tokens.get(0);
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
        return new Claim(tokenId, (String) assignment.get(0).get("id"),
                ((Timestamp) assignment.get(0).get("active_from")).toInstant());
    }

    private EnrollmentResult activate(EnrollRequest req, Claim claim, X509Certificate cert, String dekAnchorSig,
                                      Instant provisionedAt) {
        long storedEpoch = jdbc.queryForObject(
                "SELECT boot_epoch FROM devices WHERE device_id = ? FOR UPDATE", Long.class, req.deviceId());

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

        CertKey newKey = CertKey.from(cert);
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
            throw new IllegalStateException("bootstrap token was reclaimed during enrollment");
        }
        log.info("Enrolled {}: serial {} boot_epoch {} (superseded {})", req.deviceId(), newKey.serial(),
                counters.bootEpoch(), superseded.size());
        return EnrollmentResult.created(Pems.certificate(cert), counters.bootEpoch(), claim.assignmentId(),
                claim.assignmentActiveFrom().toString(), superseded);
    }

    private void setTokenStatus(UUID tokenId, String status) {
        tx.executeWithoutResult(s -> jdbc.update(
                "UPDATE device_bootstrap_tokens SET status = ?::token_status, claimed_at = CASE WHEN ? = 'ISSUED' "
                        + "THEN NULL ELSE claimed_at END WHERE token_id = ? AND status = 'CLAIMING'",
                status, status, tokenId));
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
