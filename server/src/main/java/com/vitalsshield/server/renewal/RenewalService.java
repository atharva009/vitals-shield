package com.vitalsshield.server.renewal;

// LOCK ORDER (DECISIONS #82, extends #70), in every transaction: devices -> certificates -> telemetry_records
// -> patient_device_assignments -> clinical_alerts -> audit advisory lock LAST. This class: Tx 1 locks devices FOR
// UPDATE, inserts the nonce, reads the ACTIVE assignment (no lock) and reserves the serial; Tx 2 locks devices FOR
// UPDATE, then the presenting and pending certificates rows FOR UPDATE, then inserts the new certificate.

import com.vitalsshield.crypto.CsrFactory;
import com.vitalsshield.crypto.DerSignatures;
import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import com.vitalsshield.server.enrollment.EnrollmentService;
import com.vitalsshield.server.gateway.ResolvedCert;
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
import com.vitalsshield.server.telemetry.TelemetryMetrics;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Protocol B (spec Section 4): the device proves it holds its current OLK and a new key, and gets a new leaf that
 * stays ISSUED_PENDING_USE until its first accepted batch (first-use switchover, {@link CertificateActivationService}).
 *
 * <p>Checks before any write, in order: body matches the TLS certificate (403 RENEWAL_CERT_MISMATCH, DECISIONS #81),
 * HMAC challenge (401 CHALLENGE_INVALID), presenting certificate ACTIVE and unexpired (409 CERT_NOT_RENEWABLE), OLK
 * proof and CSR (400 PROOF_INVALID). Then Short Tx 1 (device ACTIVE, nonce consumed, assignment and horizon, serial
 * RESERVED), the KMS Sign with no transaction open, and Short Tx 2 (any unused pending certificate REVOKED
 * REPLACED_BEFORE_USE and deny-listed, new certificate ISSUED_PENDING_USE, serial RECORDED).
 */
@Service
public class RenewalService {

    private static final Logger log = LoggerFactory.getLogger(RenewalService.class);
    static final java.time.Duration NONCE_LIFETIME = java.time.Duration.ofMinutes(5);

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final RenewalChallenge challenges;
    private final CertificateIssuer issuer;
    private final CaIssuerRepository issuers;
    private final IssuedSerialLedger ledger;
    private final CertificateDenyList denyList;
    private final ActiveSessionRegistry sessions;
    private final CrlService crls;
    private final PkiProperties pki;
    private final TelemetryMetrics metrics;
    private final Clock clock;
    private final RenewalHooks hooks;

    public RenewalService(JdbcTemplate jdbc, TransactionTemplate tx, RenewalChallenge challenges,
                          CertificateIssuer issuer, CaIssuerRepository issuers, IssuedSerialLedger ledger,
                          CertificateDenyList denyList, ActiveSessionRegistry sessions, CrlService crls,
                          PkiProperties pki, TelemetryMetrics metrics, Clock clock,
                          ObjectProvider<RenewalHooks> hooks) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.challenges = challenges;
        this.issuer = issuer;
        this.issuers = issuers;
        this.ledger = ledger;
        this.denyList = denyList;
        this.sessions = sessions;
        this.crls = crls;
        this.pki = pki;
        this.metrics = metrics;
        this.clock = clock;
        this.hooks = hooks.getIfAvailable(() -> RenewalHooks.NONE);
    }

    /** 503 Retry-After: a random integer from 3 to 8 seconds. */
    static int retryAfterSeconds() {
        return ThreadLocalRandom.current().nextInt(3, 9);
    }

    /** Blocking work on boundedElastic; then evicts sockets of a revoked pending certificate and republishes the CRL. */
    public Mono<RenewalResult> renew(RenewRequest req, X509Certificate tlsLeaf, ResolvedCert cert) {
        return Mono.fromCallable(() -> renewBlocking(req, tlsLeaf, cert))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(o -> {
                    metrics.increment("renewal." + o.result().status()
                            + (o.result().status() == 200 ? "" : "." + o.result().body().get("error")));
                    if (o.revokedPending() == null) {
                        return Mono.just(o.result());
                    }
                    return sessions.evictByCert(o.revokedPending())
                            .doOnNext(n -> crls.revocationCommitted(o.revokedPending().issuerKeyHash()))
                            .thenReturn(o.result());
                });
    }

    record Outcome(RenewalResult result, CertKey revokedPending) {
        static Outcome of(RenewalResult r) {
            return new Outcome(r, null);
        }
    }

    record Claim(CertKey reserved, BigInteger serial, String assignmentId, Instant assignmentActiveFrom) {
    }

    /** Tx 2 found the reservation gone, or the device or presenting certificate no longer renewable. */
    static final class Aborted extends RuntimeException {
        final int status;
        final String code;

        Aborted(int status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }
    }

    Outcome renewBlocking(RenewRequest req, X509Certificate tlsLeaf, ResolvedCert cert) {
        CertKey presenting = new CertKey(cert.issuerKeyHash(), cert.serial());
        String deviceId = cert.deviceId();

        // 1. The body names the certificate of this TLS connection (DECISIONS #81).
        if (!presenting.issuerKeyHash().equals(req.issuerKeyHash()) || !presenting.serial().equals(req.serialNumber())) {
            return Outcome.of(RenewalResult.error(403, "RENEWAL_CERT_MISMATCH"));
        }
        // 2. Our HMAC tag, for this certificate, within 60 s.
        if (!challenges.verify(req.issuerKeyHash(), req.serialNumber(), req.issuedAtMs(), req.nonce(), req.hmacTag())) {
            return Outcome.of(RenewalResult.error(401, "CHALLENGE_INVALID"));
        }
        // 3. Only the ACTIVE certificate renews: not a pending one (it has not been used yet), not a RENEWED one.
        Instant now = clock.instant();
        if (!"ACTIVE".equals(cert.status()) || !now.isBefore(tlsLeaf.getNotAfter().toInstant())) {
            return Outcome.of(RenewalResult.error(409, "CERT_NOT_RENEWABLE"));
        }
        // 4. The current OLK signed the challenge and the new CSR (spec encoding 5).
        byte[] proof = CanonicalEncodings.olkRenewalProofBytes(req.issuerKeyHash(), req.serialNumber(),
                req.issuedAtMs(), req.nonce(), req.newCsrDer());
        if (!DerSignatures.verify(tlsLeaf.getPublicKey(), proof, req.renewalSig())) {
            return Outcome.of(RenewalResult.error(400, "PROOF_INVALID"));
        }
        // 5. The CSR proves possession of the new key, which must be neither the current OLK nor the DEK.
        SubjectPublicKeyInfo newSpki;
        try {
            newSpki = CsrFactory.parseAndVerify(req.newCsrDer());
        } catch (RuntimeException e) {
            return Outcome.of(RenewalResult.error(400, "PROOF_INVALID"));
        }
        byte[] newKey = encoded(newSpki);
        List<String> dek = jdbc.queryForList("SELECT dek_spki_der_b64 FROM devices WHERE device_id = ?", String.class,
                deviceId);
        if (Arrays.equals(newKey, tlsLeaf.getPublicKey().getEncoded())
                || (!dek.isEmpty() && dek.get(0) != null
                    && Arrays.equals(newKey, Base64.getDecoder().decode(dek.get(0))))) {
            return Outcome.of(RenewalResult.error(400, "PROOF_INVALID"));
        }

        // ---- Short Tx 1 ---------------------------------------------------------------------------------------------
        Object claimed;
        try {
            claimed = tx.execute(s -> claim(req, deviceId));
        } catch (RuntimeException e) {
            log.warn("Renewal Tx 1 for {} failed: {}", deviceId, e.toString());
            return Outcome.of(RenewalResult.unavailable(retryAfterSeconds()));
        }
        if (claimed instanceof RenewalResult early) {
            return Outcome.of(early);
        }
        Claim claim = (Claim) claimed;

        // ---- No transaction: KMS Sign -----------------------------------------------------------------------------
        X509Certificate leaf;
        try {
            leaf = issuer.issueDeviceLeaf(deviceId, newSpki, pki.leafTtl(), claim.serial());
        } catch (RuntimeException e) {
            log.warn("Renewal for {} hit a transient KMS failure; serial {} voided: {}", deviceId,
                    claim.reserved().serial(), e.toString());
            voidQuietly(deviceId, claim, null);
            return Outcome.of(RenewalResult.unavailable(retryAfterSeconds()));
        }
        // An Error thrown here (test crash simulation) skips every cleanup path: only the stale sweep recovers.
        hooks.afterLeafSigned(deviceId);

        // ---- Short Tx 2 ---------------------------------------------------------------------------------------------
        try {
            CertKey revoked = tx.execute(s -> store(deviceId, presenting, claim, leaf));
            log.info("Renewed {}: {} -> {} (pending first use){}", deviceId, presenting.serial(),
                    CertKey.from(leaf).serial(), revoked == null ? "" : "; unused pending " + revoked.serial()
                            + " REVOKED REPLACED_BEFORE_USE");
            return new Outcome(RenewalResult.ok(Pems.certificate(leaf), claim.assignmentId(),
                    claim.assignmentActiveFrom().toString()), revoked);
        } catch (Aborted a) {
            log.warn("Renewal for {} aborted in Tx 2 ({}): {}", deviceId, a.code, a.getMessage());
            voidQuietly(deviceId, claim, leaf);
            return Outcome.of(RenewalResult.error(a.status, a.code));
        } catch (RuntimeException e) {
            log.warn("Renewal Tx 2 for {} failed: {}", deviceId, e.toString());
            voidQuietly(deviceId, claim, leaf);
            return Outcome.of(RenewalResult.unavailable(retryAfterSeconds()));
        }
    }

    /** Short Tx 1. Returns a Claim, or a RenewalResult to return as is (the transaction still commits). */
    private Object claim(RenewRequest req, String deviceId) {
        List<String> state = jdbc.queryForList("SELECT trust_state::text FROM devices WHERE device_id = ? FOR UPDATE",
                String.class, deviceId);
        if (state.isEmpty() || !"ACTIVE".equals(state.get(0))) {
            return RenewalResult.error(403, "DEVICE_NOT_ACTIVE");
        }
        int inserted = jdbc.update("""
                INSERT INTO consumed_challenge_nonces (nonce_b64, device_id, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT (nonce_b64) DO NOTHING
                """, Base64.getEncoder().encodeToString(req.nonce()), deviceId,
                Timestamp.from(Instant.ofEpochMilli(req.issuedAtMs()).plus(NONCE_LIFETIME)));
        if (inserted == 0) {
            return RenewalResult.error(409, "CHALLENGE_REPLAYED");
        }
        List<Map<String, Object>> a = jdbc.queryForList("""
                SELECT assignment_id::text AS id, active_from, max_renewal_horizon FROM patient_device_assignments
                 WHERE device_id = ? AND status = 'ACTIVE'
                """, deviceId);
        if (a.isEmpty()) {
            return RenewalResult.error(409, "DEVICE_UNASSIGNED");
        }
        // max_renewal_horizon is the periodic authorization check: past it, the device needs a new assignment.
        if (!clock.instant().isBefore(((Timestamp) a.get(0).get("max_renewal_horizon")).toInstant())) {
            return RenewalResult.error(409, "RENEWAL_HORIZON_EXCEEDED");
        }
        String issuerKeyHash = issuers.requireActive(KeyPurpose.DEVICE_INTERMEDIATE).issuerKeyHash();
        BigInteger serial = ledger.reserve(issuerKeyHash, deviceId);
        return new Claim(CertKey.of(issuerKeyHash, SerialNumbers.toHex(serial)), serial, (String) a.get(0).get("id"),
                ((Timestamp) a.get(0).get("active_from")).toInstant());
    }

    /** Short Tx 2. Returns the unused pending certificate it revoked, or null. Deny-list adds happen before commit. */
    private CertKey store(String deviceId, CertKey presenting, Claim claim, X509Certificate leaf) {
        String state = jdbc.queryForObject("SELECT trust_state::text FROM devices WHERE device_id = ? FOR UPDATE",
                String.class, deviceId);
        if (!"ACTIVE".equals(state)) {
            throw new Aborted(403, "DEVICE_NOT_ACTIVE", "device is " + state);
        }
        List<String> presentingStatus = jdbc.queryForList("""
                SELECT status::text FROM certificates WHERE issuer_key_hash = ? AND serial_number = ? FOR UPDATE
                """, String.class, presenting.issuerKeyHash(), presenting.serial());
        if (presentingStatus.isEmpty() || !"ACTIVE".equals(presentingStatus.get(0))) {
            throw new Aborted(409, "CERT_NOT_RENEWABLE", "presenting certificate is " + presentingStatus);
        }
        CertKey newKey = CertKey.from(leaf);
        if (!newKey.equals(claim.reserved()) || !ledger.record(newKey)) {
            throw new Aborted(409, "RENEWAL_SUPERSEDED", "serial reservation no longer RESERVED");
        }

        // The lost-response case (DECISIONS #85): an earlier renewal's certificate never reached the device, or never
        // carried a batch. It is revoked as REPLACED_BEFORE_USE and stays on the CRL like any other signed serial.
        Instant revokedAt = clock.instant();
        List<CertKey> pending = jdbc.query("""
                SELECT issuer_key_hash, serial_number FROM certificates
                 WHERE device_id = ? AND status = 'ISSUED_PENDING_USE'
                 FOR UPDATE
                """, (rs, i) -> CertKey.of(rs.getString(1), rs.getString(2)), deviceId);
        for (CertKey p : pending) {
            denyList.add(p, revokedAt, "REVOKED"); // before commit: fail closed
        }
        if (!pending.isEmpty()) {
            jdbc.update("""
                    UPDATE certificates
                       SET status = 'REVOKED', revocation_reason = 'REPLACED_BEFORE_USE', revoked_at = ?
                     WHERE device_id = ? AND status = 'ISSUED_PENDING_USE'
                    """, Timestamp.from(revokedAt), deviceId);
        }

        byte[] der = encoded(leaf);
        jdbc.update("""
                INSERT INTO certificates (issuer_key_hash, serial_number, device_id, cert_thumbprint_s256, cert_pem,
                                          superseded_serial, not_before, not_after, status, issued_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ISSUED_PENDING_USE', ?)
                """, newKey.issuerKeyHash(), newKey.serial(), deviceId, EnrollmentService.x5tS256(der),
                Pems.certificate(leaf), presenting.serial(), Timestamp.from(leaf.getNotBefore().toInstant()),
                Timestamp.from(leaf.getNotAfter().toInstant()), Timestamp.from(revokedAt));
        return pending.isEmpty() ? null : pending.get(0);
    }

    /**
     * One short transaction: VOID the reserved serial; if a leaf was signed, store it REVOKED (REPLACED_BEFORE_USE)
     * and deny-list it before commit. Then republish the CRL. A failure here leaves the serial RESERVED for the sweep.
     */
    private void voidQuietly(String deviceId, Claim claim, X509Certificate signedOrNull) {
        Instant voidedAt = clock.instant();
        try {
            tx.executeWithoutResult(s -> {
                ledger.voidSerial(claim.reserved(), deviceId, voidedAt);
                if (signedOrNull != null) {
                    CertKey key = CertKey.from(signedOrNull);
                    if (!key.equals(claim.reserved())) {
                        ledger.voidSerial(key, deviceId, voidedAt);
                    }
                    denyList.add(key, voidedAt, "REVOKED");
                    jdbc.update("""
                            INSERT INTO certificates (issuer_key_hash, serial_number, device_id, cert_thumbprint_s256,
                                                      cert_pem, not_before, not_after, status, revocation_reason,
                                                      revoked_at, issued_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 'REVOKED', 'REPLACED_BEFORE_USE', ?, ?)
                            ON CONFLICT (issuer_key_hash, serial_number) DO NOTHING
                            """, key.issuerKeyHash(), key.serial(), deviceId,
                            EnrollmentService.x5tS256(encoded(signedOrNull)), Pems.certificate(signedOrNull),
                            Timestamp.from(signedOrNull.getNotBefore().toInstant()),
                            Timestamp.from(signedOrNull.getNotAfter().toInstant()), Timestamp.from(voidedAt),
                            Timestamp.from(voidedAt));
                }
            });
            crls.revocationCommitted(claim.reserved().issuerKeyHash());
        } catch (RuntimeException e) {
            log.error("Could not void renewal serial {} for {}; the stale sweep will: {}", claim.reserved().serial(),
                    deviceId, e.toString());
        }
    }

    private static byte[] encoded(X509Certificate c) {
        try {
            return c.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] encoded(SubjectPublicKeyInfo spki) {
        try {
            return spki.getEncoded();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
