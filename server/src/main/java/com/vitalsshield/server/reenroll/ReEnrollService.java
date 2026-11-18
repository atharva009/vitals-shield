package com.vitalsshield.server.reenroll;

// LOCK ORDER (DECISIONS #82, extends #70), in every transaction: devices -> certificates -> telemetry_records
// -> patient_device_assignments -> clinical_alerts -> audit advisory lock LAST. This class: Tx 1 locks devices FOR
// UPDATE, inserts the nonce, reads the device's certificates and the ACTIVE assignment (no lock), and either reserves
// the serial or raises the anomaly (AnomalyService.raiseInTx: certificates FOR UPDATE, clinical_alerts insert, audit
// last). Tx 2 locks devices FOR UPDATE, then the device's certificates FOR UPDATE, then inserts the new certificate.

import com.vitalsshield.crypto.CsrFactory;
import com.vitalsshield.crypto.DerSignatures;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import com.vitalsshield.server.anomaly.AnomalyService;
import com.vitalsshield.server.enrollment.DekAnchorVerifier;
import com.vitalsshield.server.enrollment.EnrollmentService;
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
import com.vitalsshield.server.signer.EvictionProperties;
import com.vitalsshield.server.telemetry.TelemetryMetrics;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Protocol C (spec Section 4): a device whose operational certificate is gone (expired offline, revoked by an anomaly
 * and then restored, or lost with a state reset) proves its identity with the DEK and gets a new ACTIVE leaf.
 *
 * <p>Checks before any write, in order: the HMAC challenge for this device_id (401 CHALLENGE_INVALID), the DEK
 * registry anchor (403 DEVICE_NOT_ENROLLABLE, the same body for an unknown device, a missing DEK and a forged anchor),
 * the DEK signature (400 PROOF_INVALID), the CSR and a key never used before by this device (400 PROOF_INVALID).
 *
 * <p>Short Tx 1: nonce, trust_state, assignment and horizon, epoch rules, collision check, serial RESERVED. An epoch
 * violation or a collision commits the nonce together with the anomaly response (DECISIONS #92) and returns 409. KMS
 * signs with no transaction open. Short Tx 2: every non-revoked certificate deny-listed and REVOKED
 * SUPERSEDED_BY_REENROLL, the new certificate ACTIVE, the serial RECORDED, boot_epoch set.
 */
@Service
public class ReEnrollService {

    private static final Logger log = LoggerFactory.getLogger(ReEnrollService.class);
    static final Duration NONCE_LIFETIME = Duration.ofMinutes(5);
    public static final String REVOCATION_REASON = "SUPERSEDED_BY_REENROLL";

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final ReEnrollChallenge challenges;
    private final DekAnchorVerifier anchors;
    private final CertificateIssuer issuer;
    private final CaIssuerRepository issuers;
    private final IssuedSerialLedger ledger;
    private final CertificateDenyList denyList;
    private final ActiveSessionRegistry sessions;
    private final CrlService crls;
    private final PkiProperties pki;
    private final ReEnrollProperties props;
    private final AnomalyService anomalies;
    private final EvictionProperties eviction;
    private final TelemetryMetrics metrics;
    private final Clock clock;
    private final ReEnrollHooks hooks;
    private com.vitalsshield.server.signer.SignerRevocationService revocationLog;

    /** The dashboard's revocation log (optional, to keep the constructor as it is). */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setRevocationLog(com.vitalsshield.server.signer.SignerRevocationService log) {
        this.revocationLog = log;
    }

    public ReEnrollService(JdbcTemplate jdbc, TransactionTemplate tx, ReEnrollChallenge challenges,
                           DekAnchorVerifier anchors, CertificateIssuer issuer, CaIssuerRepository issuers,
                           IssuedSerialLedger ledger, CertificateDenyList denyList, ActiveSessionRegistry sessions,
                           CrlService crls, PkiProperties pki, ReEnrollProperties props, AnomalyService anomalies,
                           EvictionProperties eviction, TelemetryMetrics metrics, Clock clock,
                           ObjectProvider<ReEnrollHooks> hooks) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.challenges = challenges;
        this.anchors = anchors;
        this.issuer = issuer;
        this.issuers = issuers;
        this.ledger = ledger;
        this.denyList = denyList;
        this.sessions = sessions;
        this.crls = crls;
        this.pki = pki;
        this.props = props;
        this.anomalies = anomalies;
        this.eviction = eviction;
        this.metrics = metrics;
        this.clock = clock;
        this.hooks = hooks.getIfAvailable(() -> ReEnrollHooks.NONE);
    }

    static int retryAfterSeconds() {
        return ThreadLocalRandom.current().nextInt(3, 9);
    }

    /** What the blocking part decided, and what to do after commit. */
    record Outcome(ReEnrollResult result, List<CertKey> revoked, AnomalyService.Raised anomaly) {
        static Outcome of(ReEnrollResult r) {
            return new Outcome(r, List.of(), null);
        }
    }

    record Claim(long storedEpoch, EpochRules.Decision epoch, String reason, CertKey reserved, BigInteger serial,
                 String assignmentId, Instant assignmentActiveFrom) {
    }

    /** Tx 2 found the device changed since Tx 1. */
    static final class Aborted extends RuntimeException {
        final int status;
        final String code;

        Aborted(int status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }
    }

    /** Blocking work on boundedElastic; then evicts old sockets (or the anomaly's) and republishes the CRL. */
    public Mono<ReEnrollResult> reEnroll(ReEnrollRequest req) {
        return Mono.fromCallable(() -> reEnrollBlocking(req))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(o -> {
                    metrics.increment("reenroll." + o.result().status()
                            + (o.result().status() == 200 ? "" : "." + o.result().body().get("error")));
                    Mono<Void> after = o.anomaly() != null ? anomalies.afterCommit(o.anomaly())
                            : Flux.fromIterable(o.revoked())
                                    .concatMap(k -> (eviction.enabled() ? sessions.evictByCert(k) : Mono.just(0))
                                            .doOnNext(closed -> {
                                                if (revocationLog != null) {
                                                    revocationLog.recordCommitted(new com.vitalsshield.server
                                                            .signer.RevocationResult(k, req.deviceId(),
                                                            REVOCATION_REASON, clock.instant(), closed, 0));
                                                }
                                            }))
                                    .then(Mono.fromRunnable(() -> o.revoked().stream().map(CertKey::issuerKeyHash)
                                            .distinct().forEach(crls::revocationCommitted)));
                    return after.thenReturn(o.result());
                });
    }

    Outcome reEnrollBlocking(ReEnrollRequest req) {
        String deviceId = req.deviceId();
        // 1. Our HMAC tag, for this device, within 60 s of the JVM clock (it produced issued_at_ms, DECISIONS #89).
        if (!challenges.verify(deviceId, req.issuedAtMs(), req.nonce(), req.hmacTag())) {
            return Outcome.of(ReEnrollResult.error(401, "CHALLENGE_INVALID"));
        }
        // 2. The DEK on record is anchored by KMS Key #4. Unknown device, no DEK and a forged anchor look the same.
        List<String> dekCol = jdbc.queryForList("SELECT dek_spki_der_b64 FROM devices WHERE device_id = ?",
                String.class, deviceId);
        if (dekCol.isEmpty() || dekCol.get(0) == null || !anchors.verify(deviceId)) {
            return Outcome.of(ReEnrollResult.error(403, "DEVICE_NOT_ENROLLABLE"));
        }
        byte[] dekSpki = Base64.getDecoder().decode(dekCol.get(0));
        // 3. The DEK signed (device_id, issued_at_ms, nonce, boot_epoch, sha256(csr)).
        byte[] proof;
        try {
            proof = CanonicalEncodings.reEnrollProofBytes(deviceId, req.issuedAtMs(), req.nonce(), req.bootEpoch(),
                    req.olkCsrDer());
        } catch (IllegalArgumentException e) {
            return Outcome.of(ReEnrollResult.error(400, "PROOF_INVALID"));
        }
        PublicKey dek = EcKeys.publicKeyFromSpki(dekSpki);
        if (!DerSignatures.verify(dek, proof, req.dekSig())) {
            return Outcome.of(ReEnrollResult.error(400, "PROOF_INVALID"));
        }
        // 4. The CSR proves the new key, which is neither the DEK nor any key this device has had a certificate for.
        SubjectPublicKeyInfo newSpki;
        try {
            newSpki = CsrFactory.parseAndVerify(req.olkCsrDer());
        } catch (RuntimeException e) {
            return Outcome.of(ReEnrollResult.error(400, "PROOF_INVALID"));
        }
        byte[] newKey = encoded(newSpki);
        if (Arrays.equals(newKey, dekSpki) || previousKeys(deviceId).stream().anyMatch(k -> Arrays.equals(k, newKey))) {
            return Outcome.of(ReEnrollResult.error(400, "PROOF_INVALID"));
        }

        // ---- Short Tx 1 ---------------------------------------------------------------------------------------------
        Object claimed;
        try {
            claimed = tx.execute(s -> claim(req));
        } catch (RuntimeException e) {
            log.warn("Re-enrollment Tx 1 for {} failed: {}", deviceId, e.toString());
            return Outcome.of(ReEnrollResult.unavailable(retryAfterSeconds()));
        }
        if (claimed instanceof Outcome early) {
            return early;
        }
        Claim claim = (Claim) claimed;

        // ---- No transaction: KMS Sign -----------------------------------------------------------------------------
        X509Certificate leaf;
        try {
            leaf = issuer.issueDeviceLeaf(deviceId, newSpki, pki.leafTtl(), claim.serial());
        } catch (RuntimeException e) {
            log.warn("Re-enrollment for {} hit a transient KMS failure; serial {} voided: {}", deviceId,
                    claim.reserved().serial(), e.toString());
            voidQuietly(deviceId, claim, null);
            return Outcome.of(ReEnrollResult.unavailable(retryAfterSeconds()));
        }
        hooks.afterLeafSigned(deviceId);

        // ---- Short Tx 2 ---------------------------------------------------------------------------------------------
        try {
            List<CertKey> revoked = tx.execute(s -> store(deviceId, claim, leaf));
            log.info("Re-enrolled {} via DEK ({}): serial {} boot_epoch {} -> {}{}; {} certificate(s) REVOKED {}",
                    deviceId, claim.reason(), CertKey.from(leaf).serial(), claim.storedEpoch(),
                    claim.epoch().assignedEpoch(), claim.epoch().kind() == EpochRules.Kind.RESYNC
                            ? " (resync, sequence window reset)" : "", revoked.size(), REVOCATION_REASON);
            return new Outcome(ReEnrollResult.ok(Pems.certificate(leaf), claim.epoch().assignedEpoch(),
                    claim.assignmentId(), claim.assignmentActiveFrom().toString()), revoked, null);
        } catch (Aborted a) {
            log.warn("Re-enrollment for {} aborted in Tx 2 ({}): {}", deviceId, a.code, a.getMessage());
            voidQuietly(deviceId, claim, leaf);
            return Outcome.of(ReEnrollResult.error(a.status, a.code));
        } catch (RuntimeException e) {
            log.warn("Re-enrollment Tx 2 for {} failed: {}", deviceId, e.toString());
            voidQuietly(deviceId, claim, leaf);
            return Outcome.of(ReEnrollResult.unavailable(retryAfterSeconds()));
        }
    }

    /** Short Tx 1. Returns a Claim, or an Outcome to return as is (the transaction still commits). */
    private Object claim(ReEnrollRequest req) {
        String deviceId = req.deviceId();
        Map<String, Object> d = jdbc.queryForMap("""
                SELECT trust_state::text AS ts, boot_epoch, epoch_resync_allowed FROM devices
                 WHERE device_id = ? FOR UPDATE
                """, deviceId);
        int inserted = jdbc.update("""
                INSERT INTO consumed_challenge_nonces (nonce_b64, device_id, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT (nonce_b64) DO NOTHING
                """, Base64.getEncoder().encodeToString(req.nonce()), deviceId,
                Timestamp.from(Instant.ofEpochMilli(req.issuedAtMs()).plus(NONCE_LIFETIME)));
        if (inserted == 0) {
            return Outcome.of(ReEnrollResult.error(409, "CHALLENGE_REPLAYED"));
        }
        if (!"ACTIVE".equals(d.get("ts"))) {
            return Outcome.of(ReEnrollResult.error(403, "DEVICE_NOT_ACTIVE"));
        }
        List<Map<String, Object>> a = jdbc.queryForList("""
                SELECT assignment_id::text AS id, active_from, max_renewal_horizon FROM patient_device_assignments
                 WHERE device_id = ? AND status = 'ACTIVE'
                """, deviceId);
        if (a.isEmpty()) {
            return Outcome.of(ReEnrollResult.error(409, "DEVICE_UNASSIGNED"));
        }
        Instant jvmNow = clock.instant();
        // max_renewal_horizon is JVM-written (ProvisioningRecords), so it is compared with the JVM clock (#89).
        if (!jvmNow.isBefore(((Timestamp) a.get(0).get("max_renewal_horizon")).toInstant())) {
            return Outcome.of(ReEnrollResult.error(409, "RENEWAL_HORIZON_EXCEEDED"));
        }

        long stored = ((Number) d.get("boot_epoch")).longValue();
        boolean resyncAllowed = Boolean.TRUE.equals(d.get("epoch_resync_allowed"));
        EpochRules.Decision epoch = EpochRules.decide(stored, req.bootEpoch(), resyncAllowed);
        Map<String, Object> epochDetail = new LinkedHashMap<>();
        epochDetail.put("presented_boot_epoch", req.bootEpoch());
        epochDetail.put("stored_boot_epoch", stored);
        epochDetail.put("epoch_resync_allowed", resyncAllowed);
        switch (epoch.kind()) {
            case INVALID -> {
                return anomaly(deviceId, "BOOT_EPOCH_INVALID", 409, "BOOT_EPOCH_INVALID",
                        "Re-enrollment presented boot_epoch " + req.bootEpoch() + ", above the server's "
                                + stored + ". Epochs are assigned by the server, so no genuine device can hold it.",
                        epochDetail);
            }
            case REGRESSION -> {
                return anomaly(deviceId, "BOOT_EPOCH_REGRESSION", 409, "BOOT_EPOCH_REGRESSION",
                        "Re-enrollment presented boot_epoch " + req.bootEpoch() + ", below the server's " + stored
                                + ", without a clinician restore: an old copy of the device state is in use.",
                        epochDetail);
            }
            case RESYNC -> // consumed here, atomically with the nonce, so a second copy cannot also resync
                    jdbc.update("UPDATE devices SET epoch_resync_allowed = FALSE WHERE device_id = ?", deviceId);
            case SAME -> {
            }
        }

        // DECISIONS #91, after the resync branch: a resync follows a clinician restore, which already revoked every
        // certificate, so it can only collide if a copy re-enrolled first and is streaming.
        List<CollisionRule.Cert> certs = new ArrayList<>();
        List<CertKey> keys = new ArrayList<>();
        Instant newestNotAfter = null;
        for (Map<String, Object> c : jdbc.queryForList("""
                SELECT issuer_key_hash, serial_number, status::text AS status, not_after, grace_expires_at
                  FROM certificates WHERE device_id = ? ORDER BY not_before DESC
                """, deviceId)) {
            Timestamp grace = (Timestamp) c.get("grace_expires_at");
            Instant notAfter = ((Timestamp) c.get("not_after")).toInstant();
            certs.add(new CollisionRule.Cert((String) c.get("status"), notAfter,
                    grace == null ? null : grace.toInstant()));
            keys.add(CertKey.of((String) c.get("issuer_key_hash"), (String) c.get("serial_number")));
            if (newestNotAfter == null) {
                newestNotAfter = notAfter;
            }
        }
        boolean liveSocket = keys.stream().anyMatch(k -> !sessions.liveSocketsFor(k).isEmpty());
        boolean recentIngest = recentIngest(deviceId);
        if (CollisionRule.fires(certs, jvmNow, liveSocket, recentIngest)) {
            Map<String, Object> detail = new LinkedHashMap<>(epochDetail);
            detail.put("live_socket", liveSocket);
            detail.put("ingest_within_ms", props.collisionWindow().toMillis());
            detail.put("recent_ingest", recentIngest);
            return anomaly(deviceId, "REENROLL_COLLISION", 409, "REAUTH_REQUIRED",
                    "Re-enrollment with the device key while the device's current certificate is still in use ("
                            + (liveSocket ? "live mTLS socket" : "ingest within the last "
                            + props.collisionWindow().toSeconds() + " s") + "): two holders of the device key.",
                    detail);
        }

        String reason = epoch.kind() == EpochRules.Kind.RESYNC ? "epoch_resync"
                : newestNotAfter != null && !newestNotAfter.isAfter(jvmNow) ? "cert_expired" : "no_usable_cert";
        String issuerKeyHash = issuers.requireActive(KeyPurpose.DEVICE_INTERMEDIATE).issuerKeyHash();
        BigInteger serial = ledger.reserve(issuerKeyHash, deviceId);
        return new Claim(stored, epoch, reason, CertKey.of(issuerKeyHash, SerialNumbers.toHex(serial)), serial,
                (String) a.get(0).get("id"), ((Timestamp) a.get(0).get("active_from")).toInstant());
    }

    /** Inside Tx 1: the anomaly response commits with the nonce; the caller returns the 409 after commit. */
    private Outcome anomaly(String deviceId, String condition, int status, String code, String explanation,
                            Map<String, Object> detail) {
        AnomalyService.Raised r = anomalies.raiseInTx(deviceId, condition, explanation, detail);
        return new Outcome(ReEnrollResult.error(status, code), List.of(), r);
    }

    /**
     * DECISIONS #91: last_ingested_at is stamped by Postgres (the ingest CTE sets it to NOW()), so the window is
     * evaluated against Postgres now() (DECISIONS #89), never against the JVM clock.
     */
    public boolean recentIngest(String deviceId) {
        Boolean b = jdbc.queryForObject("""
                SELECT COALESCE(last_ingested_at >= now() - (? * INTERVAL '1 millisecond'), FALSE)
                  FROM devices WHERE device_id = ?
                """, Boolean.class, props.collisionWindow().toMillis(), deviceId);
        return Boolean.TRUE.equals(b);
    }

    /** Short Tx 2. Returns the certificates it revoked. Deny-list adds happen before commit. */
    private List<CertKey> store(String deviceId, Claim claim, X509Certificate leaf) {
        Map<String, Object> d = jdbc.queryForMap(
                "SELECT trust_state::text AS ts, boot_epoch FROM devices WHERE device_id = ? FOR UPDATE", deviceId);
        if (!"ACTIVE".equals(d.get("ts"))) {
            throw new Aborted(403, "DEVICE_NOT_ACTIVE", "device is " + d.get("ts"));
        }
        if (((Number) d.get("boot_epoch")).longValue() != claim.storedEpoch()) {
            throw new Aborted(409, "REENROLL_SUPERSEDED", "boot_epoch changed since Tx 1");
        }
        Instant now = clock.instant();
        List<CertKey> old = jdbc.query("""
                SELECT issuer_key_hash, serial_number FROM certificates
                 WHERE device_id = ? AND status <> 'REVOKED'
                 FOR UPDATE
                """, (rs, i) -> CertKey.of(rs.getString(1), rs.getString(2)), deviceId);
        old.forEach(k -> denyList.add(k, now, "REVOKED")); // before commit: fail closed
        jdbc.update("""
                UPDATE certificates SET status = 'REVOKED', revocation_reason = ?, revoked_at = ?
                 WHERE device_id = ? AND status <> 'REVOKED'
                """, REVOCATION_REASON, Timestamp.from(now), deviceId);

        CertKey newKey = CertKey.from(leaf);
        if (!newKey.equals(claim.reserved()) || !ledger.record(newKey)) {
            throw new Aborted(409, "REENROLL_SUPERSEDED", "serial reservation no longer RESERVED");
        }
        // issued_at and activated_at are Postgres-stamped (DECISIONS #89): ACTIVE from the start, no pending phase.
        jdbc.update("""
                INSERT INTO certificates (issuer_key_hash, serial_number, device_id, cert_thumbprint_s256, cert_pem,
                                          not_before, not_after, status, activated_at, issued_via, reenroll_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', NOW(), 'REENROLL', ?)
                """, newKey.issuerKeyHash(), newKey.serial(), deviceId, EnrollmentService.x5tS256(encoded(leaf)),
                Pems.certificate(leaf), Timestamp.from(leaf.getNotBefore().toInstant()),
                Timestamp.from(leaf.getNotAfter().toInstant()), claim.reason());
        if (claim.epoch().kind() == EpochRules.Kind.RESYNC) {
            jdbc.update("""
                    UPDATE devices SET boot_epoch = ?, last_sequence_num = 0, replay_bitmap = 0, updated_at = NOW()
                     WHERE device_id = ?
                    """, claim.epoch().assignedEpoch(), deviceId);
        } else {
            jdbc.update("UPDATE devices SET updated_at = NOW() WHERE device_id = ?", deviceId);
        }
        return old;
    }

    /**
     * One short transaction: VOID the reserved serial; if a leaf was signed, store it REVOKED (REPLACED_BEFORE_USE)
     * and deny-list it before commit; give back a resync permission that Tx 1 consumed, so a transient failure never
     * turns the retry into a BOOT_EPOCH_REGRESSION anomaly. Then republish the CRL.
     */
    private void voidQuietly(String deviceId, Claim claim, X509Certificate signedOrNull) {
        Instant voidedAt = clock.instant();
        try {
            tx.executeWithoutResult(s -> {
                if (claim.epoch().kind() == EpochRules.Kind.RESYNC) {
                    jdbc.update("""
                            UPDATE devices SET epoch_resync_allowed = TRUE
                             WHERE device_id = ? AND boot_epoch = ? AND trust_state = 'ACTIVE'
                            """, deviceId, claim.storedEpoch());
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
                                                      cert_pem, not_before, not_after, status, revocation_reason,
                                                      revoked_at, issued_via)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 'REVOKED', 'REPLACED_BEFORE_USE', ?, 'REENROLL')
                            ON CONFLICT (issuer_key_hash, serial_number) DO NOTHING
                            """, key.issuerKeyHash(), key.serial(), deviceId,
                            EnrollmentService.x5tS256(encoded(signedOrNull)), Pems.certificate(signedOrNull),
                            Timestamp.from(signedOrNull.getNotBefore().toInstant()),
                            Timestamp.from(signedOrNull.getNotAfter().toInstant()), Timestamp.from(voidedAt));
                }
            });
            crls.revocationCommitted(claim.reserved().issuerKeyHash());
        } catch (RuntimeException e) {
            log.error("Could not void re-enrollment serial {} for {}; the stale sweep will: {}",
                    claim.reserved().serial(), deviceId, e.toString());
        }
    }

    /** SPKI DER of every certificate this device has ever had. */
    private List<byte[]> previousKeys(String deviceId) {
        List<byte[]> out = new ArrayList<>();
        for (String pem : jdbc.queryForList("SELECT cert_pem FROM certificates WHERE device_id = ?", String.class,
                deviceId)) {
            try {
                X509Certificate c = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
                out.add(c.getPublicKey().getEncoded());
            } catch (java.security.cert.CertificateException e) {
                log.warn("Unparseable stored certificate for {}: {}", deviceId, e.toString());
            }
        }
        return out;
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
