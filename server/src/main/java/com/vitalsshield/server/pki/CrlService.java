package com.vitalsshield.server.pki;

import com.vitalsshield.server.kms.KmsSigner;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.BiFunction;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import jakarta.annotation.PreDestroy;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * X.509 v2 CRLs for the Device Intermediate (nextUpdate +24h) and the Root (nextUpdate +180d), returned as PEM.
 *
 * <p>Publication (DECISIONS.md #27): the latest signed CRL per CA is cached in memory and HTTP GETs only ever read the
 * cache, so an unauthenticated GET never causes a KMS Sign or a CRL Number increment. A CRL is regenerated (a) after a
 * revocation of a certificate it covers commits, and (b) when its nextUpdate is closer than 12 h (intermediate) or 90
 * days (root), checked every 10 minutes. Regenerations are coalesced: at most one in flight per CRL, plus exactly one
 * more if requests arrived meanwhile. GETs keep serving the previous CRL while a new one is signed.
 *
 * <p>The CRL Number increment and the entry read happen in one transaction (the UPDATE row-locks the issuer, so
 * concurrent generations serialize). KMS signing happens after commit, so no transaction is held across a network
 * call; a failed signature leaves a gap in CRL numbers, which RFC 5280 allows (numbers must increase, not be dense).
 */
@Service
public class CrlService {

    private static final Logger log = LoggerFactory.getLogger(CrlService.class);

    static final Duration INTERMEDIATE_NEXT_UPDATE = Duration.ofHours(24);
    static final Duration ROOT_NEXT_UPDATE = Duration.ofDays(180);

    static final Duration INTERMEDIATE_REFRESH_MARGIN = Duration.ofHours(12);
    static final Duration ROOT_REFRESH_MARGIN = Duration.ofDays(90);
    static final Duration EXPIRY_CHECK_INTERVAL = Duration.ofMinutes(10);

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final CaIssuerRepository issuers;
    private final KmsSigner kmsSigner;
    private final PkiProperties pki;
    private final Clock clock = Clock.systemUTC();
    private final CrlSlot intermediateSlot;
    private final CrlSlot rootSlot;
    private volatile Disposable expiryWatch;

    public CrlService(JdbcTemplate jdbc, TransactionTemplate tx, CaIssuerRepository issuers, KmsSigner kmsSigner,
                      PkiProperties pki) {
        this.pki = pki;
        this.jdbc = jdbc;
        this.tx = tx;
        this.issuers = issuers;
        this.kmsSigner = kmsSigner;
        this.intermediateSlot = new CrlSlot("intermediate", this::publishIntermediateCrl, INTERMEDIATE_REFRESH_MARGIN);
        this.rootSlot = new CrlSlot("root", this::publishRootCrl, ROOT_REFRESH_MARGIN);
    }

    /** A signed CRL as published: PEM plus what the cache needs to order and refresh it. */
    public record SignedCrl(String pem, String issuerKeyHash, long crlNumber, Instant nextUpdate, int entryCount) {
    }

    // ---- serving (never signs once something is cached) ----------------------------------------------------------

    /** Cached Device Intermediate CRL. Signs only if nothing has been published yet, shared by concurrent callers. */
    public Mono<String> currentIntermediateCrl() {
        return intermediateSlot.current().map(SignedCrl::pem);
    }

    /** Cached Root CRL; same rules as {@link #currentIntermediateCrl()}. */
    public Mono<String> currentRootCrl() {
        return rootSlot.current().map(SignedCrl::pem);
    }

    // ---- publishing (signs) --------------------------------------------------------------------------------------

    /** Blocking: signs and caches both CRLs. Used by BootSequence before the listeners bind. */
    public void publishAll() {
        publishIntermediateCrl();
        publishRootCrl();
    }

    /**
     * Called after a revocation commits. Non-blocking: requests a coalesced regeneration of the CRL that covers the
     * revoked certificate (matched by issuer key hash, never by DN).
     */
    public void revocationCommitted(String issuerKeyHash) {
        if (intermediateSlot.covers(issuerKeyHash)) {
            intermediateSlot.requestRegeneration();
        } else if (rootSlot.covers(issuerKeyHash)) {
            rootSlot.requestRegeneration();
        } else {
            log.debug("Revoked certificate issuer {} is not covered by a published CRL", issuerKeyHash);
        }
    }

    /** Starts the 10-minute nextUpdate check on boundedElastic. Idempotent. */
    public synchronized void startExpiryWatch() {
        if (expiryWatch != null && !expiryWatch.isDisposed()) {
            return;
        }
        expiryWatch = Flux.interval(EXPIRY_CHECK_INTERVAL, EXPIRY_CHECK_INTERVAL, Schedulers.boundedElastic())
                .subscribe(tick -> {
                    intermediateSlot.refreshIfExpiring(clock.instant());
                    rootSlot.refreshIfExpiring(clock.instant());
                });
    }

    @PreDestroy
    void stopExpiryWatch() {
        Disposable w = expiryWatch;
        if (w != null) {
            w.dispose();
        }
    }

    /** Signs a new Device Intermediate CRL (increments its CRL Number) and makes it the cached one. */
    public SignedCrl publishIntermediateCrl() {
        SignedCrl crl = generate(KeyPurpose.DEVICE_INTERMEDIATE, INTERMEDIATE_NEXT_UPDATE, this::leafEntries);
        intermediateSlot.store(crl);
        return crl;
    }

    /** Signs a new Root CRL and makes it the cached one. */
    public SignedCrl publishRootCrl() {
        SignedCrl crl = generate(KeyPurpose.ROOT_CA, ROOT_NEXT_UPDATE, this::intermediateEntries);
        rootSlot.store(crl);
        return crl;
    }

    /** True when no CRL regeneration is running or pending (tests use it to wait for republication to settle). */
    public boolean isIdle() {
        return intermediateSlot.idle() && rootSlot.idle();
    }

    /** Test/metrics hook: the cached CRL for a slot, if any. */
    public java.util.Optional<SignedCrl> cachedIntermediate() {
        return java.util.Optional.ofNullable(intermediateSlot.cached.get());
    }

    /**
     * One cached CRL with coalesced regeneration. {@code running} guards a single in-flight generation; {@code pending}
     * records that another one was requested while it ran, which triggers exactly one more run.
     */
    private final class CrlSlot {
        private final String name;
        private final java.util.function.Supplier<SignedCrl> generator;
        private final Duration refreshMargin;
        private final AtomicReference<SignedCrl> cached = new AtomicReference<>();
        private final AtomicReference<Mono<SignedCrl>> firstLoad = new AtomicReference<>();
        private final AtomicBoolean running = new AtomicBoolean();
        private final AtomicBoolean pending = new AtomicBoolean();

        CrlSlot(String name, java.util.function.Supplier<SignedCrl> generator, Duration refreshMargin) {
            this.name = name;
            this.generator = generator;
            this.refreshMargin = refreshMargin;
        }

        Mono<SignedCrl> current() {
            SignedCrl c = cached.get();
            if (c != null) {
                return Mono.just(c);
            }
            Mono<SignedCrl> load = firstLoad.updateAndGet(existing -> existing != null ? existing
                    : Mono.fromCallable(generator::get).subscribeOn(Schedulers.boundedElastic())
                            .doOnError(e -> firstLoad.set(null))
                            .cache());
            return load;
        }

        /** Keeps the newest: a higher CRL Number from the same issuer, or any CRL from a different issuer (rebuild). */
        void store(SignedCrl crl) {
            cached.accumulateAndGet(crl, (old, incoming) -> old == null
                    || !old.issuerKeyHash().equals(incoming.issuerKeyHash())
                    || incoming.crlNumber() > old.crlNumber() ? incoming : old);
        }

        boolean idle() {
            return !running.get() && !pending.get();
        }

        boolean covers(String issuerKeyHash) {
            SignedCrl c = cached.get();
            return c == null || c.issuerKeyHash().equals(issuerKeyHash);
        }

        void refreshIfExpiring(Instant now) {
            SignedCrl c = cached.get();
            if (c == null || c.nextUpdate().minus(refreshMargin).isBefore(now)) {
                log.info("{} CRL nextUpdate within {}; republishing", name, refreshMargin);
                requestRegeneration();
            }
        }

        void requestRegeneration() {
            pending.set(true);
            drain();
        }

        private void drain() {
            if (!running.compareAndSet(false, true)) {
                return; // the running generation will pick up the pending flag
            }
            Schedulers.boundedElastic().schedule(() -> {
                try {
                    while (pending.getAndSet(false)) {
                        try {
                            generator.get();
                        } catch (RuntimeException e) {
                            log.error("{} CRL regeneration failed; still serving the previous CRL: {}", name, e.toString());
                        }
                    }
                } finally {
                    running.set(false);
                    if (pending.get()) {
                        drain();
                    }
                }
            });
        }
    }

    record Entry(BigInteger serial, Instant revokedAt, int reason) {
    }

    private record Snapshot(CaIssuer issuer, long crlNumber, List<Entry> entries) {
    }

    private SignedCrl generate(KeyPurpose purpose, Duration validity,
                            BiFunction<CaIssuer, Instant, List<Entry>> entryLoader) {
        Instant thisUpdate = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        Snapshot snap = tx.execute(status -> {
            CaIssuer ca = issuers.requireActive(purpose);
            Long number = jdbc.queryForObject(
                    "UPDATE ca_issuers SET crl_number = crl_number + 1 WHERE issuer_key_hash = ? "
                            + "RETURNING crl_number - 1", Long.class, ca.issuerKeyHash());
            return new Snapshot(ca, number, entryLoader.apply(ca, thisUpdate));
        });

        X509Certificate caCert = snap.issuer().certificate();
        X509v2CRLBuilder b = new X509v2CRLBuilder(
                X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded()), Date.from(thisUpdate));
        Instant nextUpdate = thisUpdate.plus(validity);
        b.setNextUpdate(Date.from(nextUpdate));
        for (Entry e : snap.entries()) {
            if (e.reason() == CRLReason.unspecified) {
                // RFC 5280 5.3.1: the reasonCode extension SHOULD be absent rather than carry unspecified (0).
                b.addCRLEntry(e.serial(), Date.from(e.revokedAt()), (org.bouncycastle.asn1.x509.Extensions) null);
            } else {
                b.addCRLEntry(e.serial(), Date.from(e.revokedAt()), e.reason());
            }
        }
        try {
            b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(snap.crlNumber())));
            b.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(CertificateProfiles.subjectKeyIdentifier(caCert)));
            X509CRLHolder crl = b.build(KmsContentSigner.forKmsKey(kmsSigner, snap.issuer().kmsArn()));
            new JcaX509CRLConverter().getCRL(crl).verify(caCert.getPublicKey());
            log.info("Generated {} CRL number {} with {} entries", purpose, snap.crlNumber(), snap.entries().size());
            return new SignedCrl(Pems.crl(crl.getEncoded()), snap.issuer().issuerKeyHash(), snap.crlNumber(),
                    nextUpdate, snap.entries().size());
        } catch (IOException | java.security.GeneralSecurityException e) {
            throw new IllegalStateException("cannot build " + purpose + " CRL", e);
        }
    }

    /**
     * REVOKED certificates of this issuer that have not expired, plus VOIDED ledger serials (DECISIONS #38) reserved
     * recently enough that a signed leaf could still be valid (leaf TTL + 1 h). A serial in both appears once.
     */
    private List<Entry> leafEntries(CaIssuer ca, Instant now) {
        java.util.Map<BigInteger, Entry> bySerial = new java.util.LinkedHashMap<>();
        for (Entry e : revokedCertificates(ca, now)) {
            bySerial.putIfAbsent(e.serial(), e);
        }
        Instant cutoff = now.minus(pki.deviceLeafTtl()).minus(Duration.ofHours(1));
        jdbc.query("""
                SELECT serial_number, voided_at FROM issued_serials
                 WHERE issuer_key_hash = ? AND status = 'VOIDED' AND reserved_at > ?
                 ORDER BY voided_at, serial_number
                """, rs -> {
            BigInteger serial = SerialNumbers.fromHex(rs.getString("serial_number"));
            Timestamp voided = rs.getTimestamp("voided_at");
            bySerial.putIfAbsent(serial, new Entry(serial, voided == null ? now : voided.toInstant(),
                    CRLReason.superseded));
        }, ca.issuerKeyHash(), Timestamp.from(cutoff));
        return new ArrayList<>(bySerial.values());
    }

    private List<Entry> revokedCertificates(CaIssuer ca, Instant now) {
        return jdbc.query("""
                        SELECT serial_number, revoked_at, revocation_reason
                          FROM certificates
                         WHERE issuer_key_hash = ? AND status = 'REVOKED' AND not_after > ?
                         ORDER BY revoked_at, serial_number
                        """,
                (rs, i) -> new Entry(
                        SerialNumbers.fromHex(rs.getString("serial_number")),
                        revokedAtOrNow(rs.getTimestamp("revoked_at"), now, rs.getString("serial_number")),
                        CrlReasons.toCrlReason(rs.getString("revocation_reason"))),
                ca.issuerKeyHash(), Timestamp.from(now));
    }

    /**
     * ca_issuers has no revoked_at, revocation reason or not_after column, so: issuance by this Root is checked via
     * the stored certificate's AKI, expiry via its notAfter, the revocation date is the retired_at of its KMS key
     * (falling back to thisUpdate), and the reason is left unspecified.
     */
    private List<Entry> intermediateEntries(CaIssuer root, Instant now) {
        byte[] rootSki = CertificateProfiles.subjectKeyIdentifier(root.certificate());
        List<Entry> out = new ArrayList<>();
        jdbc.query("""
                SELECT ci.cert_pem, k.retired_at
                  FROM ca_issuers ci
                  LEFT JOIN kms_keys k ON k.kms_key_id = ci.kms_primary_arn
                 WHERE ci.status = 'REVOKED'
                """, rs -> {
            X509Certificate cert = Pems.parseCertificate(rs.getString("cert_pem"));
            byte[] aki = CertificateProfiles.authorityKeyIdentifier(cert);
            boolean issuedByRoot = aki != null && java.util.Arrays.equals(aki, rootSki)
                    && cert.getBasicConstraints() >= 0;
            if (issuedByRoot && cert.getNotAfter().toInstant().isAfter(now)) {
                Timestamp retired = rs.getTimestamp("retired_at");
                out.add(new Entry(cert.getSerialNumber(),
                        retired == null ? now : retired.toInstant(), CRLReason.unspecified));
            }
        });
        return out;
    }

    private static Instant revokedAtOrNow(Timestamp revokedAt, Instant now, String serial) {
        if (revokedAt == null) {
            log.warn("REVOKED certificate {} has no revoked_at; using thisUpdate", serial);
            return now;
        }
        return revokedAt.toInstant();
    }
}
