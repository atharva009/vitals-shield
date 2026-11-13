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

/**
 * X.509 v2 CRLs for the Device Intermediate (nextUpdate +24h) and the Root (nextUpdate +180d), returned as PEM.
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

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final CaIssuerRepository issuers;
    private final KmsSigner kmsSigner;
    private final Clock clock = Clock.systemUTC();

    public CrlService(JdbcTemplate jdbc, TransactionTemplate tx, CaIssuerRepository issuers, KmsSigner kmsSigner) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.issuers = issuers;
        this.kmsSigner = kmsSigner;
    }

    /** Leaves issued by the current Device Intermediate that are REVOKED and not yet expired. */
    public String intermediateCrlPem() {
        return generate(KeyPurpose.DEVICE_INTERMEDIATE, INTERMEDIATE_NEXT_UPDATE, this::leafEntries);
    }

    /** Intermediates (Device and Server TLS CA) issued by the current Root that are REVOKED and not yet expired. */
    public String rootCrlPem() {
        return generate(KeyPurpose.ROOT_CA, ROOT_NEXT_UPDATE, this::intermediateEntries);
    }

    record Entry(BigInteger serial, Instant revokedAt, int reason) {
    }

    private record Snapshot(CaIssuer issuer, long crlNumber, List<Entry> entries) {
    }

    private String generate(KeyPurpose purpose, Duration validity,
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
        b.setNextUpdate(Date.from(thisUpdate.plus(validity)));
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
            return Pems.crl(crl.getEncoded());
        } catch (IOException | java.security.GeneralSecurityException e) {
            throw new IllegalStateException("cannot build " + purpose + " CRL", e);
        }
    }

    private List<Entry> leafEntries(CaIssuer ca, Instant now) {
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
