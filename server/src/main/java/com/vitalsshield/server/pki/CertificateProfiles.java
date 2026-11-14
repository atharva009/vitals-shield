package com.vitalsshield.server.pki;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HexFormat;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;

/**
 * RFC 5280 X.509v3 profiles from spec Section 3, plus the Server TLS CA and gateway leaf.
 *
 * <p>Common rules: v3; 20-byte positive random serial; notBefore = now (whole seconds) - 60s; SKI = SHA-256 of the
 * subject's full SPKI DER; AKI = issuer SKI only. Extensions are always added in the order BasicConstraints,
 * KeyUsage, ExtendedKeyUsage, SKI, AKI, SAN, CRLDistributionPoints (absent ones skipped).
 *
 * <p>Subject DNs are RFC 4514 strings ("CN=..., O=..."), encoded through {@link X500Principal}, so the DER RDN
 * sequence is O then CN and {@code getSubjectX500Principal().getName()} round-trips the string.
 */
public final class CertificateProfiles {

    public static final String ROOT_DN = "CN=VitalsShield Root CA, O=VitalsShield";
    public static final String DEVICE_INTERMEDIATE_DN = "CN=VitalsShield Issuing CA G1, O=VitalsShield";
    public static final String SERVER_TLS_CA_DN = "CN=VitalsShield Server TLS CA G1, O=VitalsShield";
    public static final String GATEWAY_DN = "CN=VitalsShield Gateway, O=VitalsShield";
    public static final String DEVICE_LEAF_ORG = "VitalsShield Devices";
    public static final String DEVICE_URN_PREFIX = "urn:vitalsshield:device:";

    static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    /** Matches devices.device_id VARCHAR(64); restricted so the CN and URN need no escaping. */
    private static final Pattern DEVICE_ID = Pattern.compile("[A-Za-z0-9_.-]{1,64}");

    private static final int CA_KEY_USAGE = KeyUsage.keyCertSign | KeyUsage.cRLSign;
    private static final HexFormat HEX = HexFormat.of();

    private final Clock clock;
    private final SecureRandom random;
    private final String publicBaseUrl;

    public CertificateProfiles(Clock clock, SecureRandom random, String publicBaseUrl) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        Objects.requireNonNull(publicBaseUrl, "publicBaseUrl");
        this.publicBaseUrl = publicBaseUrl.endsWith("/")
                ? publicBaseUrl.substring(0, publicBaseUrl.length() - 1) : publicBaseUrl;
    }

    public String rootCrlUrl() {
        return publicBaseUrl + "/api/v1/pki/root-crl.pem";
    }

    public String intermediateCrlUrl() {
        return publicBaseUrl + "/api/v1/pki/intermediate-crl.pem";
    }

    /** Self-signed Root CA: 10y, CA:TRUE pathLen 1, no EKU/AKI/SAN/CDP. {@code signer} must hold the root key. */
    public X509Certificate root(SubjectPublicKeyInfo spki, ContentSigner signer) {
        X500Name subject = name(ROOT_DN);
        Instant notBefore = notBefore();
        X509v3CertificateBuilder b = builder(subject, subject, notBefore, plusYears(notBefore, 10), spki);
        add(b, Extension.basicConstraints, true, new BasicConstraints(1));
        add(b, Extension.keyUsage, true, new KeyUsage(CA_KEY_USAGE));
        add(b, Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(sha256(spki)));
        return finish(b, signer, toPublicKey(spki));
    }

    /** Device Issuing Intermediate: 1y, CA:TRUE pathLen 0, EKU clientAuth (non-critical), CDP = root CRL. */
    public X509Certificate deviceIntermediate(SubjectPublicKeyInfo spki, X509Certificate root, ContentSigner rootSigner) {
        return intermediate(DEVICE_INTERMEDIATE_DN, KeyPurposeId.id_kp_clientAuth, spki, root, rootSigner);
    }

    /** Server TLS CA: 1y, CA:TRUE pathLen 0, EKU serverAuth (non-critical), CDP = root CRL. */
    public X509Certificate serverTlsCa(SubjectPublicKeyInfo spki, X509Certificate root, ContentSigner rootSigner) {
        return intermediate(SERVER_TLS_CA_DN, KeyPurposeId.id_kp_serverAuth, spki, root, rootSigner);
    }

    /**
     * Wearable operational leaf: CN=device_id, CA:FALSE, digitalSignature, EKU clientAuth (CRITICAL), non-critical
     * SAN URI urn:vitalsshield:device:device_id, CDP = intermediate CRL.
     */
    public X509Certificate deviceLeaf(String deviceId, SubjectPublicKeyInfo spki, X509Certificate intermediate,
                                      Duration ttl, ContentSigner intermediateSigner) {
        if (deviceId == null || !DEVICE_ID.matcher(deviceId).matches()) {
            throw new IllegalArgumentException("device_id must match " + DEVICE_ID.pattern());
        }
        Instant notBefore = notBefore();
        X509v3CertificateBuilder b = builder(subjectOf(intermediate),
                name("CN=" + deviceId + ", O=" + DEVICE_LEAF_ORG), notBefore, notBefore.plus(positive(ttl)), spki);
        add(b, Extension.basicConstraints, true, new BasicConstraints(false));
        add(b, Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        add(b, Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        add(b, Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(sha256(spki)));
        add(b, Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(subjectKeyIdentifier(intermediate)));
        add(b, Extension.subjectAlternativeName, false, new GeneralNames(
                new GeneralName(GeneralName.uniformResourceIdentifier, DEVICE_URN_PREFIX + deviceId)));
        add(b, Extension.cRLDistributionPoints, false, crlDistributionPoint(intermediateCrlUrl()));
        return finish(b, intermediateSigner, intermediate.getPublicKey());
    }

    /**
     * Gateway TLS server leaf: CA:FALSE, digitalSignature, EKU serverAuth (non-critical), non-critical SAN
     * DNS:localhost + IP:127.0.0.1, no CDP.
     */
    public X509Certificate gatewayLeaf(SubjectPublicKeyInfo spki, X509Certificate serverTlsCa, Duration ttl,
                                       ContentSigner serverCaSigner) {
        Instant notBefore = notBefore();
        X509v3CertificateBuilder b = builder(subjectOf(serverTlsCa), name(GATEWAY_DN),
                notBefore, notBefore.plus(positive(ttl)), spki);
        add(b, Extension.basicConstraints, true, new BasicConstraints(false));
        add(b, Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        add(b, Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        add(b, Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(sha256(spki)));
        add(b, Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(subjectKeyIdentifier(serverTlsCa)));
        add(b, Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")}));
        return finish(b, serverCaSigner, serverTlsCa.getPublicKey());
    }

    /** issuer_key_hash: lowercase hex of the certificate's own SKI (32 bytes). */
    public static String issuerKeyHash(X509Certificate cert) {
        return HEX.formatHex(subjectKeyIdentifier(cert));
    }

    /** The SKI extension value of {@code cert}. */
    public static byte[] subjectKeyIdentifier(X509Certificate cert) {
        Extension ext = holder(cert).getExtension(Extension.subjectKeyIdentifier);
        if (ext == null) {
            throw new IllegalArgumentException("certificate has no SubjectKeyIdentifier: " + cert.getSubjectX500Principal());
        }
        return SubjectKeyIdentifier.getInstance(ext.getParsedValue()).getKeyIdentifier();
    }

    /** The AKI keyIdentifier of {@code cert}, or null if absent. */
    public static byte[] authorityKeyIdentifier(X509Certificate cert) {
        Extension ext = holder(cert).getExtension(Extension.authorityKeyIdentifier);
        return ext == null ? null : AuthorityKeyIdentifier.getInstance(ext.getParsedValue()).getKeyIdentifierOctets();
    }

    // ---- internals ----------------------------------------------------------------------------------------------

    private X509Certificate intermediate(String dn, KeyPurposeId eku, SubjectPublicKeyInfo spki, X509Certificate root,
                                         ContentSigner rootSigner) {
        Instant notBefore = notBefore();
        X509v3CertificateBuilder b = builder(subjectOf(root), name(dn), notBefore, plusYears(notBefore, 1), spki);
        add(b, Extension.basicConstraints, true, new BasicConstraints(0));
        add(b, Extension.keyUsage, true, new KeyUsage(CA_KEY_USAGE));
        add(b, Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        add(b, Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(sha256(spki)));
        add(b, Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(subjectKeyIdentifier(root)));
        add(b, Extension.cRLDistributionPoints, false, crlDistributionPoint(rootCrlUrl()));
        return finish(b, rootSigner, root.getPublicKey());
    }

    private X509v3CertificateBuilder builder(X500Name issuer, X500Name subject, Instant notBefore, Instant notAfter,
                                             SubjectPublicKeyInfo spki) {
        BigInteger serial = SerialNumbers.random(random);
        return new X509v3CertificateBuilder(issuer, serial, Date.from(notBefore), Date.from(notAfter), subject, spki);
    }

    /** Builds, converts and verifies the signature against the expected issuer key (catches a wrong KMS key). */
    private static X509Certificate finish(X509v3CertificateBuilder b, ContentSigner signer, PublicKey issuerKey) {
        try {
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(b.build(signer));
            cert.verify(issuerKey);
            return cert;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("issued certificate failed issuer-key verification", e);
        }
    }

    private Instant notBefore() {
        return clock.instant().truncatedTo(ChronoUnit.SECONDS).minus(CLOCK_SKEW);
    }

    private static Instant plusYears(Instant instant, int years) {
        return instant.atZone(ZoneOffset.UTC).plusYears(years).toInstant();
    }

    private static Duration positive(Duration ttl) {
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        return ttl;
    }

    private static CRLDistPoint crlDistributionPoint(String url) {
        DistributionPointName dpn = new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, url)));
        return new CRLDistPoint(new DistributionPoint[] {new DistributionPoint(dpn, null, null)});
    }

    private static void add(X509v3CertificateBuilder b, org.bouncycastle.asn1.ASN1ObjectIdentifier oid,
                            boolean critical, org.bouncycastle.asn1.ASN1Encodable value) {
        try {
            b.addExtension(oid, critical, value);
        } catch (CertIOException e) {
            throw new IllegalStateException("cannot add extension " + oid, e);
        }
    }

    static X500Name name(String rfc4514) {
        return X500Name.getInstance(new X500Principal(rfc4514).getEncoded());
    }

    /** Issuer name copied byte-for-byte from the issuer certificate's subject. */
    private static X500Name subjectOf(X509Certificate issuer) {
        return X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
    }

    private static X509CertificateHolder holder(X509Certificate cert) {
        try {
            return new X509CertificateHolder(cert.getEncoded());
        } catch (CertificateEncodingException | java.io.IOException e) {
            throw new IllegalStateException("cannot parse certificate", e);
        }
    }

    static byte[] sha256(SubjectPublicKeyInfo spki) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(spki.getEncoded(ASN1Encoding.DER));
        } catch (GeneralSecurityException | java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static PublicKey toPublicKey(SubjectPublicKeyInfo spki) {
        try {
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki.getEncoded(ASN1Encoding.DER)));
        } catch (GeneralSecurityException | java.io.IOException e) {
            throw new IllegalArgumentException("SPKI is not an EC public key", e);
        }
    }
}
