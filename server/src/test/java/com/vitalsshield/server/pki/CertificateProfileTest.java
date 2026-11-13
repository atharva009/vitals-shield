package com.vitalsshield.server.pki;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Builds every profile with local software EC keys (no KMS) and checks it field by field against spec Section 3. */
class CertificateProfileTest {

    private static final String BASE_URL = "https://localhost:8444";
    /** Half-second offset proves notBefore is truncated to whole seconds before the -60s skew. */
    private static final Instant NOW = Instant.parse("2026-11-13T12:00:00.500Z");
    private static final Instant EXPECTED_NOT_BEFORE = Instant.parse("2026-11-13T11:59:00Z");

    private static final ASN1ObjectIdentifier BC = Extension.basicConstraints;
    private static final ASN1ObjectIdentifier KU = Extension.keyUsage;
    private static final ASN1ObjectIdentifier EKU = Extension.extendedKeyUsage;
    private static final ASN1ObjectIdentifier SKI = Extension.subjectKeyIdentifier;
    private static final ASN1ObjectIdentifier AKI = Extension.authorityKeyIdentifier;
    private static final ASN1ObjectIdentifier SAN = Extension.subjectAlternativeName;
    private static final ASN1ObjectIdentifier CDP = Extension.cRLDistributionPoints;

    static KeyPair rootKey;
    static KeyPair deviceIntKey;
    static KeyPair serverCaKey;
    static KeyPair deviceLeafKey;
    static KeyPair gatewayKey;

    static CertificateProfiles profiles;
    static X509Certificate root;
    static X509Certificate deviceInt;
    static X509Certificate serverCa;
    static X509Certificate deviceLeaf;
    static X509Certificate gatewayLeaf;

    @BeforeAll
    static void buildAll() throws Exception {
        rootKey = ecKeyPair();
        deviceIntKey = ecKeyPair();
        serverCaKey = ecKeyPair();
        deviceLeafKey = ecKeyPair();
        gatewayKey = ecKeyPair();

        profiles = new CertificateProfiles(Clock.fixed(NOW, ZoneOffset.UTC), new java.security.SecureRandom(), BASE_URL);
        root = profiles.root(spki(rootKey), signer(rootKey.getPrivate()));
        deviceInt = profiles.deviceIntermediate(spki(deviceIntKey), root, signer(rootKey.getPrivate()));
        serverCa = profiles.serverTlsCa(spki(serverCaKey), root, signer(rootKey.getPrivate()));
        deviceLeaf = profiles.deviceLeaf("dev_wearable_019", spki(deviceLeafKey), deviceInt,
                Duration.ofHours(12), signer(deviceIntKey.getPrivate()));
        gatewayLeaf = profiles.gatewayLeaf(spki(gatewayKey), serverCa,
                Duration.ofHours(24), signer(serverCaKey.getPrivate()));
    }

    @Test
    void rootProfile() throws Exception {
        X509CertificateHolder h = holder(root);
        assertCommon(h, root, "CN=VitalsShield Root CA,O=VitalsShield", rootKey);
        assertThat(h.getIssuer()).isEqualTo(h.getSubject());
        assertThat(h.getNotAfter().toInstant()).isEqualTo(plusYears(EXPECTED_NOT_BEFORE, 10));
        assertThat(extensionOrder(h)).containsExactly(BC, KU, SKI);

        assertBasicConstraints(h, true, 1);
        assertKeyUsage(h, KeyUsage.keyCertSign | KeyUsage.cRLSign);
        root.verify(rootKey.getPublic());
    }

    @Test
    void deviceIntermediateProfile() throws Exception {
        X509CertificateHolder h = holder(deviceInt);
        assertCommon(h, deviceInt, "CN=VitalsShield Issuing CA G1,O=VitalsShield", deviceIntKey);
        assertIssuedBy(h, root);
        assertThat(h.getNotAfter().toInstant()).isEqualTo(plusYears(EXPECTED_NOT_BEFORE, 1));
        assertThat(extensionOrder(h)).containsExactly(BC, KU, EKU, SKI, AKI, CDP);

        assertBasicConstraints(h, true, 0);
        assertKeyUsage(h, KeyUsage.keyCertSign | KeyUsage.cRLSign);
        assertEku(h, false, KeyPurposeId.id_kp_clientAuth);
        assertCdp(h, BASE_URL + "/api/v1/pki/root-crl.pem");
        deviceInt.verify(rootKey.getPublic());
    }

    @Test
    void serverTlsCaProfile() throws Exception {
        X509CertificateHolder h = holder(serverCa);
        assertCommon(h, serverCa, "CN=VitalsShield Server TLS CA G1,O=VitalsShield", serverCaKey);
        assertIssuedBy(h, root);
        assertThat(h.getNotAfter().toInstant()).isEqualTo(plusYears(EXPECTED_NOT_BEFORE, 1));
        assertThat(extensionOrder(h)).containsExactly(BC, KU, EKU, SKI, AKI, CDP);

        assertBasicConstraints(h, true, 0);
        assertKeyUsage(h, KeyUsage.keyCertSign | KeyUsage.cRLSign);
        assertEku(h, false, KeyPurposeId.id_kp_serverAuth);
        assertCdp(h, BASE_URL + "/api/v1/pki/root-crl.pem");
        serverCa.verify(rootKey.getPublic());
    }

    @Test
    void deviceLeafProfile() throws Exception {
        X509CertificateHolder h = holder(deviceLeaf);
        assertCommon(h, deviceLeaf, "CN=dev_wearable_019,O=VitalsShield Devices", deviceLeafKey);
        assertIssuedBy(h, deviceInt);
        assertThat(Duration.between(h.getNotBefore().toInstant(), h.getNotAfter().toInstant()))
                .isEqualTo(Duration.ofHours(12));
        assertThat(extensionOrder(h)).containsExactly(BC, KU, EKU, SKI, AKI, SAN, CDP);

        assertBasicConstraints(h, false, null);
        assertKeyUsage(h, KeyUsage.digitalSignature);
        assertEku(h, true, KeyPurposeId.id_kp_clientAuth);

        Extension san = h.getExtension(SAN);
        assertThat(san.isCritical()).isFalse();
        GeneralName[] names = GeneralNames.getInstance(san.getParsedValue()).getNames();
        assertThat(names).hasSize(1);
        assertThat(names[0].getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
        assertThat(DERIA5String.getInstance(names[0].getName()).getString())
                .isEqualTo("urn:vitalsshield:device:dev_wearable_019");

        assertCdp(h, BASE_URL + "/api/v1/pki/intermediate-crl.pem");
        deviceLeaf.verify(deviceIntKey.getPublic());
    }

    @Test
    void deviceLeafTtlIsConfigurable() throws Exception {
        X509Certificate shortLeaf = profiles.deviceLeaf("dev_ttl", spki(deviceLeafKey), deviceInt,
                Duration.ofMinutes(30), signer(deviceIntKey.getPrivate()));
        assertThat(Duration.between(shortLeaf.getNotBefore().toInstant(), shortLeaf.getNotAfter().toInstant()))
                .isEqualTo(Duration.ofMinutes(30));
    }

    @Test
    void gatewayLeafProfile() throws Exception {
        X509CertificateHolder h = holder(gatewayLeaf);
        assertCommon(h, gatewayLeaf, "CN=VitalsShield Gateway,O=VitalsShield", gatewayKey);
        assertIssuedBy(h, serverCa);
        assertThat(Duration.between(h.getNotBefore().toInstant(), h.getNotAfter().toInstant()))
                .isEqualTo(Duration.ofHours(24));
        assertThat(extensionOrder(h)).containsExactly(BC, KU, EKU, SKI, AKI, SAN);

        assertBasicConstraints(h, false, null);
        assertKeyUsage(h, KeyUsage.digitalSignature);
        assertEku(h, false, KeyPurposeId.id_kp_serverAuth);

        Extension san = h.getExtension(SAN);
        assertThat(san.isCritical()).isFalse();
        GeneralName[] names = GeneralNames.getInstance(san.getParsedValue()).getNames();
        assertThat(names).containsExactly(
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1"));
        gatewayLeaf.verify(serverCaKey.getPublic());
    }

    @Test
    void serialsArePositiveAtMost20OctetsAndUnique() {
        Set<BigInteger> seen = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            BigInteger serial = SerialNumbers.random(new java.security.SecureRandom());
            assertThat(serial.signum()).isPositive();
            assertThat(serial.toByteArray().length).isLessThanOrEqualTo(20);
            assertThat(seen.add(serial)).as("serial %s repeated", serial).isTrue();
        }
    }

    @Test
    void serialHexIsLowercaseWithoutLeadingZeros() {
        assertThat(SerialNumbers.toHex(new BigInteger("00ff0a", 16))).isEqualTo("ff0a");
        assertThat(SerialNumbers.toHex(BigInteger.valueOf(0x0abc))).isEqualTo("abc");
    }

    @Test
    void issuerKeyHashIsLowercaseHexOfSki() throws Exception {
        String hash = CertificateProfiles.issuerKeyHash(root);
        assertThat(hash).matches("[0-9a-f]{64}");
        assertThat(hash).isEqualTo(java.util.HexFormat.of().formatHex(sha256(root.getPublicKey().getEncoded())));
    }

    // ---- shared assertions --------------------------------------------------------------------------------------

    private static void assertCommon(X509CertificateHolder h, X509Certificate cert, String rfc2253Subject,
                                     KeyPair subjectKey) throws Exception {
        assertThat(h.getVersionNumber()).isEqualTo(3);
        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo(rfc2253Subject);
        // RFC 4514 strings list the most specific RDN first, so the DER order is O then CN.
        RDN[] rdns = h.getSubject().getRDNs();
        assertThat(rdns).hasSize(2);
        assertThat(rdns[0].getFirst().getType()).isEqualTo(BCStyle.O);
        assertThat(rdns[1].getFirst().getType()).isEqualTo(BCStyle.CN);

        assertThat(h.getNotBefore().toInstant()).isEqualTo(EXPECTED_NOT_BEFORE);

        BigInteger serial = h.getSerialNumber();
        assertThat(serial.signum()).isPositive();
        assertThat(serial.toByteArray().length).isLessThanOrEqualTo(20);

        // Signature algorithm: ecdsa-with-SHA256 with the parameters field ABSENT (not NULL), in both places.
        AlgorithmIdentifier outer = h.getSignatureAlgorithm();
        AlgorithmIdentifier inner = h.toASN1Structure().getTBSCertificate().getSignature();
        for (AlgorithmIdentifier alg : List.of(outer, inner)) {
            assertThat(alg.getAlgorithm()).isEqualTo(X9ObjectIdentifiers.ecdsa_with_SHA256);
            assertThat(alg.getAlgorithm().getId()).isEqualTo("1.2.840.10045.4.3.2");
            assertThat(alg.getParameters()).isNull();
        }
        assertThat(outer.getEncoded()).containsExactly(
                0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02);

        Extension ski = h.getExtension(SKI);
        assertThat(ski.isCritical()).isFalse();
        byte[] expectedSki = sha256(subjectKey.getPublic().getEncoded());
        assertThat(SubjectKeyIdentifier.getInstance(ski.getParsedValue()).getKeyIdentifier())
                .hasSize(32).containsExactly(expectedSki);
    }

    private static void assertIssuedBy(X509CertificateHolder h, X509Certificate issuer) throws Exception {
        X509CertificateHolder issuerHolder = holder(issuer);
        assertThat(h.getIssuer()).isEqualTo(issuerHolder.getSubject());
        Extension aki = h.getExtension(AKI);
        assertThat(aki.isCritical()).isFalse();
        AuthorityKeyIdentifier parsed = AuthorityKeyIdentifier.getInstance(aki.getParsedValue());
        byte[] issuerSki = SubjectKeyIdentifier.getInstance(
                issuerHolder.getExtension(SKI).getParsedValue()).getKeyIdentifier();
        assertThat(parsed.getKeyIdentifierObject().getOctets()).containsExactly(issuerSki);
        assertThat(parsed.getAuthorityCertIssuer()).isNull();
        assertThat(parsed.getAuthorityCertSerialNumber()).isNull();
    }

    private static void assertBasicConstraints(X509CertificateHolder h, boolean ca, Integer pathLen) {
        Extension ext = h.getExtension(BC);
        assertThat(ext.isCritical()).isTrue();
        BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
        assertThat(bc.isCA()).isEqualTo(ca);
        if (pathLen == null) {
            assertThat(bc.getPathLenConstraint()).isNull();
        } else {
            assertThat(bc.getPathLenConstraint()).isEqualTo(BigInteger.valueOf(pathLen));
        }
    }

    private static void assertKeyUsage(X509CertificateHolder h, int bits) {
        Extension ext = h.getExtension(KU);
        assertThat(ext.isCritical()).isTrue();
        assertThat(KeyUsage.getInstance(ext.getParsedValue())).isEqualTo(new KeyUsage(bits));
    }

    private static void assertEku(X509CertificateHolder h, boolean critical, KeyPurposeId purpose) {
        Extension ext = h.getExtension(EKU);
        assertThat(ext.isCritical()).isEqualTo(critical);
        assertThat(ExtendedKeyUsage.getInstance(ext.getParsedValue()).getUsages()).containsExactly(purpose);
    }

    private static void assertCdp(X509CertificateHolder h, String url) {
        Extension ext = h.getExtension(CDP);
        assertThat(ext.isCritical()).isFalse();
        DistributionPoint[] points = CRLDistPoint.getInstance(ext.getParsedValue()).getDistributionPoints();
        assertThat(points).hasSize(1);
        GeneralName[] names = GeneralNames.getInstance(points[0].getDistributionPoint().getName()).getNames();
        assertThat(names).containsExactly(new GeneralName(GeneralName.uniformResourceIdentifier, url));
        assertThat(points[0].getReasons()).isNull();
        assertThat(points[0].getCRLIssuer()).isNull();
    }

    private static List<ASN1ObjectIdentifier> extensionOrder(X509CertificateHolder h) {
        return List.of(h.getExtensions().getExtensionOIDs());
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    static SubjectPublicKeyInfo spki(KeyPair kp) {
        return SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
    }

    /** Same ContentSigner used with KMS, backed by a local key: NONEwithECDSA signs a precomputed digest, as KMS DIGEST does. */
    static KmsContentSigner signer(PrivateKey key) {
        return new KmsContentSigner(digest -> {
            try {
                Signature s = Signature.getInstance("NONEwithECDSA");
                s.initSign(key);
                s.update(digest);
                return s.sign();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    static X509CertificateHolder holder(X509Certificate cert) throws Exception {
        return new X509CertificateHolder(cert.getEncoded());
    }

    static Instant plusYears(Instant instant, int years) {
        return instant.atZone(ZoneOffset.UTC).plusYears(years).toInstant();
    }

    static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
}
