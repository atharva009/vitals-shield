package com.vitalsshield.server.pki.trust;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vitalsshield.server.pki.CertificateProfiles;
import com.vitalsshield.server.pki.KmsContentSigner;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Trust manager against software-key CAs built with the real CertificateProfiles (no KMS, no DB). */
class DynamicMtlsTrustManagerTest {

    static final Instant NOW = Instant.parse("2026-11-13T12:00:00Z");

    static KeyPair rootKey;
    static KeyPair intKey;
    static X509Certificate root;
    static X509Certificate deviceInt;
    static CertificateProfiles profiles;

    @BeforeAll
    static void hierarchy() throws Exception {
        profiles = new CertificateProfiles(Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom(), "https://localhost:8444");
        rootKey = ec();
        intKey = ec();
        root = profiles.root(spki(rootKey), signer(rootKey.getPrivate()));
        deviceInt = profiles.deviceIntermediate(spki(intKey), root, signer(rootKey.getPrivate()));
    }

    final MutableClock clock = new MutableClock(NOW);
    final CertificateDenyList denyList = new CertificateDenyList(List::of, clock);
    final DynamicMtlsTrustManager tm = new DynamicMtlsTrustManager(anchors(root, deviceInt), denyList, clock);

    @Test
    void validLeafPasses() throws Exception {
        X509Certificate leaf = leaf("dev_ok");
        assertThatCode(() -> tm.checkClientTrusted(new X509Certificate[] {leaf}, "EC")).doesNotThrowAnyException();
    }

    @Test
    void leafFromDifferentCaWithIdenticalDnFails() throws Exception {
        KeyPair otherRootKey = ec();
        KeyPair otherIntKey = ec();
        X509Certificate otherRoot = profiles.root(spki(otherRootKey), signer(otherRootKey.getPrivate()));
        X509Certificate otherInt = profiles.deviceIntermediate(spki(otherIntKey), otherRoot,
                signer(otherRootKey.getPrivate()));
        assertThat(otherInt.getSubjectX500Principal()).isEqualTo(deviceInt.getSubjectX500Principal());

        X509Certificate impostor = profiles.deviceLeaf("dev_impostor", spki(ec()), otherInt, Duration.ofHours(12),
                signer(otherIntKey.getPrivate()));

        assertRejected(impostor);
    }

    @Test
    void expiredLeafFails() throws Exception {
        X509Certificate leaf = leaf("dev_expired");
        clock.set(leaf.getNotAfter().toInstant().plusSeconds(1));
        assertRejected(leaf);
        assertThatThrownBy(() -> tm.checkClientTrusted(new X509Certificate[] {leaf}, "EC"))
                .hasCauseInstanceOf(java.security.cert.CertPathValidatorException.class)
                .satisfies(e -> assertThat(((java.security.cert.CertPathValidatorException) e.getCause()).getReason())
                        .isEqualTo(java.security.cert.CertPathValidatorException.BasicReason.EXPIRED));
    }

    @Test
    void notYetValidLeafFails() throws Exception {
        X509Certificate leaf = leaf("dev_future");
        clock.set(leaf.getNotBefore().toInstant().minusSeconds(1));
        assertRejected(leaf);
    }

    @Test
    void ekuWithoutClientAuthFails() throws Exception {
        X509Certificate leaf = customLeaf(false, KeyPurposeId.id_kp_serverAuth, KeyUsage.digitalSignature);
        assertRejected(leaf);
    }

    @Test
    void caTrueLeafFails() throws Exception {
        X509Certificate leaf = customLeaf(true, KeyPurposeId.id_kp_clientAuth, KeyUsage.digitalSignature);
        assertRejected(leaf);
    }

    @Test
    void denyListedLeafFails() throws Exception {
        X509Certificate leaf = leaf("dev_denied");
        denyList.add(CertKey.from(leaf), NOW, "REVOKED");
        assertRejected(leaf);
        assertThatThrownBy(() -> tm.checkClientTrusted(new X509Certificate[] {leaf}, "EC"))
                .hasCauseInstanceOf(java.security.cert.CertPathValidatorException.class)
                .satisfies(e -> assertThat(((java.security.cert.CertPathValidatorException) e.getCause()).getReason())
                        .isEqualTo(java.security.cert.CertPathValidatorException.BasicReason.REVOKED));
    }

    @Test
    void denyEntryInTheFuturePassesUntilClockReachesIt() throws Exception {
        X509Certificate leaf = leaf("dev_grace");
        denyList.add(CertKey.from(leaf), NOW.plusSeconds(60), "SUPERSEDED");

        assertThatCode(() -> tm.checkClientTrusted(new X509Certificate[] {leaf}, "EC")).doesNotThrowAnyException();

        clock.advance(Duration.ofSeconds(60));
        assertRejected(leaf);
    }

    @Test
    void clientSuppliedForgedIntermediateIsIgnored() throws Exception {
        // Attacker builds their own "intermediate" with the real DN (under a fake root that also has the real DN),
        // signs a leaf with it, then sends both.
        KeyPair fakeRootKey = ec();
        X509Certificate fakeRoot = profiles.root(spki(fakeRootKey), signer(fakeRootKey.getPrivate()));
        KeyPair forgedIntKey = ec();
        X509Certificate forgedInt = profiles.deviceIntermediate(spki(forgedIntKey), fakeRoot,
                signer(fakeRootKey.getPrivate()));
        assertThat(forgedInt.getSubjectX500Principal()).isEqualTo(deviceInt.getSubjectX500Principal());
        X509Certificate forgedLeaf = profiles.deviceLeaf("dev_forged", spki(ec()), forgedInt, Duration.ofHours(12),
                signer(forgedIntKey.getPrivate()));

        assertThatThrownBy(() -> tm.checkClientTrusted(new X509Certificate[] {forgedLeaf, forgedInt}, "EC"))
                .isInstanceOf(CertificateException.class);

        // A genuine leaf passes even when the client appends junk after it.
        X509Certificate genuine = leaf("dev_genuine");
        assertThatCode(() -> tm.checkClientTrusted(new X509Certificate[] {genuine, forgedInt}, "EC"))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptedIssuersIsOnlyCurrentDeviceIntermediate() {
        assertThat(tm.getAcceptedIssuers()).containsExactly(deviceInt);
    }

    @Test
    void serverTrustIsUnsupported() {
        assertThatThrownBy(() -> tm.checkServerTrusted(new X509Certificate[] {deviceInt}, "EC"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void anchorsAreReadOnEveryCall() throws Exception {
        MutableAnchors mutable = new MutableAnchors(root, deviceInt);
        DynamicMtlsTrustManager dynamic = new DynamicMtlsTrustManager(mutable, denyList, clock);
        X509Certificate leaf = leaf("dev_rotate");
        dynamic.checkClientTrusted(new X509Certificate[] {leaf}, "EC");

        KeyPair newRootKey = ec();
        X509Certificate newRoot = profiles.root(spki(newRootKey), signer(newRootKey.getPrivate()));
        X509Certificate newInt = profiles.deviceIntermediate(spki(ec()), newRoot, signer(newRootKey.getPrivate()));
        mutable.root = newRoot;
        mutable.deviceInt = newInt;

        assertThatThrownBy(() -> dynamic.checkClientTrusted(new X509Certificate[] {leaf}, "EC"))
                .isInstanceOf(CertificateException.class);
        assertThat(dynamic.getAcceptedIssuers()).containsExactly(newInt);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    private void assertRejected(X509Certificate leaf) {
        assertThatThrownBy(() -> tm.checkClientTrusted(new X509Certificate[] {leaf}, "EC"))
                .isInstanceOf(CertificateException.class);
    }

    private static X509Certificate leaf(String deviceId) throws Exception {
        return profiles.deviceLeaf(deviceId, spki(ec()), deviceInt, Duration.ofHours(12), signer(intKey.getPrivate()));
    }

    /** A leaf signed by the real intermediate but with chosen BC / EKU / KU, to test leaf-level policy. */
    private static X509Certificate customLeaf(boolean ca, KeyPurposeId eku, int ku) throws Exception {
        KeyPair leafKey = ec();
        Instant nb = NOW.minusSeconds(60);
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(
                X500Name.getInstance(deviceInt.getSubjectX500Principal().getEncoded()),
                new BigInteger(64, new SecureRandom()).add(BigInteger.ONE),
                Date.from(nb), Date.from(nb.plus(Duration.ofHours(12))),
                X500Name.getInstance(new X500Principal("CN=dev_custom, O=VitalsShield Devices").getEncoded()),
                spki(leafKey));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(ku));
        b.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(eku));
        b.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(java.security.MessageDigest.getInstance("SHA-256")
                        .digest(leafKey.getPublic().getEncoded())));
        b.addExtension(Extension.authorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(CertificateProfiles.subjectKeyIdentifier(deviceInt)));
        return new JcaX509CertificateConverter().getCertificate(b.build(signer(intKey.getPrivate())));
    }

    static TrustAnchorSource anchors(X509Certificate root, X509Certificate deviceInt) {
        return new MutableAnchors(root, deviceInt);
    }

    static final class MutableAnchors implements TrustAnchorSource {
        volatile X509Certificate root;
        volatile X509Certificate deviceInt;

        MutableAnchors(X509Certificate root, X509Certificate deviceInt) {
            this.root = root;
            this.deviceInt = deviceInt;
        }

        @Override
        public X509Certificate root() {
            return root;
        }

        @Override
        public X509Certificate deviceIntermediate() {
            return deviceInt;
        }
    }

    static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    static SubjectPublicKeyInfo spki(KeyPair kp) {
        return SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
    }

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
}
