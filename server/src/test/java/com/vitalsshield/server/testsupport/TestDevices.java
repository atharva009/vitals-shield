package com.vitalsshield.server.testsupport;

import com.vitalsshield.server.pki.CertificateIssuer;
import com.vitalsshield.server.pki.Pems;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.pki.trust.CertKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.List;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;

/** Issues a real device leaf through the running context and inserts its rows, the way enrollment will later. */
public final class TestDevices {

    public record Leaf(String deviceId, KeyPair keyPair, X509Certificate cert, CertKey key,
                       List<X509Certificate> chain) {
    }

    private TestDevices() {
    }

    /** Issues a leaf but inserts no certificates row (an unknown-to-the-DB certificate). */
    public static Leaf issueOnly(ApplicationContext ctx, String deviceId) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = g.generateKeyPair();
            X509Certificate cert = ctx.getBean(CertificateIssuer.class).issueDeviceLeaf(deviceId,
                    SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()), Duration.ofHours(12));
            X509Certificate deviceInt = ctx.getBean(TrustAnchors.class).deviceIntermediate();
            return new Leaf(deviceId, kp, cert, CertKey.from(cert), List.of(cert, deviceInt));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Issues a leaf and inserts the devices row and an ACTIVE certificates row. */
    public static Leaf enroll(ApplicationContext ctx, String deviceId) {
        Leaf leaf = issueOnly(ctx, deviceId);
        JdbcTemplate jdbc = ctx.getBean(JdbcTemplate.class);
        jdbc.update("INSERT INTO devices (device_id, hardware_model, trust_state) VALUES (?, 'sim-v1', 'ACTIVE') "
                + "ON CONFLICT (device_id) DO NOTHING", deviceId);
        try {
            jdbc.update("""
                    INSERT INTO certificates (issuer_key_hash, serial_number, device_id, cert_thumbprint_s256,
                                              cert_pem, not_before, not_after, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
                    """, leaf.key().issuerKeyHash(), leaf.key().serial(), deviceId,
                    // DECISIONS #35: base64url(SHA-256(DER)), the JWS x5t#S256 value.
                    java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                            MessageDigest.getInstance("SHA-256").digest(leaf.cert().getEncoded())),
                    Pems.certificate(leaf.cert()),
                    Timestamp.from(leaf.cert().getNotBefore().toInstant()),
                    Timestamp.from(leaf.cert().getNotAfter().toInstant()));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        return leaf;
    }
}
