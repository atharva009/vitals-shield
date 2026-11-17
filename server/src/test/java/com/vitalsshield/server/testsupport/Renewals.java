package com.vitalsshield.server.testsupport;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.vitalsshield.crypto.CsrFactory;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.simulator.CertIds;
import com.vitalsshield.simulator.Simulator;
import com.vitalsshield.simulator.SimulatorStateStore;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** Protocol B from a test: challenge, renewal body, and the CRL check. */
public final class Renewals {

    private Renewals() {
    }

    public record Challenge(long issuedAtMs, byte[] nonce, String tagB64) {
    }

    /** A key and certificate a test can connect and sign frames with. */
    public record Identity(PrivateKey key, X509Certificate cert) {
        public SpineFixture.Device as(SpineFixture.Device base) {
            return new SpineFixture.Device(base.deviceId(), base.sim(),
                    new SimulatorStateStore.Enrollment(key, cert, base.enrollment().state()));
        }
    }

    public static Identity identity(SpineFixture.Device d) {
        return new Identity(d.enrollment().olkKey(), d.cert());
    }

    public static MtlsTestClient.Connection connect(int mtlsPort, X509Certificate root, Identity id)
            throws IOException {
        return MtlsTestClient.connect(mtlsPort, root, id.key(), List.of(id.cert()));
    }

    public static Challenge challenge(MtlsTestClient.Connection c) throws IOException {
        MtlsTestClient.Response r = c.get("/api/v1/devices/renew-challenge");
        if (r.status() != 200) {
            throw new IllegalStateException("challenge " + r.status() + " " + r.body());
        }
        Map<String, Object> m = json(r.body());
        return new Challenge(((Number) m.get("issued_at_ms")).longValue(),
                Base64.getDecoder().decode((String) m.get("random_nonce_b64")), (String) m.get("hmac_tag_b64"));
    }

    /** A correct body for {@code presenting}, signed by {@code signer}, with a CSR for {@code newKey}. */
    public static Map<String, Object> body(X509Certificate presenting, PrivateKey signer, Challenge ch, KeyPair newKey,
                                           String deviceId) {
        return Simulator.renewalBody(CertIds.issuerKeyHash(presenting), CertIds.serial(presenting), ch.issuedAtMs(),
                ch.nonce(), ch.tagB64(), CsrFactory.create(newKey, deviceId), signer);
    }

    public static MtlsTestClient.Response post(MtlsTestClient.Connection c, Map<String, Object> body)
            throws IOException {
        return c.post("/api/v1/devices/renew", "application/json", JSONObjectUtils.toJSONString(body));
    }

    /** Challenge + renew over {@code c} as {@code current}; returns the response. */
    public static MtlsTestClient.Response renew(MtlsTestClient.Connection c, Identity current, KeyPair newKey,
                                                String deviceId) throws IOException {
        return post(c, body(current.cert(), current.key(), challenge(c), newKey, deviceId));
    }

    /** Renews and returns the new identity; fails unless the response is 200. */
    public static Identity renewOk(MtlsTestClient.Connection c, Identity current, String deviceId) throws IOException {
        KeyPair next = EcKeys.generateP256();
        MtlsTestClient.Response r = renew(c, current, next, deviceId);
        if (r.status() != 200) {
            throw new IllegalStateException("renew " + r.status() + " " + r.body());
        }
        return new Identity(next.getPrivate(), cert(r));
    }

    public static X509Certificate cert(MtlsTestClient.Response r) {
        String pem = (String) json(r.body()).get("new_cert_pem");
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String error(MtlsTestClient.Response r) {
        return (String) json(r.body()).get("error");
    }

    public static Map<String, Object> json(String body) {
        try {
            return JSONObjectUtils.parse(body);
        } catch (java.text.ParseException e) {
            throw new IllegalStateException("not JSON: " + body, e);
        }
    }

    /** Polls the Device Intermediate CRL for up to 5 s; the entry, or null if the serial never appears. */
    public static X509CRLEntry awaitOnCrl(CrlService crls, BigInteger serial) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            String pem = crls.currentIntermediateCrl().block(Duration.ofSeconds(5));
            X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
                    .generateCRL(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
            X509CRLEntry e = crl.getRevokedCertificate(serial);
            if (e != null) {
                return e;
            }
            Thread.sleep(50);
        }
        return null;
    }
}
