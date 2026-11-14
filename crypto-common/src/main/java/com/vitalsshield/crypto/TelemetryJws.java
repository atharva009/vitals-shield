package com.vitalsshield.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import java.util.Set;

/**
 * Telemetry JWS (RFC 7515 compact, ES256), the only place raw R||S signatures appear (DECISIONS #33).
 *
 * <p>Header policy (DECISIONS #43): exactly {@code alg}, {@code typ}, {@code x5t#S256}; alg must be ES256; typ must be
 * {@value #TYP}; x5t#S256 must equal the expected certificate thumbprint. Any other header parameter (jwk, jku, x5c,
 * x5u, crit, ...) is rejected: the verification key always comes from the caller (the TLS client certificate), never
 * from the token.
 */
public final class TelemetryJws {

    public static final String TYP = "vitalsshield.telemetry+jws";
    static final Set<String> ALLOWED_HEADER_PARAMS = Set.of("alg", "typ", "x5t#S256");
    static final int ES256_SIGNATURE_BYTES = 64;

    /** Why a JWS was rejected. */
    public enum Reason { MALFORMED, ALG, TYP, HEADER_FORBIDDEN, X5T, SIG_LENGTH, SIG_INVALID }

    public static final class Rejected extends Exception {
        private final Reason reason;

        public Rejected(Reason reason, String message) {
            super(reason + ": " + message);
            this.reason = reason;
        }

        public Reason reason() {
            return reason;
        }
    }

    private TelemetryJws() {
    }

    /** base64url(SHA-256(cert DER)) without padding: the x5t#S256 value. */
    public static String thumbprint(byte[] certDer) {
        return Base64URL.encode(sha256(certDer)).toString();
    }

    /** Signs {@code payload} with the OLK; header {alg: ES256, typ, x5t#S256 of {@code olkCertDer}}. */
    public static String sign(byte[] payload, PrivateKey olkPrivateKey, byte[] olkCertDer) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(TYP))
                .x509CertSHA256Thumbprint(Base64URL.encode(sha256(olkCertDer)))
                .build();
        JWSObject jws = new JWSObject(header, new Payload(payload));
        try {
            jws.sign(new ECDSASigner((ECPrivateKey) olkPrivateKey));
        } catch (JOSEException e) {
            throw new IllegalStateException("JWS signing failed", e);
        }
        return jws.serialize();
    }

    /**
     * Enforces the header policy, requires a 64-byte R||S signature, verifies it with {@code key}, and returns the
     * exact payload bytes that were signed.
     */
    public static byte[] parseAndVerify(String compact, String expectedThumbprint, PublicKey key) throws Rejected {
        if (compact == null) {
            throw new Rejected(Reason.MALFORMED, "empty");
        }
        String[] parts = compact.trim().split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[2].isEmpty()) {
            throw new Rejected(Reason.MALFORMED, "not a three-part compact JWS");
        }
        Map<String, Object> header;
        try {
            header = JSONObjectUtils.parse(new String(new Base64URL(parts[0]).decode(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new Rejected(Reason.MALFORMED, "header is not base64url JSON");
        }
        if (!"ES256".equals(header.get("alg"))) {
            throw new Rejected(Reason.ALG, "alg must be ES256, got " + header.get("alg"));
        }
        if (!TYP.equals(header.get("typ"))) {
            throw new Rejected(Reason.TYP, "typ must be " + TYP);
        }
        for (String name : header.keySet()) {
            if (!ALLOWED_HEADER_PARAMS.contains(name)) {
                throw new Rejected(Reason.HEADER_FORBIDDEN, "header parameter not allowed: " + name);
            }
        }
        Object x5t = header.get("x5t#S256");
        if (!(x5t instanceof String) || !x5t.equals(expectedThumbprint)) {
            throw new Rejected(Reason.X5T, "x5t#S256 does not match the TLS client certificate");
        }
        byte[] sig = new Base64URL(parts[2]).decode();
        if (sig.length != ES256_SIGNATURE_BYTES) {
            throw new Rejected(Reason.SIG_LENGTH, "ES256 signature must be 64 bytes (R||S), got " + sig.length);
        }
        try {
            JWSObject jws = JWSObject.parse(compact.trim());
            if (!jws.verify(new ECDSAVerifier((ECPublicKey) key))) {
                throw new Rejected(Reason.SIG_INVALID, "signature does not verify");
            }
            return new Base64URL(parts[1]).decode();
        } catch (Rejected r) {
            throw r;
        } catch (java.text.ParseException | JOSEException | ClassCastException e) {
            throw new Rejected(Reason.SIG_INVALID, e.getMessage());
        }
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
