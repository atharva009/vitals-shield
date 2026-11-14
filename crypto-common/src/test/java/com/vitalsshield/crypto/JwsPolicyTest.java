package com.vitalsshield.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** DECISIONS #43: header policy and signature format for telemetry JWS. */
class JwsPolicyTest {

    static final byte[] CERT_DER = "stand-in certificate DER for the thumbprint".getBytes(StandardCharsets.US_ASCII);
    static final String X5T = TelemetryJws.thumbprint(CERT_DER);
    static final byte[] PAYLOAD = "{\"batch_id\":\"x\"}".getBytes(StandardCharsets.UTF_8);

    final KeyPair olk = EcKeys.generateP256();

    @Test
    void validJwsPassesAndReturnsExactPayload() throws Exception {
        String jws = TelemetryJws.sign(PAYLOAD, olk.getPrivate(), CERT_DER);

        assertThat(TelemetryJws.parseAndVerify(jws, X5T, olk.getPublic())).isEqualTo(PAYLOAD);
        assertThat(jws.split("\\.")).hasSize(3);
    }

    @ParameterizedTest
    @ValueSource(strings = {"none", "HS256", "ES384", "RS256"})
    void otherAlgorithmsRejected(String alg) {
        String jws = forge("{\"alg\":\"" + alg + "\",\"typ\":\"" + TelemetryJws.TYP + "\",\"x5t#S256\":\"" + X5T + "\"}");
        assertReason(jws, TelemetryJws.Reason.ALG);
    }

    @Test
    void missingTypRejected() {
        assertReason(forge("{\"alg\":\"ES256\",\"x5t#S256\":\"" + X5T + "\"}"), TelemetryJws.Reason.TYP);
    }

    @Test
    void wrongTypRejected() {
        assertReason(forge("{\"alg\":\"ES256\",\"typ\":\"JWT\",\"x5t#S256\":\"" + X5T + "\"}"), TelemetryJws.Reason.TYP);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AA\",\"y\":\"AA\"}",
            "\"x5c\":[\"MIIB\"]",
            "\"jku\":\"https://attacker.example/keys\"",
            "\"x5u\":\"https://attacker.example/cert.pem\"",
            "\"crit\":[\"exp\"]",
            "\"kid\":\"other\""})
    void forbiddenHeaderParametersRejected(String extra) {
        String header = "{\"alg\":\"ES256\",\"typ\":\"" + TelemetryJws.TYP + "\",\"x5t#S256\":\"" + X5T + "\"," + extra + "}";
        assertReason(forge(header), TelemetryJws.Reason.HEADER_FORBIDDEN);
    }

    @Test
    void missingOrWrongX5tRejected() {
        assertReason(forge("{\"alg\":\"ES256\",\"typ\":\"" + TelemetryJws.TYP + "\"}"), TelemetryJws.Reason.X5T);
        String other = TelemetryJws.thumbprint("another cert".getBytes(StandardCharsets.US_ASCII));
        assertReason(forge("{\"alg\":\"ES256\",\"typ\":\"" + TelemetryJws.TYP + "\",\"x5t#S256\":\"" + other + "\"}"),
                TelemetryJws.Reason.X5T);
    }

    @Test
    void derSignatureInJwsRejected() throws Exception {
        String header = "{\"alg\":\"ES256\",\"typ\":\"" + TelemetryJws.TYP + "\",\"x5t#S256\":\"" + X5T + "\"}";
        String signingInput = b64(header.getBytes(StandardCharsets.UTF_8)) + "." + b64(PAYLOAD);
        byte[] der = derSign(signingInput);

        assertReason(signingInput + "." + b64(der), TelemetryJws.Reason.SIG_LENGTH);
    }

    @Test
    void tamperedPayloadRejected() {
        String[] parts = TelemetryJws.sign(PAYLOAD, olk.getPrivate(), CERT_DER).split("\\.");
        String tampered = parts[0] + "." + b64("{\"batch_id\":\"y\"}".getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
        assertReason(tampered, TelemetryJws.Reason.SIG_INVALID);
    }

    @Test
    void wrongKeyRejected() {
        String jws = TelemetryJws.sign(PAYLOAD, olk.getPrivate(), CERT_DER);
        assertThatThrownBy(() -> TelemetryJws.parseAndVerify(jws, X5T, EcKeys.generateP256().getPublic()))
                .isInstanceOfSatisfying(TelemetryJws.Rejected.class,
                        r -> assertThat(r.reason()).isEqualTo(TelemetryJws.Reason.SIG_INVALID));
    }

    @Test
    void malformedRejected() {
        assertReason("only.two", TelemetryJws.Reason.MALFORMED);
        assertReason("", TelemetryJws.Reason.MALFORMED);
        assertReason("!!!.e30.AAAA", TelemetryJws.Reason.MALFORMED);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    /** A JWS with an arbitrary header, signed correctly (raw R||S) with the OLK. */
    private String forge(String headerJson) {
        try {
            String signingInput = b64(headerJson.getBytes(StandardCharsets.UTF_8)) + "." + b64(PAYLOAD);
            byte[] raw = ECDSA.transcodeSignatureToConcat(derSign(signingInput), 64);
            return signingInput + "." + b64(raw);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] derSign(String signingInput) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(olk.getPrivate());
        s.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return s.sign();
    }

    private static String b64(byte[] b) {
        return Base64URL.encode(b).toString();
    }

    private void assertReason(String jws, TelemetryJws.Reason reason) {
        assertThatThrownBy(() -> TelemetryJws.parseAndVerify(jws, X5T, olk.getPublic()))
                .isInstanceOfSatisfying(TelemetryJws.Rejected.class, r -> assertThat(r.reason()).isEqualTo(reason));
    }
}
