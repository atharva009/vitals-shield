package com.vitalsshield.server.enrollment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vitalsshield.server.enrollment.EnrollmentRequestValidator.ValidationException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EnrollmentRequestValidatorTest {

    static String b64(int n) {
        return Base64.getEncoder().encodeToString(new byte[n]);
    }

    static Map<String, Object> valid() {
        Map<String, Object> m = new HashMap<>();
        m.put("device_id", "dev_wearable_019");
        m.put("bootstrap_token", "tok-ABC123");
        m.put("dek_spki_der_b64", b64(91));
        m.put("olk_csr_der_b64", b64(300));
        m.put("dek_proof_sig_b64", b64(71));
        return m;
    }

    @Test
    void validRequestDecodes() {
        EnrollRequest r = EnrollmentRequestValidator.validate(valid());
        assertThat(r.deviceId()).isEqualTo("dev_wearable_019");
        assertThat(r.dekSpkiDer()).hasSize(91);
        assertThat(r.olkCsrDer()).hasSize(300);
        assertThat(r.dekProofSig()).hasSize(71);
    }

    @ParameterizedTest
    @ValueSource(strings = {"device_id", "bootstrap_token", "dek_spki_der_b64", "olk_csr_der_b64", "dek_proof_sig_b64"})
    void everyFieldRequired(String field) {
        Map<String, Object> m = valid();
        m.remove(field);
        assertInvalid(m);
    }

    @ParameterizedTest
    @ValueSource(strings = {"device_id", "bootstrap_token", "dek_spki_der_b64", "olk_csr_der_b64", "dek_proof_sig_b64"})
    void everyFieldMustBeAString(String field) {
        Map<String, Object> m = valid();
        m.put(field, 42);
        assertInvalid(m);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "has space", "slash/no", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "é", "semi;colon"})
    void deviceIdPattern(String id) {
        Map<String, Object> m = valid();
        m.put("device_id", id);
        assertInvalid(m);
    }

    @Test
    void deviceIdAtMaxLengthAccepted() {
        Map<String, Object> m = valid();
        m.put("device_id", "a".repeat(64));
        assertThat(EnrollmentRequestValidator.validate(m).deviceId()).hasSize(64);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dek_spki_der_b64", "olk_csr_der_b64", "dek_proof_sig_b64"})
    void base64MustDecode(String field) {
        Map<String, Object> m = valid();
        m.put(field, "not base64 !!");
        assertInvalid(m);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dek_spki_der_b64", "olk_csr_der_b64", "dek_proof_sig_b64"})
    void emptyBlobRejected(String field) {
        Map<String, Object> m = valid();
        m.put(field, "");
        assertInvalid(m);
    }

    @Test
    void sizeCaps() {
        assertCap("dek_spki_der_b64", 512);
        assertCap("olk_csr_der_b64", 2048);
        assertCap("dek_proof_sig_b64", 128);

        Map<String, Object> okToken = valid();
        okToken.put("bootstrap_token", "t".repeat(128));
        EnrollmentRequestValidator.validate(okToken);
        Map<String, Object> longToken = valid();
        longToken.put("bootstrap_token", "t".repeat(129));
        assertInvalid(longToken);
    }

    @Test
    void nonAsciiTokenRejected() {
        Map<String, Object> m = valid();
        m.put("bootstrap_token", "tok-é");
        assertInvalid(m);
    }

    @Test
    void nullBodyRejected() {
        assertThatThrownBy(() -> EnrollmentRequestValidator.validate(null)).isInstanceOf(ValidationException.class);
    }

    private static void assertCap(String field, int max) {
        Map<String, Object> atCap = valid();
        atCap.put(field, b64(max));
        EnrollmentRequestValidator.validate(atCap);
        Map<String, Object> over = valid();
        over.put(field, b64(max + 1));
        assertInvalid(over);
    }

    private static void assertInvalid(Map<String, Object> m) {
        assertThatThrownBy(() -> EnrollmentRequestValidator.validate(m)).isInstanceOf(ValidationException.class);
    }
}
