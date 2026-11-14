package com.vitalsshield.server.enrollment;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Shape checks for POST /api/v1/devices/enroll, before any token or crypto work. A failure here is a 400
 * VALIDATION_FAILED and never changes token state.
 */
public final class EnrollmentRequestValidator {

    static final Pattern DEVICE_ID = Pattern.compile("[A-Za-z0-9_.-]{1,64}");
    static final int MAX_SPKI_BYTES = 512;
    static final int MAX_CSR_BYTES = 2048;
    static final int MAX_SIG_BYTES = 128;
    static final int MAX_TOKEN_CHARS = 128;

    /** Thrown for any shape problem; the message is for logs, not for the response body. */
    public static final class ValidationException extends RuntimeException {
        public ValidationException(String message) {
            super(message);
        }
    }

    private EnrollmentRequestValidator() {
    }

    public static EnrollRequest validate(Map<String, Object> json) {
        if (json == null) {
            throw new ValidationException("missing body");
        }
        String deviceId = string(json, "device_id", 64);
        if (!DEVICE_ID.matcher(deviceId).matches()) {
            throw new ValidationException("device_id must match " + DEVICE_ID.pattern());
        }
        String token = string(json, "bootstrap_token", MAX_TOKEN_CHARS);
        if (token.isEmpty() || !StandardCharsets.US_ASCII.newEncoder().canEncode(token)) {
            throw new ValidationException("bootstrap_token must be non-empty ASCII");
        }
        byte[] spki = base64(json, "dek_spki_der_b64", MAX_SPKI_BYTES);
        byte[] csr = base64(json, "olk_csr_der_b64", MAX_CSR_BYTES);
        byte[] sig = base64(json, "dek_proof_sig_b64", MAX_SIG_BYTES);
        return new EnrollRequest(deviceId, token, spki, csr, sig);
    }

    private static String string(Map<String, Object> json, String field, int maxChars) {
        Object v = json.get(field);
        if (!(v instanceof String s)) {
            throw new ValidationException(field + " missing or not a string");
        }
        if (s.length() > maxChars) {
            throw new ValidationException(field + " longer than " + maxChars);
        }
        return s;
    }

    private static byte[] base64(Map<String, Object> json, String field, int maxBytes) {
        // Base64 of maxBytes is at most 4 * ceil(maxBytes / 3) characters; reject longer input before decoding.
        String s = string(json, field, 4 * ((maxBytes + 2) / 3));
        byte[] out;
        try {
            out = Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new ValidationException(field + " is not standard base64");
        }
        if (out.length == 0 || out.length > maxBytes) {
            throw new ValidationException(field + " decodes to " + out.length + " bytes (1.." + maxBytes + ")");
        }
        return out;
    }
}
