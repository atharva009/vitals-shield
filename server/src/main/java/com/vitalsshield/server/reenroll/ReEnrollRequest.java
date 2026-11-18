package com.vitalsshield.server.reenroll;

import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

/** POST /api/v1/devices/re-enroll body, decoded. Any missing or undecodable field is a 400 VALIDATION_FAILED. */
public record ReEnrollRequest(String deviceId, long issuedAtMs, byte[] nonce, byte[] hmacTag, long bootEpoch,
                              byte[] olkCsrDer, byte[] dekSig) {

    static final Pattern DEVICE_ID = Pattern.compile("[A-Za-z0-9_.-]{1,64}");

    static final class Invalid extends RuntimeException {
        Invalid(String message) {
            super(message);
        }
    }

    static ReEnrollRequest parse(Map<String, Object> m) {
        if (m == null) {
            throw new Invalid("no body");
        }
        String deviceId = text(m, "device_id", 64);
        if (!DEVICE_ID.matcher(deviceId).matches()) {
            throw new Invalid("device_id");
        }
        return new ReEnrollRequest(deviceId, integer(m, "issued_at_ms"), b64(m, "random_nonce_b64", 64),
                b64(m, "hmac_tag_b64", 64), integer(m, "boot_epoch"), b64(m, "olk_csr_der_b64", 4096),
                b64(m, "dek_sig_b64", 256));
    }

    private static long integer(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (!(v instanceof Number n) || v instanceof Double || v instanceof Float) {
            throw new Invalid(key + " must be an integer");
        }
        return n.longValue();
    }

    private static String text(Map<String, Object> m, String key, int max) {
        if (!(m.get(key) instanceof String s) || s.isEmpty() || s.length() > max) {
            throw new Invalid(key);
        }
        return s;
    }

    private static byte[] b64(Map<String, Object> m, String key, int maxChars) {
        String s = text(m, key, maxChars);
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new Invalid(key);
        }
    }
}
