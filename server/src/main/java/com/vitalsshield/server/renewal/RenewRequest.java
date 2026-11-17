package com.vitalsshield.server.renewal;

import java.util.Base64;
import java.util.Map;

/** POST /api/v1/devices/renew body, decoded. Any missing or undecodable field is a 400 VALIDATION_FAILED. */
public record RenewRequest(String issuerKeyHash, String serialNumber, long issuedAtMs, byte[] nonce, byte[] hmacTag,
                           byte[] newCsrDer, byte[] renewalSig) {

    static final class Invalid extends RuntimeException {
        Invalid(String message) {
            super(message);
        }
    }

    static RenewRequest parse(Map<String, Object> m) {
        if (m == null) {
            throw new Invalid("no body");
        }
        Object issued = m.get("issued_at_ms");
        if (!(issued instanceof Number n) || issued instanceof Double || issued instanceof Float) {
            throw new Invalid("issued_at_ms must be an integer");
        }
        return new RenewRequest(text(m, "issuer_key_hash", 64), text(m, "serial_number", 64), n.longValue(),
                b64(m, "random_nonce_b64", 64), b64(m, "hmac_tag_b64", 64), b64(m, "olk_new_csr_der_b64", 4096),
                b64(m, "olk_renewal_sig_b64", 256));
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
