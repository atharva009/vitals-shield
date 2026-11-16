package com.vitalsshield.server.admin.webauthn;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/** Small byte helpers shared by the WebAuthn code. */
public final class WebAuthnBytes {

    private WebAuthnBytes() {
    }

    public static String b64url(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public static byte[] fromB64url(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256Hex(byte[] data) {
        return HexFormat.of().formatHex(sha256(data));
    }

    /** WebAuthn user handle: the first 16 bytes of SHA-256(clinician_id). Deterministic, so no extra column. */
    public static byte[] userHandle(String clinicianId) {
        return Arrays.copyOf(sha256(clinicianId.getBytes(StandardCharsets.UTF_8)), 16);
    }

    public static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
