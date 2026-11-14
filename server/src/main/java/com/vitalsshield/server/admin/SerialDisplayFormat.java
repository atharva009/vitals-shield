package com.vitalsshield.server.admin;

import java.util.Locale;

/**
 * Serial display format (DECISIONS #50): uppercase, whole bytes, exactly as {@code openssl x509 -serial} and
 * {@code openssl crl -text} print it. Storage stays lowercase hex without leading zeros.
 */
public final class SerialDisplayFormat {

    private SerialDisplayFormat() {
    }

    public static String toOpenSslHex(String storedHex) {
        if (storedHex == null || storedHex.isEmpty()) {
            return storedHex;
        }
        String upper = storedHex.toUpperCase(Locale.ROOT);
        return upper.length() % 2 == 1 ? "0" + upper : upper;
    }
}
