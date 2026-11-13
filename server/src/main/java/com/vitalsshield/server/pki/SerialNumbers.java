package com.vitalsshield.server.pki;

import java.math.BigInteger;
import java.security.SecureRandom;

/** RFC 5280 section 4.1.2.2 serials: positive, at most 20 octets, never zero. */
public final class SerialNumbers {

    private static final int SERIAL_BYTES = 20;

    private SerialNumbers() {
    }

    /** 20 random bytes with the top bit cleared, so the DER INTEGER is positive and fits in 20 octets. */
    public static BigInteger random(SecureRandom random) {
        byte[] bytes = new byte[SERIAL_BYTES];
        BigInteger serial;
        do {
            random.nextBytes(bytes);
            bytes[0] &= 0x7F;
            serial = new BigInteger(1, bytes);
        } while (serial.signum() == 0);
        return serial;
    }

    /** Canonical storage form: lowercase hex, no leading zeros. */
    public static String toHex(BigInteger serial) {
        return serial.toString(16);
    }

    public static BigInteger fromHex(String hex) {
        return new BigInteger(hex, 16);
    }
}
