package com.vitalsshield.server.pki;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Allocates device leaf serials (DECISIONS #38): 20 random bytes from a {@link SecureRandom}, top bit cleared, never
 * zero, so {@value SerialNumbers#RANDOM_BITS} random bits per serial. Stored as lowercase hex without leading zeros
 * ({@link SerialNumbers#toHex}). The caller reserves it in issued_serials before signing.
 */
@Component
public class SerialAllocator {

    private final SecureRandom random;

    /** The constructor Spring uses: the JDK's default SecureRandom. */
    @Autowired
    public SerialAllocator() {
        this(new SecureRandom());
    }

    public SerialAllocator(SecureRandom random) {
        this.random = random;
    }

    public BigInteger next() {
        return SerialNumbers.random(random);
    }

    /** The random source, for tests. */
    SecureRandom randomSource() {
        return random;
    }
}
