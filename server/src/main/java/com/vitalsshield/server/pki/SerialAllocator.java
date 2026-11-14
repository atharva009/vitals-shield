package com.vitalsshield.server.pki;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.springframework.stereotype.Component;

/**
 * Allocates device leaf serials (DECISIONS #38): 20 random bytes, top bit cleared, never zero. Stored as lowercase
 * hex without leading zeros ({@link SerialNumbers#toHex}). The caller reserves it in issued_serials before signing.
 */
@Component
public class SerialAllocator {

    private final SecureRandom random = new SecureRandom();

    public BigInteger next() {
        return SerialNumbers.random(random);
    }
}
