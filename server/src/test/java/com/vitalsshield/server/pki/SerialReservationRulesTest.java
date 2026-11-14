package com.vitalsshield.server.pki;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SerialReservationRulesTest {

    @Test
    void allocatorFormat() {
        SerialAllocator allocator = new SerialAllocator();
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            BigInteger s = allocator.next();
            assertThat(s.signum()).isPositive();
            assertThat(s.toByteArray().length).isLessThanOrEqualTo(20);
            String hex = SerialNumbers.toHex(s);
            assertThat(hex).matches("[0-9a-f]+").doesNotStartWith("0");
            assertThat(seen.add(hex)).isTrue();
        }
    }

    @Test
    void sweepCutoffBoundary() {
        Instant now = Instant.parse("2026-11-13T12:00:00Z");
        assertThat(IssuedSerialLedger.isStale(now.minus(Duration.ofMinutes(2)), now)).isFalse();   // exactly 2 min
        assertThat(IssuedSerialLedger.isStale(now.minus(Duration.ofMinutes(2)).minusMillis(1), now)).isTrue();
        assertThat(IssuedSerialLedger.isStale(now.minusSeconds(30), now)).isFalse();
    }
}
