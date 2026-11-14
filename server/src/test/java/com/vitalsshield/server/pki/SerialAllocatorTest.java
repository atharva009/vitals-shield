package com.vitalsshield.server.pki;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Device serial generation: source, range, DER size, uniqueness, unpredictability, and per-bit balance. */
class SerialAllocatorTest {

    static final int N = 10_000;
    static List<BigInteger> serials;

    @BeforeAll
    static void draw() {
        SerialAllocator allocator = new SerialAllocator(); // the constructor the Spring bean uses
        serials = new ArrayList<>(N);
        for (int i = 0; i < N; i++) {
            serials.add(allocator.next());
        }
    }

    @Test
    void productionInstanceUsesTheJdkSecureRandom() {
        SecureRandom source = new SerialAllocator().randomSource();
        assertThat(source).isNotNull();
        assertThat(source.getClass()).isEqualTo(SecureRandom.class);
    }

    @Test
    void allPositive() {
        assertThat(serials).allSatisfy(s -> assertThat(s.signum()).isEqualTo(1));
    }

    @Test
    void derIntegerContentIsAtMost20Octets() throws IOException {
        for (BigInteger s : serials) {
            byte[] der = new ASN1Integer(s).getEncoded();
            assertThat(der[0]).as("INTEGER tag").isEqualTo((byte) 0x02);
            int contentLength = der[1];
            assertThat(contentLength).isBetween(1, 20);
            assertThat(der).hasSize(2 + contentLength);
            ASN1Integer parsed = (ASN1Integer) ASN1Primitive.fromByteArray(der);
            assertThat(parsed.getValue()).isEqualTo(s);
            assertThat(parsed.getValue().signum()).isEqualTo(1);
        }
    }

    @Test
    void allUnique() {
        assertThat(new HashSet<>(serials)).hasSize(N);
    }

    @Test
    void notSequentialAndNotMonotonic() {
        int up = 0;
        int down = 0;
        for (int i = 1; i < N; i++) {
            BigInteger diff = serials.get(i).subtract(serials.get(i - 1));
            assertThat(diff.abs()).as("consecutive serials %d and %d", i - 1, i).isNotEqualTo(BigInteger.ONE);
            if (diff.signum() > 0) {
                up++;
            } else {
                down++;
            }
        }
        assertThat(up).as("increasing steps").isPositive().isLessThan(N - 1);
        assertThat(down).as("decreasing steps").isPositive().isLessThan(N - 1);
    }

    @Test
    void drawIs159BitsAndEveryBitIsBalanced() {
        assertThat(SerialNumbers.RANDOM_BITS).isEqualTo(159);
        int maxBitLength = serials.stream().mapToInt(BigInteger::bitLength).max().orElseThrow();
        assertThat(maxBitLength).as("no bit above position 158 is ever set").isEqualTo(SerialNumbers.RANDOM_BITS);
        assertThat(SerialNumbers.RANDOM_BITS).as("CA/B Forum BR minimum is 64").isGreaterThan(64);

        for (int bit = 0; bit < SerialNumbers.RANDOM_BITS; bit++) {
            final int b = bit;
            long set = serials.stream().filter(s -> s.testBit(b)).count();
            assertThat(set).as("bit %d set count of %d", bit, N).isBetween((long) (N * 0.40), (long) (N * 0.60));
        }
    }
}
