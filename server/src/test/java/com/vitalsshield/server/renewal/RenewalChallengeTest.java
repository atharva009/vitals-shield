package com.vitalsshield.server.renewal;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** Section 1: the stateless HMAC challenge (DECISIONS #81). */
class RenewalChallengeTest {

    static final String ISSUER = "9f2c0e7d4b1a8c3e5f60718293a4b5c6d7e8f901";
    static final String SERIAL = "2ed4e9af9446efdb6e9f66e21a6d47bc4c0907";
    static final Instant T0 = Instant.parse("2026-11-16T12:00:00Z");

    static final class Fixed extends Clock {
        volatile Instant now;

        Fixed(Instant now) {
            this.now = now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    static byte[] key(int fill) {
        byte[] k = new byte[32];
        Arrays.fill(k, (byte) fill);
        return k;
    }

    final Fixed clock = new Fixed(T0);
    final RenewalChallenge challenges = new RenewalChallenge(key(7), clock);

    @Test
    void validTagVerifies() {
        RenewalChallenge.Challenge c = challenges.issue(ISSUER, SERIAL);
        assertThat(c.issuedAtMs()).isEqualTo(T0.toEpochMilli());
        assertThat(c.nonce()).hasSize(16);
        assertThat(c.tag()).hasSize(32);
        assertThat(challenges.verify(ISSUER, SERIAL, c.issuedAtMs(), c.nonce(), c.tag())).isTrue();
    }

    @Test
    void everyTamperedFieldIsRejected() {
        RenewalChallenge.Challenge c = challenges.issue(ISSUER, SERIAL);
        byte[] nonce = c.nonce().clone();
        nonce[0] ^= 1;
        byte[] tag = c.tag().clone();
        tag[31] ^= 1;
        assertThat(challenges.verify(ISSUER, SERIAL, c.issuedAtMs() + 1, c.nonce(), c.tag())).as("issued_at").isFalse();
        assertThat(challenges.verify(ISSUER, SERIAL, c.issuedAtMs(), nonce, c.tag())).as("nonce").isFalse();
        assertThat(challenges.verify(ISSUER, SERIAL + "1", c.issuedAtMs(), c.nonce(), c.tag())).as("serial").isFalse();
        assertThat(challenges.verify(ISSUER.replace('9', '8'), SERIAL, c.issuedAtMs(), c.nonce(), c.tag()))
                .as("issuer").isFalse();
        assertThat(challenges.verify(ISSUER, SERIAL, c.issuedAtMs(), c.nonce(), tag)).as("tag").isFalse();
        assertThat(challenges.verify(ISSUER, SERIAL, c.issuedAtMs(), Arrays.copyOf(c.nonce(), 15), c.tag()))
                .as("short nonce").isFalse();
    }

    @Test
    void sixtySecondsAcceptedSixtyPointZeroZeroOneRejected() {
        RenewalChallenge.Challenge c = challenges.issue(ISSUER, SERIAL);
        clock.now = T0.plusSeconds(60);
        assertThat(challenges.verify(ISSUER, SERIAL, c.issuedAtMs(), c.nonce(), c.tag())).isTrue();
        clock.now = T0.plusMillis(60_001);
        assertThat(challenges.verify(ISSUER, SERIAL, c.issuedAtMs(), c.nonce(), c.tag())).isFalse();
        // The bound is |now - issued_at|: a challenge from 60.001 s in the future is rejected too.
        clock.now = T0.minusMillis(60_001);
        assertThat(challenges.verify(ISSUER, SERIAL, c.issuedAtMs(), c.nonce(), c.tag())).isFalse();
        clock.now = T0.minusSeconds(60);
        assertThat(challenges.verify(ISSUER, SERIAL, c.issuedAtMs(), c.nonce(), c.tag())).isTrue();
    }

    @Test
    void tagFromAnotherBootKeyIsRejected() {
        RenewalChallenge.Challenge c = new RenewalChallenge(key(9), clock).issue(ISSUER, SERIAL);
        assertThat(challenges.verify(ISSUER, SERIAL, c.issuedAtMs(), c.nonce(), c.tag())).isFalse();
        // Two Spring-style instances get independent random keys.
        RenewalChallenge a = new RenewalChallenge(clock);
        RenewalChallenge b = new RenewalChallenge(clock);
        RenewalChallenge.Challenge ca = a.issue(ISSUER, SERIAL);
        assertThat(b.verify(ISSUER, SERIAL, ca.issuedAtMs(), ca.nonce(), ca.tag())).isFalse();
        assertThat(a.verify(ISSUER, SERIAL, ca.issuedAtMs(), ca.nonce(), ca.tag())).isTrue();
    }

    @Test
    void tagComparisonIsConstantTime() throws Exception {
        String src = Files.readString(Path.of("src/main/java/com/vitalsshield/server/renewal/RenewalChallenge.java"));
        assertThat(src).contains("MessageDigest.isEqual(").doesNotContain("Arrays.equals(");
    }
}
