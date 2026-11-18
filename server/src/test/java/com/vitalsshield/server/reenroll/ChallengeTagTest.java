package com.vitalsshield.server.reenroll;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.renewal.RenewalChallenge;
import com.vitalsshield.server.testsupport.TestClock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** DECISIONS #90: the Protocol C challenge is bound to the device_id, every field, 60 s, and this boot's key. */
class ChallengeTagTest {

    static final Instant T0 = Instant.parse("2026-11-18T12:00:00Z");

    static byte[] key(int fill) {
        byte[] k = new byte[32];
        Arrays.fill(k, (byte) fill);
        return k;
    }

    final TestClock clock = new TestClock(T0);
    final ReEnrollChallenge challenges = new ReEnrollChallenge(key(7), clock, Duration.ofSeconds(60));

    @Test
    void validTagVerifiesForItsDeviceOnly() {
        ReEnrollChallenge.Challenge c = challenges.issue("dev_a");
        assertThat(c.nonce()).hasSize(16);
        assertThat(c.tag()).hasSize(32);
        assertThat(challenges.verify("dev_a", c.issuedAtMs(), c.nonce(), c.tag())).isTrue();
        assertThat(challenges.verify("dev_b", c.issuedAtMs(), c.nonce(), c.tag())).as("other device").isFalse();
    }

    @Test
    void everyTamperedFieldIsRejected() {
        ReEnrollChallenge.Challenge c = challenges.issue("dev_a");
        byte[] nonce = c.nonce().clone();
        nonce[15] ^= 1;
        byte[] tag = c.tag().clone();
        tag[0] ^= 1;
        assertThat(challenges.verify("dev_a", c.issuedAtMs() - 1, c.nonce(), c.tag())).as("issued_at").isFalse();
        assertThat(challenges.verify("dev_a", c.issuedAtMs(), nonce, c.tag())).as("nonce").isFalse();
        assertThat(challenges.verify("dev_a", c.issuedAtMs(), c.nonce(), tag)).as("tag").isFalse();
        assertThat(challenges.verify("dev_a", c.issuedAtMs(), Arrays.copyOf(c.nonce(), 15), c.tag()))
                .as("short nonce").isFalse();
        assertThat(challenges.verify("dev_a", c.issuedAtMs(), c.nonce(), null)).as("no tag").isFalse();
    }

    @Test
    void sixtySecondBoundaryInBothDirections() {
        ReEnrollChallenge.Challenge c = challenges.issue("dev_a");
        clock.advance(Duration.ofSeconds(60));
        assertThat(challenges.verify("dev_a", c.issuedAtMs(), c.nonce(), c.tag())).as("60 s").isTrue();
        clock.advance(Duration.ofMillis(1));
        assertThat(challenges.verify("dev_a", c.issuedAtMs(), c.nonce(), c.tag())).as("60.001 s").isFalse();

        TestClock early = new TestClock(T0.minusSeconds(60));
        ReEnrollChallenge sameKey = new ReEnrollChallenge(key(7), early, Duration.ofSeconds(60));
        assertThat(sameKey.verify("dev_a", c.issuedAtMs(), c.nonce(), c.tag())).as("issued 60 s ahead").isTrue();
        early.advance(Duration.ofMillis(-1));
        assertThat(sameKey.verify("dev_a", c.issuedAtMs(), c.nonce(), c.tag())).as("60.001 s ahead").isFalse();
    }

    @Test
    void anotherBootKeyOrTheRenewalPurposeDoesNotVerify() {
        ReEnrollChallenge.Challenge c = challenges.issue("dev_a");
        ReEnrollChallenge otherBoot = new ReEnrollChallenge(key(8), clock, Duration.ofSeconds(60));
        assertThat(otherBoot.verify("dev_a", c.issuedAtMs(), c.nonce(), c.tag())).isFalse();
        // Same key bytes, same fields, Protocol B's purpose string: the tags differ.
        assertThat(ReEnrollChallenge.PURPOSE).isNotEqualTo(RenewalChallenge.PURPOSE);
    }
}
