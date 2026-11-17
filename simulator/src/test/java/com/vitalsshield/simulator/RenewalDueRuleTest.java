package com.vitalsshield.simulator;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** DECISIONS #83: renewal is due at not_before + 2/3 of the validity period. */
class RenewalDueRuleTest {

    static final Instant ISSUED = Instant.parse("2026-11-16T12:00:00Z");
    /** CertificateProfiles backdates notBefore by 60 s; notAfter = notBefore + TTL. */
    static final Instant NOT_BEFORE = ISSUED.minusSeconds(60);

    @Test
    void twelveHourLeafRenewsAtEightHours() {
        Instant notAfter = NOT_BEFORE.plus(Duration.ofHours(12));
        Instant due = NOT_BEFORE.plus(Duration.ofHours(8));
        assertThat(RenewalDueRule.dueAt(NOT_BEFORE, notAfter)).isEqualTo(due);
        assertThat(RenewalDueRule.isDue(NOT_BEFORE, notAfter, due.minusMillis(1))).isFalse();
        assertThat(RenewalDueRule.isDue(NOT_BEFORE, notAfter, due)).isTrue();
        // 7h59m after issuance is 8h after the backdated notBefore.
        assertThat(Duration.between(ISSUED, due)).isEqualTo(Duration.ofHours(8).minusSeconds(60));
    }

    @Test
    void fourMinuteDemoLeafRenewsOneMinuteFortyAfterIssuance() {
        Instant notAfter = NOT_BEFORE.plus(Duration.ofMinutes(4));
        Instant due = RenewalDueRule.dueAt(NOT_BEFORE, notAfter);
        assertThat(due).isEqualTo(NOT_BEFORE.plusSeconds(160));
        assertThat(Duration.between(ISSUED, due)).isEqualTo(Duration.ofSeconds(100));
        assertThat(Duration.between(ISSUED, notAfter)).isEqualTo(Duration.ofMinutes(3));
        assertThat(RenewalDueRule.isDue(NOT_BEFORE, notAfter, due.minusMillis(1))).isFalse();
        assertThat(RenewalDueRule.isDue(NOT_BEFORE, notAfter, due)).isTrue();
    }

    @Test
    void fortySecondTestLeaf() {
        Instant notAfter = NOT_BEFORE.plusSeconds(40);
        // 2/3 of 40 000 ms is 26 666 ms (integer milliseconds, rounded down).
        assertThat(RenewalDueRule.dueAt(NOT_BEFORE, notAfter)).isEqualTo(NOT_BEFORE.plusMillis(26_666));
    }
}
