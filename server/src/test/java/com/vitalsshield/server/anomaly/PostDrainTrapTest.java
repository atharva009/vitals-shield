package com.vitalsshield.server.anomaly;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** DECISIONS #94: the rule the post-drain trap applies to each recorded event. */
class PostDrainTrapTest {

    static final Instant GRACE = Instant.parse("2026-11-18T12:00:00Z");
    static final Duration SLACK = Duration.ofSeconds(5);

    @Test
    void withinGraceDoesNotFire() {
        assertThat(PostDrainTrap.shouldFire(GRACE, GRACE.minusSeconds(10), SLACK, true)).isFalse();
    }

    @Test
    void fourSecondsAfterGraceDoesNotFire() {
        assertThat(PostDrainTrap.shouldFire(GRACE, GRACE.plusSeconds(4), SLACK, true)).isFalse();
        assertThat(PostDrainTrap.shouldFire(GRACE, GRACE.plusSeconds(5), SLACK, true)).as("exactly 5 s").isFalse();
    }

    @Test
    void sixSecondsAfterGraceWithActiveSuccessorFires() {
        assertThat(PostDrainTrap.shouldFire(GRACE, GRACE.plusSeconds(6), SLACK, true)).isTrue();
    }

    @Test
    void noActiveSuccessorDoesNotFire() {
        assertThat(PostDrainTrap.shouldFire(GRACE, GRACE.plusSeconds(6), SLACK, false)).isFalse();
    }

    @Test
    void noGraceRecordedDoesNotFire() {
        assertThat(PostDrainTrap.shouldFire(null, GRACE.plusSeconds(60), SLACK, true)).isFalse();
    }
}
