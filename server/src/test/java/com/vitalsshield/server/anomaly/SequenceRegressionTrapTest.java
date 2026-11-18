package com.vitalsshield.server.anomaly;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.testsupport.TestClock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** DECISIONS #93. */
class SequenceRegressionTrapTest {

    final TestClock clock = new TestClock(Instant.parse("2026-11-18T12:00:00Z"));
    final List<SequenceRegressionTrap.Fired> fired = new ArrayList<>();
    final SequenceRegressionTrap trap = new SequenceRegressionTrap(
            new AnomalyProperties.SequenceRegression(true, 3, Duration.ofSeconds(60)), clock, fired::add);

    @Test
    void twoInSixtySecondsDoNotFireThreeDo() {
        trap.record("d", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 5);
        clock.advance(Duration.ofSeconds(20));
        assertThat(trap.record("d", UUID.randomUUID(), "SEQUENCE_TOO_OLD", 6)).isFalse();
        assertThat(fired).isEmpty();
        clock.advance(Duration.ofSeconds(20));
        assertThat(trap.record("d", UUID.randomUUID(), "BOOT_EPOCH_MISMATCH", 7)).isTrue();
        assertThat(fired).hasSize(1);
        assertThat(fired.get(0).deviceId()).isEqualTo("d");
        assertThat(fired.get(0).batchIds()).hasSize(3);
        assertThat(fired.get(0).span()).isEqualTo(Duration.ofSeconds(40));
    }

    @Test
    void idempotentRetriesOfTheSameBatchNeverCount() {
        UUID same = UUID.randomUUID();
        for (int i = 0; i < 10; i++) {
            trap.record("d", same, "DUPLICATE_SEQUENCE_REPLAY", 5);
        }
        trap.record("d", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 6);
        assertThat(fired).as("two distinct batch ids").isEmpty();
    }

    @Test
    void otherRejectionCodesDoNotCount() {
        for (int i = 0; i < 5; i++) {
            assertThat(trap.record("d", UUID.randomUUID(), "BATCH_ID_REUSED", i)).isFalse();
        }
        assertThat(fired).isEmpty();
    }

    @Test
    void theWindowSlides() {
        trap.record("d", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 1);
        clock.advance(Duration.ofSeconds(31));
        trap.record("d", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 2);
        clock.advance(Duration.ofSeconds(30)); // the first is now 61 s old
        assertThat(trap.record("d", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 3)).isFalse();
        clock.advance(Duration.ofSeconds(1));
        assertThat(trap.record("d", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 4)).isTrue();
        assertThat(fired).hasSize(1);
    }

    @Test
    void devicesAreCountedSeparatelyAndTheWindowClearsAfterFiring() {
        trap.record("a", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 1);
        trap.record("b", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 1);
        trap.record("a", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 2);
        trap.record("b", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 2);
        assertThat(fired).isEmpty();
        trap.record("a", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 3);
        assertThat(fired).extracting(SequenceRegressionTrap.Fired::deviceId).containsExactly("a");
        trap.record("a", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", 4);
        assertThat(fired).as("cleared after firing").hasSize(1);
    }

    @Test
    void disabledNeverFires() {
        SequenceRegressionTrap off = new SequenceRegressionTrap(
                new AnomalyProperties.SequenceRegression(false, 3, Duration.ofSeconds(60)), clock, fired::add);
        for (int i = 0; i < 5; i++) {
            off.record("d", UUID.randomUUID(), "DUPLICATE_SEQUENCE_REPLAY", i);
        }
        assertThat(fired).isEmpty();
    }
}
