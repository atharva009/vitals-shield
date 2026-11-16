package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class DegradedCriticalStreakTest {

    static final ClinicalProperties P = ClinicalProperties.defaults();
    static final BatchMetrics CRITICAL = new BatchMetrics(75, 50, 88, 0.3, 0, 0.02);
    static final BatchMetrics FINE = new BatchMetrics(75, 50, 97, 0.3, 0, 0.02);

    /** Feeds a sequence (true = critical degraded, false = non-critical degraded); returns the fire flags. */
    static List<Boolean> run(DegradedCriticalStreak.State[] state, boolean... critical) {
        List<Boolean> fires = new ArrayList<>();
        for (boolean c : critical) {
            DegradedCriticalStreak.Step s = DegradedCriticalStreak.onDegraded(state[0], UUID.randomUUID(),
                    c ? CRITICAL : FINE, P);
            state[0] = s.next();
            fires.add(s.fire());
        }
        return fires;
    }

    @Test
    void twoThenResetDoesNotFire() {
        DegradedCriticalStreak.State[] st = {DegradedCriticalStreak.State.EMPTY};
        assertThat(run(st, true, true, false, true, true)).containsExactly(false, false, false, false, false);
    }

    @Test
    void threeFiresFourAndFiveDoNot() {
        DegradedCriticalStreak.State[] st = {DegradedCriticalStreak.State.EMPTY};
        assertThat(run(st, true, true, true, true, true)).containsExactly(false, false, true, false, false);
        assertThat(st[0].batchIds()).hasSize(3);
    }

    @Test
    void resetThenThreeFiresAgain() {
        DegradedCriticalStreak.State[] st = {DegradedCriticalStreak.State.EMPTY};
        assertThat(run(st, true, true, true, true)).containsExactly(false, false, true, false);
        st[0] = DegradedCriticalStreak.onAccepted();
        assertThat(run(st, true, true, true)).containsExactly(false, false, true);
    }

    @Test
    void triggeringIdsAreTheThreeBatches() {
        DegradedCriticalStreak.State s = DegradedCriticalStreak.State.EMPTY;
        List<UUID> ids = List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
        DegradedCriticalStreak.Step step = null;
        for (UUID id : ids) {
            step = DegradedCriticalStreak.onDegraded(s, id, CRITICAL, P);
            s = step.next();
        }
        assertThat(step.fire()).isTrue();
        assertThat(step.next().batchIds()).containsExactlyElementsOf(ids);
    }

    @Test
    void criticalBoundaries() {
        assertThat(DegradedCriticalStreak.critical(new BatchMetrics(75, 50, 90.0, 0.3, 0, 0), P)).isTrue();
        assertThat(DegradedCriticalStreak.critical(new BatchMetrics(40, 50, 97, 0.3, 0, 0), P)).isTrue();
        assertThat(DegradedCriticalStreak.critical(new BatchMetrics(150, 50, 97, 0.3, 0, 0), P)).isTrue();
        assertThat(DegradedCriticalStreak.critical(new BatchMetrics(41, 50, 90.1, 0.3, 0, 0), P)).isFalse();
        assertThat(DegradedCriticalStreak.critical(new BatchMetrics(149, 50, 90.1, 0.3, 0, 0), P)).isFalse();
    }
}
