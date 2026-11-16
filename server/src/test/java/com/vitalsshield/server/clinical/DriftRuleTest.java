package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class DriftRuleTest {

    static final ClinicalProperties P = ClinicalProperties.defaults();
    static final CalibrationStats.Baseline B = new CalibrationStats.Baseline(66, 2, 50, 3, 98, 0.5);

    static boolean breach(int hr, double hrv, double spo2) {
        return DriftRule.breach(DriftRule.z(new BatchMetrics(hr, hrv, spo2, 4, 0, 0.02), B), P);
    }

    @Test
    void twoOfThreeRequired() {
        assertThat(breach(70, 44.5, 98)).as("z_hr +2.0, z_hrv -1.83").isTrue();
        assertThat(breach(70, 50, 97.2)).as("z_hr +2.0, z_spo2 -1.6").isTrue();
        assertThat(breach(66, 44.5, 97.2)).as("z_hrv, z_spo2").isTrue();
    }

    @Test
    void eachSingleBreachAloneDoesNotCount() {
        assertThat(breach(80, 50, 98)).as("HR only").isFalse();
        assertThat(breach(66, 30, 98)).as("HRV only").isFalse();
        assertThat(breach(66, 50, 95)).as("SpO2 only").isFalse();
        assertThat(breach(69, 44.7, 97.3)).as("all just inside").isFalse();
    }

    @Test
    void streakFourFiresAndResets() {
        DriftRule.State s = DriftRule.State.EMPTY;
        for (int i = 1; i <= 3; i++) {
            DriftRule.Step step = DriftRule.onResting(s, UUID.randomUUID(), true, P);
            assertThat(step.fire()).isFalse();
            s = step.next();
            assertThat(s.streak()).isEqualTo(i);
        }
        DriftRule.Step fourth = DriftRule.onResting(s, UUID.randomUUID(), true, P);
        assertThat(fourth.fire()).isTrue();
        assertThat(fourth.trigger()).hasSize(4);
        assertThat(fourth.next()).isEqualTo(DriftRule.State.EMPTY);
    }

    @Test
    void exertionNeitherCountsNorResets() {
        // EXERTION batches never reach onResting (the evaluator skips them), so the state passes through unchanged.
        DriftRule.State s = DriftRule.State.EMPTY;
        s = DriftRule.onResting(s, UUID.randomUUID(), true, P).next();
        s = DriftRule.onResting(s, UUID.randomUUID(), true, P).next();
        DriftRule.State beforeExertion = s;
        // ... an EXERTION batch here: no call ...
        assertThat(s).isEqualTo(beforeExertion);
        s = DriftRule.onResting(s, UUID.randomUUID(), true, P).next();
        DriftRule.Step fourth = DriftRule.onResting(s, UUID.randomUUID(), true, P);
        assertThat(fourth.fire()).isTrue();
    }

    @Test
    void nonBreachingRestingBatchResets() {
        DriftRule.State s = DriftRule.State.EMPTY;
        s = DriftRule.onResting(s, UUID.randomUUID(), true, P).next();
        s = DriftRule.onResting(s, UUID.randomUUID(), true, P).next();
        s = DriftRule.onResting(s, UUID.randomUUID(), true, P).next();
        s = DriftRule.onResting(s, UUID.randomUUID(), false, P).next();
        assertThat(s).isEqualTo(DriftRule.State.EMPTY);
        assertThat(DriftRule.onResting(s, UUID.randomUUID(), true, P).fire()).isFalse();
    }

    @Test
    void explanationListsMeanZScores() {
        String e = DriftRule.explanation(2, java.util.List.of(new DriftRule.ZScores(2.3, -2.0, -0.2),
                new DriftRule.ZScores(2.5, -2.2, -0.4)));
        assertThat(e).isEqualTo("Drift vs baseline v2: HR z=+2.4, HRV z=-2.1, SpO2 z=-0.3 over 2 resting batches");
    }
}
