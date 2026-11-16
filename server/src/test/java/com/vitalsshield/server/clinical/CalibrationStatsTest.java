package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import java.util.List;
import org.junit.jupiter.api.Test;

class CalibrationStatsTest {

    static final ClinicalProperties P = ClinicalProperties.defaults();

    @Test
    void sampleSdAgainstHandComputedValues() {
        // 2, 4, 4, 4, 5, 5, 7, 9: mean 5, sum of squares 32, sample variance 32/7, SD 2.13809
        CalibrationStats.Stats s = CalibrationStats.of(new double[] {2, 4, 4, 4, 5, 5, 7, 9}, 0);
        assertThat(s.mean()).isEqualTo(5.0);
        assertThat(s.sd()).isCloseTo(Math.sqrt(32.0 / 7.0), within(1e-12)).isCloseTo(2.13809, within(1e-5));
        // 62, 66, 70: mean 66, squares 16 + 0 + 16 = 32, variance 32 / 2 = 16, SD 4
        assertThat(CalibrationStats.of(new double[] {62, 66, 70}, 1.0)).isEqualTo(new CalibrationStats.Stats(66, 4));
    }

    @Test
    void floorAppliedWhenAllValuesAreEqual() {
        List<BatchMetrics> flat = java.util.Collections.nCopies(10, new BatchMetrics(66, 50, 98, 4, 0, 0.02));
        CalibrationStats.Baseline b = CalibrationStats.compute(flat, P);
        assertThat(b.hrMean()).isEqualTo(66);
        assertThat(b.hrSd()).isEqualTo(1.0);
        assertThat(b.hrvSd()).isEqualTo(1.0);
        assertThat(b.spo2Sd()).isEqualTo(0.5);
    }

    @Test
    void acuteTriggeringBatchesExcluded() {
        assertThat(CalibrationStats.eligible("ACCEPTED", ActivityContext.RESTING, false)).isTrue();
        assertThat(CalibrationStats.eligible("ACCEPTED", ActivityContext.RESTING, true)).isFalse();
        assertThat(CalibrationStats.eligible("ACCEPTED", ActivityContext.EXERTION, false)).isFalse();
        assertThat(CalibrationStats.eligible("SIGNAL_DEGRADED", ActivityContext.RESTING, false)).isFalse();
    }
}
