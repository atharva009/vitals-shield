package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class AcuteRulesTest {

    static final ClinicalProperties P = ClinicalProperties.defaults();

    static List<String> codes(int hr, double spo2, ActivityContext ctx, int age) {
        return AcuteRules.evaluate(new BatchMetrics(hr, 50, spo2, 4, 0, 0.02), ctx, age, P).stream()
                .map(AcuteRules.Condition::code).toList();
    }

    @Test
    void ageFormula() {
        int age = AcuteRules.age(Instant.parse("2026-03-01T00:00:00Z"), 1985);
        assertThat(age).isEqualTo(41);
        assertThat(AcuteRules.exertionHrLimit(age, P)).isCloseTo(0.95 * (208 - 28.7), within(1e-9))
                .isCloseTo(170.335, within(1e-9));
    }

    @Test
    void restingHighBoundary() {
        assertThat(codes(140, 98, ActivityContext.RESTING, 41)).containsExactly(AcuteRules.RESTING_HR_HIGH);
        assertThat(codes(139, 98, ActivityContext.RESTING, 41)).isEmpty();
        assertThat(codes(150, 98, ActivityContext.EXERTION, 41)).as("not resting").isEmpty();
    }

    @Test
    void restingLowBoundary() {
        assertThat(codes(40, 98, ActivityContext.RESTING, 41)).containsExactly(AcuteRules.RESTING_HR_LOW);
        assertThat(codes(41, 98, ActivityContext.RESTING, 41)).isEmpty();
    }

    @Test
    void exertionBoundaryIsStrictlyAboveTheLimit() {
        // limit 170.335 for age 41
        assertThat(codes(171, 98, ActivityContext.EXERTION, 41)).containsExactly(AcuteRules.EXERTION_HR_HIGH);
        assertThat(codes(170, 98, ActivityContext.EXERTION, 41)).isEmpty();
        assertThat(codes(171, 98, ActivityContext.RESTING, 41)).as("resting uses 140").containsExactly(
                AcuteRules.RESTING_HR_HIGH);
    }

    @Test
    void spo2AnyState() {
        assertThat(codes(70, 90.0, ActivityContext.RESTING, 41)).containsExactly(AcuteRules.SPO2_LOW);
        assertThat(codes(70, 90.0, ActivityContext.EXERTION, 41)).containsExactly(AcuteRules.SPO2_LOW);
        assertThat(codes(70, 90.1, ActivityContext.RESTING, 41)).isEmpty();
    }

    @Test
    void explanationHasNumbers() {
        AcuteRules.Condition c = AcuteRules.evaluate(new BatchMetrics(152, 50, 98, 4, 0, 0.02),
                ActivityContext.RESTING, 41, P).get(0);
        assertThat(c.explanation()).isEqualTo("Resting heart rate 152 bpm for 5+ min (limit 140)");
    }
}
