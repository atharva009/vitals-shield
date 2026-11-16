package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class AlertDedupeTest {

    static final Duration W = Duration.ofMinutes(5);
    static final Instant NOW = Instant.parse("2026-11-16T09:00:00Z");

    @Test
    void insideTheWindowIsSuppressed() {
        List<AlertDedupe.Prior> priors = List.of(new AlertDedupe.Prior("RESTING_HR_HIGH", NOW.minus(W)));
        assertThat(AlertDedupe.suppressed(priors, "RESTING_HR_HIGH", NOW, W)).as("exactly 5 min").isTrue();
        assertThat(AlertDedupe.suppressed(List.of(new AlertDedupe.Prior("RESTING_HR_HIGH", NOW.minusSeconds(60))),
                "RESTING_HR_HIGH", NOW, W)).isTrue();
    }

    @Test
    void outsideTheWindowIsNotSuppressed() {
        List<AlertDedupe.Prior> priors = List.of(new AlertDedupe.Prior("RESTING_HR_HIGH",
                NOW.minus(W).minusSeconds(1)));
        assertThat(AlertDedupe.suppressed(priors, "RESTING_HR_HIGH", NOW, W)).isFalse();
        assertThat(AlertDedupe.suppressed(List.of(), "RESTING_HR_HIGH", NOW, W)).isFalse();
    }

    @Test
    void differentConditionCodesAreIndependent() {
        List<AlertDedupe.Prior> priors = List.of(new AlertDedupe.Prior("SPO2_LOW", NOW.minusSeconds(60)));
        assertThat(AlertDedupe.suppressed(priors, "RESTING_HR_HIGH", NOW, W)).isFalse();
        assertThat(AlertDedupe.suppressed(priors, "SPO2_LOW", NOW, W)).isTrue();
    }
}
