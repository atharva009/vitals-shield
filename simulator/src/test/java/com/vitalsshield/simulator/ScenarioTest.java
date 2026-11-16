package com.vitalsshield.simulator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.Random;
import org.junit.jupiter.api.Test;

class ScenarioTest {

    @Test
    void generatorsStayInTheirRanges() {
        Random r = new Random(7);
        for (int i = 0; i < 2000; i++) {
            TelemetryFrames.Metrics m = Scenario.RESTING.generate(r);
            assertThat(m.heartRateBpm()).isBetween(62, 70);
            assertThat(m.hrvRmssdMs()).isBetween(45.0, 55.0);
            assertThat(m.spo2Pct()).isBetween(97.0, 99.0);
            assertThat(m.stepCadenceSpm()).isZero();
            assertThat(m.motionGRms()).isBetween(0.01, 0.03);
            TelemetryFrames.Metrics e = Scenario.EXERTION.generate(r);
            assertThat(e.heartRateBpm()).isBetween(125, 135);
            assertThat(e.stepCadenceSpm()).isBetween(100, 120);
            assertThat(e.motionGRms()).isBetween(0.3, 0.5);
            TelemetryFrames.Metrics d = Scenario.DRIFT.generate(r);
            assertThat(d.heartRateBpm()).isBetween(80, 86);
            assertThat(d.hrvRmssdMs()).isBetween(28.0, 34.0);
            assertThat(d.spo2Pct()).isBetween(95.0, 96.0);
            assertThat(Scenario.ACUTE.generate(r).heartRateBpm()).isBetween(150, 158);
            TelemetryFrames.Metrics l = Scenario.LOW_PERFUSION_CRITICAL.generate(r);
            assertThat(l.signalPerfusionIndex()).isBetween(0.2, 0.4);
            assertThat(l.spo2Pct()).isBetween(87.0, 89.0);
            assertThat(l.heartRateBpm()).isBetween(70, 80);
        }
    }

    @Test
    void seededNoiseIsDeterministic() {
        assertThat(Scenario.DRIFT.generate("dev_a", 42)).isEqualTo(Scenario.DRIFT.generate("dev_a", 42));
        assertThat(Scenario.DRIFT.generate("dev_a", 42)).isNotEqualTo(Scenario.DRIFT.generate("dev_a", 43));
    }

    @Test
    void cliNames() {
        assertThat(Scenario.parse("low-perfusion-critical")).isEqualTo(Scenario.LOW_PERFUSION_CRITICAL);
        assertThat(Scenario.LOW_PERFUSION_CRITICAL.cliName()).isEqualTo("low-perfusion-critical");
        assertThatThrownBy(() -> Scenario.parse("sprint")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void scriptRunsThenHoldsTheLastScenario() {
        ScenarioScript s = ScenarioScript.parse("resting:15,drift:6,acute:2");
        assertThat(s.totalBatches()).isEqualTo(23);
        assertThat(s.at(0)).isEqualTo(Scenario.RESTING);
        assertThat(s.at(14)).isEqualTo(Scenario.RESTING);
        assertThat(s.at(15)).isEqualTo(Scenario.DRIFT);
        assertThat(s.at(20)).isEqualTo(Scenario.DRIFT);
        assertThat(s.at(21)).isEqualTo(Scenario.ACUTE);
        assertThat(s.at(1000)).isEqualTo(Scenario.ACUTE);
        assertThatThrownBy(() -> ScenarioScript.parse("resting")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ScenarioScript.parse("resting:0")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void compressedClock() {
        Instant now = Instant.parse("2026-11-16T12:00:00Z");
        assertThat(CompressedClock.next(null, now)).isEqualTo(now.minus(Duration.ofHours(12)));
        Instant last = now.minus(Duration.ofHours(3));
        assertThat(CompressedClock.next(last, now)).isEqualTo(last.plusSeconds(60));
        assertThat(CompressedClock.next(now.minus(Duration.ofHours(20)), now))
                .as("never older than 12 h").isEqualTo(now.minus(Duration.ofHours(12)));
        assertThat(CompressedClock.next(now.minusSeconds(10), now)).as("capped at now").isEqualTo(now);
    }
}
