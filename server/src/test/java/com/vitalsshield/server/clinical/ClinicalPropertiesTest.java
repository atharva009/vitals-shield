package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

/** The @DefaultValue annotations (what Spring binds) and defaults() (what unit tests use) are the same spec values. */
class ClinicalPropertiesTest {

    @Test
    void boundDefaultsEqualDefaults() {
        ClinicalProperties bound = new Binder(new MapConfigurationPropertySource(Map.of()))
                .bindOrCreate("vitalsshield.clinical", ClinicalProperties.class);
        assertThat(bound).isEqualTo(ClinicalProperties.defaults());
    }

    @Test
    void demoCalibrationSizeOverrides() {
        ClinicalProperties bound = new Binder(new MapConfigurationPropertySource(
                Map.of("vitalsshield.clinical.calibration-size", "10", "vitalsshield.clinical.drift.z-hr-min", "2.5")))
                .bindOrCreate("vitalsshield.clinical", ClinicalProperties.class);
        assertThat(bound.calibrationSize()).isEqualTo(10);
        assertThat(bound.drift().zHrMin()).isEqualTo(2.5);
        assertThat(bound.acute().restingHrHigh()).isEqualTo(140);
    }

    @Test
    void phase8DefaultsForFloorsAndQueue() {
        ClinicalProperties d = ClinicalProperties.defaults();
        assertThat(d.sdFloors()).isEqualTo(new ClinicalProperties.SdFloors(3.0, 5.0, 1.0));
        assertThat(d.queueCapacity()).isEqualTo(1000);
    }

    @Test
    void alertTransitions() {
        assertThat(AlertTransitions.allowed("ACTIVE", "ACKNOWLEDGED")).isTrue();
        assertThat(AlertTransitions.allowed("ACTIVE", "RESOLVED")).isTrue();
        assertThat(AlertTransitions.allowed("ACKNOWLEDGED", "RESOLVED")).isTrue();
        assertThat(AlertTransitions.allowed("ACKNOWLEDGED", "ACKNOWLEDGED")).isFalse();
        assertThat(AlertTransitions.allowed("RESOLVED", "ACKNOWLEDGED")).isFalse();
        assertThat(AlertTransitions.allowed("RETRACTED_BY_QUARANTINE", "RESOLVED")).isFalse();
        assertThat(AlertTransitions.allowed("RETRACTED_BY_QUARANTINE", "ACKNOWLEDGED")).isFalse();
    }
}
