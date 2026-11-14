package com.vitalsshield.server.telemetry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TelemetryPayloadValidatorTest {

    static final Instant NOW = Instant.parse("2026-11-13T18:45:12.150Z");
    static final String DEVICE = "dev_wearable_019";

    static String json(String overrides) {
        String base = """
                {"batch_id":"b7f9c2d0-81e4-4c1a-9f32-112233445566","device_id":"dev_wearable_019",
                 "assignment_id":"018f7b2a-4c91-7d3e-8a12-9b4e5f6a7c8d","boot_epoch":3,"sequence_number":1042,
                 "measured_at":"2026-11-13T18:40:00.000Z","transmitted_at":"2026-11-13T18:45:12.150Z",
                 "firmware_hash":"sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
                 "metrics":{"heart_rate_bpm":76,"hrv_rmssd_ms":42.5,"spo2_pct":98.0,"signal_perfusion_index":3.4,
                            "step_cadence_spm":0,"motion_g_rms":0.02}}
                """;
        return overrides == null ? base : overrides;
    }

    static TelemetryPayload parse(String json) {
        return TelemetryPayloadValidator.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void specExampleParsesAndValidates() {
        TelemetryPayload p = parse(json(null));
        TelemetryPayloadValidator.validate(p, DEVICE, NOW);
        assertThat(p.batchId()).isEqualTo(UUID.fromString("b7f9c2d0-81e4-4c1a-9f32-112233445566"));
        assertThat(p.metrics().signalPerfusionIndex()).isEqualTo(3.4);
        assertThat(p.sequenceNumber()).isEqualTo(1042L);
    }

    @Test
    void unknownTopLevelFieldRejected() {
        assertStatus(() -> parse(json(null).replace("\"device_id\"", "\"extra\":1,\"device_id\"")), 400);
    }

    @Test
    void unknownMetricRejected() {
        assertStatus(() -> parse(json(null).replace("\"motion_g_rms\"", "\"temperature\":36.6,\"motion_g_rms\"")), 400);
    }

    @Test
    void specMetricNameOnly() {
        // perfusion_index is the DB column name; the payload field is signal_perfusion_index (spec Section 5).
        assertStatus(() -> parse(json(null).replace("signal_perfusion_index", "perfusion_index")), 400);
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"batch_id\":\"b7f9c2d0-81e4-4c1a-9f32-112233445566\",", "\"boot_epoch\":3,",
            "\"firmware_hash\":\"sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b\","})
    void missingFieldRejected(String field) {
        assertStatus(() -> TelemetryPayloadValidator.validate(parse(json(null).replace(field, "")), DEVICE, NOW), 400);
    }

    @Test
    void batchIdMustBeUuid() {
        assertStatus(() -> parse(json(null).replace("b7f9c2d0-81e4-4c1a-9f32-112233445566", "not-a-uuid")), 400);
    }

    @Test
    void otherDeviceIs403() {
        assertStatus(() -> TelemetryPayloadValidator.validate(parse(json(null)), "dev_other", NOW), 403);
    }

    @Test
    void sequenceAndEpochMustBePositive() {
        assertStatus(() -> TelemetryPayloadValidator.validate(
                parse(json(null).replace("\"sequence_number\":1042", "\"sequence_number\":0")), DEVICE, NOW), 400);
        assertStatus(() -> TelemetryPayloadValidator.validate(
                parse(json(null).replace("\"boot_epoch\":3", "\"boot_epoch\":0")), DEVICE, NOW), 400);
        TelemetryPayloadValidator.validate(
                parse(json(null).replace("\"sequence_number\":1042", "\"sequence_number\":1")), DEVICE, NOW);
    }

    @Test
    void transmittedAtWithinFiveMinutes() {
        TelemetryPayloadValidator.validate(parse(json(null)), DEVICE, NOW.plus(Duration.ofMinutes(5)));
        assertStatus(() -> TelemetryPayloadValidator.validate(parse(json(null)), DEVICE,
                NOW.plus(Duration.ofMinutes(5)).plusMillis(1)), 400);
        assertStatus(() -> TelemetryPayloadValidator.validate(parse(json(null)), DEVICE,
                NOW.minus(Duration.ofMinutes(5)).minusMillis(1)), 400);
    }

    @Test
    void measuredAtAtMostOneMinuteAfterTransmittedAt() {
        TelemetryPayloadValidator.validate(parse(json(null).replace("2026-11-13T18:40:00.000Z", "2026-11-13T18:46:12.150Z")),
                DEVICE, NOW);
        assertStatus(() -> TelemetryPayloadValidator.validate(
                parse(json(null).replace("2026-11-13T18:40:00.000Z", "2026-11-13T18:46:12.151Z")), DEVICE, NOW), 400);
    }

    @ParameterizedTest
    @ValueSource(strings = {"sha256:3A7BD3", "md5:3a7bd3e2360a3d29eea436fcfb7e44c7",
            "sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1", "3a7bd3e2"})
    void firmwareHashFormat(String bad) {
        String j = json(null).replace("sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b", bad);
        assertStatus(() -> TelemetryPayloadValidator.validate(parse(j), DEVICE, NOW), 400);
    }

    @Test
    void metricsRequiredAndTyped() {
        assertStatus(() -> TelemetryPayloadValidator.validate(
                parse(json(null).replace("\"spo2_pct\":98.0,", "")), DEVICE, NOW), 400);
        assertStatus(() -> parse(json(null).replace("\"heart_rate_bpm\":76", "\"heart_rate_bpm\":76.5")), 400);
        assertStatus(() -> parse(json(null).replace("\"spo2_pct\":98.0", "\"spo2_pct\":null")), 400);
        assertStatus(() -> parse(json(null).replace("\"spo2_pct\":98.0", "\"spo2_pct\":\"98\"")), 400);
    }

    @Test
    void trailingGarbageRejected() {
        assertStatus(() -> parse(json(null) + "{}"), 400);
    }

    private static void assertStatus(Runnable r, int status) {
        assertThatThrownBy(r::run).isInstanceOfSatisfying(IngestRejection.class,
                e -> assertThat(e.status()).isEqualTo(status));
    }
}
