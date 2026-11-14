package com.vitalsshield.server.telemetry;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.UUID;

/**
 * The signed JWS payload, field names exactly as in spec Section 5. Names are explicit (a naming strategy would map
 * motionGRms to motion_grms). Jackson 3 keeps its annotations in com.fasterxml.jackson.annotation.
 */
public record TelemetryPayload(
        @JsonProperty("batch_id") UUID batchId,
        @JsonProperty("device_id") String deviceId,
        @JsonProperty("assignment_id") UUID assignmentId,
        @JsonProperty("boot_epoch") Long bootEpoch,
        @JsonProperty("sequence_number") Long sequenceNumber,
        @JsonProperty("measured_at") Instant measuredAt,
        @JsonProperty("transmitted_at") Instant transmittedAt,
        @JsonProperty("firmware_hash") String firmwareHash,
        @JsonProperty("metrics") Metrics metrics) {

    public record Metrics(
            @JsonProperty("heart_rate_bpm") Integer heartRateBpm,
            @JsonProperty("hrv_rmssd_ms") Double hrvRmssdMs,
            @JsonProperty("spo2_pct") Double spo2Pct,
            @JsonProperty("signal_perfusion_index") Double signalPerfusionIndex,
            @JsonProperty("step_cadence_spm") Integer stepCadenceSpm,
            @JsonProperty("motion_g_rms") Double motionGRms) {
    }
}
