package com.vitalsshield.simulator;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

/** Builds spec Section 5 telemetry payloads (exact field names and nesting). */
public final class TelemetryFrames {

    /** sha256 of a fixed firmware identifier string. */
    public static final String FIRMWARE_HASH = "sha256:" + sha256Hex("vitalsshield-sim-firmware-1.0");

    public record Metrics(int heartRateBpm, double hrvRmssdMs, double spo2Pct, double signalPerfusionIndex,
                          int stepCadenceSpm, double motionGRms) {

        /** Plausible resting values with small noise (HR 60-80, HRV 35-55, SpO2 96-99, perfusion 2-5). */
        public static Metrics resting(Random rnd) {
            return new Metrics(60 + rnd.nextInt(21), round(35 + 20 * rnd.nextDouble()), round(96 + 3 * rnd.nextDouble()),
                    round(2 + 3 * rnd.nextDouble()), 0, round(0.01 + 0.02 * rnd.nextDouble()));
        }

        static double round(double v) {
            return Math.round(v * 100.0) / 100.0;
        }
    }

    private TelemetryFrames() {
    }

    public static byte[] payload(String deviceId, String assignmentId, long bootEpoch, long sequenceNumber,
                                 UUID batchId, Instant measuredAt, Instant transmittedAt, Metrics m) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("heart_rate_bpm", m.heartRateBpm());
        metrics.put("hrv_rmssd_ms", m.hrvRmssdMs());
        metrics.put("spo2_pct", m.spo2Pct());
        metrics.put("signal_perfusion_index", m.signalPerfusionIndex());
        metrics.put("step_cadence_spm", m.stepCadenceSpm());
        metrics.put("motion_g_rms", m.motionGRms());
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("batch_id", batchId.toString());
        p.put("device_id", deviceId);
        p.put("assignment_id", assignmentId);
        p.put("boot_epoch", bootEpoch);
        p.put("sequence_number", sequenceNumber);
        p.put("measured_at", measuredAt.toString());
        p.put("transmitted_at", transmittedAt.toString());
        p.put("firmware_hash", FIRMWARE_HASH);
        p.put("metrics", metrics);
        return JSONObjectUtils.toJSONString(p).getBytes(StandardCharsets.UTF_8);
    }

    static String sha256Hex(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
