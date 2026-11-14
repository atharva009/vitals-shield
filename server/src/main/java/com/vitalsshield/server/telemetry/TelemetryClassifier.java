package com.vitalsshield.server.telemetry;

/**
 * Phase 4 trust classification (DECISIONS #46; spec Section 6 steps 1 and 3, without activity context or alerts):
 * hardware plausibility first, then signal perfusion.
 */
public final class TelemetryClassifier {

    static final int HR_MIN = 15;
    static final int HR_MAX = 300;
    static final double SPO2_MIN = 40.0;
    static final double SPO2_MAX = 100.0;
    static final double PERFUSION_MIN = 0.5;

    private TelemetryClassifier() {
    }

    public static String classify(TelemetryPayload.Metrics m) {
        if (m.heartRateBpm() < HR_MIN || m.heartRateBpm() > HR_MAX || m.spo2Pct() < SPO2_MIN || m.spo2Pct() > SPO2_MAX) {
            return "REJECTED_IMPLAUSIBLE";
        }
        if (m.signalPerfusionIndex() < PERFUSION_MIN) {
            return "SIGNAL_DEGRADED";
        }
        return "ACCEPTED";
    }
}
