package com.vitalsshield.server.telemetry;

import com.vitalsshield.server.clinical.ClinicalProperties;

/**
 * Trust classification at ingest (DECISIONS #46; spec Section 6 steps 1 and 3): hardware plausibility first, then
 * signal perfusion. Since Phase 7 the bounds come from {@code vitalsshield.clinical.*} (hr-bounds, spo2-bounds,
 * perfusion-min); activity context, acute bounds, calibration and drift run afterwards in ClinicalEvaluator.
 */
public final class TelemetryClassifier {

    private TelemetryClassifier() {
    }

    /** With the spec defaults. */
    public static String classify(TelemetryPayload.Metrics m) {
        return classify(m, ClinicalProperties.defaults());
    }

    public static String classify(TelemetryPayload.Metrics m, ClinicalProperties p) {
        if (m.heartRateBpm() < p.hrMin() || m.heartRateBpm() > p.hrMax() || m.spo2Pct() < p.spo2Min()
                || m.spo2Pct() > p.spo2Max()) {
            return "REJECTED_IMPLAUSIBLE";
        }
        if (m.signalPerfusionIndex() < p.perfusionMin()) {
            return "SIGNAL_DEGRADED";
        }
        return "ACCEPTED";
    }
}
