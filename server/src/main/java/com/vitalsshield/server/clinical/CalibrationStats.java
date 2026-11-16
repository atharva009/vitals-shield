package com.vitalsshield.server.clinical;

import java.util.List;

/**
 * Resting baseline statistics (spec Section 6 step 4, DECISIONS #72): sample mean and sample SD (n - 1) per metric,
 * each SD raised to its floor.
 */
public final class CalibrationStats {

    public record Stats(double mean, double sd) {
    }

    public record Baseline(double hrMean, double hrSd, double hrvMean, double hrvSd, double spo2Mean, double spo2Sd) {
    }

    private CalibrationStats() {
    }

    /** Only ACCEPTED RESTING batches that did not trigger an acute condition (even a suppressed one) calibrate. */
    public static boolean eligible(String trustState, ActivityContext ctx, boolean acuteTriggering) {
        return "ACCEPTED".equals(trustState) && ctx == ActivityContext.RESTING && !acuteTriggering;
    }

    /** Sample mean and SD (n - 1); the SD is {@code max(sd, floor)}. Needs at least 2 values. */
    public static Stats of(double[] values, double floor) {
        if (values.length < 2) {
            throw new IllegalArgumentException("sample SD needs at least 2 values");
        }
        double sum = 0;
        for (double v : values) {
            sum += v;
        }
        double mean = sum / values.length;
        double sq = 0;
        for (double v : values) {
            sq += (v - mean) * (v - mean);
        }
        double sd = Math.sqrt(sq / (values.length - 1));
        return new Stats(mean, Math.max(sd, floor));
    }

    public static Baseline compute(List<BatchMetrics> batches, ClinicalProperties p) {
        double[] hr = batches.stream().mapToDouble(BatchMetrics::hr).toArray();
        double[] hrv = batches.stream().mapToDouble(BatchMetrics::hrv).toArray();
        double[] spo2 = batches.stream().mapToDouble(BatchMetrics::spo2).toArray();
        Stats h = of(hr, p.sdFloors().hr());
        Stats v = of(hrv, p.sdFloors().hrv());
        Stats s = of(spo2, p.sdFloors().spo2());
        return new Baseline(h.mean(), h.sd(), v.mean(), v.sd(), s.mean(), s.sd());
    }
}
