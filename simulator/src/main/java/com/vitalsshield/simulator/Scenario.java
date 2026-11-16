package com.vitalsshield.simulator;

import java.util.Locale;
import java.util.Random;

/**
 * Fixed metric generators with small seeded noise (DECISIONS #74). Ranges are inclusive. The CLI names are the
 * lowercase, hyphenated forms ({@code low-perfusion-critical}).
 */
public enum Scenario {
    /** HR 62-70, HRV 45-55, SpO2 97-99, perfusion 3-5, cadence 0, motion 0.01-0.03. */
    RESTING,
    /** HR 125-135, HRV 20-30, SpO2 96-98, perfusion 3-5, cadence 100-120, motion 0.3-0.5. */
    EXERTION,
    /** Like resting but HR 80-86, HRV 28-34, SpO2 95-96: breaches z_hr and z_hrv against a resting baseline. */
    DRIFT,
    /** Like resting but HR 150-158. */
    ACUTE,
    /** Perfusion 0.2-0.4 (SIGNAL_DEGRADED), SpO2 87-89, HR 70-80, still. */
    LOW_PERFUSION_CRITICAL;

    public TelemetryFrames.Metrics generate(Random r) {
        return switch (this) {
            case RESTING -> new TelemetryFrames.Metrics(between(r, 62, 70), range(r, 45, 55), range(r, 97, 99),
                    range(r, 3, 5), 0, range(r, 0.01, 0.03));
            case EXERTION -> new TelemetryFrames.Metrics(between(r, 125, 135), range(r, 20, 30), range(r, 96, 98),
                    range(r, 3, 5), between(r, 100, 120), range(r, 0.3, 0.5));
            case DRIFT -> new TelemetryFrames.Metrics(between(r, 80, 86), range(r, 28, 34), range(r, 95, 96),
                    range(r, 3, 5), 0, range(r, 0.01, 0.03));
            case ACUTE -> new TelemetryFrames.Metrics(between(r, 150, 158), range(r, 45, 55), range(r, 97, 99),
                    range(r, 3, 5), 0, range(r, 0.01, 0.03));
            case LOW_PERFUSION_CRITICAL -> new TelemetryFrames.Metrics(between(r, 70, 80), range(r, 45, 55),
                    range(r, 87, 89), range(r, 0.2, 0.4), 0, range(r, 0.01, 0.03));
        };
    }

    /** Deterministic noise for one batch: the same device and sequence number always give the same metrics. */
    public TelemetryFrames.Metrics generate(String deviceId, long sequenceNumber) {
        return generate(new Random(deviceId.hashCode() * 1_000_003L + sequenceNumber));
    }

    public String cliName() {
        return name().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    public static Scenario parse(String s) {
        try {
            return valueOf(s.trim().toUpperCase(Locale.ROOT).replace('-', '_'));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("unknown scenario: " + s
                    + " (resting, exertion, drift, acute, low-perfusion-critical)");
        }
    }

    private static int between(Random r, int lo, int hi) {
        return lo + r.nextInt(hi - lo + 1);
    }

    private static double range(Random r, double lo, double hi) {
        return Math.round((lo + (hi - lo) * r.nextDouble()) * 100.0) / 100.0;
    }
}
