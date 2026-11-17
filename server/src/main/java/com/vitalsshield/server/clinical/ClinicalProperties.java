package com.vitalsshield.server.clinical;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * {@code queueCapacity} caps evaluations queued or running in this process (DECISIONS #79); overflow stays unevaluated.
 *
 * <p>{@code vitalsshield.clinical.*}: every threshold the clinical engine uses (spec Section 6). The defaults are the
 * spec's values. They are engineering defaults and have not been clinically validated (spec Section 6 disclaimer).
 * {@link #defaults()} returns the same values for unit tests; ClinicalPropertiesTest checks the two agree.
 */
@ConfigurationProperties("vitalsshield.clinical")
public record ClinicalProperties(
        @DefaultValue({"15", "300"}) List<Integer> hrBounds,
        @DefaultValue({"40", "100"}) List<Double> spo2Bounds,
        @DefaultValue("0") int restingCadenceMax,
        @DefaultValue("0.05") double restingMotionMax,
        @DefaultValue("PT5M") Duration restingSustain,
        @DefaultValue("0.5") double perfusionMin,
        @DefaultValue DegradedCritical degradedCritical,
        @DefaultValue Acute acute,
        @DefaultValue("30") int calibrationSize,
        @DefaultValue Drift drift,
        @DefaultValue SdFloors sdFloors,
        @DefaultValue("PT5M") Duration acuteDedupeWindow,
        @DefaultValue("1000") int queueCapacity) {

    /** SIGNAL_DEGRADED batches that also show a critical reading (spec Section 6 step 3, DECISIONS #71). */
    public record DegradedCritical(@DefaultValue("90.0") double spo2Max, @DefaultValue("40") int hrMaxLow,
                                   @DefaultValue("150") int hrMinHigh, @DefaultValue("3") int streak) {
    }

    /** Context-aware acute bounds on ACCEPTED batches (spec Section 6 step 3). */
    public record Acute(@DefaultValue("140") int restingHrHigh, @DefaultValue("40") int restingHrLow,
                        @DefaultValue("0.95") double exertionHrFactor, @DefaultValue("208") double exertionHrIntercept,
                        @DefaultValue("0.7") double exertionHrSlope, @DefaultValue("90.0") double spo2Max) {
    }

    /** Directional z-score thresholds (spec Section 6 step 4, DECISIONS #73). */
    public record Drift(@DefaultValue("2.0") double zHrMin, @DefaultValue("-1.8") double zHrvMax,
                        @DefaultValue("-1.5") double zSpo2Max, @DefaultValue("2") int metricsRequired,
                        @DefaultValue("4") int streak) {
    }

    /** Lower bounds on the calibrated SD, so a flat calibration cannot make every later batch a breach (DECISIONS #72). */
    public record SdFloors(@DefaultValue("3.0") double hr, @DefaultValue("5.0") double hrv,
                           @DefaultValue("1.0") double spo2) {
    }

    public int hrMin() {
        return hrBounds.get(0);
    }

    public int hrMax() {
        return hrBounds.get(1);
    }

    public double spo2Min() {
        return spo2Bounds.get(0);
    }

    public double spo2Max() {
        return spo2Bounds.get(1);
    }

    /** The spec defaults, for unit tests that do not start Spring. */
    public static ClinicalProperties defaults() {
        return new ClinicalProperties(List.of(15, 300), List.of(40.0, 100.0), 0, 0.05, Duration.ofMinutes(5), 0.5,
                new DegradedCritical(90.0, 40, 150, 3), new Acute(140, 40, 0.95, 208, 0.7, 90.0), 30,
                new Drift(2.0, -1.8, -1.5, 2, 4), new SdFloors(3.0, 5.0, 1.0), Duration.ofMinutes(5), 1000);
    }

    /** Same thresholds with a different calibration window (the demo profile uses 10). */
    public ClinicalProperties withCalibrationSize(int size) {
        return new ClinicalProperties(hrBounds, spo2Bounds, restingCadenceMax, restingMotionMax, restingSustain,
                perfusionMin, degradedCritical, acute, size, drift, sdFloors, acuteDedupeWindow, queueCapacity);
    }
}
