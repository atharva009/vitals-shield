package com.vitalsshield.server.clinical;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Context-aware acute bounds on ACCEPTED batches (spec Section 6 step 3). Each condition met becomes one
 * ACUTE_PHYSIOLOGICAL_ALERT unless deduplicated (DECISIONS #71).
 */
public final class AcuteRules {

    public static final String RESTING_HR_HIGH = "RESTING_HR_HIGH";
    public static final String RESTING_HR_LOW = "RESTING_HR_LOW";
    public static final String EXERTION_HR_HIGH = "EXERTION_HR_HIGH";
    public static final String SPO2_LOW = "SPO2_LOW";

    public record Condition(String code, String explanation) {
    }

    private AcuteRules() {
    }

    /** Age in whole years as the spec uses it: year(measured_at, UTC) - patient_birth_year. */
    public static int age(Instant measuredAt, int birthYear) {
        return measuredAt.atZone(ZoneOffset.UTC).getYear() - birthYear;
    }

    /** {@code factor * (intercept - slope * age)}: 0.95 * (208 - 0.7 * age) with the defaults. */
    public static double exertionHrLimit(int age, ClinicalProperties p) {
        ClinicalProperties.Acute a = p.acute();
        return a.exertionHrFactor() * (a.exertionHrIntercept() - a.exertionHrSlope() * age);
    }

    public static List<Condition> evaluate(BatchMetrics m, ActivityContext ctx, int age, ClinicalProperties p) {
        ClinicalProperties.Acute a = p.acute();
        List<Condition> out = new ArrayList<>();
        if (ctx == ActivityContext.RESTING && m.hr() >= a.restingHrHigh()) {
            out.add(new Condition(RESTING_HR_HIGH, String.format(Locale.ROOT,
                    "Resting heart rate %d bpm for %s+ min (limit %d)", m.hr(), sustainMinutes(p), a.restingHrHigh())));
        }
        if (ctx == ActivityContext.RESTING && m.hr() <= a.restingHrLow()) {
            out.add(new Condition(RESTING_HR_LOW, String.format(Locale.ROOT,
                    "Resting heart rate %d bpm for %s+ min (limit %d)", m.hr(), sustainMinutes(p), a.restingHrLow())));
        }
        if (ctx == ActivityContext.EXERTION) {
            double limit = exertionHrLimit(age, p);
            if (m.hr() > limit) {
                out.add(new Condition(EXERTION_HR_HIGH, String.format(Locale.ROOT,
                        "Heart rate %d bpm during exertion (limit %.1f = %.2f x (%.0f - %.1f x age %d))", m.hr(), limit,
                        a.exertionHrFactor(), a.exertionHrIntercept(), a.exertionHrSlope(), age)));
            }
        }
        if (m.spo2() <= a.spo2Max()) {
            out.add(new Condition(SPO2_LOW, String.format(Locale.ROOT, "SpO2 %.1f%% (limit %.1f%%)", m.spo2(),
                    a.spo2Max())));
        }
        return out;
    }

    private static String sustainMinutes(ClinicalProperties p) {
        long s = p.restingSustain().toSeconds();
        return s % 60 == 0 ? Long.toString(s / 60) : String.format(Locale.ROOT, "%.1f", s / 60.0);
    }
}
