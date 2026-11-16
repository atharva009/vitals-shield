package com.vitalsshield.server.clinical;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Drift against a LOCKED personal baseline (spec Section 6 step 4, DECISIONS #73). A RESTING ACCEPTED batch breaches
 * when at least metrics-required (2) of z_hr >= +2.0, z_hrv <= -1.8, z_spo2 <= -1.5 hold. Breaches extend the streak;
 * a non-breaching RESTING batch resets it; EXERTION and SIGNAL_DEGRADED batches are not passed in, so they neither
 * count nor reset. At streak 4 the alert fires and the streak resets.
 */
public final class DriftRule {

    public record ZScores(double hr, double hrv, double spo2) {
    }

    public record State(int streak, List<UUID> batchIds) {
        public static final State EMPTY = new State(0, List.of());
    }

    /** {@code trigger}: the batch ids of the alert when {@code fire}, otherwise empty. */
    public record Step(State next, boolean fire, List<UUID> trigger) {
    }

    private DriftRule() {
    }

    public static ZScores z(BatchMetrics m, CalibrationStats.Baseline b) {
        return new ZScores((m.hr() - b.hrMean()) / b.hrSd(), (m.hrv() - b.hrvMean()) / b.hrvSd(),
                (m.spo2() - b.spo2Mean()) / b.spo2Sd());
    }

    public static int breachCount(ZScores z, ClinicalProperties p) {
        ClinicalProperties.Drift d = p.drift();
        int n = 0;
        if (z.hr() >= d.zHrMin()) {
            n++;
        }
        if (z.hrv() <= d.zHrvMax()) {
            n++;
        }
        if (z.spo2() <= d.zSpo2Max()) {
            n++;
        }
        return n;
    }

    public static boolean breach(ZScores z, ClinicalProperties p) {
        return breachCount(z, p) >= p.drift().metricsRequired();
    }

    /** A RESTING ACCEPTED batch on a LOCKED baseline. */
    public static Step onResting(State s, UUID batchId, boolean breach, ClinicalProperties p) {
        if (!breach) {
            return new Step(State.EMPTY, false, List.of());
        }
        List<UUID> ids = new ArrayList<>(s.batchIds());
        ids.add(batchId);
        int n = s.streak() + 1;
        if (n >= p.drift().streak()) {
            return new Step(State.EMPTY, true, List.copyOf(ids));
        }
        return new Step(new State(n, List.copyOf(ids)), false, List.of());
    }

    /** Mean z-scores over the streak's batches, e.g. "Drift vs baseline v2: HR z=+2.4, HRV z=-2.1, SpO2 z=-0.3 ...". */
    public static String explanation(int baselineVersion, List<ZScores> zs) {
        double hr = zs.stream().mapToDouble(ZScores::hr).average().orElse(0);
        double hrv = zs.stream().mapToDouble(ZScores::hrv).average().orElse(0);
        double spo2 = zs.stream().mapToDouble(ZScores::spo2).average().orElse(0);
        return String.format(Locale.ROOT, "Drift vs baseline v%d: HR z=%+.1f, HRV z=%+.1f, SpO2 z=%+.1f over %d resting "
                + "batches", baselineVersion, hr, hrv, spo2, zs.size());
    }
}
