package com.vitalsshield.server.clinical;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Spec Section 6 step 3, first bullet; DECISIONS #71. Counts consecutive SIGNAL_DEGRADED batches with a critical
 * reading (SpO2 <= 90.0, HR <= 40, or HR >= 150). The alert fires when the streak reaches 3 and not again until the
 * streak resets: a non-critical degraded batch or any ACCEPTED batch resets it. Only the last {@code streak} batch ids
 * are kept; they are the alert's triggering batches.
 */
public final class DegradedCriticalStreak {

    public record State(int streak, List<UUID> batchIds) {
        public static final State EMPTY = new State(0, List.of());
    }

    /** {@code fire}: insert LOW_PERFUSION_CRITICAL_ALERT with {@code next.batchIds()} as its triggering batches. */
    public record Step(State next, boolean fire) {
    }

    private DegradedCriticalStreak() {
    }

    public static boolean critical(BatchMetrics m, ClinicalProperties p) {
        ClinicalProperties.DegradedCritical c = p.degradedCritical();
        return m.spo2() <= c.spo2Max() || m.hr() <= c.hrMaxLow() || m.hr() >= c.hrMinHigh();
    }

    public static Step onDegraded(State s, UUID batchId, BatchMetrics m, ClinicalProperties p) {
        if (!critical(m, p)) {
            return new Step(State.EMPTY, false);
        }
        int required = p.degradedCritical().streak();
        List<UUID> ids = new ArrayList<>(s.batchIds());
        ids.add(batchId);
        while (ids.size() > required) {
            ids.remove(0);
        }
        int n = s.streak() + 1;
        return new Step(new State(n, List.copyOf(ids)), n == required);
    }

    /** An ACCEPTED batch ends the degraded run. */
    public static State onAccepted() {
        return State.EMPTY;
    }

    public static String explanation(BatchMetrics m, int streak, ClinicalProperties p) {
        return String.format(Locale.ROOT,
                "%d consecutive low-perfusion batches with a critical reading: latest SpO2 %.1f%%, HR %d bpm, "
                        + "perfusion %.2f (limit %.1f; critical: SpO2 <= %.1f%%, HR <= %d or >= %d)",
                streak, m.spo2(), m.hr(), m.perfusion(), p.perfusionMin(), p.degradedCritical().spo2Max(),
                p.degradedCritical().hrMaxLow(), p.degradedCritical().hrMinHigh());
    }
}
