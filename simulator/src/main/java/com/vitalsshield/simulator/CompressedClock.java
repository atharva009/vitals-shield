package com.vitalsshield.simulator;

import java.time.Duration;
import java.time.Instant;

/**
 * Demo clock compression (DECISIONS #6, refined by #74): each batch is measured 60 s after the previous one, starting
 * no earlier than 12 h ago, and never later than now. At about one batch per real second, a demo covers clinical time
 * (5-minute rest, 10-batch calibration) in seconds, while measured_at stays monotonic across restarts because the last
 * value is persisted in state.json.
 */
public final class CompressedClock {

    public static final Duration STEP = Duration.ofSeconds(60);
    public static final Duration MAX_BACK_OFFSET = Duration.ofHours(12);

    private CompressedClock() {
    }

    /** {@code min(max(last + 60 s, now - 12 h), now)}; with no previous batch, {@code now - 12 h}. */
    public static Instant next(Instant lastMeasuredAt, Instant now) {
        Instant floor = now.minus(MAX_BACK_OFFSET);
        Instant candidate = lastMeasuredAt == null ? floor : lastMeasuredAt.plus(STEP);
        if (candidate.isBefore(floor)) {
            candidate = floor;
        }
        return candidate.isAfter(now) ? now : candidate;
    }
}
