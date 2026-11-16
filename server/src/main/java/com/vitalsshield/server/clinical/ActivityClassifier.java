package com.vitalsshield.server.clinical;

import java.time.Duration;
import java.time.Instant;

/**
 * Spec Section 6 step 2. A batch "qualifies" as still (cadence at most resting-cadence-max and motion below
 * resting-motion-max). It is RESTING only once qualifying batches have been seen continuously for resting-sustain,
 * judged on measured_at: {@code measured_at - resting_since >= sustain}. Anything else is EXERTION, including a
 * qualifying batch before the sustain period has elapsed ("not yet sustained").
 *
 * <p>resting_since: set to measured_at by the first qualifying batch, cleared by a non-qualifying batch, and reset
 * when measured_at goes backwards relative to the previous evaluated batch (DECISIONS #69).
 */
public final class ActivityClassifier {

    public record Result(ActivityContext context, Instant restingSince, boolean qualifies) {

        /** Still, but for less than the sustain period. */
        public boolean notYetSustained() {
            return qualifies && context == ActivityContext.EXERTION;
        }
    }

    private ActivityClassifier() {
    }

    public static Result classify(BatchMetrics m, Instant measuredAt, Instant restingSince,
                                  Instant lastEvaluatedMeasuredAt, ClinicalProperties p) {
        Instant since = restingSince;
        if (lastEvaluatedMeasuredAt != null && measuredAt.isBefore(lastEvaluatedMeasuredAt)) {
            since = null;
        }
        boolean qualifies = m.cadence() <= p.restingCadenceMax() && m.motion() < p.restingMotionMax();
        if (!qualifies) {
            return new Result(ActivityContext.EXERTION, null, false);
        }
        if (since == null) {
            since = measuredAt;
        }
        boolean sustained = Duration.between(since, measuredAt).compareTo(p.restingSustain()) >= 0;
        return new Result(sustained ? ActivityContext.RESTING : ActivityContext.EXERTION, since, true);
    }
}
