package com.vitalsshield.server.clinical;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * DECISIONS #71, acute alerts: a new ACUTE_PHYSIOLOGICAL_ALERT is suppressed if an ACTIVE or ACKNOWLEDGED acute alert
 * on the same assignment with the same condition_code has a triggering batch measured within the window before this
 * batch ({@code measuredAt - window <= t <= measuredAt}). The caller passes only ACTIVE or ACKNOWLEDGED acute alerts
 * of the same assignment; the evaluator holds that assignment's row lock, so the check cannot race another evaluation.
 */
public final class AlertDedupe {

    /** One triggering batch of an existing open alert. */
    public record Prior(String conditionCode, Instant triggerMeasuredAt) {
    }

    private AlertDedupe() {
    }

    public static boolean suppressed(List<Prior> priors, String conditionCode, Instant measuredAt, Duration window) {
        Instant from = measuredAt.minus(window);
        return priors.stream().anyMatch(p -> p.conditionCode().equals(conditionCode)
                && !p.triggerMeasuredAt().isBefore(from) && !p.triggerMeasuredAt().isAfter(measuredAt));
    }
}
