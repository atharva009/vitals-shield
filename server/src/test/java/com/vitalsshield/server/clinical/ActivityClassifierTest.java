package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class ActivityClassifierTest {

    static final ClinicalProperties P = ClinicalProperties.defaults();
    static final Instant T0 = Instant.parse("2026-11-16T08:00:00Z");

    static BatchMetrics still(int cadence, double motion) {
        return new BatchMetrics(66, 50, 98, 4, cadence, motion);
    }

    @Test
    void motionBoundary() {
        Instant since = T0.minus(Duration.ofMinutes(10));
        assertThat(ActivityClassifier.classify(still(0, 0.049), T0, since, null, P).context())
                .isEqualTo(ActivityContext.RESTING);
        ActivityClassifier.Result atLimit = ActivityClassifier.classify(still(0, 0.05), T0, since, null, P);
        assertThat(atLimit.context()).isEqualTo(ActivityContext.EXERTION);
        assertThat(atLimit.restingSince()).as("a non-qualifying batch clears resting_since").isNull();
    }

    @Test
    void cadenceBoundary() {
        Instant since = T0.minus(Duration.ofMinutes(10));
        assertThat(ActivityClassifier.classify(still(0, 0.02), T0, since, null, P).context())
                .isEqualTo(ActivityContext.RESTING);
        assertThat(ActivityClassifier.classify(still(1, 0.02), T0, since, null, P).context())
                .isEqualTo(ActivityContext.EXERTION);
    }

    @Test
    void sustainExactlyFiveMinutesVersusFourFiftyNine() {
        Instant since = T0;
        assertThat(ActivityClassifier.classify(still(0, 0.02), T0.plus(Duration.ofMinutes(5)), since, null, P)
                .context()).isEqualTo(ActivityContext.RESTING);
        ActivityClassifier.Result early = ActivityClassifier.classify(still(0, 0.02),
                T0.plus(Duration.ofSeconds(4 * 60 + 59)), since, null, P);
        assertThat(early.context()).isEqualTo(ActivityContext.EXERTION);
        assertThat(early.notYetSustained()).isTrue();
        assertThat(early.restingSince()).isEqualTo(since);
    }

    @Test
    void firstQualifyingBatchStartsTheClock() {
        ActivityClassifier.Result r = ActivityClassifier.classify(still(0, 0.02), T0, null, null, P);
        assertThat(r.context()).isEqualTo(ActivityContext.EXERTION);
        assertThat(r.restingSince()).isEqualTo(T0);
        assertThat(r.notYetSustained()).isTrue();
    }

    @Test
    void measuredAtRegressionResets() {
        Instant since = T0.minus(Duration.ofMinutes(30));
        Instant last = T0.plus(Duration.ofMinutes(1));
        ActivityClassifier.Result r = ActivityClassifier.classify(still(0, 0.02), T0, since, last, P);
        assertThat(r.restingSince()).as("restarted at this batch").isEqualTo(T0);
        assertThat(r.context()).isEqualTo(ActivityContext.EXERTION);
    }

    @Test
    void sixStillBatchesOneMinuteApartReachRestingOnTheSixth() {
        Instant since = null;
        Instant last = null;
        for (int i = 0; i < 6; i++) {
            Instant m = T0.plus(Duration.ofMinutes(i));
            ActivityClassifier.Result r = ActivityClassifier.classify(still(0, 0.02), m, since, last, P);
            assertThat(r.context()).as("batch %d", i + 1)
                    .isEqualTo(i < 5 ? ActivityContext.EXERTION : ActivityContext.RESTING);
            since = r.restingSince();
            last = m;
        }
    }
}
