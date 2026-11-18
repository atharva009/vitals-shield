package com.vitalsshield.server.clock;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

/** DECISIONS #98: 0, 1999, 2001 and 10001 ms map to GREEN, GREEN, AMBER, RED. */
class ClockSkewMonitorTest {

    static final ClockProperties PROPS = new ClockProperties(2000, 10000, Duration.ofSeconds(60));
    static final Clock JVM = Clock.fixed(Instant.parse("2026-11-18T12:00:00Z"), ZoneOffset.UTC);

    static ClockSkewMonitor.Snapshot measure(long dbAheadMs) {
        return new ClockSkewMonitor(() -> JVM.instant().plusMillis(dbAheadMs), JVM, PROPS).checkNow();
    }

    @Test
    void thresholds() {
        assertThat(measure(0)).extracting(ClockSkewMonitor.Snapshot::skewMs, ClockSkewMonitor.Snapshot::state)
                .containsExactly(0L, ClockSkewMonitor.State.GREEN);
        assertThat(measure(1999).state()).isEqualTo(ClockSkewMonitor.State.GREEN);
        assertThat(measure(2001).state()).isEqualTo(ClockSkewMonitor.State.AMBER);
        assertThat(measure(10001).state()).isEqualTo(ClockSkewMonitor.State.RED);
    }

    @Test
    void postgresBehindCountsTheSame() {
        ClockSkewMonitor.Snapshot s = measure(-13_580); // the Phase 8 soak run: Docker VM 13.58 s behind
        assertThat(s.skewMs()).isEqualTo(-13_580L);
        assertThat(s.state()).isEqualTo(ClockSkewMonitor.State.RED);
    }

    @Test
    void failedQueryIsUnknown() {
        ClockSkewMonitor m = new ClockSkewMonitor(() -> {
            throw new IllegalStateException("db down");
        }, JVM, PROPS);
        assertThat(m.checkNow().state()).isEqualTo(ClockSkewMonitor.State.UNKNOWN);
        assertThat(m.snapshot().error()).contains("db down");
    }
}
