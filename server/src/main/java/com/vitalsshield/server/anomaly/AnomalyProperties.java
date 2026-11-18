package com.vitalsshield.server.anomaly;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * {@code vitalsshield.anomaly.*}: the split-brain traps (spec Section 2 layer 5).
 *
 * @param sequenceRegression DECISIONS #93: {@code threshold} rejections with distinct batch ids within {@code window}
 * @param postDrain          DECISIONS #94: a RENEWED certificate presented more than {@code slack} after its grace;
 *                           queued events are drained every {@code drainInterval}
 */
@ConfigurationProperties("vitalsshield.anomaly")
public record AnomalyProperties(@DefaultValue SequenceRegression sequenceRegression,
                                @DefaultValue PostDrain postDrain) {

    public record SequenceRegression(@DefaultValue("true") boolean enabled, @DefaultValue("3") int threshold,
                                     @DefaultValue("PT60S") Duration window) {
    }

    public record PostDrain(@DefaultValue("true") boolean enabled, @DefaultValue("PT5S") Duration slack,
                            @DefaultValue("PT0.25S") Duration drainInterval, @DefaultValue("1024") int queueCapacity) {
    }

    public static AnomalyProperties defaults() {
        return new AnomalyProperties(new SequenceRegression(true, 3, Duration.ofSeconds(60)),
                new PostDrain(true, Duration.ofSeconds(5), Duration.ofMillis(250), 1024));
    }
}
