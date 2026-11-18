package com.vitalsshield.server.clock;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * {@code vitalsshield.clock.*} (DECISIONS #98): the skew between Postgres clock_timestamp() and the JVM clock is GREEN
 * up to {@code amberMs}, AMBER up to {@code redMs}, RED above; checked at boot and every {@code checkInterval}.
 */
@ConfigurationProperties("vitalsshield.clock")
public record ClockProperties(@DefaultValue("2000") long amberMs, @DefaultValue("10000") long redMs,
                              @DefaultValue("PT60S") Duration checkInterval) {
}
