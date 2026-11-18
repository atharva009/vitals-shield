package com.vitalsshield.server.reenroll;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * {@code vitalsshield.reenroll.*}: Protocol C (spec Section 4).
 *
 * @param challengeMaxAge  |JVM now - issued_at_ms| allowed for a challenge (DECISIONS #90)
 * @param perAddressLimit  challenges per {@code rateWindow} per remote address (DECISIONS #90)
 * @param globalLimit      challenges per {@code rateWindow} in total (DECISIONS #90)
 * @param collisionWindow  an ingest this recent counts as a live session for the collision check (DECISIONS #91)
 */
@ConfigurationProperties("vitalsshield.reenroll")
public record ReEnrollProperties(@DefaultValue("PT60S") Duration challengeMaxAge,
                                 @DefaultValue("10") int perAddressLimit,
                                 @DefaultValue("100") int globalLimit,
                                 @DefaultValue("PT1M") Duration rateWindow,
                                 @DefaultValue("PT30S") Duration collisionWindow) {

    public static ReEnrollProperties defaults() {
        return new ReEnrollProperties(Duration.ofSeconds(60), 10, 100, Duration.ofMinutes(1), Duration.ofSeconds(30));
    }
}
