package com.vitalsshield.server.signer;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** {@code vitalsshield.backstop.*} (DECISIONS #96): poll every {@code interval} for revocations since the last poll. */
@ConfigurationProperties("vitalsshield.backstop")
public record BackstopProperties(@DefaultValue("true") boolean enabled, @DefaultValue("PT3S") Duration interval,
                                 @DefaultValue("PT30S") Duration lookback) {
}
