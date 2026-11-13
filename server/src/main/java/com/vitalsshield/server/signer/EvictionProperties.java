package com.vitalsshield.server.signer;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** {@code vitalsshield.eviction.enabled}: close live sockets on revoke (default true; tests may turn it off). */
@ConfigurationProperties("vitalsshield.eviction")
public record EvictionProperties(@DefaultValue("true") boolean enabled) {
}
