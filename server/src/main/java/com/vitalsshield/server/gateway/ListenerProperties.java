package com.vitalsshield.server.gateway;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** Listener ports and bind host ({@code vitalsshield.listeners.*}). The admin listener always binds 127.0.0.1. */
@ConfigurationProperties("vitalsshield.listeners")
public record ListenerProperties(
        @DefaultValue("127.0.0.1") String bindHost,
        @DefaultValue("8443") int mtlsPort,
        @DefaultValue("8444") int publicPort,
        @DefaultValue("8445") int adminPort) {

    public static final String ADMIN_BIND_HOST = "127.0.0.1";
}
