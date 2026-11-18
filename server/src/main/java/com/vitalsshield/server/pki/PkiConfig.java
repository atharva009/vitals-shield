package com.vitalsshield.server.pki;

import java.security.SecureRandom;
import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
public class PkiConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public CertificateProfiles certificateProfiles(PkiProperties props, Clock clock) {
        // The one JVM clock (DECISIONS #89): validity windows are written and checked with the same clock.
        return new CertificateProfiles(clock, new SecureRandom(), props.publicBaseUrl());
    }
}
