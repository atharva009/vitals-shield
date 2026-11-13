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
    public CertificateProfiles certificateProfiles(PkiProperties props) {
        return new CertificateProfiles(Clock.systemUTC(), new SecureRandom(), props.publicBaseUrl());
    }
}
