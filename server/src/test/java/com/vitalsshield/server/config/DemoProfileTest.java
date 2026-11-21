package com.vitalsshield.server.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * DECISIONS 99: the effective configuration under --spring.profiles.active=demo, from the real application*.yml files,
 * with no beans and no Docker. Phase 10a.1 regression: with a profile group, application-local.yml was applied after
 * application-demo.yml and its leaf-ttl PT4M won over demo's PT3M.
 */
class DemoProfileTest {

    @Configuration(proxyBeanMethods = false)
    static class Empty {
    }

    @Test
    void demoValuesWinAndLocalValuesAreInherited() {
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(Empty.class)
                .web(WebApplicationType.NONE).profiles("demo").logStartupInfo(false)
                .properties("spring.main.keep-alive=false").run()) {
            Environment env = ctx.getEnvironment();
            // Demo's own values (they differ from local or default).
            assertThat(env.getProperty("vitalsshield.pki.leaf-ttl")).isEqualTo("PT3M");
            assertThat(env.getProperty("vitalsshield.pki.renewal-grace")).isEqualTo("PT60S");
            assertThat(env.getProperty("vitalsshield.clinical.calibration-size")).isEqualTo("10");
            assertThat(env.getProperty("vitalsshield.reenroll.per-address-limit")).isEqualTo("60");
            assertThat(env.getProperty("vitalsshield.reenroll.global-limit")).isEqualTo("300");
            assertThat(env.getProperty("vitalsshield.anomaly.sequence-regression.enabled")).isEqualTo("true");
            assertThat(env.getProperty("vitalsshield.anomaly.post-drain.enabled")).isEqualTo("true");
            // Inherited from local.
            assertThat(env.getProperty("vitalsshield.pki.allow-hierarchy-rebuild")).isEqualTo("true");
            assertThat(env.getProperty("vitalsshield.kms.endpoint")).isEqualTo("http://localhost:4566");
            assertThat(env.getActiveProfiles()).contains("demo");
        }
    }

    @Test
    void localProfileIsUnchanged() {
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(Empty.class)
                .web(WebApplicationType.NONE).profiles("local").logStartupInfo(false)
                .properties("spring.main.keep-alive=false").run()) {
            Environment env = ctx.getEnvironment();
            assertThat(env.getProperty("vitalsshield.pki.leaf-ttl")).isEqualTo("PT4M");
            assertThat(env.getProperty("vitalsshield.reenroll.per-address-limit")).isEqualTo("10");
        }
    }
}
