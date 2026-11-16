package com.vitalsshield.server.admin.webauthn;

import com.vitalsshield.server.gateway.ListenerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

/** Origins come from the configured admin port; the Next.js dev proxy origin only with profile dashboard-dev. */
@Configuration(proxyBeanMethods = false)
public class WebAuthnConfig {

    @Bean
    public WebAuthnOrigins webAuthnOrigins(ListenerProperties listeners, Environment env) {
        return WebAuthnOrigins.forAdminPort(listeners.adminPort(), env.acceptsProfiles(Profiles.of("dashboard-dev")));
    }

    /** DECISIONS #66: DEV_SEED passkeys work only in the local profile. */
    @Bean
    public DevSeedPolicy devSeedPolicy(Environment env) {
        return new DevSeedPolicy(env.acceptsProfiles(Profiles.of("local")));
    }
}
