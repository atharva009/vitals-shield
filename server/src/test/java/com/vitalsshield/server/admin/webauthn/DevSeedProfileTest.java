package com.vitalsshield.server.admin.webauthn;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/** DECISIONS #66, 99: DEV_SEED approvals in local and demo only, never in the default (production) profile. */
class DevSeedProfileTest {

    static MockEnvironment with(String... profiles) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles(profiles);
        return env;
    }

    @Test
    void localAndDemoAllowDevSeedNothingElseDoes() {
        assertThat(WebAuthnConfig.devSeedAllowed(with("local"))).isTrue();
        assertThat(WebAuthnConfig.devSeedAllowed(with("demo"))).isTrue();
        assertThat(WebAuthnConfig.devSeedAllowed(with())).isFalse();
        assertThat(WebAuthnConfig.devSeedAllowed(with("prod"))).isFalse();
    }
}
