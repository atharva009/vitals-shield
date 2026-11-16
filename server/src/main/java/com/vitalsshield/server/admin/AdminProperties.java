package com.vitalsshield.server.admin;

import com.vitalsshield.server.admin.webauthn.AuthMode;
import java.nio.file.Path;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * {@code vitalsshield.admin.*}. {@code auth}: {@code webauthn} (default, Phase 6) or {@code bearer} (the Phase 5
 * setup-code behavior, kept as the cut path, DECISIONS #41 and #60).
 */
@ConfigurationProperties("vitalsshield.admin")
public record AdminProperties(@DefaultValue("var/admin/setup-code") Path setupCodeFile,
                              @DefaultValue("webauthn") AuthMode auth) {

    public boolean webauthn() {
        return auth == AuthMode.WEBAUTHN;
    }
}
