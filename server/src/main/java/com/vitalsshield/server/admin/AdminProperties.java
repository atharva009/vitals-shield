package com.vitalsshield.server.admin;

import java.nio.file.Path;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** {@code vitalsshield.admin.*}. */
@ConfigurationProperties("vitalsshield.admin")
public record AdminProperties(@DefaultValue("var/admin/setup-code") Path setupCodeFile) {
}
