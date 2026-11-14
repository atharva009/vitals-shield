package com.vitalsshield.server.admin;

import java.nio.file.Path;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** {@code vitalsshield.dashboard.dir}: the Next.js static export served on the admin port (DECISIONS #47). */
@ConfigurationProperties("vitalsshield.dashboard")
public record DashboardProperties(@DefaultValue("dashboard/out") Path dir) {
}
