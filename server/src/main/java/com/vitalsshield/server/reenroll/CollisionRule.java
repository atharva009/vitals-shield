package com.vitalsshield.server.reenroll;

import java.time.Instant;
import java.util.List;

/**
 * DECISIONS #91: the epoch-agnostic active-session collision. A re-enrollment collides only if the device still has a
 * usable certificate AND that identity is in use right now (a live mTLS socket for any of its certificates, or an
 * ingest within the collision window). An expired certificate is never usable, so the laptop-sleep case (the
 * certificate expired, the last batch was seconds ago) is normal recovery, not a collision.
 *
 * <p>Same-clock rule (DECISIONS #89): {@code notAfter} and {@code graceExpiresAt} are JVM-written and compared with
 * {@code jvmNow}; the recent-ingest flag is computed in SQL against Postgres now(), because last_ingested_at is
 * stamped by Postgres.
 */
public final class CollisionRule {

    public record Cert(String status, Instant notAfter, Instant graceExpiresAt) {
    }

    private CollisionRule() {
    }

    public static boolean usable(Cert c, Instant jvmNow) {
        if (!c.notAfter().isAfter(jvmNow)) {
            return false;
        }
        return switch (c.status()) {
            case "ACTIVE", "ISSUED_PENDING_USE" -> true;
            case "RENEWED" -> c.graceExpiresAt() != null && c.graceExpiresAt().isAfter(jvmNow);
            default -> false;
        };
    }

    public static boolean fires(List<Cert> certs, Instant jvmNow, boolean liveSocket, boolean recentIngest) {
        boolean anyUsable = certs.stream().anyMatch(c -> usable(c, jvmNow));
        return anyUsable && (liveSocket || recentIngest);
    }
}
