package com.vitalsshield.simulator;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

/**
 * DECISIONS #83: renewal is due at not_before + 2/3 x (not_after - not_before) of the current certificate, in every
 * profile. Production 12 h renews at 8 h; the demo PT4M leaf (notBefore backdated 60 s) renews 2m40s after
 * notBefore, about 1m40s after issuance. Checked before each batch.
 */
public final class RenewalDueRule {

    private RenewalDueRule() {
    }

    public static Instant dueAt(Instant notBefore, Instant notAfter) {
        long validityMs = Duration.between(notBefore, notAfter).toMillis();
        return notBefore.plusMillis(validityMs * 2 / 3);
    }

    public static Instant dueAt(X509Certificate cert) {
        return dueAt(cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant());
    }

    /** True from the due instant on (inclusive). */
    public static boolean isDue(Instant notBefore, Instant notAfter, Instant now) {
        return !now.isBefore(dueAt(notBefore, notAfter));
    }

    public static boolean isDue(X509Certificate cert, Instant now) {
        return isDue(cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant(), now);
    }
}
