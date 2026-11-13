package com.vitalsshield.server.pki.trust;

import java.time.Instant;

/** A certificates row relevant to the deny-list: REVOKED, EXPIRED or RENEWED. */
public record DenyRow(CertKey key, String status, Instant revokedAt, Instant graceExpiresAt) {
}
