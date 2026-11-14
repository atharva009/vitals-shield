package com.vitalsshield.server.signer;

import com.vitalsshield.server.pki.trust.CertKey;
import java.time.Instant;

/**
 * Outcome of one certificate revocation: when, why, how many live sockets were closed, and the latency (DECISIONS #11:
 * from the start of the revoke, or of the quarantine request, to every close future complete).
 */
public record RevocationResult(CertKey key, String deviceId, String reason, Instant revokedAt, int channelsClosed,
                               long evictionLatencyMicros) {
}
