package com.vitalsshield.server.signer;

import com.vitalsshield.server.pki.trust.CertKey;
import java.time.Instant;

/** Outcome of one revoke: when, how many live sockets were closed, and wall time from call to sockets closed. */
public record RevocationResult(CertKey key, Instant revokedAt, int channelsClosed, long evictionLatencyMicros) {
}
