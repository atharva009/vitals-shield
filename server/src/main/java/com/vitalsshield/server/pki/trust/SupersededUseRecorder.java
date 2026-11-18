package com.vitalsshield.server.pki.trust;

import java.time.Instant;

/**
 * Where the handshake and per-request paths report a RENEWED certificate presented after its grace (DECISIONS #94).
 * Must not block or do I/O: it is called on a Netty event loop during the TLS handshake.
 */
public interface SupersededUseRecorder {

    SupersededUseRecorder NONE = (key, presentedAt) -> {
    };

    void recordSupersededUse(CertKey key, Instant presentedAt);
}
