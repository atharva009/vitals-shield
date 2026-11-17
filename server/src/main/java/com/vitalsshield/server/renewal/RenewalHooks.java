package com.vitalsshield.server.renewal;

/**
 * Test seam inside the renewal flow. Production uses {@link #NONE}. Integration tests register a bean to throw an
 * {@link Error} right after KMS signed the leaf, which simulates a process crash: no cleanup path runs, and only the
 * stale-reservation sweep can VOID the serial.
 */
public interface RenewalHooks {

    RenewalHooks NONE = new RenewalHooks() {
    };

    /** Called after KMS has signed the leaf and before Tx 2. */
    default void afterLeafSigned(String deviceId) {
    }
}
