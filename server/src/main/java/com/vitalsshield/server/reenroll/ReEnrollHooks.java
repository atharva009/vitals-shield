package com.vitalsshield.server.reenroll;

/** Test seam inside Protocol C, like RenewalHooks. Production uses {@link #NONE}. */
public interface ReEnrollHooks {

    ReEnrollHooks NONE = new ReEnrollHooks() {
    };

    /** Called after KMS has signed the leaf and before Tx 2. */
    default void afterLeafSigned(String deviceId) {
    }
}
