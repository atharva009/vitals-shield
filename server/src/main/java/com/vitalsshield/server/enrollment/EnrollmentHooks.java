package com.vitalsshield.server.enrollment;

/**
 * Test seam inside the enrollment flow. Production uses {@link #NONE}. Integration tests register a bean to pause
 * (race tests) or to throw an {@link Error} that simulates a process crash right after the leaf is signed.
 */
public interface EnrollmentHooks {

    EnrollmentHooks NONE = new EnrollmentHooks() {
    };

    /** Called after KMS has signed the leaf and before the activation transaction. */
    default void afterLeafSigned(String deviceId) {
    }
}
