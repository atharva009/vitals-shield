package com.vitalsshield.server.clinical;

import java.util.UUID;

/**
 * Test seam: called on the evaluation thread before the evaluation transaction opens (so it holds no lock). An
 * integration test uses it to hold evaluations queued while a quarantine commits.
 */
@FunctionalInterface
public interface ClinicalHooks {

    ClinicalHooks NONE = (deviceId, batchId) -> {
    };

    void beforeEvaluate(String deviceId, UUID batchId);
}
