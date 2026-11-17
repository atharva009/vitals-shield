package com.vitalsshield.server.clinical;

import java.util.UUID;

/**
 * Test seams. {@link #beforeEvaluate} runs on the evaluation thread before the evaluation transaction opens (so it
 * holds no lock); an integration test uses it to hold evaluations queued while a quarantine commits.
 * {@link #afterAlertsInserted} runs inside the evaluation transaction right after its alert INSERTs, while the
 * device, telemetry, assignment and alert locks are still held (InFlightRetractionIT).
 */
@FunctionalInterface
public interface ClinicalHooks {

    ClinicalHooks NONE = (deviceId, batchId) -> {
    };

    void beforeEvaluate(String deviceId, UUID batchId);

    default void afterAlertsInserted(String deviceId, UUID batchId, java.util.List<UUID> alertIds) {
    }
}
