package com.vitalsshield.server.quarantine;

/** Test seam: runs inside the quarantine transaction after the sanitize CTE and the audit entry, before commit. */
public interface QuarantineHooks {

    QuarantineHooks NONE = deviceId -> { };

    void beforeCommit(String deviceId);
}
