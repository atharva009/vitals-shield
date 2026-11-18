package com.vitalsshield.server.reenroll;

import java.util.LinkedHashMap;
import java.util.Map;

/** HTTP status, JSON body and optional Retry-After of one Protocol C request. */
public record ReEnrollResult(int status, Map<String, Object> body, Integer retryAfterSeconds) {

    static ReEnrollResult error(int status, String code) {
        return new ReEnrollResult(status, Map.of("error", code), null);
    }

    static ReEnrollResult unavailable(int retryAfterSeconds) {
        return new ReEnrollResult(503, Map.of("error", "TEMPORARILY_UNAVAILABLE"), retryAfterSeconds);
    }

    static ReEnrollResult ok(String certPem, long assignedEpoch, String assignmentId, String assignmentActiveFrom) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("new_cert_pem", certPem);
        body.put("assigned_boot_epoch", assignedEpoch);
        body.put("current_assignment_id", assignmentId);
        body.put("assignment_active_from", assignmentActiveFrom);
        return new ReEnrollResult(200, body, null);
    }
}
