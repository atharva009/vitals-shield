package com.vitalsshield.server.renewal;

import java.util.LinkedHashMap;
import java.util.Map;

/** HTTP status, JSON body and optional Retry-After of one renewal request. */
public record RenewalResult(int status, Map<String, Object> body, Integer retryAfterSeconds) {

    static RenewalResult error(int status, String code) {
        return new RenewalResult(status, Map.of("error", code), null);
    }

    static RenewalResult unavailable(int retryAfterSeconds) {
        return new RenewalResult(503, Map.of("error", "TEMPORARILY_UNAVAILABLE"), retryAfterSeconds);
    }

    static RenewalResult ok(String certPem, String assignmentId, String assignmentActiveFrom) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("new_cert_pem", certPem);
        body.put("current_assignment_id", assignmentId);
        body.put("assignment_active_from", assignmentActiveFrom);
        return new RenewalResult(200, body, null);
    }
}
