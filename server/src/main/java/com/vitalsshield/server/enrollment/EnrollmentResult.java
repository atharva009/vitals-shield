package com.vitalsshield.server.enrollment;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.vitalsshield.server.pki.trust.CertKey;

/** What the enrollment flow produced: an HTTP status and JSON body, plus after-commit work for a success. */
public record EnrollmentResult(int status, Map<String, Object> body, Integer retryAfterSeconds,
                               List<CertKey> supersededCerts) {

    static EnrollmentResult error(int status, String error) {
        return new EnrollmentResult(status, Map.of("error", error), null, List.of());
    }

    static EnrollmentResult unavailable(int retryAfterSeconds) {
        return new EnrollmentResult(503, Map.of("error", "TEMPORARILY_UNAVAILABLE"), retryAfterSeconds, List.of());
    }

    static EnrollmentResult created(String certPem, long bootEpoch, String assignmentId, String activeFrom,
                                    List<CertKey> superseded) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("new_cert_pem", certPem);
        body.put("assigned_boot_epoch", bootEpoch);
        body.put("current_assignment_id", assignmentId);
        body.put("assignment_active_from", activeFrom);
        return new EnrollmentResult(201, body, null, List.copyOf(superseded));
    }
}
