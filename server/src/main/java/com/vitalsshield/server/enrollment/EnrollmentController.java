package com.vitalsshield.server.enrollment;

import com.vitalsshield.server.enrollment.EnrollmentRequestValidator.ValidationException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/** POST /api/v1/devices/enroll, public port only (PortEnforcementWebFilter). */
@RestController
public class EnrollmentController {

    private final EnrollmentService service;
    private final AtomicLong requests = new AtomicLong();

    public EnrollmentController(EnrollmentService service) {
        this.service = service;
    }

    @PostMapping("/api/v1/devices/enroll")
    public Mono<ResponseEntity<Map<String, Object>>> enroll(@RequestBody(required = false) Mono<Map<String, Object>> body) {
        requests.incrementAndGet();
        return body
                .map(EnrollmentRequestValidator::validate)
                .flatMap(service::enroll)
                .map(EnrollmentController::toResponse)
                .switchIfEmpty(Mono.fromSupplier(() -> validationFailed()))
                // Undecodable JSON, oversized body, or a failed shape check: 400, token untouched.
                .onErrorResume(e -> e instanceof ValidationException
                                || e instanceof org.springframework.web.server.ServerWebInputException
                                || e instanceof org.springframework.core.io.buffer.DataBufferLimitException,
                        e -> Mono.just(validationFailed()));
    }

    /** Number of enroll requests received (tests check the simulator does not re-enroll). */
    public long requestCount() {
        return requests.get();
    }

    private static ResponseEntity<Map<String, Object>> validationFailed() {
        return ResponseEntity.badRequest().body(Map.of("error", "VALIDATION_FAILED"));
    }

    private static ResponseEntity<Map<String, Object>> toResponse(EnrollmentResult r) {
        ResponseEntity.BodyBuilder b = ResponseEntity.status(r.status());
        if (r.retryAfterSeconds() != null) {
            b.header(HttpHeaders.RETRY_AFTER, String.valueOf(r.retryAfterSeconds()));
        }
        return b.body(r.body());
    }
}
