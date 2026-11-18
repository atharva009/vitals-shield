package com.vitalsshield.server.reenroll;

import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Protocol C on the public port (PortEnforcementWebFilter); no client certificate, because the device has none that
 * works any more.
 * <ul>
 *   <li>GET /api/v1/devices/challenge?device_id=: stateless HMAC challenge (DECISIONS #90). Rate-limited per remote
 *       address and globally (429 with Retry-After). No DB access at all, so it does not reveal whether the device
 *       exists.</li>
 *   <li>POST /api/v1/devices/re-enroll: {@link ReEnrollService}.</li>
 * </ul>
 */
@RestController
public class ReEnrollController {

    private final ReEnrollChallenge challenges;
    private final RateLimiter limiter;
    private final ReEnrollService service;

    public ReEnrollController(ReEnrollChallenge challenges, RateLimiter limiter, ReEnrollService service) {
        this.challenges = challenges;
        this.limiter = limiter;
        this.service = service;
    }

    @GetMapping("/api/v1/devices/challenge")
    public ResponseEntity<Map<String, Object>> challenge(
            @RequestParam(name = "device_id", required = false) String deviceId, ServerWebExchange exchange) {
        InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
        RateLimiter.Decision d = limiter.tryAcquire(remote == null || remote.getAddress() == null ? null
                : remote.getAddress().getHostAddress());
        if (!d.allowed()) {
            return ResponseEntity.status(429).header(HttpHeaders.RETRY_AFTER, String.valueOf(d.retryAfterSeconds()))
                    .body(Map.of("error", "RATE_LIMITED"));
        }
        if (deviceId == null || !ReEnrollRequest.DEVICE_ID.matcher(deviceId).matches()) {
            return ResponseEntity.badRequest().body(Map.of("error", "VALIDATION_FAILED"));
        }
        ReEnrollChallenge.Challenge c = challenges.issue(deviceId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("issued_at_ms", c.issuedAtMs());
        body.put("random_nonce_b64", Base64.getEncoder().encodeToString(c.nonce()));
        body.put("hmac_tag_b64", Base64.getEncoder().encodeToString(c.tag()));
        return ResponseEntity.ok(body);
    }

    @PostMapping("/api/v1/devices/re-enroll")
    public Mono<ResponseEntity<Map<String, Object>>> reEnroll(
            @RequestBody(required = false) Mono<Map<String, Object>> body) {
        return body
                .map(ReEnrollRequest::parse)
                .flatMap(service::reEnroll)
                .map(ReEnrollController::toResponse)
                .switchIfEmpty(Mono.fromSupplier(ReEnrollController::validationFailed))
                .onErrorResume(e -> e instanceof ReEnrollRequest.Invalid
                                || e instanceof org.springframework.web.server.ServerWebInputException
                                || e instanceof org.springframework.core.io.buffer.DataBufferLimitException,
                        e -> Mono.just(validationFailed()));
    }

    private static ResponseEntity<Map<String, Object>> validationFailed() {
        return ResponseEntity.badRequest().body(Map.of("error", "VALIDATION_FAILED"));
    }

    private static ResponseEntity<Map<String, Object>> toResponse(ReEnrollResult r) {
        ResponseEntity.BodyBuilder b = ResponseEntity.status(r.status());
        if (r.retryAfterSeconds() != null) {
            b.header(HttpHeaders.RETRY_AFTER, String.valueOf(r.retryAfterSeconds()));
        }
        return b.body(r.body());
    }
}
