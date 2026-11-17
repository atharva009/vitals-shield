package com.vitalsshield.server.renewal;

import com.vitalsshield.server.gateway.ResolvedCert;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Protocol B on the mTLS port (PortEnforcementWebFilter). CertStatusResolver runs first, so both endpoints only see a
 * certificate that passed the handshake and the per-request status check.
 * <ul>
 *   <li>GET /api/v1/devices/renew-challenge: a stateless HMAC challenge for this connection's certificate. No DB
 *       write.</li>
 *   <li>POST /api/v1/devices/renew: {@link RenewalService}.</li>
 * </ul>
 */
@RestController
public class RenewalController {

    private final RenewalChallenge challenges;
    private final RenewalService service;

    public RenewalController(RenewalChallenge challenges, RenewalService service) {
        this.challenges = challenges;
        this.service = service;
    }

    @GetMapping("/api/v1/devices/renew-challenge")
    public ResponseEntity<Map<String, Object>> challenge(ServerWebExchange exchange) {
        ResolvedCert cert = exchange.getAttribute(ResolvedCert.ATTRIBUTE);
        if (cert == null) {
            return ResponseEntity.status(403).body(Map.of("error", "CERT_NOT_ACCEPTED"));
        }
        RenewalChallenge.Challenge c = challenges.issue(cert.issuerKeyHash(), cert.serial());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("issued_at_ms", c.issuedAtMs());
        body.put("random_nonce_b64", Base64.getEncoder().encodeToString(c.nonce()));
        body.put("hmac_tag_b64", Base64.getEncoder().encodeToString(c.tag()));
        return ResponseEntity.ok(body);
    }

    @PostMapping("/api/v1/devices/renew")
    public Mono<ResponseEntity<Map<String, Object>>> renew(
            @RequestBody(required = false) Mono<Map<String, Object>> body, ServerWebExchange exchange) {
        ResolvedCert cert = exchange.getAttribute(ResolvedCert.ATTRIBUTE);
        SslInfo ssl = exchange.getRequest().getSslInfo();
        X509Certificate[] peer = ssl == null ? null : ssl.getPeerCertificates();
        if (cert == null || peer == null || peer.length == 0) {
            return Mono.just(ResponseEntity.status(403).body(Map.of("error", "CERT_NOT_ACCEPTED")));
        }
        return body
                .map(RenewRequest::parse)
                .flatMap(req -> service.renew(req, peer[0], cert))
                .map(RenewalController::toResponse)
                .switchIfEmpty(Mono.fromSupplier(RenewalController::validationFailed))
                .onErrorResume(e -> e instanceof RenewRequest.Invalid
                                || e instanceof org.springframework.web.server.ServerWebInputException
                                || e instanceof org.springframework.core.io.buffer.DataBufferLimitException,
                        e -> Mono.just(validationFailed()));
    }

    private static ResponseEntity<Map<String, Object>> validationFailed() {
        return ResponseEntity.badRequest().body(Map.of("error", "VALIDATION_FAILED"));
    }

    private static ResponseEntity<Map<String, Object>> toResponse(RenewalResult r) {
        ResponseEntity.BodyBuilder b = ResponseEntity.status(r.status());
        if (r.retryAfterSeconds() != null) {
            b.header(HttpHeaders.RETRY_AFTER, String.valueOf(r.retryAfterSeconds()));
        }
        return b.body(r.body());
    }
}
