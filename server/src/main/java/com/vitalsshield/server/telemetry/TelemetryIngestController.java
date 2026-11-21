package com.vitalsshield.server.telemetry;

import com.vitalsshield.server.gateway.ResolvedCert;
import java.security.cert.X509Certificate;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** POST /api/v1/telemetry/ingest on the mTLS port. Body: the compact JWS (Content-Type application/jose). */
@RestController
public class TelemetryIngestController {

    private final TelemetryIngestService service;

    public TelemetryIngestController(TelemetryIngestService service) {
        this.service = service;
    }

    @PostMapping(value = "/api/v1/telemetry/ingest")
    public Mono<ResponseEntity<Map<String, Object>>> ingest(@RequestBody(required = false) String body,
                                                            ServerWebExchange exchange) {
        ResolvedCert cert = exchange.getAttribute(ResolvedCert.ATTRIBUTE);
        SslInfo ssl = exchange.getRequest().getSslInfo();
        X509Certificate[] peer = ssl == null ? null : ssl.getPeerCertificates();
        if (cert == null || peer == null || peer.length == 0) {
            return Mono.just(ResponseEntity.status(403).body(Map.of("error", "CERT_NOT_ACCEPTED")));
        }
        if (body == null || body.isBlank()) {
            return Mono.just(ResponseEntity.status(401).body(Map.of("error", "JWS_INVALID", "reason", "MALFORMED")));
        }
        return service.ingest(body.trim(), peer[0], cert)
                .map(o -> {
                    ResponseEntity.BodyBuilder b = ResponseEntity.status(o.status());
                    if (o.retryAfterSeconds() != null) {
                        b.header(org.springframework.http.HttpHeaders.RETRY_AFTER,
                                String.valueOf(o.retryAfterSeconds()));
                    }
                    return b.body(o.body());
                });
    }
}
