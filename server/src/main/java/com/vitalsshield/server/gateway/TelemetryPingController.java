package com.vitalsshield.server.gateway;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

/** mTLS connectivity check: echoes the certificate CertStatusResolver accepted. */
@RestController
public class TelemetryPingController {

    @GetMapping("/api/v1/telemetry/ping")
    public ResponseEntity<Map<String, Object>> ping(ServerWebExchange exchange) {
        ResolvedCert cert = exchange.getAttribute(ResolvedCert.ATTRIBUTE);
        if (cert == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("serial", cert.serial());
        body.put("issuer_key_hash", cert.issuerKeyHash());
        body.put("device_id", cert.deviceId());
        body.put("status", cert.status());
        return ResponseEntity.ok(body);
    }
}
