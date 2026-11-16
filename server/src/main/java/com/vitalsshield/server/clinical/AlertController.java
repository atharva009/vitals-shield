package com.vitalsshield.server.clinical;

import com.vitalsshield.server.admin.AdminProperties;
import com.vitalsshield.server.admin.webauthn.AdminSessionStore;
import com.vitalsshield.server.admin.webauthn.AdminSessionWebFilter;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * POST /api/v1/admin/alerts/{id}/acknowledge and /resolve (DECISIONS #76). AdminSessionWebFilter has already required
 * a passkey session and an allowed Origin. Bearer mode has no clinician identity to audit, so the routes are 404 there,
 * like the other session-only routes.
 */
@RestController
public class AlertController {

    private final AdminProperties admin;
    private final AlertService alerts;

    public AlertController(AdminProperties admin, AlertService alerts) {
        this.admin = admin;
        this.alerts = alerts;
    }

    @PostMapping("/api/v1/admin/alerts/{alertId}/acknowledge")
    public Mono<ResponseEntity<Map<String, Object>>> acknowledge(ServerWebExchange exchange,
                                                                 @PathVariable String alertId) {
        return act(exchange, alertId, AlertService.Action.ACKNOWLEDGE);
    }

    @PostMapping("/api/v1/admin/alerts/{alertId}/resolve")
    public Mono<ResponseEntity<Map<String, Object>>> resolve(ServerWebExchange exchange, @PathVariable String alertId) {
        return act(exchange, alertId, AlertService.Action.RESOLVE);
    }

    private Mono<ResponseEntity<Map<String, Object>>> act(ServerWebExchange exchange, String alertId,
                                                          AlertService.Action action) {
        AdminSessionStore.Session s = exchange.getAttribute(AdminSessionWebFilter.SESSION_ATTR);
        if (!admin.webauthn() || s == null) {
            return Mono.just(ResponseEntity.status(admin.webauthn() ? 401 : 404).body(Map.of("error", "NOT_AVAILABLE")));
        }
        UUID id;
        try {
            id = UUID.fromString(alertId);
        } catch (IllegalArgumentException e) {
            return Mono.just(ResponseEntity.status(400).body(Map.of("error", "VALIDATION_FAILED")));
        }
        return Mono.fromCallable(() -> alerts.apply(id, action, s.clinicianId()))
                .subscribeOn(Schedulers.boundedElastic())
                .map(r -> ResponseEntity.status(r.status()).body(r.body()));
    }
}
