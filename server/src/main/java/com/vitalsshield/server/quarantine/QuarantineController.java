package com.vitalsshield.server.quarantine;

import com.vitalsshield.server.admin.AdminProperties;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Single-step POST /api/v1/admin/devices/{deviceId}/quarantine. Bearer mode only (Phase 4/5 behavior); in webauthn
 * mode it is 404 and quarantine goes through the step-up begin/finish pair (DECISIONS #58).
 */
@RestController
public class QuarantineController {

    /** Validated quarantine parameters (Phase 4 rules). */
    public record Params(String deviceId, int lookbackMinutes, String reason) {
    }

    private final QuarantineService service;
    private final AdminProperties admin;

    public QuarantineController(QuarantineService service, AdminProperties admin) {
        this.service = service;
        this.admin = admin;
    }

    /** The Phase 4 validation: lookback 1..1440, reason 1..128 characters, device id pattern. */
    public static Optional<Params> validate(String deviceId, Map<String, Object> json) {
        Object lookback = json.get("lookback_minutes");
        Object reason = json.get("reason");
        if (!(lookback instanceof Integer minutes) || minutes < 1 || minutes > 1440
                || !(reason instanceof String r) || r.isBlank() || r.length() > 128
                || deviceId == null || !deviceId.matches("[A-Za-z0-9_.-]{1,64}")) {
            return Optional.empty();
        }
        return Optional.of(new Params(deviceId, minutes, r));
    }

    @PostMapping("/api/v1/admin/devices/{deviceId}/quarantine")
    public Mono<ResponseEntity<Map<String, Object>>> quarantine(@PathVariable String deviceId,
                                                                @RequestBody(required = false) Mono<Map<String, Object>> body) {
        if (admin.webauthn()) {
            return Mono.just(ResponseEntity.notFound().build());
        }
        return body.defaultIfEmpty(Map.of())
                .onErrorReturn(Map.of())
                .flatMap(json -> validate(deviceId, json)
                        .map(p -> service.quarantine(p.deviceId(), p.lookbackMinutes(), p.reason())
                                .map(res -> ResponseEntity.ok(res.toJson()))
                                .onErrorResume(QuarantineService.StateConflict.class, e -> Mono.just(conflict(e))))
                        .orElseGet(() -> Mono.just(ResponseEntity.badRequest()
                                .body(Map.<String, Object>of("error", "VALIDATION_FAILED")))));
    }

    public static ResponseEntity<Map<String, Object>> conflict(QuarantineService.StateConflict e) {
        return ResponseEntity.status("DEVICE_NOT_FOUND".equals(e.code()) ? 404 : 409)
                .body(Map.<String, Object>of("error", e.code()));
    }
}
