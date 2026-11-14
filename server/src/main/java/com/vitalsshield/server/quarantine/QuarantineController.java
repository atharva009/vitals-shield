package com.vitalsshield.server.quarantine;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/** POST /api/v1/admin/devices/{deviceId}/quarantine (admin port; bearer checked by AdminAuthWebFilter). */
@RestController
public class QuarantineController {

    private final QuarantineService service;

    public QuarantineController(QuarantineService service) {
        this.service = service;
    }

    @PostMapping("/api/v1/admin/devices/{deviceId}/quarantine")
    public Mono<ResponseEntity<Map<String, Object>>> quarantine(@PathVariable String deviceId,
                                                                @RequestBody(required = false) Mono<Map<String, Object>> body) {
        return body.defaultIfEmpty(Map.of())
                .onErrorReturn(Map.of())
                .flatMap(json -> {
                    Object lookback = json.get("lookback_minutes");
                    Object reason = json.get("reason");
                    if (!(lookback instanceof Integer minutes) || minutes < 1 || minutes > 1440
                            || !(reason instanceof String r) || r.isBlank() || r.length() > 128
                            || !deviceId.matches("[A-Za-z0-9_.-]{1,64}")) {
                        return Mono.just(ResponseEntity.badRequest()
                                .body(Map.<String, Object>of("error", "VALIDATION_FAILED")));
                    }
                    return service.quarantine(deviceId, minutes, r)
                            .map(res -> ResponseEntity.ok(res.toJson()))
                            .onErrorResume(QuarantineService.StateConflict.class, e -> Mono.just(
                                    ResponseEntity.status("DEVICE_NOT_FOUND".equals(e.code()) ? 404 : 409)
                                            .body(Map.<String, Object>of("error", e.code()))));
                });
    }
}
