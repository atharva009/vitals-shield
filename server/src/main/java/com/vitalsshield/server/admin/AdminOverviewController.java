package com.vitalsshield.server.admin;

import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/** Read-only admin API for the dashboard (bearer enforced by AdminAuthWebFilter). */
@RestController
public class AdminOverviewController {

    private final AdminOverviewService service;

    public AdminOverviewController(AdminOverviewService service) {
        this.service = service;
    }

    @GetMapping("/api/v1/admin/overview")
    public Mono<Map<String, Object>> overview() {
        return Mono.fromCallable(service::snapshot).subscribeOn(Schedulers.boundedElastic());
    }

    @GetMapping("/api/v1/admin/devices/{deviceId}/telemetry")
    public Mono<List<Map<String, Object>>> telemetry(@PathVariable String deviceId,
                                                     @RequestParam(defaultValue = "30") int limit) {
        int capped = Math.max(1, Math.min(limit, 200));
        return Mono.fromCallable(() -> service.telemetry(deviceId, capped)).subscribeOn(Schedulers.boundedElastic());
    }
}
