package com.vitalsshield.server.gateway;

import com.vitalsshield.server.boot.BootStatusTracker;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Admin port: completed boot steps with timestamps. No secrets. */
@RestController
public class AdminBootStatusController {

    private final BootStatusTracker tracker;

    public AdminBootStatusController(BootStatusTracker tracker) {
        this.tracker = tracker;
    }

    @GetMapping("/api/v1/admin/boot-status")
    public Map<String, Object> bootStatus() {
        List<Map<String, String>> steps = tracker.completed().stream()
                .map(s -> Map.of("step", s.step().name(), "completed_at", s.completedAt().toString()))
                .toList();
        return Map.of("steps", steps);
    }
}
