package com.vitalsshield.server.gateway;

import com.vitalsshield.server.admin.KmsHealthMonitor;
import com.vitalsshield.server.boot.BootStatusTracker;
import com.vitalsshield.server.clock.ClockSkewMonitor;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin port, no session needed: completed boot steps with timestamps, plus what scripts/stage/00-prestage.sh checks
 * before a demo (Phase 10a): the active Spring profiles (DECISIONS 99), the KMS health state, and the clock skew
 * (DECISIONS 98). No secrets: no key ARNs, no codes, no device data.
 */
@RestController
public class AdminBootStatusController {

    private final BootStatusTracker tracker;
    private final KmsHealthMonitor kms;
    private final ClockSkewMonitor clock;
    private final Environment env;

    public AdminBootStatusController(BootStatusTracker tracker, KmsHealthMonitor kms, ClockSkewMonitor clock,
                                     Environment env) {
        this.tracker = tracker;
        this.kms = kms;
        this.clock = clock;
        this.env = env;
    }

    @GetMapping("/api/v1/admin/boot-status")
    public Map<String, Object> bootStatus() {
        List<Map<String, String>> steps = tracker.completed().stream()
                .map(s -> Map.of("step", s.step().name(), "completed_at", s.completedAt().toString()))
                .toList();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("steps", steps);
        out.put("active_profiles", List.of(env.getActiveProfiles()));
        out.put("kms_state", kms.current().state().name());
        ClockSkewMonitor.Snapshot skew = clock.snapshot();
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("skew_ms", skew.skewMs());
        c.put("state", skew.state().name());
        out.put("clock", c);
        return out;
    }
}
