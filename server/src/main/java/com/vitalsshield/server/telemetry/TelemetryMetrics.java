package com.vitalsshield.server.telemetry;

import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/** In-memory ingest counters for the Phase 5 dashboard. */
@Component
public class TelemetryMetrics {

    private final Map<String, AtomicLong> counters = new ConcurrentHashMap<>();

    public void increment(String name) {
        counters.computeIfAbsent(name, k -> new AtomicLong()).incrementAndGet();
    }

    public long get(String name) {
        AtomicLong c = counters.get(name);
        return c == null ? 0 : c.get();
    }

    public Map<String, Long> snapshot() {
        Map<String, Long> out = new TreeMap<>();
        counters.forEach((k, v) -> out.put(k, v.get()));
        return out;
    }
}
