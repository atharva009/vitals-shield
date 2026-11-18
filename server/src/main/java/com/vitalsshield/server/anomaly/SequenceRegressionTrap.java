package com.vitalsshield.server.anomaly;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * DECISIONS #93: two holders of the same OLK and device state send the same sequence numbers with different batch
 * ids, so one of them keeps getting DUPLICATE_SEQUENCE_REPLAY (or SEQUENCE_TOO_OLD, or BOOT_EPOCH_MISMATCH once
 * epochs diverge). A genuine device never does: its sequence number is persisted before every send. Fed by the ingest
 * conflict classifier only after the idempotent-retry check, so a retried frame (same batch id, same payload) never
 * reaches it.
 *
 * <p>A sliding window per device, in memory, on the JVM clock. When {@code threshold} distinct batch ids fall within
 * {@code window}, the trap fires once and the window is cleared.
 */
@Component
public class SequenceRegressionTrap {

    /** Rejection codes that count (DECISIONS #93). */
    public static final Set<String> CODES = Set.of("DUPLICATE_SEQUENCE_REPLAY", "SEQUENCE_TOO_OLD",
            "BOOT_EPOCH_MISMATCH");
    public static final String CONDITION_CODE = "SEQUENCE_REGRESSION";

    public record Hit(Instant at, UUID batchId, String code, long sequenceNumber) {
    }

    /** What the trap saw when it fired. */
    public record Fired(String deviceId, Set<UUID> batchIds, Map<String, Long> codes, Duration span) {
    }

    private final AnomalyProperties.SequenceRegression props;
    private final Clock clock;
    private final Consumer<Fired> sink;
    private final Map<String, Deque<Hit>> windows = new ConcurrentHashMap<>();

    @Autowired
    public SequenceRegressionTrap(AnomalyProperties props, Clock clock, AnomalyService anomalies) {
        this(props.sequenceRegression(), clock, f -> anomalies.raiseAsync(f.deviceId(), CONDITION_CODE,
                explanation(f), detail(f)).subscribe());
    }

    public SequenceRegressionTrap(AnomalyProperties.SequenceRegression props, Clock clock, Consumer<Fired> sink) {
        this.props = props;
        this.clock = clock;
        this.sink = sink;
    }

    /** One counted rejection. Returns true if this call fired the trap. */
    public boolean record(String deviceId, UUID batchId, String code, long sequenceNumber) {
        if (!props.enabled() || !CODES.contains(code)) {
            return false;
        }
        Instant now = clock.instant();
        Fired fired = null;
        Deque<Hit> w = windows.computeIfAbsent(deviceId, d -> new ArrayDeque<>());
        synchronized (w) {
            Instant cutoff = now.minus(props.window());
            while (!w.isEmpty() && w.peekFirst().at().isBefore(cutoff)) {
                w.pollFirst();
            }
            w.addLast(new Hit(now, batchId, code, sequenceNumber));
            Set<UUID> distinct = new LinkedHashSet<>();
            Map<String, Long> codes = new LinkedHashMap<>();
            for (Hit h : w) {
                distinct.add(h.batchId());
                codes.merge(h.code(), 1L, Long::sum);
            }
            if (distinct.size() >= props.threshold()) {
                fired = new Fired(deviceId, distinct, codes, Duration.between(w.peekFirst().at(), now));
                w.clear();
            }
        }
        if (fired != null) {
            sink.accept(fired);
            return true;
        }
        return false;
    }

    static String explanation(Fired f) {
        String codes = String.join(", ", f.codes().entrySet().stream()
                .map(e -> e.getValue() + " " + e.getKey()).toList());
        return f.batchIds().size() + " batches with distinct batch ids were rejected as replayed or out of window ("
                + codes + ") within " + f.span().toMillis() / 1000.0 + " s: two senders share this device's "
                + "certificate and sequence numbers.";
    }

    static Map<String, Object> detail(Fired f) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("rejections", f.batchIds().size());
        d.put("codes", f.codes().toString());
        d.put("span_ms", f.span().toMillis());
        d.put("batch_ids", String.join(",", f.batchIds().stream().map(UUID::toString).toList()));
        return d;
    }
}
