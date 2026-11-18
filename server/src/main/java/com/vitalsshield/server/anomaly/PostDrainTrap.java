package com.vitalsshield.server.anomaly;

import com.vitalsshield.server.boot.BootStep;
import com.vitalsshield.server.boot.BootStepCompleted;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.SupersededUseRecorder;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * DECISIONS #94: a RENEWED certificate presented more than {@code slack} after its grace_expires_at, while the device
 * has an ACTIVE certificate, means someone still holds the old key after the real device moved on.
 *
 * <p>The TLS trust manager (on a Netty event loop) and CertStatusResolver only call {@link #recordSupersededUse}: one
 * lock-free queue offer, bounded, never blocking. A consumer drains the queue on boundedElastic every
 * {@code drainInterval}, checks the rule against the database row, and raises the anomaly at most once per
 * certificate.
 */
@Component
public class PostDrainTrap implements SupersededUseRecorder {

    private static final Logger log = LoggerFactory.getLogger(PostDrainTrap.class);
    public static final String CONDITION_CODE = "POST_DRAIN_USE";

    record Event(CertKey key, Instant at) {
    }

    private final AnomalyProperties.PostDrain props;
    private final JdbcTemplate jdbc;
    private final AnomalyService anomalies;
    private final ConcurrentLinkedQueue<Event> queue = new ConcurrentLinkedQueue<>();
    private final AtomicInteger size = new AtomicInteger();
    private final Set<CertKey> fired = ConcurrentHashMap.newKeySet();
    private volatile Disposable consumer;

    public PostDrainTrap(AnomalyProperties props, JdbcTemplate jdbc, AnomalyService anomalies) {
        this.props = props.postDrain();
        this.jdbc = jdbc;
        this.anomalies = anomalies;
    }

    /**
     * The rule (unit-tested): fires only if the certificate had a grace end, it was presented more than {@code slack}
     * after it, and the device has an ACTIVE successor.
     */
    public static boolean shouldFire(Instant graceExpiresAt, Instant presentedAt, Duration slack,
                                     boolean successorActive) {
        return graceExpiresAt != null && presentedAt.isAfter(graceExpiresAt.plus(slack)) && successorActive;
    }

    @Override
    public void recordSupersededUse(CertKey key, Instant presentedAt) {
        if (!props.enabled() || fired.contains(key)) {
            return;
        }
        if (size.incrementAndGet() > props.queueCapacity()) {
            size.decrementAndGet(); // full: drop; a clone keeps presenting the key, so a later event gets through
            return;
        }
        queue.offer(new Event(key, presentedAt));
    }

    @EventListener
    public void onBoot(BootStepCompleted e) {
        if (e.step() == BootStep.LISTENERS_BOUND) {
            start();
        }
    }

    synchronized void start() {
        if (consumer != null && !consumer.isDisposed()) {
            return;
        }
        consumer = Flux.interval(props.drainInterval(), props.drainInterval())
                .onBackpressureDrop()
                .concatMap(t -> Mono.fromRunnable(this::drain).subscribeOn(Schedulers.boundedElastic())
                        .onErrorResume(err -> {
                            log.warn("Post-drain trap drain failed: {}", err.toString());
                            return Mono.empty();
                        }))
                .subscribe();
    }

    /** Blocking. Checks every queued event; returns how many fired. */
    int drain() {
        Map<CertKey, Instant> latest = new LinkedHashMap<>();
        for (Event e; (e = queue.poll()) != null; ) {
            size.decrementAndGet();
            latest.merge(e.key(), e.at(), (a, b) -> a.isAfter(b) ? a : b);
        }
        int n = 0;
        for (Map.Entry<CertKey, Instant> e : latest.entrySet()) {
            if (!fired.contains(e.getKey()) && check(e.getKey(), e.getValue())) {
                n++;
            }
        }
        return n;
    }

    private boolean check(CertKey key, Instant presentedAt) {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT c.device_id, c.status::text AS status, c.grace_expires_at,
                       EXISTS (SELECT 1 FROM certificates s WHERE s.device_id = c.device_id AND s.status = 'ACTIVE'
                                                            AND s.serial_number <> c.serial_number) AS successor_active
                  FROM certificates c
                 WHERE c.issuer_key_hash = ? AND c.serial_number = ?
                """, key.issuerKeyHash(), key.serial());
        if (rows.isEmpty() || !"RENEWED".equals(rows.get(0).get("status"))) {
            return false;
        }
        Map<String, Object> r = rows.get(0);
        Timestamp graceTs = (Timestamp) r.get("grace_expires_at");
        Instant grace = graceTs == null ? null : graceTs.toInstant(); // JVM-written, compared with JVM times (#89)
        if (!shouldFire(grace, presentedAt, props.slack(), Boolean.TRUE.equals(r.get("successor_active")))) {
            return false;
        }
        if (!fired.add(key)) {
            return false;
        }
        String deviceId = (String) r.get("device_id");
        long lateMs = Duration.between(grace, presentedAt).toMillis();
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("serial", key.serial());
        detail.put("grace_expires_at", grace.toString());
        detail.put("presented_at", presentedAt.toString());
        detail.put("ms_after_grace", lateMs);
        anomalies.raise(deviceId, CONDITION_CODE, "Superseded certificate " + key.serial().toUpperCase()
                + " was presented " + lateMs / 1000.0 + " s after its grace ended while its successor is ACTIVE: a"
                + " copy of the old key is still in use.", detail);
        return true;
    }

    /** Events waiting (tests). */
    int queued() {
        return size.get();
    }

    @jakarta.annotation.PreDestroy
    void shutdown() {
        Disposable c = consumer;
        if (c != null) {
            c.dispose();
        }
    }
}
