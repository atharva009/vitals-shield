package com.vitalsshield.server.admin;

import com.vitalsshield.server.kms.KmsKeyAdmin;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

/**
 * KMS key health (DECISIONS #49): DescribeKey on every ACTIVE key, once at boot after reconciliation and every 30 s on
 * boundedElastic. It reports and alarms; it never rebuilds at runtime (a rebuild revokes every device, so it only
 * happens on a deliberate restart). A network or auth error is UNKNOWN, not "missing".
 */
@Component
public class KmsHealthMonitor implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(KmsHealthMonitor.class);
    static final Duration INTERVAL = Duration.ofSeconds(30);
    static final String ALARM = "KMS keys missing or disabled: restart the server to rebuild the hierarchy "
            + "(this revokes every device)";

    public enum State { HEALTHY, UNHEALTHY, UNKNOWN }

    /** One key's last check. {@code enabled} is null when the check itself failed (state UNKNOWN). */
    public record KeyHealth(String purpose, String arnSuffix, Boolean enabled, Instant checkedAt, String error) {
    }

    public record Snapshot(State state, List<KeyHealth> keys, Instant checkedAt) {
        public boolean healthy() {
            return state == State.HEALTHY;
        }
    }

    private final ActiveKeySource keys;
    private final KmsKeyAdmin keyAdmin;
    private final Clock clock;
    private volatile Snapshot current = new Snapshot(State.UNKNOWN, List.of(), null);
    private volatile Disposable ticker;

    @Autowired
    public KmsHealthMonitor(JdbcActiveKeySource keys, KmsKeyAdmin keyAdmin, Clock clock) {
        this((ActiveKeySource) keys, keyAdmin, clock);
    }

    public KmsHealthMonitor(ActiveKeySource keys, KmsKeyAdmin keyAdmin, Clock clock) {
        this.keys = keys;
        this.keyAdmin = keyAdmin;
        this.clock = clock;
    }

    public Snapshot current() {
        return current;
    }

    /** Blocking check (boot thread or boundedElastic). */
    public synchronized Snapshot checkNow() {
        Instant now = clock.instant();
        List<KeyHealth> results = new ArrayList<>();
        boolean unknown = false;
        boolean allEnabled = true;
        List<ActiveKeySource.ActiveKey> active;
        try {
            active = keys.load();
        } catch (RuntimeException e) {
            return transition(new Snapshot(State.UNKNOWN, List.of(), now), e.getClass().getSimpleName());
        }
        for (ActiveKeySource.ActiveKey k : active) {
            String suffix = k.arn().length() > 12 ? k.arn().substring(k.arn().length() - 12) : k.arn();
            try {
                boolean enabled = keyAdmin.describeEnabled(k.arn());
                allEnabled &= enabled;
                results.add(new KeyHealth(k.purpose(), suffix, enabled, now, null));
            } catch (RuntimeException e) {
                unknown = true;
                results.add(new KeyHealth(k.purpose(), suffix, null, now, e.getClass().getSimpleName()));
            }
        }
        State state = unknown ? State.UNKNOWN
                : (allEnabled && active.size() == 4) ? State.HEALTHY : State.UNHEALTHY;
        return transition(new Snapshot(state, List.copyOf(results), now), null);
    }

    public synchronized void start() {
        if (ticker == null || ticker.isDisposed()) {
            ticker = Flux.interval(INTERVAL, INTERVAL, Schedulers.boundedElastic())
                    .subscribe(t -> checkNow(), e -> log.warn("KMS health ticker stopped: {}", e.toString()));
        }
    }

    @Override
    public void destroy() {
        Disposable t = ticker;
        if (t != null) {
            t.dispose();
        }
    }

    private Snapshot transition(Snapshot next, String error) {
        Snapshot prev = current;
        current = next;
        if (prev.state() != State.UNHEALTHY && next.state() == State.UNHEALTHY) {
            log.error(ALARM);
        } else if (next.state() == State.UNKNOWN && prev.state() != State.UNKNOWN) {
            log.warn("KMS health UNKNOWN: {}", error != null ? error : next.keys().stream()
                    .filter(k -> k.error() != null).map(KeyHealth::error).findFirst().orElse("?"));
        } else if (prev.state() != State.HEALTHY && next.state() == State.HEALTHY && prev.checkedAt() != null) {
            log.info("KMS health recovered: all ACTIVE keys enabled");
        }
        return next;
    }
}
