package com.vitalsshield.server.clock;

import com.vitalsshield.server.boot.BootStep;
import com.vitalsshield.server.boot.BootStepCompleted;
import java.time.Clock;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * DECISIONS #98: compares Postgres clock_timestamp() with the JVM clock, at boot (on RECONCILED, the first step that
 * has a database) and every 60 s on boundedElastic. The Phase 8 soak run showed why: the Docker VM that runs Postgres
 * stops its clock while the Mac sleeps and catches up later, so the two clocks can disagree by seconds.
 *
 * <p>skew_ms = Postgres time minus the midpoint of the JVM readings taken just before and just after the query, so
 * the round trip does not count as skew. Positive means Postgres is ahead.
 */
@Component
public class ClockSkewMonitor {

    private static final Logger log = LoggerFactory.getLogger(ClockSkewMonitor.class);

    public enum State { UNKNOWN, GREEN, AMBER, RED }

    /** The database side, injectable for unit tests. */
    @FunctionalInterface
    public interface DbClock {
        Instant now();
    }

    public record Snapshot(Long skewMs, Instant checkedAt, State state, String error) {
    }

    private final DbClock db;
    private final Clock jvm;
    private final ClockProperties props;
    private volatile Snapshot last = new Snapshot(null, null, State.UNKNOWN, null);
    private volatile Disposable ticker;

    @Autowired
    public ClockSkewMonitor(JdbcTemplate jdbc, Clock jvm, ClockProperties props) {
        this(() -> jdbc.queryForObject("SELECT clock_timestamp()", java.sql.Timestamp.class).toInstant(), jvm, props);
    }

    public ClockSkewMonitor(DbClock db, Clock jvm, ClockProperties props) {
        this.db = db;
        this.jvm = jvm;
        this.props = props;
    }

    /** GREEN at or below amber-ms (absolute), AMBER at or below red-ms, RED above. */
    public static State classify(long skewMs, ClockProperties props) {
        long abs = Math.abs(skewMs);
        if (abs <= props.amberMs()) {
            return State.GREEN;
        }
        return abs <= props.redMs() ? State.AMBER : State.RED;
    }

    /** Blocking: one measurement. Never throws; a failed query keeps state UNKNOWN with the error. */
    public Snapshot checkNow() {
        try {
            long before = jvm.millis();
            Instant dbNow = db.now();
            long after = jvm.millis();
            long skew = dbNow.toEpochMilli() - (before + after) / 2;
            State state = classify(skew, props);
            Snapshot s = new Snapshot(skew, Instant.ofEpochMilli(after), state, null);
            if (state != State.GREEN && (last.state() != state)) {
                log.warn("Clock skew {}: Postgres clock_timestamp() is {} ms {} the JVM clock (DECISIONS #98)",
                        state, Math.abs(skew), skew > 0 ? "ahead of" : "behind");
            } else if (state == State.GREEN && last.state() != State.GREEN && last.state() != State.UNKNOWN) {
                log.info("Clock skew back to GREEN ({} ms)", skew);
            }
            last = s;
            // One line per check (every 60 s), so a soak run can report min and max skew from the log.
            log.info("Clock skew check: {} ms ({})", skew, state);
            return s;
        } catch (RuntimeException e) {
            Snapshot s = new Snapshot(null, jvm.instant(), State.UNKNOWN, e.toString());
            last = s;
            return s;
        }
    }

    public Snapshot snapshot() {
        return last;
    }

    @EventListener
    public void onBoot(BootStepCompleted e) {
        if (e.step() == BootStep.RECONCILED) {
            Snapshot s = checkNow();
            log.info("Clock skew at boot: {} ms ({})", s.skewMs(), s.state());
            start();
        }
    }

    synchronized void start() {
        if (ticker != null && !ticker.isDisposed()) {
            return;
        }
        ticker = Flux.interval(props.checkInterval(), props.checkInterval())
                .onBackpressureDrop()
                .concatMap(t -> Mono.fromRunnable(this::checkNow).subscribeOn(Schedulers.boundedElastic()))
                .subscribe();
    }

    @jakarta.annotation.PreDestroy
    void shutdown() {
        Disposable t = ticker;
        if (t != null) {
            t.dispose();
        }
    }
}
