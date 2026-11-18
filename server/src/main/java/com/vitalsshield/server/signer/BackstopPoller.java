package com.vitalsshield.server.signer;

import com.vitalsshield.server.boot.BootStep;
import com.vitalsshield.server.boot.BootStepCompleted;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import com.vitalsshield.server.telemetry.TelemetryMetrics;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
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
 * Eviction backstop (spec Section 4 "Revocation Enforcement Path", DECISIONS #96). Every 3 s: certificates that
 * became REVOKED since (previous poll's Postgres now() - 30 s) are deny-listed and their live sockets closed.
 * Idempotent, so the in-process path and this poller can both act on the same revocation. It catches revocations made
 * outside the in-process path, such as direct SQL, or an event lost between deny-list and eviction.
 *
 * <p>Same-clock rule (DECISIONS #89): the window compares revoked_db_at, stamped by a Postgres trigger whenever a row
 * becomes REVOKED (V7), with Postgres now(). revoked_at itself is JVM-written (or anything, for direct SQL) and is not
 * compared with a Postgres time.
 */
@Component
public class BackstopPoller {

    private static final Logger log = LoggerFactory.getLogger(BackstopPoller.class);

    public record Poll(Instant dbNow, int revocationsSeen, int socketsClosed) {
    }

    record Row(CertKey key, Instant revokedAt) {
    }

    private final JdbcTemplate jdbc;
    private final CertificateDenyList denyList;
    private final ActiveSessionRegistry sessions;
    private final EvictionProperties eviction;
    private final BackstopProperties props;
    private final TelemetryMetrics metrics;
    private final Clock clock;
    private volatile Instant previousDbNow;
    private volatile Poll last;
    private volatile Disposable ticker;

    public BackstopPoller(JdbcTemplate jdbc, CertificateDenyList denyList, ActiveSessionRegistry sessions,
                          EvictionProperties eviction, BackstopProperties props, TelemetryMetrics metrics,
                          Clock clock) {
        this.jdbc = jdbc;
        this.denyList = denyList;
        this.sessions = sessions;
        this.eviction = eviction;
        this.props = props;
        this.metrics = metrics;
        this.clock = clock;
    }

    @EventListener
    public void onBoot(BootStepCompleted e) {
        if (e.step() == BootStep.LISTENERS_BOUND && props.enabled()) {
            start();
        }
    }

    synchronized void start() {
        if (ticker != null && !ticker.isDisposed()) {
            return;
        }
        ticker = Flux.interval(props.interval(), props.interval())
                .onBackpressureDrop()
                .concatMap(t -> Mono.fromCallable(this::poll).subscribeOn(Schedulers.boundedElastic())
                        .onErrorResume(err -> {
                            log.warn("Backstop poll failed: {}", err.toString());
                            return Mono.empty();
                        }))
                .subscribe();
    }

    /** Blocking: one poll. */
    public synchronized Poll poll() {
        Instant dbNow = jdbc.queryForObject("SELECT now()", Timestamp.class).toInstant();
        Instant from = (previousDbNow == null ? dbNow : previousDbNow).minus(props.lookback());
        List<Row> rows = jdbc.query("""
                SELECT issuer_key_hash, serial_number, revoked_at FROM certificates
                 WHERE status = 'REVOKED' AND revoked_db_at >= ?
                """, (rs, i) -> new Row(CertKey.of(rs.getString(1), rs.getString(2)),
                rs.getTimestamp(3) == null ? null : rs.getTimestamp(3).toInstant()), Timestamp.from(from));
        Instant jvmNow = clock.instant();
        int closed = 0;
        for (Row r : rows) {
            // deniedFrom is compared with the JVM clock: never later than JVM now, whatever revoked_at says.
            Instant deniedFrom = r.revokedAt() == null || r.revokedAt().isAfter(jvmNow) ? jvmNow : r.revokedAt();
            denyList.add(r.key(), deniedFrom, "REVOKED");
            if (eviction.enabled() && !sessions.liveSocketsFor(r.key()).isEmpty()) {
                Integer n = sessions.evictByCert(r.key()).block();
                closed += n == null ? 0 : n;
                log.warn("Backstop poller closed {} live socket(s) of revoked certificate {}", n, r.key().serial());
            }
        }
        if (closed > 0) {
            metrics.add("backstop.sockets_closed", closed);
        }
        previousDbNow = dbNow;
        Poll p = new Poll(dbNow, rows.size(), closed);
        last = p;
        return p;
    }

    public Poll lastPoll() {
        return last;
    }

    @jakarta.annotation.PreDestroy
    void shutdown() {
        Disposable t = ticker;
        if (t != null) {
            t.dispose();
        }
    }
}
