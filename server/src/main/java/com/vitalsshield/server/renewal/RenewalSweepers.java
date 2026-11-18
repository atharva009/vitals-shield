package com.vitalsshield.server.renewal;

// LOCK ORDER (DECISIONS #82, extends #70): the expiry sweep runs one transaction per certificate and locks the
// devices row FOR UPDATE, then that certificates row FOR UPDATE (DECISIONS #87). The nonce sweep and the ledger sweep
// touch only their own tables.

import com.vitalsshield.server.admin.SerialDisplayFormat;
import com.vitalsshield.server.boot.BootStep;
import com.vitalsshield.server.boot.BootStepCompleted;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.pki.IssuedSerialLedger;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import com.vitalsshield.server.telemetry.TelemetryMetrics;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.Disposable;
import reactor.core.Disposables;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Periodic work for the certificate lifecycle, started once the listeners are bound:
 * <ul>
 *   <li>every 30 s, and once at boot inside DENY_LIST_SEEDED, ExpiredCertSweeper (DECISIONS #84, #87): ACTIVE,
 *       ISSUED_PENDING_USE and RENEWED certificates past not_after become EXPIRED, are deny-listed from not_after
 *       before commit, and lose their live sockets;</li>
 *   <li>every 30 s, the stale-reservation sweep (DECISIONS #38): RESERVED serials older than 2 minutes (a crash after
 *       KMS Sign) become VOIDED, are deny-listed before commit and are added to the next CRL;</li>
 *   <li>every 5 minutes, the nonce sweep: consumed_challenge_nonces rows past expires_at are deleted. A challenge is
 *       rejected after 60 s anyway, so a deleted nonce can never be replayed.</li>
 * </ul>
 * Each tick runs on the class's own one-thread scheduler; a failed tick is logged and the next one runs normally.
 */
@Component
public class RenewalSweepers {

    private static final Logger log = LoggerFactory.getLogger(RenewalSweepers.class);
    static final Duration EXPIRY_INTERVAL = Duration.ofSeconds(30);
    static final Duration NONCE_INTERVAL = Duration.ofMinutes(5);

    public record ExpiredCert(CertKey key, String deviceId, Instant notAfter, String previousStatus) {
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final CertificateDenyList denyList;
    private final ActiveSessionRegistry sessions;
    private final IssuedSerialLedger ledger;
    private final CrlService crls;
    private final TelemetryMetrics metrics;
    private final Clock clock;
    private final Disposable.Composite running = Disposables.composite();
    /**
     * Its own single-thread scheduler, not the shared boundedElastic one that ingest uses: a tick that waits on a slow
     * or unreachable database (up to the pool's 30 s connection timeout) then delays only the next sweep.
     */
    private final reactor.core.scheduler.Scheduler scheduler =
            Schedulers.newBoundedElastic(1, 16, "renewal-sweep");

    public RenewalSweepers(JdbcTemplate jdbc, TransactionTemplate tx, CertificateDenyList denyList,
                           ActiveSessionRegistry sessions, IssuedSerialLedger ledger, CrlService crls,
                           TelemetryMetrics metrics, Clock clock) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.denyList = denyList;
        this.sessions = sessions;
        this.ledger = ledger;
        this.crls = crls;
        this.metrics = metrics;
        this.clock = clock;
    }

    @EventListener
    public void onBoot(BootStepCompleted e) {
        if (e.step() == BootStep.LISTENERS_BOUND) {
            start();
        }
    }

    synchronized void start() {
        if (running.size() > 0) {
            return;
        }
        running.add(every(EXPIRY_INTERVAL, "expired-cert sweep", () -> {
            sweepExpired();
            sweepStaleReservations();
        }));
        running.add(every(NONCE_INTERVAL, "nonce sweep", this::sweepNonces));
    }

    private Disposable every(Duration interval, String name, Runnable task) {
        return Flux.interval(interval, interval, scheduler)
                .onBackpressureDrop()
                .concatMap(t -> Mono.fromRunnable(task)
                        .subscribeOn(scheduler)
                        .onErrorResume(err -> {
                            log.warn("{} failed: {}", name, err.toString());
                            return Mono.empty();
                        }))
                .subscribe();
    }

    /**
     * Blocking. ExpiredCertSweeper: returns what it expired. Candidates are read without locks; each one is then
     * re-checked under devices FOR UPDATE -> certificates FOR UPDATE (DECISIONS #82) in its own transaction, deny-listed
     * from not_after before commit, and its live sockets are evicted after commit.
     */
    public List<ExpiredCert> sweepExpired() {
        // The server's clock, not Postgres NOW(): the handshake and the per-request check refuse on the JVM clock,
        // and a Docker VM clock can fall behind the host after a sleep (Phase 8 soak run: 13.6 s, DECISIONS #87).
        Timestamp now = Timestamp.from(clock.instant());
        List<CertKey> candidates = jdbc.query("""
                SELECT issuer_key_hash, serial_number FROM certificates
                 WHERE status IN ('ACTIVE', 'ISSUED_PENDING_USE', 'RENEWED') AND not_after <= ?
                 ORDER BY not_after
                """, (rs, i) -> CertKey.of(rs.getString(1), rs.getString(2)), now);
        List<ExpiredCert> expired = new ArrayList<>();
        for (CertKey key : candidates) {
            ExpiredCert c;
            try {
                c = tx.execute(s -> expireInTx(key, now));
            } catch (RuntimeException e) {
                // One bad row must not hold back the others; the next tick retries it.
                log.warn("Expiry sweep of {} failed: {}", key, e.toString());
                continue;
            }
            if (c == null) {
                continue; // renewed, revoked or already expired by another sweep in the meantime
            }
            expired.add(c);
            sessions.evictByCert(c.key()).subscribe();
            metrics.increment("renewal.expired");
            log.info("Certificate {} of {} EXPIRED (was {}, not_after {})",
                    SerialDisplayFormat.toOpenSslHex(c.key().serial()), c.deviceId(), c.previousStatus(), c.notAfter());
        }
        return expired;
    }

    private ExpiredCert expireInTx(CertKey key, Timestamp now) {
        List<String> device = jdbc.queryForList(
                "SELECT device_id FROM certificates WHERE issuer_key_hash = ? AND serial_number = ?", String.class,
                key.issuerKeyHash(), key.serial());
        if (device.isEmpty()) {
            return null;
        }
        jdbc.queryForList("SELECT 1 FROM devices WHERE device_id = ? FOR UPDATE", device.get(0));
        List<ExpiredCert> row = jdbc.query("""
                SELECT device_id, not_after, status::text FROM certificates
                 WHERE issuer_key_hash = ? AND serial_number = ?
                   AND status IN ('ACTIVE', 'ISSUED_PENDING_USE', 'RENEWED') AND not_after <= ?
                 FOR UPDATE
                """, (rs, i) -> new ExpiredCert(key, rs.getString(1), rs.getTimestamp(2).toInstant(), rs.getString(3)),
                key.issuerKeyHash(), key.serial(), now);
        if (row.isEmpty()) {
            return null;
        }
        ExpiredCert c = row.get(0);
        denyList.add(key, c.notAfter(), "EXPIRED"); // before commit: fail closed
        jdbc.update("UPDATE certificates SET status = 'EXPIRED' WHERE issuer_key_hash = ? AND serial_number = ?",
                key.issuerKeyHash(), key.serial());
        return c;
    }

    /** Blocking. Voids stale RESERVED serials, deny-lists them before commit, then republishes the CRLs. */
    public List<CertKey> sweepStaleReservations() {
        List<CertKey> voided = tx.execute(s -> {
            List<CertKey> keys = ledger.sweepStale();
            Instant now = clock.instant();
            keys.forEach(k -> denyList.add(k, now, "REVOKED"));
            return keys;
        });
        if (!voided.isEmpty()) {
            log.warn("Voided {} stale serial reservation(s): {}", voided.size(), voided);
            voided.stream().map(CertKey::issuerKeyHash).distinct().forEach(crls::revocationCommitted);
        }
        return voided;
    }

    /** Blocking. Deletes consumed nonces past expires_at; returns the number deleted. */
    public int sweepNonces() {
        // expires_at is JVM-written (issued_at_ms + 5 min), so the JVM clock decides (DECISIONS #89).
        int n = jdbc.update("DELETE FROM consumed_challenge_nonces WHERE expires_at < ?",
                Timestamp.from(clock.instant()));
        if (n > 0) {
            log.info("Nonce sweep deleted {} expired consumed challenge nonce(s)", n);
        }
        return n;
    }

    @jakarta.annotation.PreDestroy
    void shutdown() {
        running.dispose();
        scheduler.dispose();
    }
}
