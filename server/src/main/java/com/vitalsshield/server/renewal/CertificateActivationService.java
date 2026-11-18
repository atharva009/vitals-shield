package com.vitalsshield.server.renewal;

// LOCK ORDER (DECISIONS #82, extends #70), in every transaction: devices -> certificates -> telemetry_records
// -> patient_device_assignments -> clinical_alerts -> audit advisory lock LAST. This class: devices FOR UPDATE, then
// the new certificate row FOR UPDATE, then the superseded certificate row. Nothing else.

import com.vitalsshield.server.pki.PkiProperties;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import com.vitalsshield.server.signer.EvictionProperties;
import com.vitalsshield.server.telemetry.TelemetryMetrics;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.Disposable;
import reactor.core.Disposables;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * First-use switchover (spec Section 4, Protocol B step 4). The first accepted batch signed by an ISSUED_PENDING_USE
 * certificate makes it ACTIVE and its predecessor RENEWED with grace_expires_at = now + renewal-grace. The old
 * certificate is deny-listed from grace_expires_at before commit, and after commit an eviction is scheduled for that
 * instant (GraceEviction, DECISIONS #84), so its live keep-alive sockets close when the grace ends.
 *
 * <p>The old row is updated before the new one so idx_one_active_cert_per_device never sees two ACTIVE rows. The
 * device row lock serializes concurrent first batches; every one after the first finds the certificate already
 * ACTIVE and returns without a change.
 */
@Service
public class CertificateActivationService {

    private static final Logger log = LoggerFactory.getLogger(CertificateActivationService.class);

    /** One switchover, as committed. */
    public record Activation(String deviceId, CertKey newKey, CertKey oldKey, Instant activatedAt,
                             Instant graceExpiresAt) {
    }

    /** What the scheduled eviction did when the grace ended. */
    public record GraceEviction(CertKey oldKey, Instant at, int socketsClosed) {
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final CertificateDenyList denyList;
    private final ActiveSessionRegistry sessions;
    private final PkiProperties pki;
    private final TelemetryMetrics metrics;
    private final Clock clock;
    private final EvictionProperties eviction;
    private final AtomicInteger pending = new AtomicInteger();
    private final Disposable.Composite scheduled = Disposables.composite();
    private final Map<CertKey, GraceEviction> evictions = new ConcurrentHashMap<>();

    public CertificateActivationService(JdbcTemplate jdbc, TransactionTemplate tx, CertificateDenyList denyList,
                                        ActiveSessionRegistry sessions, PkiProperties pki, TelemetryMetrics metrics,
                                        Clock clock, EvictionProperties eviction) {
        this.eviction = eviction;
        this.jdbc = jdbc;
        this.tx = tx;
        this.denyList = denyList;
        this.sessions = sessions;
        this.pki = pki;
        this.metrics = metrics;
        this.clock = clock;
    }

    /**
     * Runs {@link #activate} on boundedElastic, off the ingest response path, then {@code andThen} (the clinical
     * evaluation submit for the same batch) whether or not activation succeeded. Never throws.
     */
    public void activateAsync(String deviceId, CertKey newKey, Runnable andThen) {
        pending.incrementAndGet();
        Mono.fromCallable(() -> activate(deviceId, newKey))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(e -> {
                    metrics.increment("renewal.activation_failures");
                    log.error("Activation of {} for {} failed; the next batch retries it", newKey, deviceId, e);
                })
                .onErrorResume(e -> Mono.empty())
                .doFinally(s -> {
                    try {
                        andThen.run();
                    } finally {
                        pending.decrementAndGet();
                    }
                })
                .subscribe();
    }

    /** Activations queued or running (tests wait for zero). */
    public int pending() {
        return pending.get();
    }

    public boolean awaitIdle(Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (pending.get() > 0) {
            if (System.nanoTime() > deadline) {
                return false;
            }
            Thread.sleep(10);
        }
        return true;
    }

    /** Blocking. Empty if the certificate is no longer ISSUED_PENDING_USE (already activated, or revoked). */
    public Optional<Activation> activate(String deviceId, CertKey newKey) {
        Activation a = tx.execute(s -> activateInTx(deviceId, newKey));
        if (a == null) {
            return Optional.empty();
        }
        metrics.increment("renewal.activations");
        log.info("Activated {} for {}; {} RENEWED, grace until {}", a.newKey().serial(), deviceId,
                a.oldKey() == null ? "(none)" : a.oldKey().serial(), a.graceExpiresAt());
        if (a.oldKey() != null) {
            scheduleGraceEviction(a.oldKey(), a.graceExpiresAt());
        }
        return Optional.of(a);
    }

    private Activation activateInTx(String deviceId, CertKey newKey) {
        jdbc.queryForList("SELECT 1 FROM devices WHERE device_id = ? FOR UPDATE", deviceId);
        List<Map<String, Object>> row = jdbc.queryForList("""
                SELECT status::text AS status, superseded_serial FROM certificates
                 WHERE issuer_key_hash = ? AND serial_number = ? AND device_id = ?
                 FOR UPDATE
                """, newKey.issuerKeyHash(), newKey.serial(), deviceId);
        if (row.isEmpty() || !"ISSUED_PENDING_USE".equals(row.get(0).get("status"))) {
            return null; // idempotent: a concurrent first batch already switched over, or the cert was revoked
        }
        Instant now = clock.instant();
        Instant grace = now.plus(pki.renewalGrace());
        String supersededSerial = (String) row.get(0).get("superseded_serial");

        CertKey oldKey = null;
        if (supersededSerial != null) {
            List<CertKey> old = jdbc.query("""
                    SELECT issuer_key_hash, serial_number FROM certificates
                     WHERE device_id = ? AND serial_number = ? AND status = 'ACTIVE'
                     FOR UPDATE
                    """, (rs, i) -> CertKey.of(rs.getString(1), rs.getString(2)), deviceId, supersededSerial);
            if (!old.isEmpty()) {
                oldKey = old.get(0);
                denyList.add(oldKey, grace, "SUPERSEDED"); // before commit: fail closed
                // Old first, so the partial unique index never sees two ACTIVE rows for the device.
                jdbc.update("""
                        UPDATE certificates SET status = 'RENEWED', grace_expires_at = ?
                         WHERE issuer_key_hash = ? AND serial_number = ? AND status = 'ACTIVE'
                        """, Timestamp.from(grace), oldKey.issuerKeyHash(), oldKey.serial());
            }
        }
        jdbc.update("""
                UPDATE certificates SET status = 'ACTIVE', activated_at = NOW()
                 WHERE issuer_key_hash = ? AND serial_number = ? AND status = 'ISSUED_PENDING_USE'
                """, newKey.issuerKeyHash(), newKey.serial());
        // activated_at is Postgres-stamped like issued_at, so issue-to-activation is one clock (DECISIONS #89);
        // grace_expires_at above is JVM time because the handshake and per-request checks compare it with the JVM.
        return new Activation(deviceId, newKey, oldKey, now, grace);
    }

    /** DECISIONS #84: at grace_expires_at, close every live socket of the old certificate. */
    void scheduleGraceEviction(CertKey oldKey, Instant at) {
        Duration delay = Duration.between(clock.instant(), at);
        if (delay.isNegative()) {
            delay = Duration.ZERO;
        }
        Disposable[] self = new Disposable[1];
        self[0] = Mono.delay(delay, Schedulers.boundedElastic())
                // vitalsshield.eviction.enabled=false (tests) leaves sockets open, like revocation does; the deny-list
                // and the per-request status check still refuse the old certificate.
                .flatMap(t -> eviction.enabled() ? sessions.evictByCert(oldKey) : Mono.just(0))
                .subscribe(closed -> {
                    evictions.put(oldKey, new GraceEviction(oldKey, clock.instant(), closed));
                    metrics.increment("renewal.grace_evictions");
                    if (closed > 0) {
                        metrics.add("renewal.grace_evicted_sockets", closed);
                    }
                    log.info("Grace ended for {}: closed {} live socket(s)", oldKey.serial(), closed);
                    scheduled.remove(self[0]);
                }, e -> log.warn("Grace eviction for {} failed: {}", oldKey, e.toString()));
        scheduled.add(self[0]);
    }

    /** The eviction that ran when this certificate's grace ended, if it has run in this process. */
    public Optional<GraceEviction> graceEviction(CertKey oldKey) {
        return Optional.ofNullable(evictions.get(oldKey));
    }

    @jakarta.annotation.PreDestroy
    void shutdown() {
        scheduled.dispose();
    }
}
