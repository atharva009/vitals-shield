package com.vitalsshield.server.signer;

import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Revokes a leaf. Order: deny-list first (fails closed: if the DB write then fails, the cert stays blocked in this
 * process), then the DB row, then live socket eviction. No HTTP endpoint in Phase 2; quarantine (Phase 4) calls it.
 */
@Service
public class SignerRevocationService {

    private static final Logger log = LoggerFactory.getLogger(SignerRevocationService.class);
    private static final int RECENT_LIMIT = 50;

    private final CertificateDenyList denyList;
    private final ActiveSessionRegistry sessions;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final EvictionProperties eviction;
    private final Clock clock;
    private final CrlService crls;
    private final Deque<RevocationResult> recent = new ConcurrentLinkedDeque<>();

    public SignerRevocationService(CertificateDenyList denyList, ActiveSessionRegistry sessions, JdbcTemplate jdbc,
                                   TransactionTemplate tx, EvictionProperties eviction, Clock clock,
                                   CrlService crls) {
        this.denyList = denyList;
        this.sessions = sessions;
        this.jdbc = jdbc;
        this.tx = tx;
        this.eviction = eviction;
        this.clock = clock;
        this.crls = crls;
    }

    public Mono<RevocationResult> revoke(CertKey key, String reason) {
        return Mono.defer(() -> {
            long t0 = System.nanoTime();
            Instant revokedAt = clock.instant();
            denyList.add(key, revokedAt, "REVOKED");

            return Mono.fromCallable(() -> tx.execute(status -> jdbc.queryForList("""
                                    UPDATE certificates
                                       SET status = 'REVOKED', revoked_at = ?, revocation_reason = ?
                                     WHERE issuer_key_hash = ? AND serial_number = ? AND status <> 'REVOKED'
                                    RETURNING device_id
                                    """, String.class,
                            Timestamp.from(revokedAt), reason, key.issuerKeyHash(), key.serial())))
                    .subscribeOn(Schedulers.boundedElastic())
                    .doOnError(e -> log.error("Revocation DB write failed for {}; deny-list entry kept: {}",
                            key, e.toString()))
                    .flatMap(devices -> (eviction.enabled() ? sessions.evictByCert(key) : Mono.just(0))
                            .map(closed -> {
                                long micros = (System.nanoTime() - t0) / 1000;
                                log.info("Revoked {} (devices {}, reason {}): closed {} live socket(s) in {} us",
                                        key, devices, reason, closed, micros);
                                return new RevocationResult(key, devices.isEmpty() ? null : devices.get(0), reason,
                                        revokedAt, closed, micros);
                            }))
                    .doOnNext(this::remember)
                    // After eviction, so republishing never adds to eviction latency. Non-blocking, coalesced.
                    .doOnNext(r -> crls.revocationCommitted(key.issuerKeyHash()));
        });
    }

    /** Result of revoking every live certificate of a device. */
    public record BulkRevocation(String deviceId, List<CertKey> keys, int channelsClosed, long latencyMicros) {
    }

    /**
     * Revokes every ACTIVE, ISSUED_PENDING_USE, or RENEWED certificate of {@code deviceId}: all keys deny-listed at
     * one instant first, then one transaction updates the rows, then every channel is closed in parallel and the
     * returned Mono completes when all close futures have. CRL republication is triggered after.
     */
    public Mono<BulkRevocation> revokeAllForDevice(String deviceId, String reason) {
        return revokeAllForDevice(deviceId, reason, System.nanoTime());
    }

    /**
     * As above; {@code t0Nanos} is when the caller (quarantine) received its request, so the per-certificate latency
     * recorded in the revocation log matches the latency the caller reports (DECISIONS #11).
     */
    public Mono<BulkRevocation> revokeAllForDevice(String deviceId, String reason, long t0Nanos) {
        Instant[] revokedAtHolder = new Instant[1];
        return Mono.fromCallable(() -> {
                    List<CertKey> keys = jdbc.query("""
                            SELECT issuer_key_hash, serial_number FROM certificates
                             WHERE device_id = ? AND status IN ('ACTIVE', 'ISSUED_PENDING_USE', 'RENEWED')
                            """, (rs, i) -> CertKey.of(rs.getString(1), rs.getString(2)), deviceId);
                    Instant revokedAt = clock.instant();
                    revokedAtHolder[0] = revokedAt;
                    keys.forEach(k -> denyList.add(k, revokedAt, "REVOKED")); // before the DB write: fail closed
                    tx.executeWithoutResult(status -> jdbc.update("""
                            UPDATE certificates
                               SET status = 'REVOKED', revoked_at = ?, revocation_reason = ?
                             WHERE device_id = ? AND status IN ('ACTIVE', 'ISSUED_PENDING_USE', 'RENEWED')
                            """, Timestamp.from(revokedAt), reason, deviceId));
                    return keys;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(keys -> reactor.core.publisher.Flux.fromIterable(keys)
                        .flatMap(k -> (eviction.enabled() ? sessions.evictByCert(k) : Mono.just(0))
                                .map(closed -> java.util.Map.entry(k, closed)))
                        .collectList()
                        .map(perKey -> {
                            long micros = (System.nanoTime() - t0Nanos) / 1000;
                            int total = 0;
                            for (var e : perKey) {
                                total += e.getValue();
                                remember(new RevocationResult(e.getKey(), deviceId, reason, revokedAtHolder[0],
                                        e.getValue(), micros));
                            }
                            return new BulkRevocation(deviceId, keys, total, micros);
                        }))
                .doOnNext(r -> r.keys().stream().map(CertKey::issuerKeyHash).distinct()
                        .forEach(crls::revocationCommitted));
    }

    /** Most recent results, newest first (at most 50). */
    public List<RevocationResult> recentResults() {
        return new ArrayList<>(recent);
    }

    private void remember(RevocationResult r) {
        recent.addFirst(r);
        while (recent.size() > RECENT_LIMIT) {
            recent.pollLast();
        }
    }
}
