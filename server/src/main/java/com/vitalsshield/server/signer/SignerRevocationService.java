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
                                return new RevocationResult(key, revokedAt, closed, micros);
                            }))
                    .doOnNext(this::remember)
                    // After eviction, so republishing never adds to eviction latency. Non-blocking, coalesced.
                    .doOnNext(r -> crls.revocationCommitted(key.issuerKeyHash()));
        });
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
