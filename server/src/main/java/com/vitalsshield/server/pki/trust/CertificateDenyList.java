package com.vitalsshield.server.pki.trust;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * In-memory set of certificates that must not connect, read by the TLS handshake path (no I/O there).
 *
 * <p>A deny-list, not an allow-list: a certificate that is not listed passes the handshake, so a freshly issued leaf
 * works immediately. Authoritative status is still checked per request by CertStatusResolver. Entries are never
 * removed: revocation is one-way, and refresh only unions new rows in.
 */
@Component
public class CertificateDenyList implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(CertificateDenyList.class);

    static final Duration REFRESH_INTERVAL = Duration.ofSeconds(30);

    /** Why an entry exists; used for the per-request 403 reason. */
    public record Entry(Instant deniedFrom, String reason) {
    }

    private final Map<CertKey, Entry> entries = new ConcurrentHashMap<>();
    private final DenySource source;
    private final Clock clock;
    private volatile Disposable refresher;

    @Autowired
    public CertificateDenyList(JdbcDenySource source, Clock clock) {
        this((DenySource) source, clock);
    }

    public CertificateDenyList(DenySource source, Clock clock) {
        this.source = source;
        this.clock = clock;
    }

    /** True when the key is listed and {@code now >= deniedFrom}. In-memory only; safe on an event loop. */
    public boolean isDenied(CertKey key, Instant now) {
        Entry e = entries.get(key);
        return e != null && !now.isBefore(e.deniedFrom());
    }

    public boolean isDenied(CertKey key) {
        return isDenied(key, clock.instant());
    }

    public Optional<Entry> entry(CertKey key) {
        return Optional.ofNullable(entries.get(key));
    }

    /** Adds or tightens an entry: if the key exists, the earliest deniedFrom wins. */
    public void add(CertKey key, Instant deniedFrom, String reason) {
        Entry candidate = new Entry(deniedFrom, reason);
        entries.merge(key, candidate,
                (existing, incoming) -> incoming.deniedFrom().isBefore(existing.deniedFrom()) ? incoming : existing);
    }

    public int size() {
        return entries.size();
    }

    /** Blocking: loads every deny-worthy row. Run on the boot thread or boundedElastic. */
    public void seedFromDb() {
        int before = size();
        load();
        log.info("Deny-list seeded: {} entries ({} new)", size(), size() - before);
    }

    /** Blocking union refresh; never removes entries. */
    public void refreshFromDb() {
        int before = size();
        load();
        if (size() != before) {
            log.info("Deny-list refresh added {} entries (total {})", size() - before, size());
        }
    }

    /** Starts the 30-second refresh; each tick runs on boundedElastic. Idempotent. */
    public synchronized void startPeriodicRefresh() {
        if (refresher != null && !refresher.isDisposed()) {
            return;
        }
        refresher = Flux.interval(REFRESH_INTERVAL, REFRESH_INTERVAL)
                .concatMap(tick -> Mono.fromRunnable(this::refreshFromDb)
                        .subscribeOn(Schedulers.boundedElastic())
                        .onErrorResume(e -> {
                            log.warn("Deny-list refresh failed; keeping current entries: {}", e.toString());
                            return Mono.empty();
                        }))
                .subscribe();
    }

    @Override
    public void destroy() {
        Disposable r = refresher;
        if (r != null) {
            r.dispose();
        }
    }

    private void load() {
        for (DenyRow row : source.load()) {
            switch (row.status()) {
                case "REVOKED" -> add(row.key(), row.revokedAt() == null ? Instant.EPOCH : row.revokedAt(), "REVOKED");
                case "EXPIRED" -> add(row.key(), Instant.EPOCH, "EXPIRED");
                case "RENEWED" -> add(row.key(),
                        row.graceExpiresAt() == null ? Instant.EPOCH : row.graceExpiresAt(), "SUPERSEDED");
                default -> log.warn("Ignoring deny row with status {}", row.status());
            }
        }
    }
}
