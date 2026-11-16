package com.vitalsshield.server.admin.webauthn;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Pending WebAuthn ceremonies, server-side: 2-minute TTL, single use. {@link #take} removes the entry on the first
 * attempt, whether that attempt then succeeds or fails, so a challenge can never be answered twice.
 */
public final class CeremonyStore<T> {

    public static final Duration TTL = Duration.ofMinutes(2);
    private static final SecureRandom RANDOM = new SecureRandom();

    private record Entry<T>(T value, Instant expiresAt) {
    }

    private final Map<String, Entry<T>> entries = new ConcurrentHashMap<>();
    private final Clock clock;

    public CeremonyStore(Clock clock) {
        this.clock = clock;
    }

    /** Stores under a fresh random id and returns it. */
    public String put(T value) {
        byte[] id = new byte[16];
        RANDOM.nextBytes(id);
        String key = WebAuthnBytes.b64url(id);
        put(key, value);
        return key;
    }

    /** Stores under a caller-chosen key (the challenge, for ceremonies whose finish carries no id). */
    public void put(String key, T value) {
        purgeExpired();
        entries.put(key, new Entry<>(value, clock.instant().plus(TTL)));
    }

    /** Removes and returns the entry; empty if it never existed, was already taken, or has expired. */
    public Optional<T> take(String key) {
        if (key == null) {
            return Optional.empty();
        }
        Entry<T> e = entries.remove(key);
        if (e == null || !clock.instant().isBefore(e.expiresAt())) {
            return Optional.empty();
        }
        return Optional.of(e.value());
    }

    public int size() {
        return entries.size();
    }

    private void purgeExpired() {
        Instant now = clock.instant();
        entries.values().removeIf(e -> !now.isBefore(e.expiresAt()));
    }
}
