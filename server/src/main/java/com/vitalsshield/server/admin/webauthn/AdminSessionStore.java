package com.vitalsshield.server.admin.webauthn;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Admin sessions (DECISIONS #59): random 32-byte id, in memory only (lost on restart), 30 minutes idle and 8 hours
 * absolute. A session remembers which credential signed it in, so step-up ceremonies can be restricted to it.
 */
@Component
public class AdminSessionStore {

    public static final Duration IDLE = Duration.ofMinutes(30);
    public static final Duration ABSOLUTE = Duration.ofHours(8);
    public static final String COOKIE = "vs_admin_session";
    private static final SecureRandom RANDOM = new SecureRandom();

    public static final class Session {
        private final String id;
        private final String clinicianId;
        private final String credentialId;
        private final Instant createdAt;
        private volatile Instant lastSeen;

        Session(String id, String clinicianId, String credentialId, Instant createdAt) {
            this.id = id;
            this.clinicianId = clinicianId;
            this.credentialId = credentialId;
            this.createdAt = createdAt;
            this.lastSeen = createdAt;
        }

        public String id() {
            return id;
        }

        public String clinicianId() {
            return clinicianId;
        }

        public String credentialId() {
            return credentialId;
        }

        public Instant createdAt() {
            return createdAt;
        }
    }

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Clock clock;

    public AdminSessionStore(Clock clock) {
        this.clock = clock;
    }

    public Session create(String clinicianId, String credentialId) {
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        Session s = new Session(WebAuthnBytes.b64url(raw), clinicianId, credentialId, clock.instant());
        sessions.put(s.id(), s);
        return s;
    }

    /** The live session for {@code id}, refreshing its idle timer; expired sessions are removed. */
    public Optional<Session> get(String id) {
        if (id == null) {
            return Optional.empty();
        }
        Session s = sessions.get(id);
        if (s == null) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        if (!now.isBefore(s.lastSeen.plus(IDLE)) || !now.isBefore(s.createdAt.plus(ABSOLUTE))) {
            sessions.remove(id);
            return Optional.empty();
        }
        s.lastSeen = now;
        return Optional.of(s);
    }

    public void remove(String id) {
        if (id != null) {
            sessions.remove(id);
        }
    }
}
