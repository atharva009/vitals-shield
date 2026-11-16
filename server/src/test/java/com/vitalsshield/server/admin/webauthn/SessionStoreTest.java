package com.vitalsshield.server.admin.webauthn;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.testsupport.TestClock;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** DECISIONS #59: 30 minutes idle, 8 hours absolute, 32-byte random ids. */
class SessionStoreTest {

    final TestClock clock = new TestClock(Instant.parse("2026-11-16T10:00:00Z"));
    final AdminSessionStore store = new AdminSessionStore(clock);

    @Test
    void idsAre32RandomBytes() {
        AdminSessionStore.Session a = store.create("dr_a", "cred");
        AdminSessionStore.Session b = store.create("dr_a", "cred");
        assertThat(WebAuthnBytes.fromB64url(a.id())).hasSize(32);
        assertThat(a.id()).isNotEqualTo(b.id());
    }

    @Test
    void idleExpiryAt30Minutes() {
        AdminSessionStore.Session s = store.create("dr_a", "cred");
        clock.advance(Duration.ofMinutes(29).plusSeconds(59));
        assertThat(store.get(s.id())).isPresent();
        clock.advance(Duration.ofMinutes(30));
        assertThat(store.get(s.id())).isEmpty();
        assertThat(store.get(s.id())).as("removed, not just hidden").isEmpty();
    }

    @Test
    void activityKeepsItAliveUntilTheAbsoluteLimit() {
        AdminSessionStore.Session s = store.create("dr_a", "cred");
        for (int i = 0; i < 31; i++) {          // 31 x 15 min = 7 h 45 min, touched every 15 minutes
            clock.advance(Duration.ofMinutes(15));
            assertThat(store.get(s.id())).as("after %d x 15 min", i + 1).isPresent();
        }
        clock.advance(Duration.ofMinutes(15));   // 8 h exactly
        assertThat(store.get(s.id())).isEmpty();
    }

    @Test
    void unknownAndRemovedIdsAreEmpty() {
        assertThat(store.get(null)).isEmpty();
        assertThat(store.get("nope")).isEmpty();
        AdminSessionStore.Session s = store.create("dr_a", "cred");
        store.remove(s.id());
        assertThat(store.get(s.id())).isEmpty();
    }
}
