package com.vitalsshield.server.admin.webauthn;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.testsupport.TestClock;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** 2-minute TTL, single use: the first take removes the entry whether or not the caller then succeeds. */
class CeremonyStoreTest {

    final TestClock clock = new TestClock(Instant.parse("2026-11-16T10:00:00Z"));
    final CeremonyStore<String> store = new CeremonyStore<>(clock);

    @Test
    void singleUse() {
        String id = store.put("x");
        assertThat(store.take(id)).hasValue("x");
        assertThat(store.take(id)).isEmpty();
    }

    @Test
    void expiresAfterTwoMinutes() {
        String id = store.put("x");
        String other = store.put("y");
        clock.advance(Duration.ofSeconds(119));
        assertThat(store.take(id)).hasValue("x");
        clock.advance(Duration.ofSeconds(1));
        assertThat(store.take(other)).isEmpty();
    }

    @Test
    void unknownIdIsEmpty() {
        assertThat(store.take("nope")).isEmpty();
        assertThat(store.take(null)).isEmpty();
    }
}
