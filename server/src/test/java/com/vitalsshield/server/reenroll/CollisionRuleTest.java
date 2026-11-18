package com.vitalsshield.server.reenroll;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/** DECISIONS #91. */
class CollisionRuleTest {

    static final Instant NOW = Instant.parse("2026-11-18T12:00:00Z");
    static final CollisionRule.Cert ACTIVE = new CollisionRule.Cert("ACTIVE", NOW.plusSeconds(60), null);

    @Test
    void usableCertPlusLiveSocketFires() {
        assertThat(CollisionRule.fires(List.of(ACTIVE), NOW, true, false)).isTrue();
    }

    @Test
    void usableCertPlusRecentIngestFires() {
        assertThat(CollisionRule.fires(List.of(ACTIVE), NOW, false, true)).isTrue();
        CollisionRule.Cert pending = new CollisionRule.Cert("ISSUED_PENDING_USE", NOW.plusSeconds(60), null);
        assertThat(CollisionRule.fires(List.of(pending), NOW, false, true)).isTrue();
    }

    @Test
    void expiredCertPlusRecentIngestDoesNotFire() {
        // The laptop-sleep case: the last batch was seconds ago, but the certificate has expired.
        CollisionRule.Cert expiredActive = new CollisionRule.Cert("ACTIVE", NOW.minusSeconds(1), null);
        CollisionRule.Cert swept = new CollisionRule.Cert("EXPIRED", NOW.minusSeconds(1), null);
        assertThat(CollisionRule.fires(List.of(expiredActive, swept), NOW, false, true)).isFalse();
        assertThat(CollisionRule.fires(List.of(new CollisionRule.Cert("ACTIVE", NOW, null)), NOW, true, true))
                .as("not_after == now is expired").isFalse();
    }

    @Test
    void revokedCertDoesNotFire() {
        CollisionRule.Cert revoked = new CollisionRule.Cert("REVOKED", NOW.plusSeconds(60), null);
        assertThat(CollisionRule.fires(List.of(revoked), NOW, true, true)).isFalse();
    }

    @Test
    void renewedPastGraceWithNoLiveSocketDoesNotFire() {
        CollisionRule.Cert renewedPastGrace = new CollisionRule.Cert("RENEWED", NOW.plusSeconds(60), NOW.minusSeconds(1));
        assertThat(CollisionRule.fires(List.of(renewedPastGrace), NOW, false, false)).isFalse();
        assertThat(CollisionRule.fires(List.of(renewedPastGrace), NOW, true, true))
                .as("past grace it is not usable at all").isFalse();
        CollisionRule.Cert renewedInGrace = new CollisionRule.Cert("RENEWED", NOW.plusSeconds(60), NOW.plusSeconds(5));
        assertThat(CollisionRule.fires(List.of(renewedInGrace), NOW, true, false)).as("within grace").isTrue();
    }

    @Test
    void usableCertWithNoActivityDoesNotFire() {
        assertThat(CollisionRule.fires(List.of(ACTIVE), NOW, false, false)).isFalse();
    }
}
