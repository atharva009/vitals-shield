package com.vitalsshield.server.pki.trust;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class CertificateDenyListTest {

    static final Instant T0 = Instant.parse("2026-11-13T12:00:00Z");
    static final CertKey KEY = CertKey.of("ab".repeat(32), "1f2e");

    final List<DenyRow> rows = new ArrayList<>();
    final MutableClock clock = new MutableClock(T0);
    final CertificateDenyList denyList = new CertificateDenyList(() -> List.copyOf(rows), clock);

    @Test
    void notDeniedWhenAbsent() {
        assertThat(denyList.isDenied(KEY, T0)).isFalse();
        assertThat(denyList.size()).isZero();
    }

    @Test
    void deniedFromItsInstantOnwardNotBefore() {
        denyList.add(KEY, T0, "REVOKED");

        assertThat(denyList.isDenied(KEY, T0.minusMillis(1))).isFalse();
        assertThat(denyList.isDenied(KEY, T0)).isTrue();
        assertThat(denyList.isDenied(KEY, T0.plusSeconds(3600))).isTrue();
    }

    @Test
    void addKeepsEarliestDeniedFrom() {
        denyList.add(KEY, T0.plusSeconds(60), "SUPERSEDED");
        denyList.add(KEY, T0, "REVOKED");
        denyList.add(KEY, T0.plusSeconds(120), "REVOKED");

        assertThat(denyList.isDenied(KEY, T0)).isTrue();
        assertThat(denyList.entry(KEY).orElseThrow().deniedFrom()).isEqualTo(T0);
        assertThat(denyList.entry(KEY).orElseThrow().reason()).isEqualTo("REVOKED");
    }

    @Test
    void seedMapsStatusesToDeniedFrom() {
        CertKey revokedNoTime = CertKey.of("ab".repeat(32), "01");
        CertKey expired = CertKey.of("ab".repeat(32), "02");
        CertKey renewed = CertKey.of("ab".repeat(32), "03");
        rows.add(new DenyRow(KEY, "REVOKED", T0, null));
        rows.add(new DenyRow(revokedNoTime, "REVOKED", null, null));
        rows.add(new DenyRow(expired, "EXPIRED", null, null));
        rows.add(new DenyRow(renewed, "RENEWED", null, T0.plusSeconds(60)));

        denyList.seedFromDb();

        assertThat(denyList.entry(KEY).orElseThrow().deniedFrom()).isEqualTo(T0);
        assertThat(denyList.entry(revokedNoTime).orElseThrow().deniedFrom()).isEqualTo(Instant.EPOCH);
        assertThat(denyList.entry(expired).orElseThrow().deniedFrom()).isEqualTo(Instant.EPOCH);
        assertThat(denyList.isDenied(renewed, T0)).isFalse();
        assertThat(denyList.isDenied(renewed, T0.plusSeconds(60))).isTrue();
    }

    @Test
    void refreshNeverRemovesEntries() {
        rows.add(new DenyRow(KEY, "REVOKED", T0, null));
        denyList.seedFromDb();
        CertKey added = CertKey.of("cd".repeat(32), "ff");
        denyList.add(added, T0, "REVOKED");

        rows.clear();
        denyList.refreshFromDb();

        assertThat(denyList.isDenied(KEY, T0)).isTrue();
        assertThat(denyList.isDenied(added, T0)).isTrue();
        assertThat(denyList.size()).isEqualTo(2);
    }

    @Test
    void refreshAddsNewRows() {
        denyList.seedFromDb();
        rows.add(new DenyRow(KEY, "REVOKED", T0, null));

        denyList.refreshFromDb();

        assertThat(denyList.isDenied(KEY, T0.plus(Duration.ofSeconds(1)))).isTrue();
    }

    @Test
    void serialAndHashNormalizationMapToSameKey() {
        denyList.add(CertKey.of("AB".repeat(32), "001F2E"), T0, "REVOKED");

        assertThat(denyList.isDenied(KEY, T0)).isTrue();
        assertThat(CertKey.of("AB".repeat(32), "001F2E")).isEqualTo(KEY);
        assertThat(KEY.serial()).isEqualTo("1f2e");
        assertThat(KEY.issuerKeyHash()).isEqualTo("ab".repeat(32));
    }
}
