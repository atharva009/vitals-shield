package com.vitalsshield.server.clock;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.crypto.TelemetryJws;
import com.vitalsshield.devtools.DevSeeder;
import com.vitalsshield.server.admin.AdminOverviewService;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.pki.IssuedSerialLedger;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.quarantine.QuarantineHooks;
import com.vitalsshield.server.quarantine.QuarantineService;
import com.vitalsshield.server.reenroll.ReEnrollService;
import com.vitalsshield.server.renewal.CertificateActivationService;
import com.vitalsshield.server.renewal.RenewalSweepers;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.Renewals;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.TelemetryFrames;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * DECISIONS #89, one assertion per FIXED row of docs/CLOCK_INVENTORY.md. The server's JVM clock runs 10 minutes
 * behind real time (Postgres), the mirror of the Phase 8 soak run where the Docker VM fell behind the host. Each test
 * picks a row value that the old cross-clock comparison would have treated differently, so it fails against the old
 * code and passes only if each comparison uses the clock that produced the value.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ClockDisciplineIT {

    static final Duration SKEW = Duration.ofMinutes(10);
    /**
     * Phase 10b.1: the Docker VM clock is a few milliseconds ahead of or behind the host, so a difference of SKEW is
     * compared with a tolerance. It used to be truncated to whole minutes and expected to be 9, which failed whenever
     * Postgres ran ahead of the host.
     */
    static final Duration SKEW_TOLERANCE = Duration.ofSeconds(30);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;
    static final AtomicReference<Instant> NOW_IN_QUARANTINE_TX = new AtomicReference<>();

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-clock-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    @TestConfiguration
    static class SkewedJvm {
        @Bean
        @Primary
        Clock skewedClock() {
            return Clock.offset(Clock.systemUTC(), SKEW.negated());
        }

        /** Reads Postgres now() inside the quarantine transaction, just before commit. */
        @Bean
        QuarantineHooks captureNow(JdbcTemplate jdbc) {
            return deviceId -> NOW_IN_QUARANTINE_TX.set(
                    jdbc.queryForObject("SELECT now()", Timestamp.class).toInstant());
        }
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired Clock clock;
    @Autowired TrustAnchors anchors;
    @Autowired QuarantineService quarantine;
    @Autowired RenewalSweepers sweepers;
    @Autowired CertificateDenyList denyList;
    @Autowired CrlService crls;
    @Autowired IssuedSerialLedger ledger;
    @Autowired CertificateActivationService activation;
    @Autowired AdminOverviewService overview;
    @Autowired ReEnrollService reEnroll;

    SpineFixture fx() {
        return new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
    }

    Instant dbNow() {
        return jdbc.queryForObject("SELECT now()", Timestamp.class).toInstant();
    }

    @Test
    @Order(0)
    void theJvmClockReallyIsTenMinutesBehindPostgres() {
        assertThat(Duration.between(clock.instant(), dbNow())).isBetween(SKEW.minus(SKEW_TOLERANCE), SKEW.plus(SKEW_TOLERANCE));
    }

    /** Row: EnrollmentService token claim, expires_at (JVM-written) vs JVM clock. */
    @Test
    @Order(1)
    void bootstrapTokenExpiryIsJudgedByTheJvmClock() {
        DevSeeder.Result seed = new DevSeeder(jdbc, tx, Clock.systemUTC()).seed(DevSeeder.Request.defaults("dev_clk"));
        // Expired by Postgres' clock, still valid by the JVM's (which wrote it): the old "expires_at > NOW()" said 401.
        jdbc.update("UPDATE device_bootstrap_tokens SET expires_at = NOW() - INTERVAL '2 minutes' WHERE device_id = ?",
                "dev_clk");
        SpineFixture.Device d = fx().enrollWithToken("dev_clk", seed.token());
        assertThat(d.cert()).isNotNull();
    }

    /** Row: QuarantineService :quarantineTs bound to Postgres now() inside the transaction. */
    @Test
    @Order(2)
    void quarantineBindsQuarantineTsFromPostgresNowInItsTransaction() {
        fx().enroll("dev_clk_q");
        QuarantineService.Result r = quarantine.quarantine("dev_clk_q", 5, "clock discipline").block(Duration.ofSeconds(20));
        assertThat(r.at()).isEqualTo(NOW_IN_QUARANTINE_TX.get());
        assertThat(Duration.between(clock.instant(), r.at())).as("not the JVM clock").isBetween(SKEW.minus(SKEW_TOLERANCE), SKEW.plus(SKEW_TOLERANCE));
    }

    /** Row: RenewalSweepers nonce sweep, expires_at (JVM-written) vs JVM clock. */
    @Test
    @Order(3)
    void nonceSweepUsesTheJvmClock() {
        String keep = "keep-" + UUID.randomUUID();
        String drop = "drop-" + UUID.randomUUID();
        jdbc.update("INSERT INTO consumed_challenge_nonces (nonce_b64, device_id, expires_at) VALUES (?, 'dev_clk', "
                + "NOW() - INTERVAL '1 minute')", keep);
        jdbc.update("INSERT INTO consumed_challenge_nonces (nonce_b64, device_id, expires_at) VALUES (?, 'dev_clk', "
                + "NOW() - INTERVAL '11 minutes')", drop);
        sweepers.sweepNonces();
        assertThat(jdbc.queryForList("SELECT nonce_b64 FROM consumed_challenge_nonces WHERE nonce_b64 IN (?, ?)",
                String.class, keep, drop)).containsExactly(keep);
    }

    /** Row: RenewalSweepers expiry sweep (Phase 8.1), not_after (JVM-written) vs JVM clock. */
    @Test
    @Order(4)
    void expirySweepUsesTheJvmClock() {
        SpineFixture.Device d = fx().enroll("dev_clk_exp");
        CertKey key = CertKey.from(d.cert());
        jdbc.update("UPDATE certificates SET not_after = NOW() - INTERVAL '1 minute' WHERE serial_number = ?",
                key.serial());
        assertThat(sweepers.sweepExpired()).extracting(RenewalSweepers.ExpiredCert::key).doesNotContain(key);
        jdbc.update("UPDATE certificates SET not_after = NOW() - INTERVAL '11 minutes' WHERE serial_number = ?",
                key.serial());
        assertThat(sweepers.sweepExpired()).extracting(RenewalSweepers.ExpiredCert::key).contains(key);
    }

    /** Row: JdbcDenySource cutoff, not_after (JVM-written) vs JVM clock. */
    @Test
    @Order(5)
    void denyListSeedCutoffUsesTheJvmClock() {
        SpineFixture.Device d = fx().enroll("dev_clk_deny");
        CertKey key = CertKey.from(d.cert());
        // Within a day of the JVM clock, more than a day before Postgres': the old "NOW() - 1 day" left it out.
        jdbc.update("""
                UPDATE certificates SET status = 'REVOKED', revocation_reason = 'KEY_COMPROMISE', revoked_at = NOW(),
                       not_after = NOW() - INTERVAL '1 day 5 minutes'
                 WHERE serial_number = ?
                """, key.serial());
        assertThat(denyList.entry(key)).isEmpty();
        denyList.refreshFromDb();
        assertThat(denyList.entry(key)).isPresent();
    }

    /** Row: CrlService VOIDED window, reserved_at (DEFAULT NOW()) vs Postgres now(). */
    @Test
    @Order(6)
    void crlVoidedSerialWindowUsesPostgresNow() throws Exception {
        String issuer = jdbc.queryForObject("SELECT issuer_key_hash FROM certificates LIMIT 1", String.class);
        // CRL window: ttl (PT4M) + 1 h. One serial inside it, one 5 minutes outside by Postgres' clock but inside
        // by the JVM clock (which the old code used).
        jdbc.update("INSERT INTO issued_serials (issuer_key_hash, serial_number, device_id, reserved_at, status, "
                + "voided_at) VALUES (?, 'aa01', 'dev_clk', NOW() - INTERVAL '2 minutes', 'VOIDED', NOW())", issuer);
        jdbc.update("INSERT INTO issued_serials (issuer_key_hash, serial_number, device_id, reserved_at, status, "
                + "voided_at) VALUES (?, 'aa02', 'dev_clk', NOW() - INTERVAL '1 hour 9 minutes', 'VOIDED', NOW())",
                issuer);
        crls.publishIntermediateCrl();
        X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(
                crls.currentIntermediateCrl().block(Duration.ofSeconds(5)).getBytes(StandardCharsets.US_ASCII)));
        assertThat(crl.getRevokedCertificate(new BigInteger("aa01", 16))).as("inside the window").isNotNull();
        assertThat(crl.getRevokedCertificate(new BigInteger("aa02", 16))).as("outside by Postgres' clock").isNull();
    }

    /** Row: IssuedSerialLedger.sweepStale, voided_at written with the JVM clock (it becomes a deniedFrom). */
    @Test
    @Order(7)
    void staleReservationVoidedAtIsJvmTime() {
        String issuer = jdbc.queryForObject("SELECT issuer_key_hash FROM certificates LIMIT 1", String.class);
        jdbc.update("INSERT INTO issued_serials (issuer_key_hash, serial_number, device_id, reserved_at, status) "
                + "VALUES (?, 'bb01', 'dev_clk', NOW() - INTERVAL '3 minutes', 'RESERVED')", issuer);
        assertThat(ledger.sweepStale()).contains(CertKey.of(issuer, "bb01"));
        Instant voidedAt = jdbc.queryForObject("SELECT voided_at FROM issued_serials WHERE serial_number = 'bb01'",
                Timestamp.class).toInstant();
        assertThat(Duration.between(voidedAt, dbNow())).as("JVM time, 10 min behind").isBetween(SKEW.minus(SKEW_TOLERANCE), SKEW.plus(SKEW_TOLERANCE));
    }

    /** Rows: renewal issued_at and activation activated_at, both Postgres-stamped. */
    @Test
    @Order(8)
    void renewalIssuedAtAndActivatedAtArePostgresStamped() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_clk_renew");
        Renewals.Identity cur = Renewals.identity(d);
        Renewals.Identity next;
        try (MtlsTestClient.Connection c = Renewals.connect(ports.mtls(), anchors.root(), cur)) {
            next = Renewals.renewOk(c, cur, d.deviceId());
        }
        try (MtlsTestClient.Connection n = Renewals.connect(ports.mtls(), anchors.root(), next)) {
            // Frame timestamps from the server's (skewed) clock, so the payload freshness check accepts them.
            Instant t = clock.instant();
            byte[] payload = TelemetryFrames.payload(d.deviceId(), d.assignmentId(), d.bootEpoch(), 1,
                    UUID.randomUUID(), t, t, TelemetryFrames.Metrics.resting(new Random(1)));
            MtlsTestClient.Response r = SpineFixture.ingest(n,
                    TelemetryJws.sign(payload, next.key(), next.cert().getEncoded()));
            assertThat(r.status()).as(r.body()).isEqualTo(200);
        }
        assertThat(activation.awaitIdle(Duration.ofSeconds(10))).isTrue();
        Map<String, Object> row = jdbc.queryForMap("SELECT issued_at, activated_at, now() AS db_now FROM certificates "
                + "WHERE serial_number = ?", next.cert().getSerialNumber().toString(16));
        Instant dbNow = ((Timestamp) row.get("db_now")).toInstant();
        assertThat(Duration.between(((Timestamp) row.get("issued_at")).toInstant(), dbNow).abs())
                .isLessThan(Duration.ofSeconds(30));
        assertThat(Duration.between(((Timestamp) row.get("activated_at")).toInstant(), dbNow).abs())
                .isLessThan(Duration.ofSeconds(30));
    }

    /** Row: overview db_time (dashboard relative times of ingested_at) and the skew monitor (DECISIONS #98). */
    @Test
    @Order(9)
    @SuppressWarnings("unchecked")
    void overviewReportsBothClocksAndTheSkewIsRed() {
        Map<String, Object> o = overview.snapshot();
        Instant server = Instant.parse((String) o.get("server_time"));
        Instant db = Instant.parse((String) o.get("db_time"));
        assertThat(Duration.between(server, db)).isBetween(SKEW.minus(SKEW_TOLERANCE), SKEW.plus(SKEW_TOLERANCE));
        Map<String, Object> skew = (Map<String, Object>) o.get("clock");
        assertThat(skew.get("state")).isEqualTo("RED");
        assertThat((Long) skew.get("skew_ms")).isBetween(599_000L, 601_000L);
    }

    /** Row: re-enroll collision window, last_ingested_at (Postgres) vs Postgres now() (DECISIONS #91). */
    @Test
    @Order(10)
    void collisionRecentIngestUsesPostgresNow() {
        jdbc.update("UPDATE devices SET last_ingested_at = NOW() - INTERVAL '5 seconds' WHERE device_id = 'dev_clk'");
        assertThat(reEnroll.recentIngest("dev_clk")).isTrue();
        // 40 s ago by Postgres is 9 min 20 s in the JVM's future: a JVM comparison would call it recent.
        jdbc.update("UPDATE devices SET last_ingested_at = NOW() - INTERVAL '40 seconds' WHERE device_id = 'dev_clk'");
        assertThat(reEnroll.recentIngest("dev_clk")).isFalse();
    }
}
