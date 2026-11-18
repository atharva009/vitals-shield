package com.vitalsshield.server.signer;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** DECISIONS #96: a revocation made by direct SQL (no deny-list add, no eviction) is enforced within 4 s. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class BackstopPollerIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-backstop-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired CertificateDenyList denyList;

    @Test
    void directSqlRevocationClosesTheLiveSocketWithinFourSeconds() throws Exception {
        SpineFixture.Device d = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"))
                .enroll("dev_backstop");
        CertKey key = CertKey.from(d.cert());
        try (MtlsTestClient.Connection c = MtlsTestClient.connect(ports.mtls(), anchors.root(),
                d.enrollment().olkKey(), List.of(d.cert()))) {
            assertThat(c.get("/api/v1/telemetry/ping").status()).isEqualTo(200);

            // Bypasses SignerRevocationService: nothing in this process hears about it. revoked_at is set to a
            // nonsense value on purpose; the poller's window uses revoked_db_at, stamped by Postgres (V7 trigger).
            long t0 = System.nanoTime();
            jdbc.update("""
                    UPDATE certificates SET status = 'REVOKED', revocation_reason = 'KEY_COMPROMISE',
                           revoked_at = TIMESTAMPTZ '2020-01-01 00:00:00+00'
                     WHERE issuer_key_hash = ? AND serial_number = ?
                    """, key.issuerKeyHash(), key.serial());
            assertThat(denyList.isDenied(key)).as("not yet known in memory").isFalse();

            assertThat(c.awaitClosedWithin(Duration.ofSeconds(4))).as("socket closed by the backstop").isTrue();
            long ms = (System.nanoTime() - t0) / 1_000_000;
            System.out.println("BACKSTOP_EVICTION_MS=" + ms);
            assertThat(ms).isLessThanOrEqualTo(4000);
        }
        assertThat(denyList.isDenied(key)).isTrue();
        assertThat(jdbc.queryForObject("SELECT revoked_db_at IS NOT NULL FROM certificates WHERE serial_number = ?",
                Boolean.class, key.serial())).isTrue();
        assertThat(MtlsTestClient.attempt(ports.mtls(), anchors.root(), d.enrollment().olkKey(), List.of(d.cert()),
                "/api/v1/telemetry/ping").kind()).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);
    }
}
