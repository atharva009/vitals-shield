package com.vitalsshield.server.anomaly;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.renewal.CertificateActivationService;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.Renewals;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
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

/** DECISIONS #94 against the real listeners: TTL PT2M, grace PT3S, slack 5 s. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class PostDrainTrapIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-postdrain-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        registry.add("vitalsshield.pki.leaf-ttl", () -> "PT2M");
        registry.add("vitalsshield.pki.renewal-grace", () -> "PT3S");
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired CertificateActivationService activation;

    MtlsTestClient.Attempt ping(Renewals.Identity id) {
        return MtlsTestClient.attempt(ports.mtls(), anchors.root(), id.key(), List.of(id.cert()),
                "/api/v1/telemetry/ping");
    }

    String state(String dev) {
        return jdbc.queryForObject("SELECT trust_state::text FROM devices WHERE device_id = ?", String.class, dev);
    }

    long anomalies(String dev) {
        return jdbc.queryForObject("SELECT count(*) FROM clinical_alerts WHERE device_id = ? "
                + "AND alert_type = 'SECURITY_ANOMALY_ALERT'", Long.class, dev);
    }

    @Test
    void oldCertificateWithinGraceIsFineAfterGracePlusSixIsAnAnomaly() throws Exception {
        String dev = "dev_postdrain";
        SpineFixture.Device d = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"))
                .enroll(dev);
        Renewals.Identity old = Renewals.identity(d);
        Renewals.Identity next;
        try (MtlsTestClient.Connection c = Renewals.connect(ports.mtls(), anchors.root(), old)) {
            next = Renewals.renewOk(c, old, dev);
        }
        try (MtlsTestClient.Connection n = Renewals.connect(ports.mtls(), anchors.root(), next)) {
            MtlsTestClient.Response b = SpineFixture.ingest(n, SpineFixture.frame(next.as(d), 1, UUID.randomUUID()));
            assertThat(b.status()).as(b.body()).isEqualTo(200);
        }
        assertThat(activation.awaitIdle(Duration.ofSeconds(10))).isTrue();
        Instant grace = jdbc.queryForObject("SELECT grace_expires_at FROM certificates WHERE serial_number = ?",
                Timestamp.class, old.cert().getSerialNumber().toString(16)).toInstant();

        // Within grace: the old certificate still works and nothing is raised.
        assertThat(ping(old).is200()).isTrue();
        Thread.sleep(600); // more than one drain interval
        assertThat(anomalies(dev)).isZero();
        assertThat(state(dev)).isEqualTo("ACTIVE");

        // Grace + 6 s: the handshake is refused, and the attempt is a post-drain anomaly.
        Thread.sleep(Math.max(0, Duration.between(Instant.now(), grace.plusSeconds(6)).toMillis()) + 200);
        assertThat(ping(old).kind()).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);
        long deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
        while (!"REAUTH_REQUIRED".equals(state(dev)) && System.nanoTime() < deadline) {
            Thread.sleep(50);
        }
        assertThat(state(dev)).isEqualTo("REAUTH_REQUIRED");
        assertThat(jdbc.queryForObject("SELECT condition_code FROM clinical_alerts WHERE device_id = ? "
                + "AND alert_type = 'SECURITY_ANOMALY_ALERT'", String.class, dev)).isEqualTo("POST_DRAIN_USE");
        assertThat(ping(next).kind()).as("the successor is revoked too").isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);
    }
}
