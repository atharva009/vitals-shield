package com.vitalsshield.server.reenroll;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.ReEnrolls;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.GatewayClient;
import com.vitalsshield.simulator.Simulator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
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

/** DECISIONS #91: the re-enroll collision fires on a usable certificate in use, never on an expired one. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class CollisionIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-collision-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired ActiveSessionRegistry sessions;

    SpineFixture fx() {
        return new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
    }

    Simulator simAt(Path stateRoot, String deviceId) {
        return new Simulator(new Simulator.Config(deviceId, stateRoot, dir.resolve("root-ca.pem"),
                URI.create("https://127.0.0.1:" + ports.pub()), URI.create("https://127.0.0.1:" + ports.mtls())),
                Clock.systemUTC());
    }

    @Test
    void clonedDekReEnrollingWhileTheDeviceStreamsIsReauthRequired() throws Exception {
        String dev = "dev_collide";
        SpineFixture.Device d = fx().enroll(dev);
        Path cloneRoot = dir.resolve("clone-" + dev);
        d.sim().store().cloneTo(cloneRoot);
        Simulator clone = simAt(cloneRoot, dev);
        CertKey key = CertKey.from(d.cert());

        // The real device streams (a live keep-alive socket), and the clone holds a socket with the copied OLK too.
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(buf, true, StandardCharsets.UTF_8);
        CompletableFuture<Integer> stream = CompletableFuture.supplyAsync(() -> {
            try {
                return d.sim().stream(300, 0, out);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        });
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (buf.toString(StandardCharsets.UTF_8).lines().filter(l -> l.contains("status=200")).count() < 3) {
            assertThat(System.nanoTime()).as("device streaming: " + buf).isLessThan(deadline);
            Thread.sleep(50);
        }
        long acceptedBefore = jdbc.queryForObject(
                "SELECT count(*) FROM telemetry_records WHERE device_id = ? AND trust_state = 'ACCEPTED'", Long.class, dev);
        try (MtlsTestClient.Connection cloneSocket = MtlsTestClient.connect(ports.mtls(), anchors.root(),
                d.enrollment().olkKey(), List.of(d.cert()))) {
            assertThat(cloneSocket.get("/api/v1/telemetry/ping").status()).isEqualTo(200);
            assertThat(sessions.liveSocketsFor(key)).hasSizeGreaterThanOrEqualTo(2);

            Simulator.ReEnrollOutcome o = clone.reEnroll();
            assertThat(o).isEqualTo(new Simulator.ReEnrollOutcome.Reauth(409, "REAUTH_REQUIRED"));

            assertThat(cloneSocket.awaitClosedWithin(Duration.ofSeconds(3))).as("clone socket evicted").isTrue();
        }
        int exit = stream.get(15, TimeUnit.SECONDS);
        assertThat(exit).as("the real device is refused: " + buf).isEqualTo(3);
        assertThat(sessions.liveSocketsFor(key)).as("both sockets evicted").isEmpty();

        assertThat(jdbc.queryForObject("SELECT trust_state::text FROM devices WHERE device_id = ?", String.class, dev))
                .isEqualTo("REAUTH_REQUIRED");
        assertThat(jdbc.queryForList("SELECT DISTINCT revocation_reason FROM certificates WHERE device_id = ?",
                String.class, dev)).containsExactly("SUSPECTED_CLONE");
        assertThat(jdbc.queryForList("SELECT condition_code FROM clinical_alerts WHERE device_id = ? "
                + "AND alert_type = 'SECURITY_ANOMALY_ALERT'", String.class, dev)).containsExactly("REENROLL_COLLISION");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM telemetry_records WHERE device_id = ? "
                + "AND trust_state <> 'ACCEPTED'", Long.class, dev)).as("telemetry still ACCEPTED").isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM telemetry_records WHERE device_id = ?", Long.class, dev))
                .isGreaterThanOrEqualTo(acceptedBefore);
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM security_audit_log WHERE event_type = 'SECURITY_ANOMALY'
                   AND payload_json->>'device_id' = ? AND payload_json->>'condition_code' = 'REENROLL_COLLISION'
                """, Long.class, dev)).isEqualTo(1);
    }

    @Test
    void expiredCertificateWithAnIngestFiveSecondsAgoIsNormalRecovery() throws Exception {
        String dev = "dev_sleep";
        SpineFixture.Device d = fx().enroll(dev);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        assertThat(d.sim().stream(100, 2, new PrintStream(buf, true, StandardCharsets.UTF_8))).isZero();
        // The laptop-sleep case: the last batch 5 s ago (Postgres-stamped), the certificate already past not_after.
        jdbc.update("UPDATE devices SET last_ingested_at = NOW() - INTERVAL '5 seconds' WHERE device_id = ?", dev);
        jdbc.update("UPDATE certificates SET not_after = NOW() - INTERVAL '1 second' WHERE device_id = ?", dev);

        GatewayClient.Response r = ReEnrolls.post(ports, dir.resolve("root-ca.pem"),
                ReEnrolls.body(d, ReEnrolls.challenge(ports, dir.resolve("root-ca.pem"), dev), 1));
        assertThat(r.status()).as(r.body()).isEqualTo(200);
        assertThat(jdbc.queryForObject("SELECT trust_state::text FROM devices WHERE device_id = ?", String.class, dev))
                .isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM clinical_alerts WHERE device_id = ?", Long.class, dev))
                .as("no anomaly").isZero();
        Map<String, Object> newest = jdbc.queryForMap("SELECT status::text AS s, reenroll_reason FROM certificates "
                + "WHERE device_id = ? AND issued_via = 'REENROLL'", dev);
        assertThat(newest).containsEntry("s", "ACTIVE").containsEntry("reenroll_reason", "cert_expired");
    }
}
