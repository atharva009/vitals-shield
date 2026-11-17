package com.vitalsshield.server.renewal;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.telemetry.TelemetryMetrics;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.Renewals;
import com.vitalsshield.simulator.CertIds;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.nio.file.Files;
import java.nio.file.Path;
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

/**
 * Five first batches signed by the same ISSUED_PENDING_USE certificate, sent at once on five connections: exactly one
 * switchover, no unique-index violation (SQLSTATE 23505), one ACTIVE and one RENEWED row, and all five accepted.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class ActivationConcurrencyIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-activation-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;

    SpineFixture fx() {
        return new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
    }

    @Autowired CertificateActivationService activation;
    @Autowired TelemetryMetrics metrics;

    @Test
    void fiveParallelFirstBatchesSwitchOverOnce() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_act_conc");
        Renewals.Identity old = Renewals.identity(d);
        Renewals.Identity next;
        try (MtlsTestClient.Connection c = Renewals.connect(ports.mtls(), anchors.root(), old)) {
            next = Renewals.renewOk(c, old, d.deviceId());
        }
        SpineFixture.Device asNext = next.as(d);
        long activationsBefore = metrics.get("renewal.activations");
        List<MtlsTestClient.Connection> conns = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            conns.add(Renewals.connect(ports.mtls(), anchors.root(), next));
        }
        ExecutorService pool = Executors.newFixedThreadPool(5);
        CountDownLatch go = new CountDownLatch(1);
        try {
            List<Future<MtlsTestClient.Response>> results = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                MtlsTestClient.Connection c = conns.get(i);
                String jws = SpineFixture.frame(asNext, i + 1, UUID.randomUUID());
                results.add(pool.submit(() -> {
                    go.await();
                    return SpineFixture.ingest(c, jws);
                }));
            }
            go.countDown();
            for (Future<MtlsTestClient.Response> f : results) {
                MtlsTestClient.Response r = f.get();
                assertThat(r.status()).as(r.body()).isEqualTo(200);
            }
        } finally {
            pool.shutdownNow();
            for (MtlsTestClient.Connection c : conns) {
                c.close();
            }
        }
        assertThat(activation.awaitIdle(Duration.ofSeconds(15))).isTrue();

        assertThat(metrics.get("renewal.activations") - activationsBefore).as("switchovers").isEqualTo(1);
        assertThat(metrics.get("renewal.activation_failures")).as("failed activations (23505 would land here)")
                .isZero();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT serial_number, status::text AS status FROM certificates WHERE device_id = ? ORDER BY issued_at",
                d.deviceId());
        assertThat(rows).extracting(r -> r.get("status")).containsExactly("RENEWED", "ACTIVE");
        assertThat(rows.get(1).get("serial_number")).isEqualTo(CertIds.serial(next.cert()));
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM telemetry_records WHERE device_id = ? AND serial_number = ?
                """, Integer.class, d.deviceId(), CertIds.serial(next.cert()))).as("all five accepted").isEqualTo(5);
    }
}
