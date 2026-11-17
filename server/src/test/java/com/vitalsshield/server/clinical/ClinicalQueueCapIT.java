package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.admin.AdminOverviewService;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.ClinicalStream;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.Scenario;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * DECISIONS #79: with queue-capacity 2 and the evaluator paused, a third batch is still accepted by ingest (200), is
 * never evaluated, and is counted as an overflow and as unevaluated on the overview.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class ClinicalQueueCapIT {

    static final String DEV = "dev_queue_cap";
    static final CountDownLatch RELEASE = new CountDownLatch(1);

    @TestConfiguration
    static class Pause {
        @Bean
        ClinicalHooks pauseBeforeEvaluate() {
            return (deviceId, batchId) -> {
                if (DEV.equals(deviceId)) {
                    try {
                        RELEASE.await(30, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            };
        }
    }

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-queue-cap-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        registry.add("vitalsshield.clinical.queue-capacity", () -> "2");
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired ClinicalEvaluator evaluator;
    @Autowired AdminOverviewService overview;

    @Test
    @SuppressWarnings("unchecked")
    void thirdBatchOverflowsAndStaysUnevaluated() throws Exception {
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
        SpineFixture.Device d = fx.enroll(DEV);
        UUID third;
        try (ClinicalStream s = new ClinicalStream(fx, d, anchors.root(),
                Instant.now().truncatedTo(ChronoUnit.SECONDS).minus(Duration.ofMinutes(5)), Duration.ofSeconds(60))) {
            s.send(Scenario.RESTING);                         // running, paused in the hook
            s.send(Scenario.RESTING);                         // queued behind it
            assertThat(evaluator.pending()).isEqualTo(2);
            third = s.send(Scenario.RESTING).batchId();       // ClinicalStream fails unless the answer is 200
        }
        assertThat(evaluator.pending()).as("the third batch was not queued").isEqualTo(2);
        RELEASE.countDown();
        assertThat(evaluator.awaitIdle(Duration.ofSeconds(15))).isTrue();

        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM telemetry_records WHERE device_id = ? AND clinical_evaluated_at IS NOT NULL
                """, Integer.class, DEV)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT clinical_evaluated_at IS NULL FROM telemetry_records WHERE batch_id = ?",
                Boolean.class, third)).isTrue();
        Map<String, Object> clinical = (Map<String, Object>) overview.snapshot().get("clinical");
        System.out.println("QUEUE_CAP overview clinical " + clinical);
        assertThat(clinical).containsEntry("queue_overflows", 1L).containsEntry("unevaluated_count", 1L)
                .containsEntry("queue_capacity", 2);
    }
}
