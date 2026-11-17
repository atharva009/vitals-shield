package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.quarantine.QuarantineService;
import com.vitalsshield.server.testsupport.ClinicalStream;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.TelemetryFrames;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
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
 * Deterministic in-flight retraction (Phase 8 0b): the evaluator is paused right after it inserted an alert, still
 * holding its locks (devices FOR KEY SHARE, the telemetry row, the assignment row, the new alert). A quarantine
 * started then must wait on the device row (lock order, DECISIONS #82), and once the evaluation commits it must
 * retract the alert that evaluation created. LockOrderIT remains the randomized stress version.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class InFlightRetractionIT {

    static final String DEV = "dev_inflight";
    static final CountDownLatch REACHED = new CountDownLatch(1);
    static final CountDownLatch RELEASE = new CountDownLatch(1);
    static final AtomicReference<List<UUID>> HELD_ALERTS = new AtomicReference<>();

    @TestConfiguration
    static class Pause {
        @Bean
        ClinicalHooks pauseAfterAlertInsert() {
            return new ClinicalHooks() {
                @Override
                public void beforeEvaluate(String deviceId, UUID batchId) {
                }

                @Override
                public void afterAlertsInserted(String deviceId, UUID batchId, List<UUID> alertIds) {
                    if (DEV.equals(deviceId) && HELD_ALERTS.compareAndSet(null, alertIds)) {
                        REACHED.countDown();
                        try {
                            RELEASE.await(30, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
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
        dir = Files.createTempDirectory("vs-inflight-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired QuarantineService quarantine;
    @Autowired ClinicalEvaluator evaluator;

    @Test
    void quarantineWaitsForTheInFlightEvaluationThenRetractsItsAlert() throws Exception {
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
        SpineFixture.Device d = fx.enroll(DEV);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        try (ClinicalStream s = new ClinicalStream(fx, d, anchors.root(), now.minus(Duration.ofMinutes(2)),
                Duration.ofSeconds(60))) {
            // 1. An acute SpO2 batch (89 %): its evaluation inserts an alert and then pauses in the hook.
            UUID acute = s.send(new TelemetryFrames.Metrics(68, 50, 89.0, 4, 0, 0.02)).batchId();
            assertThat(REACHED.await(15, TimeUnit.SECONDS)).as("evaluator paused after the alert insert").isTrue();
            UUID alert = HELD_ALERTS.get().get(0);

            // 2. Quarantine on another thread: blocked on the device row lock behind the evaluator.
            long t0 = System.nanoTime();
            CompletableFuture<QuarantineService.Result> q = CompletableFuture.supplyAsync(
                    () -> quarantine.quarantine(DEV, 10, "in-flight retraction").block(Duration.ofSeconds(60)));
            Thread.sleep(500);
            assertThat(q.isDone()).as("quarantine still waiting after 500 ms").isFalse();
            assertThat(jdbc.queryForObject("SELECT trust_state::text FROM devices WHERE device_id = ?", String.class,
                    DEV)).isEqualTo("ACTIVE");

            // 3. Release: the evaluation commits its alert, then the quarantine runs and retracts it.
            RELEASE.countDown();
            QuarantineService.Result r = q.get(30, TimeUnit.SECONDS);
            long waitedMs = (System.nanoTime() - t0) / 1_000_000;
            System.out.println("IN_FLIGHT quarantine waited " + waitedMs + " ms; result " + r);
            assertThat(evaluator.awaitIdle(Duration.ofSeconds(10))).isTrue();
            assertThat(jdbc.queryForObject("SELECT alert_status::text FROM clinical_alerts WHERE alert_id = ?",
                    String.class, alert)).isEqualTo("RETRACTED_BY_QUARANTINE");
            assertThat(jdbc.queryForObject("SELECT ? = ANY(triggering_batch_ids) FROM clinical_alerts WHERE alert_id = ?",
                    Boolean.class, acute, alert)).isTrue();
            assertThat(jdbc.queryForObject("SELECT trust_state::text FROM telemetry_records WHERE batch_id = ?",
                    String.class, acute)).isEqualTo("QUARANTINED");
            assertThat(jdbc.queryForObject("SELECT trust_state::text FROM devices WHERE device_id = ?", String.class,
                    DEV)).isEqualTo("QUARANTINED");
        } finally {
            RELEASE.countDown();
        }
    }
}
