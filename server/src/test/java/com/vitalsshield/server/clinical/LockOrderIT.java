package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.telemetry.TelemetryMetrics;
import com.vitalsshield.server.testsupport.AdminHttp;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.testsupport.WebAuthnSteps;
import com.vitalsshield.simulator.Scenario;
import com.vitalsshield.simulator.TelemetryFrames;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
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
 * DECISIONS #70 under load: 8 parallel ingests (each queueing a clinical evaluation that inserts alerts) race a
 * step-up quarantine of the same device, 20 times. No deadlock (SQLSTATE 40P01), the quarantine always succeeds,
 * and no alert survives with a quarantined triggering batch.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class LockOrderIT {

    static final int REPETITIONS = 20;
    static final int INGESTERS = 8;
    static final int MAX_PER_INGESTER = 12;

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-lockorder-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired ClinicalEvaluator evaluator;
    @Autowired TelemetryMetrics metrics;

    /** Alternates metrics that each create an alert when evaluated: SpO2 low (ACCEPTED) and low-perfusion critical. */
    static TelemetryFrames.Metrics metrics(long seq) {
        return seq % 2 == 0 ? new TelemetryFrames.Metrics(68, 50, 89.0, 4, 0, 0.02)
                : Scenario.LOW_PERFUSION_CRITICAL.generate(new Random(seq));
    }

    @Test
    void noDeadlockAcrossTwentyQuarantinesMidStream() throws Exception {
        SoftwareAuthenticator clinician = SoftwareAuthenticator.create();
        AdminHttp admin = new AdminHttp(ports.admin());
        WebAuthnSteps.bootstrapClinician(admin, clinician, "dr_locks", ports.adminCodeFile());
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
        long deadlocksBefore = deadlocks();
        long failuresBefore = metrics.get("clinical.evaluation_failures");
        List<String> summary = new ArrayList<>();

        for (int rep = 1; rep <= REPETITIONS; rep++) {
            String dev = "dev_lock_" + rep;
            SpineFixture.Device d = fx.enrollWithToken(dev, WebAuthnSteps.provision(admin, clinician, dev));
            AtomicLong seq = new AtomicLong();
            AtomicInteger accepted = new AtomicInteger();
            AtomicBoolean stop = new AtomicBoolean();
            ConcurrentLinkedQueue<String> errors = new ConcurrentLinkedQueue<>();
            Instant base = Instant.now().minus(Duration.ofHours(11));
            CountDownLatch go = new CountDownLatch(1);
            ExecutorService pool = Executors.newFixedThreadPool(INGESTERS);
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < INGESTERS; i++) {
                futures.add(pool.submit(() -> {
                    try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
                        go.await();
                        for (int n = 0; n < MAX_PER_INGESTER && !stop.get(); n++) {
                            long s = seq.incrementAndGet();
                            // 6 min apart in measured time: outside each other's acute dedupe window.
                            String jws = SpineFixture.frame(d, s, UUID.randomUUID(), base.plus(Duration.ofMinutes(6 * s)),
                                    metrics(s), d.assignmentId(), d.bootEpoch());
                            MtlsTestClient.Response r = SpineFixture.ingest(c, jws);
                            if (r.status() == 200) {
                                accepted.incrementAndGet();
                            } else {
                                if (r.body() != null && r.body().contains("40P01")) {
                                    errors.add(r.body());
                                }
                                return null;                 // 403 after the quarantine
                            }
                        }
                    } catch (IOException e) {
                        // the quarantine evicted this socket: expected
                    }
                    return null;
                }));
            }
            go.countDown();
            long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while (accepted.get() < 2 * INGESTERS && System.nanoTime() < deadline) {
                Thread.sleep(2);
            }
            AdminHttp.Response q = WebAuthnSteps.quarantine(admin, clinician, dev, 10, "lock order " + rep);
            stop.set(true);
            for (Future<?> f : futures) {
                f.get(30, TimeUnit.SECONDS);
            }
            pool.shutdown();
            assertThat(evaluator.awaitIdle(Duration.ofSeconds(30))).isTrue();

            assertThat(q.status()).as("rep %d: %s", rep, q.body()).isEqualTo(200);
            assertThat(q.body()).doesNotContain("40P01");
            assertThat(errors).as("rep %d", rep).isEmpty();
            long surviving = jdbc.queryForObject("""
                    SELECT count(*) FROM clinical_alerts ca
                     WHERE ca.device_id = ? AND ca.alert_status <> 'RETRACTED_BY_QUARANTINE'
                       AND EXISTS (SELECT 1 FROM telemetry_records t
                                    WHERE t.device_id = ca.device_id AND t.batch_id = ANY(ca.triggering_batch_ids)
                                      AND t.trust_state = 'QUARANTINED')
                    """, Long.class, dev);
            assertThat(surviving).as("rep %d: alerts with a QUARANTINED triggering batch not RETRACTED", rep).isZero();
            long alerts = jdbc.queryForObject("SELECT count(*) FROM clinical_alerts WHERE device_id = ?", Long.class, dev);
            long retracted = jdbc.queryForObject("SELECT count(*) FROM clinical_alerts WHERE device_id = ? "
                    + "AND alert_status = 'RETRACTED_BY_QUARANTINE'", Long.class, dev);
            long evaluated = jdbc.queryForObject("SELECT count(*) FROM telemetry_records WHERE device_id = ? "
                    + "AND clinical_evaluated_at IS NOT NULL", Long.class, dev);
            summary.add("rep=" + rep + " accepted=" + accepted.get() + " evaluated=" + evaluated + " alerts=" + alerts
                    + " retracted=" + retracted + " quarantined_batches=" + q.json().get("batches_quarantined"));
        }
        summary.forEach(l -> System.out.println("LOCK_ORDER " + l));
        assertThat(metrics.get("clinical.evaluation_failures")).as("no evaluation failed (40P01 would count here)")
                .isEqualTo(failuresBefore);
        long deadlocksAfter = deadlocks();
        System.out.println("LOCK_ORDER deadlocks before=" + deadlocksBefore + " after=" + deadlocksAfter);
        assertThat(deadlocksAfter).as("pg_stat_database.deadlocks (SQLSTATE 40P01)").isEqualTo(deadlocksBefore);
    }

    long deadlocks() throws InterruptedException {
        Thread.sleep(1500); // statistics are flushed asynchronously
        jdbc.execute("SELECT pg_stat_clear_snapshot()");
        return jdbc.queryForObject("SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()", Long.class);
    }
}
