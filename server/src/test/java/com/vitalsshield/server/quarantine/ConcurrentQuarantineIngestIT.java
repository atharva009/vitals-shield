package com.vitalsshield.server.quarantine;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Tag;
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
 * DECISIONS #42: 8 threads ingest as fast as they can while quarantine fires. Eviction is off, so only the per-request
 * layer and the row lock stand between in-flight ingests and the sanitize statement.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest(properties = "vitalsshield.eviction.enabled=false")
class ConcurrentQuarantineIngestIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-qrace-it");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired QuarantineService quarantine;

    record Sent(long startedNanos, int status, String body, String error) {
    }

    @RepeatedTest(5)
    void noAcceptedRowSurvivesAndNothingIsAcceptedAfterCommit(RepetitionInfo info) throws Exception {
        String dev = "dev_qrace_" + info.getCurrentRepetition();
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, trustFile, stateRoot);
        SpineFixture.Device d = fx.enroll(dev);
        AtomicLong seq = new AtomicLong();
        AtomicBoolean stop = new AtomicBoolean();
        ConcurrentLinkedQueue<Sent> sent = new ConcurrentLinkedQueue<>();
        AtomicInteger accepted = new AtomicInteger();

        ExecutorService pool = Executors.newFixedThreadPool(8);
        for (int t = 0; t < 8; t++) {
            pool.submit(() -> {
                MtlsTestClient.Connection c = null;
                while (!stop.get()) {
                    long started = System.nanoTime();
                    try {
                        if (c == null) {
                            c = fx.connect(d, anchors.root());
                        }
                        MtlsTestClient.Response r = SpineFixture.ingest(c, SpineFixture.frame(d, seq.incrementAndGet(),
                                UUID.randomUUID()));
                        sent.add(new Sent(started, r.status(), r.body(), null));
                        if (r.status() == 200) {
                            accepted.incrementAndGet();
                        }
                    } catch (IOException e) {
                        sent.add(new Sent(started, -1, null, e.toString()));
                        if (c != null) {
                            c.close();
                        }
                        c = null;
                    }
                }
                if (c != null) {
                    c.close();
                }
                return null;
            });
        }
        // Let traffic build, then quarantine mid-stream.
        long warmupDeadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (accepted.get() < 40 && System.nanoTime() < warmupDeadline) {
            Thread.sleep(5);
        }
        QuarantineService.Result result = quarantine.quarantine(dev, 60, "race test").block(Duration.ofSeconds(30));
        long committedNanos = System.nanoTime();
        Thread.sleep(300);
        stop.set(true);
        pool.shutdown();
        assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

        int leftover = jdbc.queryForObject("""
                SELECT count(*) FROM telemetry_records
                 WHERE device_id = ? AND trust_state IN ('ACCEPTED', 'SIGNAL_DEGRADED')
                   AND (ingested_at >= NOW() - INTERVAL '60 minutes' OR measured_at >= NOW() - INTERVAL '60 minutes')
                """, Integer.class, dev);
        List<Sent> afterCommit = sent.stream().filter(s -> s.startedNanos() > committedNanos).toList();
        long ok = sent.stream().filter(s -> s.status() == 200).count();
        System.out.printf("QRACE run %d: sent=%d ok=%d quarantined=%d afterCommit=%d latency_us=%d%n",
                info.getCurrentRepetition(), sent.size(), ok, result.batchesQuarantined(), afterCommit.size(),
                result.revocationLatencyMicros());

        assertThat(leftover).as("ACCEPTED/SIGNAL_DEGRADED rows left in the lookback window").isZero();
        assertThat(result.batchesQuarantined()).isEqualTo(ok);
        assertThat(afterCommit).isNotEmpty();
        assertThat(afterCommit).allSatisfy(s -> assertThat(s.status() == 403 || s.status() == -1)
                .as("after commit: %s %s %s", s.status(), s.body(), s.error()).isTrue());
    }
}
