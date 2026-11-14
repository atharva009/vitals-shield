package com.vitalsshield.server.telemetry;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** Spec Section 5: concurrent duplicates are serialized by the devices row lock; no 23505, no 500. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@ExtendWith(OutputCaptureExtension.class)
class ConcurrentDuplicateIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-dup-it");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    SpineFixture fx;

    @BeforeEach
    void fixture() {
        fx = new SpineFixture(jdbc, tx, ports, trustFile, stateRoot);
    }

    @Test
    void twentyIdenticalFramesStoreOneRow(CapturedOutput output) throws Exception {
        SpineFixture.Device d = fx.enroll("dev_dup_same");
        String jws = SpineFixture.frame(d, 1, UUID.randomUUID());

        List<MtlsTestClient.Response> rs = parallel(20, () -> post(d, jws));

        assertThat(rs).allSatisfy(r -> assertThat(r.status()).as(r.body()).isEqualTo(200));
        assertThat(rs.stream().filter(r -> r.body().contains("\"idempotent_retry\":false")).count()).isEqualTo(1);
        assertThat(rs.stream().filter(r -> r.body().contains("\"idempotent_retry\":true")).count()).isEqualTo(19);
        assertThat(rows("dev_dup_same")).isEqualTo(1);
        assertThat(output.getAll()).doesNotContain("23505").doesNotContain("duplicate key value");
        assertThat(POSTGRES.getLogs()).doesNotContain("duplicate key value");
    }

    @Test
    void sameSequenceDifferentBatchesAcceptsOne() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_dup_seq");
        List<String> frames = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            frames.add(SpineFixture.frame(d, 1, UUID.randomUUID()));
        }
        java.util.concurrent.atomic.AtomicInteger next = new java.util.concurrent.atomic.AtomicInteger();

        List<MtlsTestClient.Response> rs = parallel(20, () -> post(d, frames.get(next.getAndIncrement())));

        assertThat(rs.stream().filter(r -> r.status() == 200).count()).isEqualTo(1);
        assertThat(rs.stream().filter(r -> r.status() == 409 && r.body().contains("DUPLICATE_SEQUENCE_REPLAY")).count())
                .isEqualTo(19);
        assertThat(rows("dev_dup_seq")).isEqualTo(1);
    }

    @Test
    void batchIdReusedUnderNewSequenceConsumesThatSequence() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_dup_batch");
        UUID batch = UUID.randomUUID();
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            assertThat(SpineFixture.ingest(c, SpineFixture.frame(d, 1, batch)).status()).isEqualTo(200);

            MtlsTestClient.Response reused = SpineFixture.ingest(c, SpineFixture.frame(d, 2, batch));
            assertThat(reused.status()).isEqualTo(409);
            assertThat(reused.body()).contains("BATCH_ID_REUSED");

            MtlsTestClient.Response seq2 = SpineFixture.ingest(c, SpineFixture.frame(d, 2, UUID.randomUUID()));
            assertThat(seq2.status()).isEqualTo(409);
            assertThat(seq2.body()).as("sequence 2 was consumed").contains("DUPLICATE_SEQUENCE_REPLAY");
        }
        assertThat(rows("dev_dup_batch")).isEqualTo(1);
    }

    private MtlsTestClient.Response post(SpineFixture.Device d, String jws) throws IOException {
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            return SpineFixture.ingest(c, jws);
        }
    }

    private int rows(String deviceId) {
        return jdbc.queryForObject("SELECT count(*) FROM telemetry_records WHERE device_id = ?", Integer.class, deviceId);
    }

    /** Opens all connections first, then releases every request at once. */
    private static List<MtlsTestClient.Response> parallel(int n, Callable<MtlsTestClient.Response> call) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch go = new CountDownLatch(1);
        try {
            List<Future<MtlsTestClient.Response>> fs = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                fs.add(pool.submit(() -> {
                    go.await();
                    return call.call();
                }));
            }
            go.countDown();
            List<MtlsTestClient.Response> out = new ArrayList<>();
            for (Future<MtlsTestClient.Response> f : fs) {
                out.add(f.get(60, TimeUnit.SECONDS));
            }
            return out;
        } finally {
            pool.shutdownNow();
        }
    }
}
