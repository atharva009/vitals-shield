package com.vitalsshield.server.telemetry;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.GatewayClient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
import org.testcontainers.DockerClientFactory;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Ingest degraded mode (spec Section 4, DECISIONS #103): the database stops in the middle of a simulator stream and
 * comes back. While it is down, ingest answers 503 STORE_UNAVAILABLE with a Retry-After of 3 to 8 s; the simulator
 * resends the same frame (same batch_id and sequence number) until it is answered, and afterwards every sequence number
 * is stored exactly once.
 *
 * <p>The container is stopped and started with the Docker API (not Testcontainers' stop, which removes it), on a
 * fixed host port, so the data and the JDBC URL survive the outage.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class DbDownIngestIT {

    static final int PG_HOST_PORT = freePort();
    static final int FRAMES = 40;

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16")
            .withCreateContainerCmdModifier(cmd -> cmd.getHostConfig().withPortBindings(
                    new PortBinding(Ports.Binding.bindPort(PG_HOST_PORT), new ExposedPort(5432))));

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-dbdown-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;

    /** A PrintStream whose text can be read while the stream thread writes. */
    static final class Captured {
        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        final PrintStream out = new PrintStream(buf, true, StandardCharsets.UTF_8);

        synchronized String text() {
            return buf.toString(StandardCharsets.UTF_8);
        }

        long count(String regex) {
            return Pattern.compile(regex).matcher(text()).results().count();
        }
    }

    @Test
    void databaseOutageMidStreamIs503ThenTheSameFrameIsAcceptedAndNothingIsLostOrDuplicated() throws Exception {
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
        SpineFixture.Device streaming = fx.enroll("dev_dbdown_stream");
        SpineFixture.Device probe = fx.enroll("dev_dbdown_probe");

        Captured log = new Captured();
        CompletableFuture<Integer> run = CompletableFuture.supplyAsync(() -> {
            try {
                return streaming.sim().stream(250, FRAMES, log.out);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        });

        awaitUntil(() -> log.count("status=200") >= 5, Duration.ofSeconds(30), log);
        String containerId = POSTGRES.getContainerId();
        DockerClientFactory.instance().client().stopContainerCmd(containerId).withTimeout(10).exec();

        // A frame sent while the database is down: 503, Retry-After 3 to 8 s, STORE_UNAVAILABLE, nothing stored.
        UUID probeBatch = UUID.randomUUID();
        String probeFrame = SpineFixture.frame(probe, 1, probeBatch);
        URI ingest = URI.create("https://127.0.0.1:" + ports.mtls() + "/api/v1/telemetry/ingest");
        List<GatewayClient.Response> during = new ArrayList<>();
        try (GatewayClient c = GatewayClient.mtlsClient(dir.resolve("root-ca.pem"), probe.enrollment().olkKey(),
                probe.cert())) {
            for (int i = 0; i < 2; i++) {
                during.add(c.postJose(ingest, probeFrame));
            }
        }
        for (GatewayClient.Response r : during) {
            assertThat(r.status()).as(r.body()).isEqualTo(503);
            assertThat(r.body()).isEqualTo("{\"error\":\"STORE_UNAVAILABLE\"}");
            int retryAfter = Integer.parseInt(r.headers().firstValue("Retry-After").orElseThrow());
            assertThat(retryAfter).isBetween(3, 8);
        }
        awaitUntil(() -> log.count("status=503") >= 1, Duration.ofSeconds(30), log);

        DockerClientFactory.instance().client().startContainerCmd(containerId).exec();

        // The same probe frame (same batch_id and sequence number) once the database is back.
        GatewayClient.Response after = null;
        long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        try (GatewayClient c = GatewayClient.mtlsClient(dir.resolve("root-ca.pem"), probe.enrollment().olkKey(),
                probe.cert())) {
            while (System.nanoTime() < deadline) {
                after = c.postJose(ingest, probeFrame);
                if (after.status() != 503) {
                    break;
                }
                Thread.sleep(1000);
            }
        }
        assertThat(after).isNotNull();
        assertThat(after.status()).as(after.body()).isEqualTo(200);
        assertThat(after.body()).contains("\"batch_id\":\"" + probeBatch + "\"");

        int exit = run.get(120, TimeUnit.SECONDS);
        String out = log.text();
        System.out.println("DbDownIngestIT simulator output:\n" + out);   // evidence in the JUnit XML
        assertThat(exit).as(out).isZero();

        // Every 503 in the simulator's log is followed by a 200 for the same sequence number and batch id.
        Matcher m = Pattern.compile("SENT seq=(\\d+) batch=(\\w+) status=503").matcher(out);
        int retried = 0;
        while (m.find()) {
            String seq = m.group(1);
            String batch = m.group(2);
            assertThat(out).as("seq %s batch %s answered after the outage", seq, batch)
                    .containsPattern("SENT seq=" + seq + " batch=" + batch + " status=200");
            retried++;
        }
        assertThat(retried).as(out).isPositive();
        assertThat(out).doesNotContain("status=500");

        // Nothing lost, nothing duplicated: sequence numbers 1..FRAMES, each stored once with its own batch id.
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT sequence_number, batch_id FROM telemetry_records WHERE device_id = ? ORDER BY sequence_number
                """, streaming.deviceId());
        assertThat(rows).hasSize(FRAMES);
        for (int i = 0; i < FRAMES; i++) {
            assertThat(((Number) rows.get(i).get("sequence_number")).longValue()).isEqualTo(i + 1L);
        }
        assertThat(rows.stream().map(r -> r.get("batch_id")).distinct().count()).isEqualTo(FRAMES);
        assertThat(jdbc.queryForObject("SELECT last_sequence_num FROM devices WHERE device_id = ?", Long.class,
                streaming.deviceId())).isEqualTo((long) FRAMES);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM telemetry_records WHERE device_id = ?", Long.class,
                probe.deviceId())).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM clinical_alerts WHERE alert_type = "
                + "'SECURITY_ANOMALY_ALERT'", Long.class)).as("an outage is not an anomaly").isZero();
    }

    interface Check {
        boolean ok();
    }

    static void awaitUntil(Check check, Duration timeout, Captured log) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!check.ok()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out; simulator output:\n" + log.text());
            }
            Thread.sleep(100);
        }
    }

    static int freePort() {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
