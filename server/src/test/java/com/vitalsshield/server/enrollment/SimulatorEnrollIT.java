package com.vitalsshield.server.enrollment;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.devtools.DevSeeder;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.SimulatorMain;
import com.vitalsshield.simulator.SimulatorStateStore;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** The simulator CLI (SimulatorMain, in-process) against real listeners: enroll, persist, restart, ping. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class SimulatorEnrollIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-sim-it");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim-state");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired EnrollmentController enrollmentController;

    record Run(int exit, String out) {
    }

    @Test
    void enrollPersistAndPing() {
        String token = seed("dev_sim_a");

        Run enroll = cli("enroll", "--device-id", "dev_sim_a", "--token", token);
        assertThat(enroll.exit()).as(enroll.out()).isZero();
        Matcher m = Pattern.compile("ENROLLED serial=([0-9a-f]+) boot_epoch=1 not_after=\\S+").matcher(enroll.out());
        assertThat(m.find()).as(enroll.out()).isTrue();
        String serial = m.group(1);

        SimulatorStateStore store = new SimulatorStateStore(stateRoot, "dev_sim_a");
        assertThat(store.load().orElseThrow().olkCert().getSerialNumber().toString(16)).isEqualTo(serial);
        assertThat(store.load().orElseThrow().state().bootEpoch()).isEqualTo(1);
        assertThat(store.load().orElseThrow().state().sequenceNumber()).isZero();

        Run ping = cli("ping", "--device-id", "dev_sim_a");
        assertThat(ping.exit()).as(ping.out()).isZero();
        assertThat(ping.out()).startsWith("200 ").contains("\"serial\":\"" + serial + "\"");
    }

    @Test
    void restartDoesNotReenroll() {
        String token = seed("dev_sim_b");
        Run first = cli("enroll", "--device-id", "dev_sim_b", "--token", token);
        assertThat(first.exit()).as(first.out()).isZero();
        String serial = first.out().replaceAll("(?s).*serial=([0-9a-f]+).*", "$1");

        long requestsBefore = enrollmentController.requestCount();
        // A fresh process on the same state dir (each cli() call is a new Simulator instance).
        Run again = cli("enroll", "--device-id", "dev_sim_b", "--token", token);

        assertThat(again.exit()).isZero();
        assertThat(again.out().trim()).isEqualTo("ALREADY_ENROLLED serial=" + serial);
        assertThat(enrollmentController.requestCount()).as("no HTTP enroll call").isEqualTo(requestsBefore);

        Run ping = cli("ping", "--device-id", "dev_sim_b");
        assertThat(ping.out()).startsWith("200 ").contains("\"serial\":\"" + serial + "\"");
    }

    @Test
    void resetStateKeepsDek() throws IOException {
        String token = seed("dev_sim_c");
        assertThat(cli("enroll", "--device-id", "dev_sim_c", "--token", token).exit()).isZero();
        SimulatorStateStore store = new SimulatorStateStore(stateRoot, "dev_sim_c");
        byte[] dekBefore = Files.readAllBytes(store.dekKeyFile());

        Run reset = cli("reset-state", "--device-id", "dev_sim_c");

        assertThat(reset.exit()).isZero();
        assertThat(Files.readAllBytes(store.dekKeyFile())).isEqualTo(dekBefore);
        assertThat(store.olkCertFile()).doesNotExist();
        assertThat(store.stateFile()).doesNotExist();
    }

    private String seed(String deviceId) {
        return new DevSeeder(jdbc, tx, Clock.systemUTC()).seed(DevSeeder.Request.defaults(deviceId)).token();
    }

    private Run cli(String... args) {
        List<String> all = new ArrayList<>(List.of(args));
        all.addAll(List.of("--state-dir", stateRoot.toString(), "--trust-file", trustFile.toString(),
                "--public-url", "https://127.0.0.1:" + ports.pub(), "--mtls-url", "https://127.0.0.1:" + ports.mtls()));
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(buf, true, StandardCharsets.UTF_8);
        int exit = SimulatorMain.run(all.toArray(String[]::new), ps, ps);
        return new Run(exit, buf.toString(StandardCharsets.UTF_8));
    }
}
