package com.vitalsshield.server.drill;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.devtools.DevSeeder;
import com.vitalsshield.server.VitalsShieldServerApplication;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.Simulator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Drill (on demand only): restarts the Compose LocalStack, which wipes every KMS key. The server must rebuild the
 * hierarchy, refuse the old certificate, and let the device recover by re-enrolling with its surviving DEK.
 */
@Tag("drill")
@Testcontainers
class LocalStackRestartDrill {

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    final long t0 = System.nanoTime();
    Path trustFile;
    Path stateRoot;
    TestPorts.Listeners ports;

    @Test
    void localStackRestartRebuildsAndDeviceRecovers() throws Exception {
        Path dir = Files.createTempDirectory("vs-drill");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
        String dev = "dev_drill";

        ConfigurableApplicationContext ctx = start();
        step("server started (first boot)");
        SpineFixture fx = fixture(ctx);
        SpineFixture.Device d = fx.enroll(dev);
        assertThat(stream(d.sim(), 3)).isZero();
        step("1. enrolled and streamed 3 batches");
        String trustBefore = Files.readString(trustFile);
        long retiredBefore = retired(ctx);
        ctx.close();

        restartLocalStack();
        step("2. docker compose restart localstack, healthy again");

        ctx = start();
        step("3. server restarted");
        assertThat(retired(ctx)).as("old keys retired by a rebuild").isEqualTo(retiredBefore + 4);
        assertThat(Files.readString(trustFile)).as("trust file holds the new Root").isNotEqualTo(trustBefore);
        MtlsTestClient.Attempt old = MtlsTestClient.attempt(ports.mtls(), ctx.getBean(TrustAnchors.class).root(),
                d.enrollment().olkKey(), List.of(d.cert()), "/api/v1/telemetry/ping");
        assertThat(old.kind()).as(old.detail()).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);
        step("3. REBUILT confirmed; trust file changed; old certificate refused at the handshake");

        Simulator sim = fixture(ctx).simulator(dev);
        byte[] dekBefore = Files.readAllBytes(sim.store().dekKeyFile());
        sim.store().resetState();
        String token = new DevSeeder(ctx.getBean(JdbcTemplate.class), ctx.getBean(TransactionTemplate.class),
                Clock.systemUTC()).seed(DevSeeder.Request.defaults(dev)).token();
        Simulator.EnrollOutcome again = sim.enroll(token);
        assertThat(again).isInstanceOf(Simulator.EnrollOutcome.Enrolled.class);
        assertThat(((Simulator.EnrollOutcome.Enrolled) again).bootEpoch()).isEqualTo(2);
        assertThat(Files.readAllBytes(sim.store().dekKeyFile())).as("DEK survived the state reset").isEqualTo(dekBefore);
        assertThat(stream(sim, 1)).isZero();
        step("4. reset-state, new token, re-enrolled at boot_epoch=2 with the same DEK, 1 batch accepted");
        ctx.close();
    }

    private ConfigurableApplicationContext start() {
        ports = TestPorts.allocate();
        List<String> args = new ArrayList<>(List.of(
                "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "--spring.datasource.username=" + POSTGRES.getUsername(),
                "--spring.datasource.password=" + POSTGRES.getPassword(),
                "--vitalsshield.pki.trust-file=" + trustFile,
                "--spring.main.keep-alive=false"));
        args.addAll(ports.asArgs());
        return new SpringApplicationBuilder(VitalsShieldServerApplication.class).profiles("local")
                .run(args.toArray(String[]::new));
    }

    private SpineFixture fixture(ConfigurableApplicationContext ctx) {
        return new SpineFixture(ctx.getBean(JdbcTemplate.class), ctx.getBean(TransactionTemplate.class), ports,
                trustFile, stateRoot);
    }

    private static long retired(ConfigurableApplicationContext ctx) {
        return ctx.getBean(JdbcTemplate.class).queryForObject(
                "SELECT count(*) FROM kms_keys WHERE status = 'RETIRED'", Long.class);
    }

    private static int stream(Simulator sim, int n) throws InterruptedException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int exit = sim.stream(0, n, new PrintStream(out, true, StandardCharsets.UTF_8));
        System.out.print(out.toString(StandardCharsets.UTF_8));
        return exit;
    }

    private void restartLocalStack() throws Exception {
        Path repo = Path.of(System.getProperty("vitalsshield.repoRoot", ".."));
        run(repo, "docker", "compose", "restart", "localstack");
        String cid = run(repo, "docker", "compose", "ps", "-q", "localstack").trim();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(120);
        while (System.nanoTime() < deadline) {
            if ("healthy".equals(run(repo, "docker", "inspect", "-f", "{{.State.Health.Status}}", cid).trim())) {
                return;
            }
            Thread.sleep(1000);
        }
        throw new AssertionError("LocalStack did not become healthy");
    }

    private static String run(Path dir, String... cmd) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(p.waitFor(180, TimeUnit.SECONDS)).isTrue();
        assertThat(p.exitValue()).as(String.join(" ", cmd) + ": " + out).isZero();
        return out;
    }

    private void step(String what) {
        System.out.printf("DRILL t+%5d ms  %s%n", (System.nanoTime() - t0) / 1_000_000, what);
    }
}
