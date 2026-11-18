package com.vitalsshield.server.anomaly;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.testsupport.AdminHttp;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.testsupport.WebAuthnSteps;
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

/**
 * Split-brain end to end (spec Section 2 layer 5): two simulators from the same state (the clone command) stream at
 * once. The sequence-regression trap (DECISIONS #93) makes the device REAUTH_REQUIRED, both copies are refused, and no
 * telemetry changes. A clinician restores with a passkey step-up; the original re-enrolls with an epoch resync; the
 * clone's later re-enrollment presents the old epoch and is refused (BOOT_EPOCH_REGRESSION) with a second anomaly.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class CloneTrapIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;
    static final SoftwareAuthenticator ALICE = SoftwareAuthenticator.create();

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-clonetrap-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;

    Simulator simAt(Path stateRoot, String deviceId) {
        return new Simulator(new Simulator.Config(deviceId, stateRoot, dir.resolve("root-ca.pem"),
                URI.create("https://127.0.0.1:" + ports.pub()), URI.create("https://127.0.0.1:" + ports.mtls())),
                Clock.systemUTC());
    }

    String state(String dev) {
        return jdbc.queryForObject("SELECT trust_state::text FROM devices WHERE device_id = ?", String.class, dev);
    }

    List<String> anomalyCodes(String dev) {
        return jdbc.queryForList("SELECT condition_code FROM clinical_alerts WHERE device_id = ? "
                + "AND alert_type = 'SECURITY_ANOMALY_ALERT' ORDER BY created_at", String.class, dev);
    }

    String telemetry(String dev) {
        return jdbc.queryForList("SELECT batch_id::text || ':' || trust_state::text FROM telemetry_records "
                + "WHERE device_id = ? ORDER BY ingested_at, batch_id", String.class, dev).toString();
    }

    static CompletableFuture<Integer> streamAsync(Simulator sim, PrintStream out) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return sim.stream(300, 0, out);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        });
    }

    @Test
    void twoCopiesStreamingTripTheTrapThenRestoreLetsOnlyTheOriginalBack() throws Exception {
        String dev = "dev_clone_trap";
        AdminHttp alice = new AdminHttp(ports.admin());
        WebAuthnSteps.bootstrapClinician(alice, ALICE, "dr_alice", ports.adminCodeFile());
        SpineFixture.Device d = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"))
                .enrollWithToken(dev, WebAuthnSteps.provision(alice, ALICE, dev));
        Path cloneRoot = dir.resolve("clone");
        d.sim().store().cloneTo(cloneRoot);
        Simulator original = d.sim();
        Simulator clone = simAt(cloneRoot, dev);

        ByteArrayOutputStream origBuf = new ByteArrayOutputStream();
        ByteArrayOutputStream cloneBuf = new ByteArrayOutputStream();
        long t0 = System.nanoTime();
        CompletableFuture<Integer> a = streamAsync(original, new PrintStream(origBuf, true, StandardCharsets.UTF_8));
        CompletableFuture<Integer> b = streamAsync(clone, new PrintStream(cloneBuf, true, StandardCharsets.UTF_8));

        long deadline = t0 + Duration.ofSeconds(10).toNanos();
        while (!"REAUTH_REQUIRED".equals(state(dev)) && System.nanoTime() < deadline) {
            Thread.sleep(50);
        }
        long trippedMs = (System.nanoTime() - t0) / 1_000_000;
        assertThat(state(dev)).as("REAUTH_REQUIRED within 10 s").isEqualTo("REAUTH_REQUIRED");
        int exitA = a.get(20, TimeUnit.SECONDS);
        int exitB = b.get(20, TimeUnit.SECONDS);
        String outA = origBuf.toString(StandardCharsets.UTF_8);
        String outB = cloneBuf.toString(StandardCharsets.UTF_8);
        System.out.println("CLONE_TRAP tripped_ms=" + trippedMs + " exit_original=" + exitA + " exit_clone=" + exitB);
        System.out.println("ORIGINAL\n" + outA + "CLONE\n" + outB);
        assertThat(exitA).as(outA).isIn(3, 5);
        assertThat(exitB).as(outB).isIn(3, 5);
        assertThat(anomalyCodes(dev)).containsExactly(SequenceRegressionTrap.CONDITION_CODE);
        String telemetryAfterTrap = telemetry(dev);
        assertThat(telemetryAfterTrap).doesNotContain("QUARANTINED");
        assertThat(jdbc.queryForList("SELECT DISTINCT revocation_reason FROM certificates WHERE device_id = ?",
                String.class, dev)).containsExactly("SUSPECTED_CLONE");

        // A clinician decides it was benign (for example a restored backup): passkey step-up restore-active.
        AdminHttp.Response restored = WebAuthnSteps.restore(alice, ALICE, dev);
        assertThat(restored.status()).as(restored.body()).isEqualTo(200);
        assertThat(telemetry(dev)).as("historical telemetry untouched").isEqualTo(telemetryAfterTrap);

        // The original re-enrolls via Protocol C: its epoch 1 <= stored 1 with resync allowed, so it is given 2.
        Simulator.ReEnrollOutcome back = original.reEnroll();
        assertThat(back).isInstanceOf(Simulator.ReEnrollOutcome.ReEnrolled.class);
        assertThat(((Simulator.ReEnrollOutcome.ReEnrolled) back).bootEpoch()).isEqualTo(2);
        ByteArrayOutputStream again = new ByteArrayOutputStream();
        assertThat(original.stream(200, 3, new PrintStream(again, true, StandardCharsets.UTF_8))).isZero();
        assertThat(again.toString(StandardCharsets.UTF_8).lines().filter(l -> l.startsWith("SENT ")))
                .hasSize(3).allMatch(l -> l.contains("status=200"));
        assertThat(state(dev)).isEqualTo("ACTIVE");

        // The clone tries the same: it still presents epoch 1, the resync permission is spent, so the epoch rule
        // refuses it before the collision check runs, and the device is REAUTH_REQUIRED again.
        Simulator.ReEnrollOutcome cloneTry = clone.reEnroll();
        System.out.println("CLONE_REENROLL " + cloneTry);
        assertThat(cloneTry).isEqualTo(new Simulator.ReEnrollOutcome.Reauth(409, "BOOT_EPOCH_REGRESSION"));
        assertThat(state(dev)).isEqualTo("REAUTH_REQUIRED");
        assertThat(anomalyCodes(dev)).containsExactly(SequenceRegressionTrap.CONDITION_CODE, "BOOT_EPOCH_REGRESSION");
        assertThat(telemetry(dev)).doesNotContain("QUARANTINED");
    }
}
