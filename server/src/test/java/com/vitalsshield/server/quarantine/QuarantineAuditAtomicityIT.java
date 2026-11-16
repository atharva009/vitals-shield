package com.vitalsshield.server.quarantine;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.audit.AuditLog;
import com.vitalsshield.server.testsupport.AdminHttp;
import com.vitalsshield.server.testsupport.SimulatorCli;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator.Variant;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.testsupport.WebAuthnSteps;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
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
import com.vitalsshield.server.admin.webauthn.ProvisioningRecords;
import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

/** DECISIONS #67: the audit entry commits with the action it records, and the lock order cannot deadlock. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class QuarantineAuditAtomicityIT {

    static final String FAILING_DEVICE = "dev_atomic_fail";

    @TestConfiguration
    static class FailBeforeCommit {
        @Bean
        QuarantineHooks failingHook() {
            return deviceId -> {
                if (FAILING_DEVICE.equals(deviceId)) {
                    throw new IllegalStateException("injected failure after the sanitize CTE and the audit append");
                }
            };
        }
    }

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;
    static final SoftwareAuthenticator ALICE = SoftwareAuthenticator.create();
    static AdminHttp alice;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-atomic-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired AuditLog audit;

    @BeforeEach
    void clinician() {
        if (alice == null) {
            alice = new AdminHttp(ports.admin());
            WebAuthnSteps.bootstrapClinician(alice, ALICE, "dr_alice", ports.adminCodeFile());
        }
    }

    SimulatorCli sim() {
        return new SimulatorCli(dir.resolve("sim"), dir.resolve("root-ca.pem"), ports);
    }

    long count(String sql, Object... args) {
        return jdbc.queryForObject(sql, Long.class, args);
    }

    @Test
    @Order(1)
    void quarantineAndAuditAreAtomic() {
        SimulatorCli.Run e = sim().enroll(FAILING_DEVICE, WebAuthnSteps.provision(alice, ALICE, FAILING_DEVICE));
        assertThat(e.exit()).as(e.out()).isZero();
        SimulatorCli.Run s = sim().run("run", "--device-id", FAILING_DEVICE, "--count", "3", "--interval-ms", "0");
        assertThat(s.exit()).as(s.out()).isZero();
        assertThat(count("SELECT count(*) FROM telemetry_records WHERE device_id = ? AND trust_state = 'ACCEPTED'",
                FAILING_DEVICE)).isEqualTo(3);

        AdminHttp.Response r = WebAuthnSteps.quarantine(alice, ALICE, FAILING_DEVICE, 60, "atomicity");
        assertThat(r.status()).as(r.body()).isEqualTo(500);

        // The quarantine transaction rolled back as a whole: state, DEK, sanitize, and the audit entry.
        Map<String, Object> d = jdbc.queryForMap(
                "SELECT trust_state::text AS ts, dek_spki_der_b64 FROM devices WHERE device_id = ?", FAILING_DEVICE);
        assertThat(d.get("ts")).isEqualTo("ACTIVE");
        assertThat(d.get("dek_spki_der_b64")).isNotNull();
        assertThat(count("SELECT count(*) FROM telemetry_records WHERE device_id = ? AND trust_state = 'ACCEPTED'",
                FAILING_DEVICE)).isEqualTo(3);
        assertThat(count("SELECT count(*) FROM security_audit_log WHERE event_type = 'DEVICE_QUARANTINED'")).isZero();
        assertThat(audit.verify().valid()).isTrue();
        // Intended fail-closed behavior: the certificate revocation (deny-list, DB row, socket eviction) happens
        // before the quarantine transaction and is not undone. The device cannot connect until it is re-provisioned,
        // even though its data was not sanitized; the operator retries the quarantine.
        assertThat(jdbc.queryForObject("SELECT status::text FROM certificates WHERE device_id = ?", String.class,
                FAILING_DEVICE)).isEqualTo("REVOKED");
    }

    @Test
    @Order(2)
    void noDeadlockUnderMixedLoad() throws Exception {
        Instant now = Instant.now();
        ProvisioningRecords records = new ProvisioningRecords(jdbc);
        List<String> closeIds = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            String q = "dev_mix_q_" + i;
            tx.executeWithoutResult(st -> records.ensureDeviceAndAssignment(q, "sim", "p", 1985, 30, now));
            jdbc.update("UPDATE devices SET trust_state = 'ACTIVE' WHERE device_id = ?", q);
            String c = "dev_mix_c_" + i;
            closeIds.add(tx.execute(st -> records.ensureDeviceAndAssignment(c, "sim", "p", 1985, 30, now)).id().toString());
        }
        long deadlocksBefore = deadlocks();

        List<Callable<AdminHttp.Response>> work = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            String q = "dev_mix_q_" + i;
            String p = "dev_mix_p_" + i;
            String a = closeIds.get(i);
            work.add(() -> WebAuthnSteps.quarantine(client(), ALICE, q, 5, "mixed load"));
            work.add(() -> WebAuthnSteps.ceremony(client(), ALICE, "/api/v1/admin/devices/provision/begin",
                    Map.of("device_id", p, "patient_id", "p", "patient_birth_year", 1985),
                    "/api/v1/admin/devices/provision/finish", Variant.good(alice.origin())));
            work.add(() -> client().post("/api/v1/admin/assignments/" + a + "/close", "{}"));
        }
        ExecutorService pool = Executors.newFixedThreadPool(30);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<AdminHttp.Response>> futures = new ArrayList<>();
        for (Callable<AdminHttp.Response> w : work) {
            futures.add(pool.submit(() -> {
                go.await();
                return w.call();
            }));
        }
        long t0 = System.nanoTime();
        go.countDown();
        List<AdminHttp.Response> results = new ArrayList<>();
        for (Future<AdminHttp.Response> f : futures) {
            results.add(f.get(30, TimeUnit.SECONDS));
        }
        long millis = (System.nanoTime() - t0) / 1_000_000;
        pool.shutdown();
        System.out.println("MIXED_LOAD_MS=" + millis);

        assertThat(millis).isLessThan(30_000);
        assertThat(results).allSatisfy(r -> {
            assertThat(r.status()).as(r.body()).isEqualTo(200);
            assertThat(r.body()).doesNotContain("40P01");
        });
        assertThat(count("SELECT count(*) FROM devices WHERE device_id LIKE 'dev_mix_q_%' AND trust_state = 'QUARANTINED'"))
                .isEqualTo(10);
        assertThat(count("SELECT count(*) FROM security_audit_log WHERE event_type = 'DEVICE_QUARANTINED'")).isEqualTo(10);
        assertThat(count("SELECT count(*) FROM security_audit_log WHERE event_type = 'DEVICE_PROVISIONED'"))
                .isGreaterThanOrEqualTo(10);
        assertThat(count("SELECT count(*) FROM security_audit_log WHERE event_type = 'ASSIGNMENT_CLOSED'")).isEqualTo(10);
        assertThat(audit.verify().valid()).isTrue();
        assertThat(deadlocks()).as("SQLSTATE 40P01 (pg_stat_database.deadlocks)").isEqualTo(deadlocksBefore);
    }

    AdminHttp client() {
        AdminHttp h = new AdminHttp(ports.admin());
        h.cookie(alice.cookie());
        return h;
    }

    long deadlocks() throws InterruptedException {
        Thread.sleep(1500); // statistics are flushed asynchronously
        jdbc.execute("SELECT pg_stat_clear_snapshot()");
        return count("SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()");
    }
}
