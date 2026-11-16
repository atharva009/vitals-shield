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
    static final String AUDIT_FAULT_DEVICE = "dev_audit_fault";
    static final java.util.concurrent.atomic.AtomicBoolean AUDIT_FAULT = new java.util.concurrent.atomic.AtomicBoolean();

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

        /** Throws inside AuditLog.append, after its INSERT, for one quarantine of AUDIT_FAULT_DEVICE. */
        @Bean
        @org.springframework.context.annotation.Primary
        AuditLog faultyAudit(JdbcTemplate jdbc, Clock clock) {
            return new AuditLog(jdbc, clock) {
                @Override
                public String append(String eventType, String actorId, Map<String, Object> payload) {
                    String hash = super.append(eventType, actorId, payload);
                    if ("DEVICE_QUARANTINED".equals(eventType) && AUDIT_FAULT_DEVICE.equals(payload.get("device_id"))
                            && AUDIT_FAULT.getAndSet(false)) {
                        throw new IllegalStateException("injected failure inside AuditLog.append");
                    }
                    return hash;
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

    @Autowired com.vitalsshield.server.clinical.ClinicalEvaluator evaluator;

    @SuppressWarnings("unchecked")
    Object needsAttention(String deviceId) {
        List<Map<String, Object>> devices = (List<Map<String, Object>>) alice.get("/api/v1/admin/overview").json()
                .get("devices");
        return devices.stream().filter(d -> deviceId.equals(d.get("device_id"))).findFirst().orElseThrow()
                .get("needs_attention");
    }

    Map<String, Object> clinicalSnapshot(String deviceId) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("device", jdbc.queryForMap("SELECT trust_state::text AS ts, dek_spki_der_b64 IS NOT NULL AS dek "
                + "FROM devices WHERE device_id = ?", deviceId));
        m.put("telemetry", jdbc.queryForList("SELECT batch_id, trust_state::text AS ts FROM telemetry_records "
                + "WHERE device_id = ? ORDER BY sequence_number", deviceId));
        m.put("baseline", jdbc.queryForMap("""
                SELECT baseline_state::text AS bs, baseline_version AS v, cardinality(calibration_batch_ids) AS n,
                       ref_hr_mean, drift_breach_streak, degraded_critical_streak
                  FROM patient_device_assignments WHERE device_id = ? AND status = 'ACTIVE'
                """, deviceId));
        m.put("alerts", jdbc.queryForList("SELECT alert_id, alert_status::text AS s, retracted_at FROM clinical_alerts "
                + "WHERE device_id = ? ORDER BY alert_id", deviceId));
        return m;
    }

    /** Phase 7 (0c): a failure inside AuditLog.append rolls back the whole quarantine, including the clinical parts. */
    @Test
    @Order(3)
    void failureInsideAuditAppendRollsBackQuarantine() throws Exception {
        SimulatorCli.Run e = sim().enroll(AUDIT_FAULT_DEVICE, WebAuthnSteps.provision(alice, ALICE, AUDIT_FAULT_DEVICE));
        assertThat(e.exit()).as(e.out()).isZero();
        // 5 EXERTION + 10 RESTING (LOCKED v1) + 1 resting + 2 acute (one RESTING_HR_HIGH alert, one deduplicated).
        SimulatorCli.Run s = sim().run("run", "--device-id", AUDIT_FAULT_DEVICE, "--count", "18", "--interval-ms", "0",
                "--script", "resting:16,acute:2");
        assertThat(s.exit()).as(s.out()).isZero();
        assertThat(evaluator.awaitIdle(java.time.Duration.ofSeconds(20))).isTrue();
        Map<String, Object> before = clinicalSnapshot(AUDIT_FAULT_DEVICE);
        assertThat(before.get("baseline").toString()).contains("bs=LOCKED").contains("v=1");
        assertThat((List<?>) before.get("alerts")).hasSize(1);
        assertThat(needsAttention(AUDIT_FAULT_DEVICE)).isNull();
        long quarantinedEntries = count("SELECT count(*) FROM security_audit_log WHERE event_type = 'DEVICE_QUARANTINED'");

        AUDIT_FAULT.set(true);
        AdminHttp.Response r = WebAuthnSteps.quarantine(alice, ALICE, AUDIT_FAULT_DEVICE, 60, "audit fault");
        assertThat(r.status()).as(r.body()).isEqualTo(500);
        assertThat(AUDIT_FAULT.get()).as("the fault fired").isFalse();

        // Device not QUARANTINED, telemetry unchanged, no baseline reset, no alert retracted, no audit row.
        assertThat(clinicalSnapshot(AUDIT_FAULT_DEVICE)).isEqualTo(before);
        assertThat(count("SELECT count(*) FROM security_audit_log WHERE event_type = 'DEVICE_QUARANTINED'"))
                .isEqualTo(quarantinedEntries);
        assertThat(audit.verify().valid()).isTrue();
        // Fail closed: the certificate was revoked before the transaction.
        assertThat(jdbc.queryForObject("SELECT status::text FROM certificates WHERE device_id = ?", String.class,
                AUDIT_FAULT_DEVICE)).isEqualTo("REVOKED");
        assertThat(needsAttention(AUDIT_FAULT_DEVICE)).isEqualTo("CERT_REVOKED_STATE_ACTIVE");

        // Retry without the fault.
        AdminHttp.Response retry = WebAuthnSteps.quarantine(alice, ALICE, AUDIT_FAULT_DEVICE, 60, "audit fault retry");
        assertThat(retry.status()).as(retry.body()).isEqualTo(200);
        System.out.println("AUDIT_FAULT_RETRY " + retry.body());
        Map<String, Object> after = clinicalSnapshot(AUDIT_FAULT_DEVICE);
        assertThat(after.get("device").toString()).contains("ts=QUARANTINED");
        assertThat(after.get("baseline").toString()).contains("bs=CALIBRATING").contains("v=2");
        assertThat((List<Map<String, Object>>) after.get("alerts"))
                .allSatisfy(a -> assertThat(a.get("s")).isEqualTo("RETRACTED_BY_QUARANTINE"));
        assertThat(count("SELECT count(*) FROM security_audit_log WHERE event_type = 'DEVICE_QUARANTINED'"))
                .isEqualTo(quarantinedEntries + 1);
        assertThat(needsAttention(AUDIT_FAULT_DEVICE)).isNull();
        assertThat(audit.verify().valid()).isTrue();
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
