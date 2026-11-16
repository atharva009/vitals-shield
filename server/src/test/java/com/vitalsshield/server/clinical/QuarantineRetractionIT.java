package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.AdminHttp;
import com.vitalsshield.server.testsupport.ClinicalStream;
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
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
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
 * Spec Section 6 scoped retraction: lineage (triggering_batch_ids, baseline_version) decides exactly which alerts a
 * quarantine retracts, and evaluations still queued when it commits create nothing.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class QuarantineRetractionIT {

    static final String DEV = "dev_retract";
    static volatile CountDownLatch gate = null;

    @TestConfiguration
    static class Gate {
        @Bean
        ClinicalHooks holdEvaluations() {
            return (deviceId, batchId) -> {
                CountDownLatch g = gate;
                if (g != null && DEV.equals(deviceId)) {
                    try {
                        g.await(30, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
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
        dir = Files.createTempDirectory("vs-retract-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired ClinicalEvaluator evaluator;

    String status(UUID alertId) {
        return jdbc.queryForObject("SELECT alert_status::text FROM clinical_alerts WHERE alert_id = ?", String.class, alertId);
    }

    UUID alertFor(UUID batchId) {
        return jdbc.queryForObject("SELECT alert_id FROM clinical_alerts WHERE ? = ANY(triggering_batch_ids)",
                UUID.class, batchId);
    }

    @Test
    void quarantineRetractsExactlyTheTaintedAlerts() throws Exception {
        SoftwareAuthenticator clinician = SoftwareAuthenticator.create();
        AdminHttp admin = new AdminHttp(ports.admin());
        WebAuthnSteps.bootstrapClinician(admin, clinician, "dr_retract", ports.adminCodeFile());
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
        SpineFixture.Device d = fx.enrollWithToken(DEV, WebAuthnSteps.provision(admin, clinician, DEV));

        // Real-time measured clock: batch n measured at T0 + n minutes. ingested_at is then set to measured_at, as if
        // the batches had arrived live, so the lookback window below is decided by these timestamps.
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        try (ClinicalStream s = new ClinicalStream(fx, d, anchors.root(), now.minus(Duration.ofMinutes(120)),
                Duration.ofSeconds(60))) {
            // 1. Acute SpO2 alert measured 120 min ago: outside the 70-minute lookback.
            UUID oldAcuteBatch = s.send(new TelemetryFrames.Metrics(68, 50, 89.0, 4, 0, 0.02)).batchId();
            // 2. From 60 min ago: 5 EXERTION + 10 RESTING (calibration, LOCKED v1), 4 drift, 1 acute, 3 low perfusion.
            s.measureNextAt(now.minus(Duration.ofMinutes(60)));
            s.send(Scenario.RESTING, 5);
            List<ClinicalStream.Sent> calibration = s.send(Scenario.RESTING, 10);
            List<ClinicalStream.Sent> drift = s.send(Scenario.DRIFT, 4);
            UUID acuteBatch = s.send(Scenario.ACUTE).batchId();
            List<ClinicalStream.Sent> lowPerf = s.send(Scenario.LOW_PERFUSION_CRITICAL, 3);
            assertThat(evaluator.awaitIdle(Duration.ofSeconds(20))).isTrue();
            jdbc.update("UPDATE telemetry_records SET ingested_at = measured_at WHERE device_id = ?", DEV);

            UUID assignment = UUID.fromString(d.assignmentId());
            Map<String, Object> locked = jdbc.queryForMap("SELECT baseline_state::text AS bs, baseline_version AS v "
                    + "FROM patient_device_assignments WHERE assignment_id = ?", assignment);
            assertThat(locked).containsEntry("bs", "LOCKED").containsEntry("v", 1);
            UUID oldAcute = alertFor(oldAcuteBatch);
            UUID driftAlert = alertFor(drift.get(0).batchId());
            UUID acuteAlert = alertFor(acuteBatch);
            UUID lowPerfAlert = alertFor(lowPerf.get(0).batchId());
            assertThat(jdbc.queryForObject("SELECT baseline_version FROM clinical_alerts WHERE alert_id = ?",
                    Integer.class, driftAlert)).isEqualTo(1);
            // 3. A security alert with no telemetry lineage.
            UUID security = UUID.randomUUID();
            jdbc.update("""
                    INSERT INTO clinical_alerts (alert_id, device_id, assignment_id, alert_type, triggering_batch_ids,
                                                 explanation_summary, condition_code)
                    VALUES (?, ?, ?, 'SECURITY_ANOMALY_ALERT', '{}', 'test security anomaly', 'SECURITY_TEST')
                    """, security, DEV, assignment);
            assertThat(List.of(oldAcute, driftAlert, acuteAlert, lowPerfAlert, security))
                    .allSatisfy(id -> assertThat(status(id)).isEqualTo("ACTIVE"));

            // 4. Hold evaluations, then send three SpO2-low batches 6 min apart (outside each other's dedupe window):
            // evaluated, each would create a new SPO2_LOW alert.
            gate = new CountDownLatch(1);
            List<UUID> queued = new java.util.ArrayList<>();
            for (int minutesAgo : new int[] {20, 14, 8}) {
                s.measureNextAt(now.minus(Duration.ofMinutes(minutesAgo)));
                queued.add(s.send(new TelemetryFrames.Metrics(68, 50, 89.0, 4, 0, 0.02)).batchId());
            }
            assertThat(evaluator.pending()).isGreaterThanOrEqualTo(3);
            long alertsBefore = jdbc.queryForObject("SELECT count(*) FROM clinical_alerts WHERE device_id = ?", Long.class, DEV);

            // 5. Quarantine, lookback 70 min (covers calibration and drift, not the 120-minute-old batch).
            AdminHttp.Response q = WebAuthnSteps.quarantine(admin, clinician, DEV, 70, "retraction test");
            assertThat(q.status()).as(q.body()).isEqualTo(200);
            System.out.println("QUARANTINE_RESULT " + q.body());
            assertThat(((Number) q.json().get("baselines_reset")).intValue()).isEqualTo(1);
            assertThat(((Number) q.json().get("alerts_retracted")).intValue()).isEqualTo(3);

            // 6. Release the queued evaluations: the device is QUARANTINED, so they create nothing.
            gate.countDown();
            assertThat(evaluator.awaitIdle(Duration.ofSeconds(20))).isTrue();
            gate = null;

            assertThat(status(driftAlert)).isEqualTo("RETRACTED_BY_QUARANTINE");
            assertThat(status(acuteAlert)).isEqualTo("RETRACTED_BY_QUARANTINE");
            assertThat(status(lowPerfAlert)).isEqualTo("RETRACTED_BY_QUARANTINE");
            assertThat(jdbc.queryForObject("SELECT retracted_at IS NOT NULL FROM clinical_alerts WHERE alert_id = ?",
                    Boolean.class, driftAlert)).isTrue();
            assertThat(status(oldAcute)).as("before the lookback").isEqualTo("ACTIVE");
            assertThat(status(security)).as("no lineage to quarantined data").isEqualTo("ACTIVE");
            assertThat(jdbc.queryForObject("SELECT trust_state::text FROM telemetry_records WHERE batch_id = ?",
                    String.class, oldAcuteBatch)).isEqualTo("ACCEPTED");

            Map<String, Object> reset = jdbc.queryForMap("""
                    SELECT baseline_state::text AS bs, baseline_version AS v, cardinality(calibration_batch_ids) AS n,
                           ref_hr_mean, degraded_critical_streak AS dcs, cardinality(degraded_critical_batch_ids) AS dcn,
                           drift_breach_streak AS dbs, cardinality(drift_breach_batch_ids) AS dbn
                      FROM patient_device_assignments WHERE assignment_id = ?
                    """, assignment);
            assertThat(reset).containsEntry("bs", "CALIBRATING").containsEntry("v", 2).containsEntry("n", 0)
                    .containsEntry("ref_hr_mean", null).containsEntry("dcs", 0).containsEntry("dcn", 0)
                    .containsEntry("dbs", 0).containsEntry("dbn", 0);

            assertThat(jdbc.queryForObject("SELECT count(*) FROM clinical_alerts WHERE device_id = ?", Long.class, DEV))
                    .as("queued evaluations after the quarantine created no alert").isEqualTo(alertsBefore);
            assertThat(queued).allSatisfy(b -> assertThat(jdbc.queryForMap(
                    "SELECT trust_state::text AS ts, clinical_evaluated_at FROM telemetry_records WHERE batch_id = ?", b))
                    .containsEntry("ts", "QUARANTINED").containsEntry("clinical_evaluated_at", null));
            assertThat(calibration).allSatisfy(b -> assertThat(jdbc.queryForObject(
                    "SELECT trust_state::text FROM telemetry_records WHERE batch_id = ?", String.class, b.batchId()))
                    .isEqualTo("QUARANTINED"));
        }
    }
}
