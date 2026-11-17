package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
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
 * Spec Section 6 end to end through the real ingest endpoint, with the simulator's scenario generators and a fixed
 * compressed clock (one batch = 60 s of measured time). Demo profile: calibration-size 10.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class ClinicalEngineIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;
    static final SoftwareAuthenticator CLINICIAN = SoftwareAuthenticator.create();
    static AdminHttp admin;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-clinical-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired ClinicalEvaluator evaluator;

    @BeforeEach
    void clinician() {
        if (admin == null) {
            admin = new AdminHttp(ports.admin());
            WebAuthnSteps.bootstrapClinician(admin, CLINICIAN, "dr_clinical", ports.adminCodeFile());
        }
    }

    static final Instant START = Instant.now().minus(Duration.ofHours(12)).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);

    ClinicalStream stream(String dev) {
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
        SpineFixture.Device d = fx.enrollWithToken(dev, WebAuthnSteps.provision(admin, CLINICIAN, dev));
        return new ClinicalStream(fx, d, anchors.root(), START, Duration.ofSeconds(60));
    }

    void idle() throws InterruptedException {
        assertThat(evaluator.awaitIdle(Duration.ofSeconds(20))).as("evaluator drained").isTrue();
    }

    String activity(UUID batch) {
        return jdbc.queryForObject("SELECT activity_context FROM telemetry_records WHERE batch_id = ?", String.class, batch);
    }

    Map<String, Object> assignment(String dev) {
        return jdbc.queryForMap("""
                SELECT baseline_state::text AS bs, baseline_version AS v, calibration_batch_ids AS ids,
                       ref_hr_mean, ref_hr_sd, ref_hrv_mean, ref_hrv_sd, ref_spo2_mean, ref_spo2_sd, drift_breach_streak
                  FROM patient_device_assignments WHERE device_id = ? AND status = 'ACTIVE'
                """, dev);
    }

    List<Map<String, Object>> alerts(String dev) {
        return jdbc.queryForList("""
                SELECT alert_type::text AS type, condition_code, alert_status::text AS status, baseline_version,
                       triggering_batch_ids AS ids, explanation_summary AS explanation
                  FROM clinical_alerts WHERE device_id = ? ORDER BY created_at
                """, dev);
    }

    static List<UUID> ids(Object pgArray) {
        try {
            return Arrays.stream((Object[]) ((java.sql.Array) pgArray).getArray()).map(o -> (UUID) o).toList();
        } catch (java.sql.SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Six still batches: the first five are EXERTION ("not yet sustained"), the sixth RESTING. */
    @Test
    void restingNeedsFiveSustainedMinutes() throws Exception {
        try (ClinicalStream s = stream("dev_ce_sustain")) {
            List<ClinicalStream.Sent> first5 = s.send(Scenario.RESTING, 5);
            idle();
            assertThat(first5).allSatisfy(b -> assertThat(activity(b.batchId())).isEqualTo("EXERTION"));
            ClinicalStream.Sent sixth = s.send(Scenario.RESTING);
            idle();
            assertThat(activity(sixth.batchId())).isEqualTo("RESTING");
        }
    }

    @Test
    void calibrationLocksAtExactlyTenRestingBatches() throws Exception {
        try (ClinicalStream s = stream("dev_ce_calib")) {
            s.send(Scenario.RESTING, 5);                         // EXERTION: not yet sustained
            List<ClinicalStream.Sent> resting = s.send(Scenario.RESTING, 9);
            idle();
            assertThat(assignment("dev_ce_calib")).containsEntry("bs", "CALIBRATING");
            assertThat(ids(assignment("dev_ce_calib").get("ids"))).hasSize(9);
            ClinicalStream.Sent tenth = s.send(Scenario.RESTING);
            idle();
            Map<String, Object> a = assignment("dev_ce_calib");
            assertThat(a).containsEntry("bs", "LOCKED").containsEntry("v", 1);
            List<ClinicalStream.Sent> calib = new java.util.ArrayList<>(resting);
            calib.add(tenth);
            assertThat(ids(a.get("ids"))).containsExactlyElementsOf(calib.stream().map(ClinicalStream.Sent::batchId).toList());

            // Expected ref_* from the exact metrics sent (sample SD, n - 1, floors 3.0 / 5.0 / 1.0, DECISIONS #72).
            CalibrationStats.Stats hr = CalibrationStats.of(calib.stream().mapToDouble(b -> b.metrics().heartRateBpm()).toArray(), 3.0);
            CalibrationStats.Stats hrv = CalibrationStats.of(calib.stream().mapToDouble(b -> b.metrics().hrvRmssdMs()).toArray(), 5.0);
            CalibrationStats.Stats spo2 = CalibrationStats.of(calib.stream().mapToDouble(b -> b.metrics().spo2Pct()).toArray(), 1.0);
            assertThat((Double) a.get("ref_hr_mean")).isCloseTo(hr.mean(), within(1e-9));
            assertThat((Double) a.get("ref_hr_sd")).isCloseTo(hr.sd(), within(1e-9));
            assertThat((Double) a.get("ref_hrv_mean")).isCloseTo(hrv.mean(), within(1e-9));
            assertThat((Double) a.get("ref_hrv_sd")).isCloseTo(hrv.sd(), within(1e-9));
            assertThat((Double) a.get("ref_spo2_mean")).isCloseTo(spo2.mean(), within(1e-9));
            assertThat((Double) a.get("ref_spo2_sd")).isCloseTo(spo2.sd(), within(1e-9));
            System.out.printf("CALIBRATION hr %.2f+-%.2f hrv %.2f+-%.2f spo2 %.2f+-%.2f%n", hr.mean(), hr.sd(),
                    hrv.mean(), hrv.sd(), spo2.mean(), spo2.sd());
        }
    }

    @Test
    void fourDriftBatchesAfterLockGiveExactlyOneDriftAlert() throws Exception {
        try (ClinicalStream s = stream("dev_ce_drift")) {
            s.send(Scenario.RESTING, 15);                        // lock at the 15th
            List<ClinicalStream.Sent> drift = s.send(Scenario.DRIFT, 4);
            idle();
            List<Map<String, Object>> alerts = alerts("dev_ce_drift");
            assertThat(alerts).singleElement().satisfies(al -> {
                assertThat(al).containsEntry("type", "POTENTIAL_PHYSIOLOGICAL_DRIFT").containsEntry("condition_code", "DRIFT")
                        .containsEntry("status", "ACTIVE").containsEntry("baseline_version", 1);
                assertThat(ids(al.get("ids"))).containsExactlyElementsOf(drift.stream().map(ClinicalStream.Sent::batchId).toList());
                assertThat((String) al.get("explanation")).startsWith("Drift vs baseline v1: HR z=+").contains("HRV z=-")
                        .contains("SpO2 z=").endsWith("over 4 resting batches");
                System.out.println("DRIFT_EXPLANATION " + al.get("explanation"));
            });
            assertThat(assignment("dev_ce_drift")).containsEntry("drift_breach_streak", 0);
        }
    }

    @Test
    void threeAcuteBatchesWithinThreeMinutesGiveOneAlertAndDoNotCalibrate() throws Exception {
        try (ClinicalStream s = stream("dev_ce_acute")) {
            s.send(Scenario.RESTING, 6);                         // 5 EXERTION + 1 RESTING (calibration 1)
            List<ClinicalStream.Sent> acute = s.send(Scenario.ACUTE, 3);
            idle();
            assertThat(acute).allSatisfy(b -> assertThat(activity(b.batchId())).isEqualTo("RESTING"));
            assertThat(alerts("dev_ce_acute")).singleElement().satisfies(al -> {
                assertThat(al).containsEntry("type", "ACUTE_PHYSIOLOGICAL_ALERT")
                        .containsEntry("condition_code", "RESTING_HR_HIGH").containsEntry("baseline_version", null);
                assertThat(ids(al.get("ids"))).containsExactly(acute.get(0).batchId());
                assertThat((String) al.get("explanation")).matches("Resting heart rate 1[5]\\d bpm for 5\\+ min \\(limit 140\\)");
            });
            List<UUID> calib = ids(assignment("dev_ce_acute").get("ids"));
            assertThat(calib).hasSize(1).doesNotContainAnyElementsOf(acute.stream().map(ClinicalStream.Sent::batchId).toList());
        }
    }

    @Test
    void fiveLowPerfusionCriticalBatchesGiveOneAlert() throws Exception {
        try (ClinicalStream s = stream("dev_ce_lowperf")) {
            List<ClinicalStream.Sent> b = s.send(Scenario.LOW_PERFUSION_CRITICAL, 5);
            idle();
            assertThat(b).allSatisfy(x -> assertThat(x.trustState()).isEqualTo("SIGNAL_DEGRADED"));
            assertThat(alerts("dev_ce_lowperf")).singleElement().satisfies(al -> {
                assertThat(al).containsEntry("type", "LOW_PERFUSION_CRITICAL_ALERT")
                        .containsEntry("condition_code", "LOW_PERFUSION_CRITICAL").containsEntry("baseline_version", null);
                assertThat(ids(al.get("ids"))).containsExactlyElementsOf(b.subList(0, 3).stream()
                        .map(ClinicalStream.Sent::batchId).toList());
            });
        }
    }

    /**
     * EXERTION between drift breaches neither resets nor counts. The exertion batch also clears resting_since, so the
     * next five still batches are EXERTION ("not yet sustained") and are skipped too; the streak resumes after them.
     */
    @Test
    void exertionBetweenDriftBreachesNeitherResetsNorCounts() throws Exception {
        try (ClinicalStream s = stream("dev_ce_exertion")) {
            s.send(Scenario.RESTING, 15);
            List<ClinicalStream.Sent> d1 = s.send(Scenario.DRIFT, 2);
            s.send(Scenario.EXERTION);
            List<ClinicalStream.Sent> warmup = s.send(Scenario.DRIFT, 5);
            idle();
            assertThat(warmup).allSatisfy(b -> assertThat(activity(b.batchId())).isEqualTo("EXERTION"));
            assertThat(assignment("dev_ce_exertion")).containsEntry("drift_breach_streak", 2);
            assertThat(alerts("dev_ce_exertion")).isEmpty();
            List<ClinicalStream.Sent> d2 = s.send(Scenario.DRIFT, 2);
            idle();
            List<UUID> expected = new java.util.ArrayList<>(d1.stream().map(ClinicalStream.Sent::batchId).toList());
            expected.addAll(d2.stream().map(ClinicalStream.Sent::batchId).toList());
            assertThat(alerts("dev_ce_exertion")).singleElement()
                    .satisfies(al -> assertThat(ids(al.get("ids"))).containsExactlyElementsOf(expected));
        }
    }

    @Test
    void implausibleBatchIsNotEvaluated() throws Exception {
        try (ClinicalStream s = stream("dev_ce_implausible")) {
            s.send(Scenario.RESTING, 2);
            idle();
            Object before = jdbc.queryForObject("SELECT last_evaluated_measured_at FROM patient_device_assignments "
                    + "WHERE device_id = 'dev_ce_implausible'", Object.class);
            ClinicalStream.Sent bad = s.send(new TelemetryFrames.Metrics(10, 50, 98, 4, 0, 0.02));
            idle();
            assertThat(bad.trustState()).isEqualTo("REJECTED_IMPLAUSIBLE");
            Map<String, Object> row = jdbc.queryForMap("SELECT activity_context, clinical_evaluated_at FROM telemetry_records "
                    + "WHERE batch_id = ?", bad.batchId());
            assertThat(row.get("activity_context")).isNull();
            assertThat(row.get("clinical_evaluated_at")).isNull();
            assertThat(jdbc.queryForObject("SELECT last_evaluated_measured_at FROM patient_device_assignments "
                    + "WHERE device_id = 'dev_ce_implausible'", Object.class)).isEqualTo(before);
            assertThat(evaluator.evaluate("dev_ce_implausible", bad.batchId()))
                    .as("even when called directly").isEqualTo(ClinicalEvaluator.Outcome.SKIPPED_NOT_EVALUABLE);
        }
    }
}
