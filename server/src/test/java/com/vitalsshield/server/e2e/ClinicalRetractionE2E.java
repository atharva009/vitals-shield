package com.vitalsshield.server.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.clinical.ClinicalEvaluator;
import com.vitalsshield.server.testsupport.AdminHttp;
import com.vitalsshield.server.testsupport.LedgerInvariant;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.testsupport.WebAuthnSteps;
import com.vitalsshield.simulator.ScenarioScript;
import com.vitalsshield.simulator.Simulator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
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
 * Phase 7 end to end, webauthn mode, simulator in-process on --script "resting:16,drift:5": the baseline locks at 10
 * resting batches, drift raises one alert on baseline v1, a passkey step-up quarantine retracts it and resets the
 * baseline to CALIBRATING v2, and after re-provisioning and re-enrolling the new boot epoch calibrates again under v2.
 */
@Tag("e2e")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class ClinicalRetractionE2E {

    static final String DEV = "dev_clinical_e2e";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-clinical-e2e");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired ClinicalEvaluator evaluator;

    Map<String, Object> baseline() {
        return jdbc.queryForMap("""
                SELECT baseline_state::text AS bs, baseline_version AS v, cardinality(calibration_batch_ids) AS n,
                       calibration_batch_ids AS ids
                  FROM patient_device_assignments WHERE device_id = ? AND status = 'ACTIVE'
                """, DEV);
    }

    String stream(Simulator sim, long count, Simulator.StreamOptions options) throws Exception {
        ByteArrayOutputStream log = new ByteArrayOutputStream();
        int exit = sim.stream(0, count, new PrintStream(log, true, StandardCharsets.UTF_8), options);
        String out = log.toString(StandardCharsets.UTF_8);
        assertThat(exit).as(out).isZero();
        assertThat(evaluator.awaitIdle(Duration.ofSeconds(20))).isTrue();
        return out;
    }

    @Test
    void driftAlertRetractedAndRecalibratedAfterReEnrollment() throws Exception {
        SoftwareAuthenticator clinician = SoftwareAuthenticator.create();
        AdminHttp admin = new AdminHttp(ports.admin());
        WebAuthnSteps.bootstrapClinician(admin, clinician, "dr_clinical", ports.adminCodeFile());
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, trustFile, stateRoot);
        SpineFixture.Device d = fx.enrollWithToken(DEV, WebAuthnSteps.provision(admin, clinician, DEV));

        // 1. resting:16,drift:5. Lock at the 15th batch (5 not yet sustained + 10 resting), drift alert at the 20th.
        String out = stream(d.sim(), 21, new Simulator.StreamOptions(null, ScenarioScript.parse("resting:16,drift:5")));
        assertThat(out).contains("SCENARIO resting").contains("SCENARIO drift");
        assertThat(out.lines().filter(l -> l.startsWith("SENT ")).toList()).hasSize(21)
                .allSatisfy(l -> assertThat(l).contains("status=200"));
        Map<String, Object> locked = baseline();
        assertThat(locked).containsEntry("bs", "LOCKED").containsEntry("v", 1).containsEntry("n", 10);
        List<Map<String, Object>> alerts = jdbc.queryForList("""
                SELECT alert_id, alert_type::text AS t, alert_status::text AS s, baseline_version AS v,
                       cardinality(triggering_batch_ids) AS n, explanation_summary AS e
                  FROM clinical_alerts WHERE device_id = ?
                """, DEV);
        assertThat(alerts).singleElement().satisfies(a -> assertThat(a).containsEntry("t", "POTENTIAL_PHYSIOLOGICAL_DRIFT")
                .containsEntry("s", "ACTIVE").containsEntry("v", 1).containsEntry("n", 4));
        System.out.println("CLINICAL_E2E drift alert: " + alerts.get(0).get("e"));

        // 2. Step-up quarantine: the drift alert is retracted, the baseline is CALIBRATING v2.
        AdminHttp.Response q = WebAuthnSteps.quarantine(admin, clinician, DEV, 60, "clinical e2e");
        assertThat(q.status()).as(q.body()).isEqualTo(200);
        long latency = ((Number) q.json().get("revocation_latency_micros")).longValue();
        System.out.println("CLINICAL_E2E_REVOCATION_LATENCY_MICROS=" + latency + " " + q.body());
        assertThat(latency).isLessThan(500_000);
        assertThat(((Number) q.json().get("alerts_retracted")).intValue()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT alert_status::text FROM clinical_alerts WHERE alert_id = ?", String.class,
                alerts.get(0).get("alert_id"))).isEqualTo("RETRACTED_BY_QUARANTINE");
        assertThat(baseline()).containsEntry("bs", "CALIBRATING").containsEntry("v", 2).containsEntry("n", 0);

        // 3. Re-provision (software passkey) and re-enroll: boot epoch 2 calibrates again under v2. The state reset
        // loses last_measured_at, so measured_at restarts earlier and resting_since resets (DECISIONS #69): the first
        // five still batches are EXERTION again.
        String token = WebAuthnSteps.provision(admin, clinician, DEV);
        d.sim().store().resetState();
        SpineFixture.Device d2 = fx.enrollWithToken(DEV, token);
        assertThat(d2.bootEpoch()).isEqualTo(2);
        String out2 = stream(d2.sim(), 8, new Simulator.StreamOptions(com.vitalsshield.simulator.Scenario.RESTING, null));
        assertThat(out2.lines().filter(l -> l.startsWith("SENT ")).toList()).hasSize(8)
                .allSatisfy(l -> assertThat(l).contains("status=200"));
        Map<String, Object> recal = baseline();
        assertThat(recal).containsEntry("bs", "CALIBRATING").containsEntry("v", 2).containsEntry("n", 3);
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM telemetry_records t, patient_device_assignments a
                 WHERE a.device_id = ? AND a.status = 'ACTIVE' AND t.batch_id = ANY(a.calibration_batch_ids)
                   AND t.boot_epoch = 2 AND t.trust_state = 'ACCEPTED'
                """, Long.class, DEV)).as("every v2 calibration batch is from boot epoch 2").isEqualTo(3);
        assertThat(LedgerInvariant.violations(jdbc)).isZero();
    }
}
