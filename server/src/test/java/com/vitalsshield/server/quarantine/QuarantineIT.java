package com.vitalsshield.server.quarantine;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.vitalsshield.devtools.DevSeeder;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
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

/** Quarantine: revoke, evict, lock, then the spec Section 6 dual-timestamp sanitize and scoped alert retraction. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class QuarantineIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-quarantine-it");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired CrlService crls;

    final HttpClient http = HttpClient.newHttpClient();

    @Test
    void sanitizesDualTimestampResetsBaselineAndRetractsOnlyTaintedAlerts() throws Exception {
        String dev = "dev_quarantine";
        SpineFixture.Device d = new SpineFixture(jdbc, tx, ports, trustFile, stateRoot).enroll(dev);
        UUID assignment = UUID.fromString(d.assignmentId());
        String serial = d.cert().getSerialNumber().toString(16);
        DevSeeder.Result outstanding = new DevSeeder(jdbc, tx, Clock.systemUTC()).seed(DevSeeder.Request.defaults(dev));

        Instant now = Instant.now();
        Instant recent = now.minus(Duration.ofMinutes(10));
        Instant old = now.minus(Duration.ofHours(5));
        UUID inBoth = row(d, 1, recent, recent, "ACCEPTED");              // in by both timestamps
        UUID inByIngested = row(d, 2, recent, old, "ACCEPTED");           // old measured_at, recent ingested_at
        UUID inByMeasured = row(d, 3, old, recent, "SIGNAL_DEGRADED");    // old ingested_at, recent measured_at
        UUID outside = row(d, 4, old, old, "ACCEPTED");                   // outside both
        UUID implausible = row(d, 5, recent, recent, "REJECTED_IMPLAUSIBLE");

        jdbc.update("""
                UPDATE patient_device_assignments
                   SET baseline_state = 'LOCKED', baseline_version = 2, calibration_batch_ids = ARRAY[?, ?]::uuid[],
                       ref_hr_mean = 65, ref_hr_sd = 4, ref_hrv_mean = 45, ref_hrv_sd = 6, ref_spo2_mean = 97.5,
                       ref_spo2_sd = 0.8
                 WHERE assignment_id = ?
                """, inBoth, outside, assignment);
        UUID acuteTainted = alert(dev, assignment, null, "ACUTE_PHYSIOLOGICAL_ALERT", inBoth);
        UUID acuteOld = alert(dev, assignment, null, "ACUTE_PHYSIOLOGICAL_ALERT", outside);
        UUID driftTainted = alert(dev, assignment, 2, "POTENTIAL_PHYSIOLOGICAL_DRIFT", outside);
        UUID driftOlder = alert(dev, assignment, 1, "POTENTIAL_PHYSIOLOGICAL_DRIFT", outside);
        UUID security = alert(dev, assignment, null, "SECURITY_ANOMALY_ALERT", null);

        HttpResponse<String> r = quarantine(dev, 60, bearer());

        assertThat(r.statusCode()).as(r.body()).isEqualTo(200);
        Map<String, Object> body = JSONObjectUtils.parse(r.body());
        assertThat(body).containsEntry("device_id", dev);
        assertThat(((Number) body.get("certs_revoked")).intValue()).isEqualTo(1);
        assertThat(((Number) body.get("batches_quarantined")).intValue()).isEqualTo(3);
        assertThat(((Number) body.get("baselines_reset")).intValue()).isEqualTo(1);
        assertThat(((Number) body.get("alerts_retracted")).intValue()).isEqualTo(2);
        assertThat(((Number) body.get("revocation_latency_micros")).longValue()).isPositive();

        // Dual-timestamp selection.
        assertThat(state(inBoth)).isEqualTo("QUARANTINED");
        assertThat(state(inByIngested)).isEqualTo("QUARANTINED");
        assertThat(state(inByMeasured)).isEqualTo("QUARANTINED");
        assertThat(state(outside)).isEqualTo("ACCEPTED");
        assertThat(state(implausible)).isEqualTo("REJECTED_IMPLAUSIBLE");

        // Baseline reset.
        Map<String, Object> a = jdbc.queryForMap("SELECT * FROM patient_device_assignments WHERE assignment_id = ?",
                assignment);
        assertThat(a.get("baseline_state")).hasToString("CALIBRATING");
        assertThat(a.get("baseline_version")).isEqualTo(3);
        assertThat(a.get("ref_hr_mean")).isNull();
        assertThat(a.get("ref_spo2_sd")).isNull();
        assertThat(jdbc.queryForObject("SELECT cardinality(calibration_batch_ids) FROM patient_device_assignments "
                + "WHERE assignment_id = ?", Integer.class, assignment)).isZero();

        // Scoped retraction.
        assertThat(alertStatus(acuteTainted)).isEqualTo("RETRACTED_BY_QUARANTINE");
        assertThat(alertStatus(driftTainted)).isEqualTo("RETRACTED_BY_QUARANTINE");
        assertThat(alertStatus(acuteOld)).isEqualTo("ACTIVE");
        assertThat(alertStatus(driftOlder)).isEqualTo("ACTIVE");
        assertThat(alertStatus(security)).isEqualTo("ACTIVE");

        // Device and tokens.
        Map<String, Object> device = jdbc.queryForMap("SELECT * FROM devices WHERE device_id = ?", dev);
        assertThat(device.get("trust_state")).hasToString("QUARANTINED");
        assertThat(device.get("quarantine_reason")).isEqualTo("integration test");
        assertThat(device.get("dek_spki_der_b64")).isNull();
        assertThat(device.get("dek_registry_kms_sig")).isNull();
        assertThat(jdbc.queryForObject("SELECT status::text FROM device_bootstrap_tokens WHERE token_id = ?",
                String.class, outstanding.tokenId())).isEqualTo("REVOKED");

        // Certificate revoked and on the next CRL.
        assertThat(jdbc.queryForMap("SELECT status::text AS s, revocation_reason AS r FROM certificates "
                + "WHERE serial_number = ?", serial)).containsEntry("s", "REVOKED").containsEntry("r", "KEY_COMPROMISE");
        assertThat(awaitOnCrl(d.cert().getSerialNumber())).isTrue();

        // Repeat and auth.
        HttpResponse<String> again = quarantine(dev, 60, bearer());
        assertThat(again.statusCode()).isEqualTo(409);
        assertThat(again.body()).contains("ALREADY_QUARANTINED");
        assertThat(quarantine(dev, 60, null).statusCode()).isEqualTo(401);
    }

    @Test
    void invalidStateAndBodyRejected() throws Exception {
        String dev = "dev_quarantine_new";
        new DevSeeder(jdbc, tx, Clock.systemUTC()).seed(DevSeeder.Request.defaults(dev)); // PROVISIONED, never enrolled
        HttpResponse<String> r = quarantine(dev, 60, bearer());
        assertThat(r.statusCode()).isEqualTo(409);
        assertThat(r.body()).contains("INVALID_STATE");
        assertThat(quarantine(dev, 0, bearer()).statusCode()).isEqualTo(400);
        assertThat(quarantine(dev, 1441, bearer()).statusCode()).isEqualTo(400);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    private UUID row(SpineFixture.Device d, long seq, Instant ingestedAt, Instant measuredAt, String trustState) {
        UUID batch = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO telemetry_records (batch_id, device_id, assignment_id, issuer_key_hash, serial_number,
                    boot_epoch, sequence_number, measured_at, transmitted_at, ingested_at, heart_rate_bpm, hrv_rmssd_ms,
                    spo2_pct, perfusion_index, payload_sha256, jws_compact, trust_state)
                VALUES (?, ?, ?::uuid, 'issuer', 'serial', ?, ?, ?, ?, ?, 70, 45, 98, 3, 'sha', 'jws', ?::telemetry_trust_state)
                """, batch, d.deviceId(), d.assignmentId(), d.bootEpoch(), 1000 + seq, Timestamp.from(measuredAt),
                Timestamp.from(measuredAt), Timestamp.from(ingestedAt), trustState);
        return batch;
    }

    private UUID alert(String dev, UUID assignment, Integer baselineVersion, String type, UUID trigger) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO clinical_alerts (alert_id, device_id, assignment_id, baseline_version, alert_type,
                                             triggering_batch_ids, explanation_summary)
                VALUES (?, ?, ?, ?, ?::alert_severity_type, ?::uuid[], 'seeded')
                """, id, dev, assignment, baselineVersion, type, trigger == null ? "{}" : "{" + trigger + "}");
        return id;
    }

    private String state(UUID batch) {
        return jdbc.queryForObject("SELECT trust_state::text FROM telemetry_records WHERE batch_id = ?", String.class, batch);
    }

    private String alertStatus(UUID id) {
        return jdbc.queryForObject("SELECT alert_status::text FROM clinical_alerts WHERE alert_id = ?", String.class, id);
    }

    private String bearer() throws IOException {
        return "Bearer " + Files.readString(ports.adminCodeFile()).trim();
    }

    private HttpResponse<String> quarantine(String dev, int lookback, String auth) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + ports.admin()
                        + "/api/v1/admin/devices/" + dev + "/quarantine"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"lookback_minutes\":" + lookback + ",\"reason\":\"integration test\"}"));
        if (auth != null) {
            b.header("Authorization", auth);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private boolean awaitOnCrl(java.math.BigInteger serial) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            String pem = crls.currentIntermediateCrl().block(Duration.ofSeconds(5));
            X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
                    .generateCRL(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
            if (crl.getRevokedCertificate(serial) != null) {
                return true;
            }
            Thread.sleep(50);
        }
        return false;
    }
}
