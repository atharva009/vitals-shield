package com.vitalsshield.server.reenroll;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.server.audit.AuditLog;
import com.vitalsshield.server.testsupport.AdminHttp;
import com.vitalsshield.server.testsupport.LedgerInvariant;
import com.vitalsshield.server.testsupport.ReEnrolls;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.testsupport.WebAuthnSteps;
import com.vitalsshield.simulator.GatewayClient;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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
 * Protocol C against the real listeners, webauthn mode (the resync test needs a passkey step-up restore). Leaf TTL
 * PT100S: notBefore is backdated 60 s, so a leaf lives about 40 s and is due for renewal about 7 s after issuance
 * (PT80S would be due before it was issued, DECISIONS #83).
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class ReEnrollIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;
    static final SoftwareAuthenticator ALICE = SoftwareAuthenticator.create();
    static AdminHttp alice;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-reenroll-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        registry.add("vitalsshield.pki.leaf-ttl", () -> "PT100S");
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

    Path trust() {
        return dir.resolve("root-ca.pem");
    }

    SpineFixture.Device enroll(String deviceId) {
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, trust(), dir.resolve("sim"));
        return fx.enrollWithToken(deviceId, WebAuthnSteps.provision(alice, ALICE, deviceId));
    }

    GatewayClient.Response reEnroll(Map<String, Object> body) {
        return ReEnrolls.post(ports, trust(), body);
    }

    ReEnrolls.Challenge challenge(String deviceId) {
        return ReEnrolls.challenge(ports, trust(), deviceId);
    }

    String stream(SpineFixture.Device d, int count) throws InterruptedException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int exit = d.sim().stream(200, count, new PrintStream(buf, true, StandardCharsets.UTF_8));
        String out = buf.toString(StandardCharsets.UTF_8);
        assertThat(exit).as(out).isZero();
        return out;
    }

    Map<String, Object> device(String deviceId) {
        return jdbc.queryForMap("""
                SELECT trust_state::text AS ts, boot_epoch, last_sequence_num, replay_bitmap, epoch_resync_allowed
                  FROM devices WHERE device_id = ?
                """, deviceId);
    }

    List<Map<String, Object>> certs(String deviceId) {
        return jdbc.queryForList("""
                SELECT serial_number, status::text AS status, revocation_reason, issued_via, reenroll_reason
                  FROM certificates WHERE device_id = ? ORDER BY issued_at, not_before
                """, deviceId);
    }

    long count(String sql, Object... args) {
        return jdbc.queryForObject(sql, Long.class, args);
    }

    @Test
    void offlineExpiryHappyPathKeepsEpochAndSequence() throws Exception {
        String dev = "dev_reenroll_ok";
        SpineFixture.Device d = enroll(dev);
        String first = stream(d, 3);
        assertThat(first.lines().filter(l -> l.startsWith("SENT ") && l.contains("status=200"))).hasSize(3);

        // The device goes offline; its leaf expires (about 40 s after issuance).
        Instant notAfter = d.cert().getNotAfter().toInstant();
        Thread.sleep(Math.max(0, Duration.between(Instant.now(), notAfter).toMillis()) + 500);

        String second = stream(d, 3);
        assertThat(second).contains("RE-ENROLLED serial=").contains("boot_epoch=1 reason=cert_expired");
        List<String> sent = second.lines().filter(l -> l.startsWith("SENT ")).toList();
        assertThat(sent).hasSize(3).allMatch(l -> l.contains("status=200"));
        assertThat(sent.get(0)).startsWith("SENT seq=4 ");
        assertThat(sent.get(2)).startsWith("SENT seq=6 ");

        Map<String, Object> row = device(dev);
        assertThat(row).containsEntry("ts", "ACTIVE").containsEntry("boot_epoch", 1L)
                .containsEntry("last_sequence_num", 6L);
        List<Map<String, Object>> certs = certs(dev);
        assertThat(certs).hasSize(2);
        assertThat(certs.get(0)).containsEntry("status", "REVOKED")
                .containsEntry("revocation_reason", ReEnrollService.REVOCATION_REASON);
        assertThat(certs.get(1)).containsEntry("status", "ACTIVE").containsEntry("issued_via", "REENROLL")
                .containsEntry("reenroll_reason", "cert_expired");
        assertThat(LedgerInvariant.violations(jdbc)).isZero();
        assertThat(count("SELECT count(*) FROM clinical_alerts WHERE device_id = ? "
                + "AND alert_type = 'SECURITY_ANOMALY_ALERT'", dev)).isZero();
    }

    @Test
    void midStreamOutsideValidityRecoversAndResendsTheSameFrame() throws Exception {
        String dev = "dev_reenroll_midstream";
        SpineFixture.Device d = enroll(dev);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        java.util.concurrent.CompletableFuture<Integer> run = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try {
                return d.sim().stream(300, 12, new PrintStream(buf, true, StandardCharsets.UTF_8));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        });
        while (buf.toString(StandardCharsets.UTF_8).lines().filter(l -> l.contains("status=200")).count() < 3) {
            Thread.sleep(50);
        }
        // The stored not_after passes while the socket is open: the per-request check answers 403 OUTSIDE_VALIDITY.
        jdbc.update("UPDATE certificates SET not_after = NOW() - INTERVAL '1 second' WHERE device_id = ?", dev);
        int exit = run.get(30, java.util.concurrent.TimeUnit.SECONDS);
        String out = buf.toString(StandardCharsets.UTF_8);
        assertThat(exit).as(out).isZero();
        assertThat(out).contains("REJECTED cert_expired serial=").contains("reason=OUTSIDE_VALIDITY")
                .contains("RE-ENROLLED serial=").contains("reason=cert_expired");
        List<String> sent = out.lines().filter(l -> l.startsWith("SENT ")).toList();
        // The refused frame is sent again with the new key: one 403 and twelve 200s, sequence 1 to 12.
        assertThat(sent.stream().filter(l -> l.contains("status=200"))).hasSize(12);
        assertThat(sent.stream().filter(l -> l.contains("status=403"))).hasSize(1);
        assertThat(device(dev)).containsEntry("last_sequence_num", 12L).containsEntry("ts", "ACTIVE");
    }

    @Test
    void tamperedAnchorAndUnknownDeviceAreTheSame403() {
        String dev = "dev_reenroll_anchor";
        SpineFixture.Device d = enroll(dev);
        jdbc.update("UPDATE devices SET provisioned_at = provisioned_at + INTERVAL '1 millisecond' WHERE device_id = ?",
                dev);
        GatewayClient.Response r = reEnroll(ReEnrolls.body(d, challenge(dev), 1));
        assertThat(r.status()).isEqualTo(403);
        GatewayClient.Response unknown = reEnroll(ReEnrolls.body("dev_never_seen", challenge("dev_never_seen"), 1,
                EcKeys.generateP256(), ReEnrolls.dek(d)));
        assertThat(unknown.status()).isEqualTo(403);
        assertThat(unknown.body()).isEqualTo(r.body()).isEqualTo("{\"error\":\"DEVICE_NOT_ENROLLABLE\"}");
    }

    @Test
    void wrongDekSignatureIs400() {
        String dev = "dev_reenroll_badsig";
        SpineFixture.Device d = enroll(dev);
        GatewayClient.Response r = reEnroll(ReEnrolls.body(dev, challenge(dev), 1, EcKeys.generateP256(),
                EcKeys.generateP256().getPrivate()));
        assertThat(r.status()).isEqualTo(400);
        assertThat(ReEnrolls.error(r)).isEqualTo("PROOF_INVALID");
        assertThat(certs(dev)).hasSize(1).allMatch(c -> "ACTIVE".equals(c.get("status")));
        assertThat(d).isNotNull();
    }

    @Test
    void reauthRequiredDeviceIs403AndItsNonceCannotBeReplayed() {
        String dev = "dev_reenroll_replay";
        SpineFixture.Device d = enroll(dev);
        jdbc.update("UPDATE devices SET trust_state = 'REAUTH_REQUIRED' WHERE device_id = ?", dev);
        Map<String, Object> body = ReEnrolls.body(d, challenge(dev), 1);
        GatewayClient.Response first = reEnroll(body);
        assertThat(first.status()).isEqualTo(403);
        assertThat(ReEnrolls.error(first)).isEqualTo("DEVICE_NOT_ACTIVE");

        jdbc.update("UPDATE devices SET trust_state = 'ACTIVE' WHERE device_id = ?", dev);
        GatewayClient.Response replay = reEnroll(body);
        assertThat(replay.status()).isEqualTo(409);
        assertThat(ReEnrolls.error(replay)).isEqualTo("CHALLENGE_REPLAYED");
    }

    @Test
    void challengeMintedForAnotherDeviceIs401() {
        SpineFixture.Device d = enroll("dev_reenroll_a");
        GatewayClient.Response r = reEnroll(ReEnrolls.body("dev_reenroll_a", challenge("dev_reenroll_b"), 1,
                EcKeys.generateP256(), ReEnrolls.dek(d)));
        assertThat(r.status()).isEqualTo(401);
        assertThat(ReEnrolls.error(r)).isEqualTo("CHALLENGE_INVALID");
    }

    @Test
    void horizonExceededIs409() {
        String dev = "dev_reenroll_horizon";
        SpineFixture.Device d = enroll(dev);
        int n = jdbc.update("UPDATE patient_device_assignments SET max_renewal_horizon = NOW() - INTERVAL '1 minute' "
                + "WHERE device_id = ?", dev);
        assertThat(n).isEqualTo(1);
        GatewayClient.Response r = reEnroll(ReEnrolls.body(d, challenge(dev), 1));
        assertThat(r.status()).isEqualTo(409);
        assertThat(ReEnrolls.error(r)).isEqualTo("RENEWAL_HORIZON_EXCEEDED");
    }

    @Test
    void csrKeyOfAnOldCertificateIs400() {
        String dev = "dev_reenroll_oldkey";
        SpineFixture.Device d = enroll(dev);
        KeyPair currentOlk = new KeyPair(d.cert().getPublicKey(), d.enrollment().olkKey());
        GatewayClient.Response r = reEnroll(ReEnrolls.body(dev, challenge(dev), 1, currentOlk, ReEnrolls.dek(d)));
        assertThat(r.status()).isEqualTo(400);
        assertThat(ReEnrolls.error(r)).isEqualTo("PROOF_INVALID");
    }

    @Test
    void epochAboveStoredIsInvalidAndRaisesTheAnomaly() throws Exception {
        String dev = "dev_reenroll_above";
        SpineFixture.Device d = enroll(dev);
        stream(d, 2);
        String before = telemetry(dev);

        GatewayClient.Response r = reEnroll(ReEnrolls.body(d, challenge(dev), 2));
        assertThat(r.status()).isEqualTo(409);
        assertThat(ReEnrolls.error(r)).isEqualTo("BOOT_EPOCH_INVALID");
        assertAnomaly(dev, "BOOT_EPOCH_INVALID");
        assertThat(telemetry(dev)).as("telemetry untouched").isEqualTo(before);
    }

    @Test
    void epochBelowStoredIsRegressionThenRestoreAllowsResync() throws Exception {
        String dev = "dev_reenroll_resync";
        SpineFixture.Device d = enroll(dev);
        stream(d, 2);
        jdbc.update("UPDATE devices SET boot_epoch = 3 WHERE device_id = ?", dev);
        String before = telemetry(dev);

        GatewayClient.Response r = reEnroll(ReEnrolls.body(d, challenge(dev), 1));
        assertThat(r.status()).isEqualTo(409);
        assertThat(ReEnrolls.error(r)).isEqualTo("BOOT_EPOCH_REGRESSION");
        assertAnomaly(dev, "BOOT_EPOCH_REGRESSION");
        assertThat(telemetry(dev)).isEqualTo(before);

        // A clinician decides it was a benign state reset: step-up restore-active.
        AdminHttp.Response restored = WebAuthnSteps.restore(alice, ALICE, dev);
        assertThat(restored.status()).as(restored.body()).isEqualTo(200);
        assertThat(device(dev)).containsEntry("ts", "ACTIVE").containsEntry("epoch_resync_allowed", true);
        assertThat(count("SELECT count(*) FROM security_audit_log WHERE event_type = 'DEVICE_RESTORED' "
                + "AND payload_json->>'device_id' = ?", dev)).isEqualTo(1);

        GatewayClient.Response resync = reEnroll(ReEnrolls.body(d, challenge(dev), 1));
        assertThat(resync.status()).as(resync.body()).isEqualTo(200);
        assertThat(ReEnrolls.json(resync.body())).containsEntry("assigned_boot_epoch", 4L);
        assertThat(device(dev)).containsEntry("ts", "ACTIVE").containsEntry("boot_epoch", 4L)
                .containsEntry("last_sequence_num", 0L).containsEntry("replay_bitmap", 0L)
                .containsEntry("epoch_resync_allowed", false);
        assertThat(certs(dev)).last().satisfies(c -> assertThat(c).containsEntry("status", "ACTIVE")
                .containsEntry("reenroll_reason", "epoch_resync"));
        assertThat(LedgerInvariant.violations(jdbc)).isZero();
    }

    /** DECISIONS #92: REAUTH_REQUIRED, everything revoked SUSPECTED_CLONE, one alert, one audit entry by system. */
    void assertAnomaly(String dev, String condition) {
        assertThat(device(dev)).containsEntry("ts", "REAUTH_REQUIRED");
        assertThat(certs(dev)).allSatisfy(c -> assertThat(c).containsEntry("status", "REVOKED")
                .containsEntry("revocation_reason", "SUSPECTED_CLONE"));
        Map<String, Object> alert = jdbc.queryForMap("""
                SELECT alert_type::text AS t, condition_code, baseline_version, cardinality(triggering_batch_ids) AS n
                  FROM clinical_alerts WHERE device_id = ?
                """, dev);
        assertThat(alert).containsEntry("t", "SECURITY_ANOMALY_ALERT").containsEntry("condition_code", condition)
                .containsEntry("n", 0);
        assertThat(alert.get("baseline_version")).isNull();
        assertThat(count("""
                SELECT count(*) FROM security_audit_log WHERE event_type = 'SECURITY_ANOMALY' AND actor_id = 'system'
                   AND payload_json->>'device_id' = ? AND payload_json->>'condition_code' = ?
                """, dev, condition)).isEqualTo(1);
        assertThat(audit.verify().valid()).isTrue();
    }

    String telemetry(String dev) {
        return jdbc.queryForList("SELECT batch_id::text || ':' || trust_state::text FROM telemetry_records "
                + "WHERE device_id = ? ORDER BY sequence_number", String.class, dev).toString();
    }
}
