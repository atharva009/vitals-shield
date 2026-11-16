package com.vitalsshield.server.admin.webauthn;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import com.vitalsshield.server.testsupport.AdminHttp;
import com.vitalsshield.server.testsupport.SimulatorCli;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator.Variant;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.testsupport.WebAuthnSteps;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** Step-up approvals bound to the exact action (DECISIONS #58). */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class StepUpIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;
    static final SoftwareAuthenticator ALICE = SoftwareAuthenticator.create();
    static final SoftwareAuthenticator BOB = SoftwareAuthenticator.create();
    static AdminHttp alice;
    static AdminHttp bob;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-stepup-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;

    @org.junit.jupiter.api.BeforeEach
    void clinicians() {
        if (alice != null) {
            return;
        }
        alice = new AdminHttp(ports.admin());
        WebAuthnSteps.bootstrapClinician(alice, ALICE, "dr_alice", ports.adminCodeFile());
        assertThat(WebAuthnSteps.register(alice, BOB, "dr_bob", null).status()).isEqualTo(200);
        bob = new AdminHttp(ports.admin());
        assertThat(WebAuthnSteps.signIn(bob, BOB).status()).isEqualTo(200);
    }

    String enrolledDevice(String deviceId) {
        String token = WebAuthnSteps.provision(alice, ALICE, deviceId);
        SimulatorCli.Run r = new SimulatorCli(dir.resolve("sim"), dir.resolve("root-ca.pem"), ports).enroll(deviceId, token);
        assertThat(r.exit()).as(r.out()).isZero();
        return deviceId;
    }

    String state(String deviceId) {
        return jdbc.queryForObject("SELECT trust_state::text FROM devices WHERE device_id = ?", String.class, deviceId);
    }

    @Test
    @Order(1)
    void quarantineBeginFinishSucceedsWithApprovedBy() {
        String d = enrolledDevice("dev_stepup_ok");
        AdminHttp.Response r = WebAuthnSteps.quarantine(alice, ALICE, d, 10, "suspected clone");
        assertThat(r.status()).as(r.body()).isEqualTo(200);
        assertThat(r.json()).containsEntry("approved_by", "dr_alice").containsEntry("certs_revoked", 1)
                .containsKey("revocation_latency_micros");
        assertThat(state(d)).isEqualTo("QUARANTINED");
    }

    @Test
    @Order(2)
    void assertionForADifferentDigestIsRejectedAndNothingIsQuarantined() {
        String d = enrolledDevice("dev_stepup_swap");
        AdminHttp.Response begin = alice.post("/api/v1/admin/devices/" + d + "/quarantine/begin",
                AdminHttp.json(Map.of("lookback_minutes", 10, "reason", "suspected clone")));
        assertThat(begin.status()).isEqualTo(200);
        String ceremonyId = (String) begin.json().get("ceremony_id");
        // The clinician's authenticator signs an approval for other parameters (lookback 1440, another reason).
        byte[] other = CanonicalEncodings.quarantineApprovalDigest(d, 1440, "wipe everything", new byte[16]);
        String credential = ALICE.assertion(other, Variant.good(alice.origin()));
        AdminHttp.Response finish = alice.post("/api/v1/admin/devices/" + d + "/quarantine/finish",
                SoftwareAuthenticator.finishBody(credential, ceremonyId));
        assertThat(finish.status()).as(finish.body()).isEqualTo(401);
        assertThat(finish.body()).contains("ASSERTION_REJECTED");
        assertThat(state(d)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM certificates WHERE device_id = ? AND status = 'ACTIVE'",
                Integer.class, d)).isEqualTo(1);
    }

    @Test
    @Order(3)
    void bodyParametersAtFinishAreIgnored() {
        String d = enrolledDevice("dev_stepup_params");
        AdminHttp.Response begin = alice.post("/api/v1/admin/devices/" + d + "/quarantine/begin",
                AdminHttp.json(Map.of("lookback_minutes", 7, "reason", "approved reason")));
        String ceremonyId = (String) begin.json().get("ceremony_id");
        String credential = ALICE.assert_(begin.body(), Variant.good(alice.origin()));
        String json = SoftwareAuthenticator.finishBody(credential, ceremonyId)
                .replaceFirst("\\{", "{\"lookback_minutes\":1440,\"reason\":\"swapped\",");
        AdminHttp.Response finish = alice.post("/api/v1/admin/devices/" + d + "/quarantine/finish", json);
        assertThat(finish.status()).as(finish.body()).isEqualTo(200);
        assertThat(jdbc.queryForObject("SELECT quarantine_reason FROM devices WHERE device_id = ?", String.class, d))
                .isEqualTo("approved reason");
    }

    @Test
    @Order(4)
    void finishingTwiceIs410() {
        String d = enrolledDevice("dev_stepup_twice");
        AdminHttp.Response begin = alice.post("/api/v1/admin/devices/" + d + "/quarantine/begin",
                AdminHttp.json(Map.of("lookback_minutes", 5, "reason", "twice")));
        String ceremonyId = (String) begin.json().get("ceremony_id");
        String body = SoftwareAuthenticator.finishBody(ALICE.assert_(begin.body(), Variant.good(alice.origin())), ceremonyId);
        assertThat(alice.post("/api/v1/admin/devices/" + d + "/quarantine/finish", body).status()).isEqualTo(200);
        AdminHttp.Response again = alice.post("/api/v1/admin/devices/" + d + "/quarantine/finish", body);
        assertThat(again.status()).isEqualTo(410);
    }

    @Test
    @Order(5)
    void singleStepQuarantineIs404InWebAuthnMode() {
        AdminHttp.Response r = alice.post("/api/v1/admin/devices/dev_stepup_ok/quarantine",
                AdminHttp.json(Map.of("lookback_minutes", 5, "reason", "x")));
        assertThat(r.status()).isEqualTo(404);
    }

    @Test
    @Order(6)
    void anotherClinicianCannotFinishThisCeremony() {
        String d = enrolledDevice("dev_stepup_bob");
        AdminHttp.Response begin = alice.post("/api/v1/admin/devices/" + d + "/quarantine/begin",
                AdminHttp.json(Map.of("lookback_minutes", 5, "reason", "alice's approval")));
        String ceremonyId = (String) begin.json().get("ceremony_id");
        String credential = BOB.assert_(begin.body(), Variant.good(bob.origin()));
        AdminHttp.Response r = bob.post("/api/v1/admin/devices/" + d + "/quarantine/finish",
                SoftwareAuthenticator.finishBody(credential, ceremonyId));
        assertThat(r.status()).as(r.body()).isEqualTo(403);
        assertThat(state(d)).isEqualTo("ACTIVE");
    }

    @Test
    @Order(7)
    void restoreActiveOnlyFromReauthRequired() {
        String d = enrolledDevice("dev_stepup_restore");
        AdminHttp.Response notYet = alice.post("/api/v1/admin/devices/" + d + "/restore-active/begin", "{}");
        assertThat(notYet.status()).isEqualTo(409);

        jdbc.update("UPDATE devices SET trust_state = 'REAUTH_REQUIRED' WHERE device_id = ?", d);
        AdminHttp.Response r = WebAuthnSteps.ceremony(alice, ALICE, "/api/v1/admin/devices/" + d + "/restore-active/begin",
                Map.of(), "/api/v1/admin/devices/" + d + "/restore-active/finish", Variant.good(alice.origin()));
        assertThat(r.status()).as(r.body()).isEqualTo(200);
        assertThat(r.json()).containsEntry("trust_state", "ACTIVE").containsEntry("epoch_resync_allowed", true)
                .containsEntry("approved_by", "dr_alice");
        assertThat(jdbc.queryForObject("SELECT epoch_resync_allowed FROM devices WHERE device_id = ?", Boolean.class, d))
                .isTrue();
    }
}
