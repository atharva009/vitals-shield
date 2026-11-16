package com.vitalsshield.server.admin.webauthn;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.audit.AuditLog;
import com.vitalsshield.server.testsupport.AdminHttp;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator.Variant;
import com.vitalsshield.server.testsupport.TestClock;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.testsupport.WebAuthnSteps;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
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
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** Registration, sign-in, and every rejected assertion variant (DECISIONS #55, #59, #60, #61). */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WebAuthnFlowsIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static final SoftwareAuthenticator ALICE = SoftwareAuthenticator.create(5); // non-zero counter
    static final SoftwareAuthenticator BOB = SoftwareAuthenticator.create();

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-webauthn-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired PasskeyRepository passkeys;
    @Autowired RegistryAnchorKey anchorKey;
    @Autowired WebAuthnOrigins origins;
    @Autowired AuditLog audit;

    AdminHttp http() {
        return new AdminHttp(ports.admin());
    }

    String code() {
        return WebAuthnSteps.setupCode(ports.adminCodeFile());
    }

    @Test
    @Order(1)
    void statusReportsZeroPasskeys() {
        AdminHttp.Response r = http().get("/api/v1/admin/auth/status");
        assertThat(r.status()).isEqualTo(200);
        assertThat(r.json()).containsEntry("mode", "webauthn").containsEntry("passkeys_registered", 0);
    }

    @Test
    @Order(2)
    void firstRegistrationNeedsTheSetupCode() {
        AdminHttp h = http();
        assertThat(WebAuthnSteps.register(h, ALICE, "dr_alice", null).status()).isEqualTo(401);
        assertThat(WebAuthnSteps.register(h, ALICE, "dr_alice", "wrong-code").status()).isEqualTo(401);
        AdminHttp.Response ok = WebAuthnSteps.register(h, ALICE, "dr_alice", code());
        assertThat(ok.status()).as(ok.body()).isEqualTo(200);
        assertThat(ok.json()).containsEntry("clinician_id", "dr_alice");

        Map<String, Object> row = jdbc.queryForMap("SELECT * FROM clinician_passkeys WHERE clinician_id = 'dr_alice'");
        assertThat(row.get("credential_id_b64")).isEqualTo(ALICE.credentialIdB64url());
        assertThat((String) row.get("passkey_registry_kms_sig")).isNotBlank().isNotEqualTo("ANCHOR-NOT-IMPLEMENTED");
        assertThat(row.get("sign_count")).isEqualTo(5L);
    }

    @Test
    @Order(3)
    void secondRegistrationWithoutSessionIs401EvenWithTheSetupCode() {
        assertThat(WebAuthnSteps.register(http(), BOB, "dr_bob", code()).status()).isEqualTo(401);
    }

    @Test
    @Order(4)
    void signInSetsAStrictHttpOnlyCookie() {
        AdminHttp h = http();
        AdminHttp.Response r = WebAuthnSteps.signIn(h, ALICE);
        assertThat(r.status()).as(r.body()).isEqualTo(200);
        String setCookie = r.headers().firstValue("Set-Cookie").orElseThrow();
        assertThat(setCookie).startsWith("vs_admin_session=").contains("HttpOnly").contains("SameSite=Strict")
                .contains("Path=/api/v1/admin").doesNotContain("Secure");
        assertThat(h.get("/api/v1/admin/session").json()).containsEntry("clinician_id", "dr_alice");
        assertThat(h.get("/api/v1/admin/overview").status()).isEqualTo(200);
        assertThat(http().get("/api/v1/admin/overview").status()).as("no cookie").isEqualTo(401);
    }

    @Test
    @Order(5)
    void secondRegistrationWithASessionSucceeds() {
        AdminHttp h = http();
        WebAuthnSteps.signIn(h, ALICE);
        AdminHttp.Response r = WebAuthnSteps.register(h, BOB, "dr_bob", null);
        assertThat(r.status()).as(r.body()).isEqualTo(200);
        assertThat(passkeys.countClinicianPasskeys()).isEqualTo(2);
    }

    @Test
    @Order(6)
    void bearerIsRefusedOnEveryOtherRoute() {
        AdminHttp h = http();
        assertThat(h.post("/api/v1/admin/devices/provision/begin", "{}", h.origin(), code()).status()).isEqualTo(401);
        assertThat(h.post("/api/v1/admin/devices/x/quarantine/begin", "{}", h.origin(), code()).status()).isEqualTo(401);
    }

    @Test
    @Order(10)
    void wrongOriginIsRejected() {
        assertRejected(Variant.good("http://localhost:" + ports.admin()).withOrigin("http://evil.example"));
    }

    @Test
    @Order(11)
    void wrongRpIdIsRejected() {
        assertRejected(good().withRpId("evil.example"));
    }

    @Test
    @Order(12)
    void uvUnsetIsRejected() {
        assertRejected(good().withFlags(SoftwareAuthenticator.UP));
    }

    @Test
    @Order(13)
    void upUnsetIsRejected() {
        assertRejected(good().withFlags(SoftwareAuthenticator.UV));
    }

    @Test
    @Order(14)
    void wrongChallengeIsRejected() {
        // Sign-in ceremonies are looked up by challenge, so a forged challenge matches no pending ceremony: 410, and
        // no session. (StepUpIT covers a wrong challenge under a valid ceremony id: the library's equality check.)
        AdminHttp h = http();
        AdminHttp.Response r = WebAuthnSteps.signIn(h, ALICE, good().withChallenge(new byte[32]));
        assertThat(r.status()).isEqualTo(410);
        assertThat(h.cookie()).isNull();
    }

    @Test
    @Order(15)
    void counterRegressionIsRejected() {
        long stored = passkeys.find(ALICE.credentialIdB64url()).orElseThrow().signCount();
        assertThat(stored).isGreaterThan(5);
        assertRejected(good().withCounter(stored - 1));
        assertRejected(good().withCounter(stored));
    }

    @Test
    @Order(16)
    void tamperedSignatureIsRejected() {
        assertRejected(good().tampered());
    }

    @Test
    @Order(17)
    void syncedPasskeyCounterZeroIsAccepted() {
        assertThat(WebAuthnSteps.signIn(http(), ALICE, good().withCounter(0)).status()).isEqualTo(200);
    }

    @Test
    @Order(20)
    void replayedChallengeIsRejected() {
        AdminHttp h = http();
        AdminHttp.Response begin = h.post("/api/v1/admin/session/begin", "{}");
        String credential = ALICE.assert_(begin.body(), good());
        assertThat(h.post("/api/v1/admin/session/finish", SoftwareAuthenticator.finishBody(credential, null)).status())
                .isEqualTo(200);
        AdminHttp.Response again = h.post("/api/v1/admin/session/finish", SoftwareAuthenticator.finishBody(credential, null));
        assertThat(again.status()).isEqualTo(410);
        assertThat(again.body()).contains("CEREMONY_EXPIRED");
    }

    @Test
    @Order(21)
    void expiredChallengeIsRejected() {
        TestClock clock = new TestClock(Instant.now());
        WebAuthnService service = new WebAuthnService(passkeys, anchorKey, origins, tx, audit, new DevSeedPolicy(true),
                clock);
        String options = service.signInBegin();
        clock.advance(Duration.ofMinutes(2).plusSeconds(1));
        String credential = ALICE.assert_(options, good());
        try {
            service.signInFinish(credential);
            org.assertj.core.api.Assertions.fail("expired challenge accepted");
        } catch (WebAuthnFailure e) {
            assertThat(e.status()).isEqualTo(410);
        }
    }

    private Variant good() {
        return Variant.good("http://localhost:" + ports.admin());
    }

    private void assertRejected(Variant v) {
        AdminHttp h = http();
        AdminHttp.Response r = WebAuthnSteps.signIn(h, ALICE, v);
        assertThat(r.status()).as(r.body()).isEqualTo(401);
        assertThat(h.cookie()).isNull();
    }
}
