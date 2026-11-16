package com.vitalsshield.server.admin.webauthn;

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
import com.vitalsshield.devtools.DevSeeder;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * DECISIONS #66: the DEV_SEED passkey (private key in a file) may only finish the seed tool's provisioning, and only
 * in the local profile. Every refusal is checked to leave the database unchanged.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DevSeedPasskeyIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;
    static final SoftwareAuthenticator ALICE = SoftwareAuthenticator.create();
    static AdminHttp alice;
    static String device;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-devseed-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired RegistryAnchorKey anchorKey;
    @Autowired PasskeyRepository passkeys;
    @Autowired WebAuthnOrigins origins;
    @Autowired AuditLog audit;
    @Autowired AdminSessionStore sessions;

    Path keyFile() {
        return dir.resolve("devseed/passkey.key");
    }

    SimulatorCli sim() {
        return new SimulatorCli(dir.resolve("sim"), dir.resolve("root-ca.pem"), ports);
    }

    @BeforeEach
    void clinicianAndDevice() {
        if (alice != null) {
            return;
        }
        alice = new AdminHttp(ports.admin());
        WebAuthnSteps.bootstrapClinician(alice, ALICE, "dr_alice", ports.adminCodeFile());
        device = "dev_seedrules_target";
        SimulatorCli.Run r = sim().enroll(device, WebAuthnSteps.provision(alice, ALICE, device));
        assertThat(r.exit()).as(r.out()).isZero();
    }

    /** Everything a refused DEV_SEED assertion could have touched. */
    Map<String, Object> snapshot() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("passkeys", jdbc.queryForList(
                "SELECT credential_id_b64, sign_count, purpose FROM clinician_passkeys ORDER BY credential_id_b64"));
        m.put("tokens", jdbc.queryForList("SELECT token_id, status::text FROM device_bootstrap_tokens ORDER BY token_id"));
        m.put("devices", jdbc.queryForList(
                "SELECT device_id, trust_state::text, epoch_resync_allowed FROM devices ORDER BY device_id"));
        m.put("certs", jdbc.queryForList("SELECT serial_number, status::text FROM certificates ORDER BY serial_number"));
        m.put("assignments", jdbc.queryForList(
                "SELECT assignment_id, status::text FROM patient_device_assignments ORDER BY assignment_id"));
        m.put("audit", jdbc.queryForObject("SELECT count(*) FROM security_audit_log", Long.class));
        return m;
    }

    @Test
    @Order(1)
    void devSeedProvisioningStillWorks() {
        long clinicianPasskeys = passkeys.countClinicianPasskeys();
        DevSeeder.Result seeded = DevSeeder.seedWebAuthn(jdbc, tx, Clock.systemUTC(), anchorKey, keyFile(), ports.admin(),
                Set.of("local"), DevSeeder.Request.defaults("dev_seeded_ok"));
        assertThat(jdbc.queryForObject("SELECT purpose FROM clinician_passkeys WHERE clinician_id = 'dev-seed-clinician'",
                String.class)).isEqualTo("DEV_SEED");
        assertThat(passkeys.countClinicianPasskeys()).as("DEV_SEED is not a clinician passkey").isEqualTo(clinicianPasskeys);
        SimulatorCli.Run r = sim().enroll("dev_seeded_ok", seeded.token());
        assertThat(r.exit()).as(r.out()).isZero();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> devices = (List<Map<String, Object>>) alice.get("/api/v1/admin/overview").json().get("devices");
        assertThat(devices).filteredOn(d -> "dev_seeded_ok".equals(d.get("device_id")))
                .singleElement().satisfies(d -> assertThat(d.get("dev_seed")).isEqualTo(true));
    }

    @Test
    @Order(2)
    void devSeedCannotSignIn() {
        SoftwareAuthenticator seed = SoftwareAuthenticator.load(keyFile());
        Map<String, Object> before = snapshot();
        AdminHttp h = new AdminHttp(ports.admin());
        AdminHttp.Response r = WebAuthnSteps.signIn(h, seed);
        assertThat(r.status()).as(r.body()).isEqualTo(403);
        assertThat(r.body()).contains("DEV_SEED_NOT_ALLOWED");
        assertThat(h.cookie()).as("no session created").isNull();
        assertThat(snapshot()).isEqualTo(before);
    }

    @Test
    @Order(3)
    void devSeedCannotApproveQuarantine() {
        SoftwareAuthenticator seed = SoftwareAuthenticator.load(keyFile());
        Map<String, Object> before = snapshot();
        AdminHttp.Response begin = alice.post("/api/v1/admin/devices/" + device + "/quarantine/begin",
                AdminHttp.json(Map.of("lookback_minutes", 10, "reason", "dev seed approval")));
        assertThat(begin.status()).isEqualTo(200);
        AdminHttp.Response finish = alice.post("/api/v1/admin/devices/" + device + "/quarantine/finish",
                SoftwareAuthenticator.finishBody(seed.assert_(begin.body(), Variant.good(alice.origin())),
                        (String) begin.json().get("ceremony_id")));
        assertThat(finish.status()).as(finish.body()).isEqualTo(403);
        assertThat(finish.body()).contains("DEV_SEED_NOT_ALLOWED");
        assertThat(snapshot()).isEqualTo(before);
    }

    @Test
    @Order(4)
    void devSeedCannotApproveRestore() {
        SoftwareAuthenticator seed = SoftwareAuthenticator.load(keyFile());
        jdbc.update("UPDATE devices SET trust_state = 'REAUTH_REQUIRED' WHERE device_id = ?", device);
        Map<String, Object> before = snapshot();
        AdminHttp.Response begin = alice.post("/api/v1/admin/devices/" + device + "/restore-active/begin", "{}");
        assertThat(begin.status()).isEqualTo(200);
        AdminHttp.Response finish = alice.post("/api/v1/admin/devices/" + device + "/restore-active/finish",
                SoftwareAuthenticator.finishBody(seed.assert_(begin.body(), Variant.good(alice.origin())),
                        (String) begin.json().get("ceremony_id")));
        assertThat(finish.status()).as(finish.body()).isEqualTo(403);
        assertThat(finish.body()).contains("DEV_SEED_NOT_ALLOWED");
        assertThat(snapshot()).isEqualTo(before);
        jdbc.update("UPDATE devices SET trust_state = 'ACTIVE' WHERE device_id = ?", device);
    }

    @Test
    @Order(5)
    void devSeedRefusedOutsideLocalProfile() {
        SoftwareAuthenticator seed = SoftwareAuthenticator.load(keyFile());
        Map<String, Object> before = snapshot();

        // a) The seed tool refuses to run without the local profile, before touching anything.
        Path otherKey = dir.resolve("devseed-prod/passkey.key");
        assertThatThrownBy(() -> DevSeeder.seedWebAuthn(jdbc, tx, Clock.systemUTC(), anchorKey, otherKey, ports.admin(),
                Set.of("default"), DevSeeder.Request.defaults("dev_seed_prod")))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("local profile");
        assertThat(otherKey).doesNotExist();

        // b) Outside local (what Spring builds without the profile), a DEV_SEED assertion is refused even on the
        //    seed tool's own provisioning path. The device already has an assignment, so begin writes nothing.
        DevSeedPolicy outsideLocal = new DevSeedPolicy(false);
        WebAuthnService webauthn = new WebAuthnService(passkeys, anchorKey, origins, tx, audit, outsideLocal,
                Clock.systemUTC());
        ProvisioningService provisioning = new ProvisioningService(jdbc, tx, webauthn, audit, Clock.systemUTC());
        ProvisioningService.Begun begun = provisioning.beginForSeedTool("dev-seed-clinician", seed.credentialIdB64url(),
                new ProvisioningService.BeginRequest(device, "vitalsshield-sim-v1", "p", 1985, 30));
        String credential = seed.assert_(begun.optionsJson(), Variant.good(alice.origin()));
        assertThatThrownBy(() -> provisioning.finish("dev-seed-clinician", begun.ceremonyId(), credential))
                .isInstanceOfSatisfying(WebAuthnFailure.class, e -> assertThat(e.status()).isEqualTo(403));
        assertThatThrownBy(() -> webauthn.registerBeginDevSeed("dev-seed-clinician", "dev-seed"))
                .isInstanceOf(WebAuthnFailure.class);

        // c) Protocol A outside local refuses a token that a DEV_SEED credential approved.
        Map<String, Object> t = jdbc.queryForMap("""
                SELECT t.webauthn_cred_id_b64, t.webauthn_auth_data, t.webauthn_client_json, t.webauthn_signature, t.expires_at
                  FROM device_bootstrap_tokens t JOIN clinician_passkeys p ON p.credential_id_b64 = t.webauthn_cred_id_b64
                 WHERE p.purpose = 'DEV_SEED' AND t.device_id = 'dev_seeded_ok'
                """);
        ProvisioningAssertionVerifier.StoredApproval approval = new ProvisioningAssertionVerifier.StoredApproval(
                (String) t.get("webauthn_cred_id_b64"), (String) t.get("webauthn_auth_data"),
                (String) t.get("webauthn_client_json"), (String) t.get("webauthn_signature"),
                ((java.sql.Timestamp) t.get("expires_at")).toInstant());
        ProvisioningAssertionVerifier strict = new ProvisioningAssertionVerifier(passkeys, anchorKey, origins, outsideLocal);
        assertThat(strict.verify("dev_seeded_ok", "any-token", approval)).hasValueSatisfying(
                reason -> assertThat(reason).contains("DEV_SEED"));

        assertThat(snapshot()).isEqualTo(before);
    }
}
