package com.vitalsshield.server.admin.webauthn;

import static org.assertj.core.api.Assertions.assertThat;

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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.vitalsshield.server.kms.KmsSigner;

/** Protocol A re-verifies the stored provisioning approval before any KMS call (DECISIONS #57). */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ProvisioningReverifyIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;
    static final SoftwareAuthenticator ALICE = SoftwareAuthenticator.create();
    static AdminHttp alice;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-reverify-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired KmsSigner kms;
    @Autowired com.vitalsshield.server.pki.CrlService crls;

    /** KMS Sign count once no CRL republication from an earlier step is still running. */
    long settledSignCount() {
        for (int i = 0; i < 100 && !crls.isIdle(); i++) {
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        return kms.signCount();
    }

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

    String tokenStatus(String deviceId) {
        return jdbc.queryForObject("SELECT status::text FROM device_bootstrap_tokens WHERE device_id = ? "
                + "ORDER BY expires_at DESC LIMIT 1", String.class, deviceId);
    }

    @Test
    @Order(1)
    void provisionedThroughTheApiEnrolls() {
        String token = WebAuthnSteps.provision(alice, ALICE, "dev_reverify_ok");
        Map<String, Object> row = jdbc.queryForMap("SELECT * FROM device_bootstrap_tokens WHERE device_id = 'dev_reverify_ok'");
        assertThat(row.get("issued_by_clinician")).isEqualTo("dr_alice");
        assertThat(row.get("webauthn_cred_id_b64")).isEqualTo(ALICE.credentialIdB64url());
        assertThat((String) row.get("webauthn_client_json")).doesNotContain("DEV-SEED");
        SimulatorCli.Run r = sim().enroll("dev_reverify_ok", token);
        assertThat(r.exit()).as(r.out()).isZero();
        assertThat(r.out()).startsWith("ENROLLED");
        assertThat(tokenStatus("dev_reverify_ok")).isEqualTo("CONSUMED");
    }

    @Test
    @Order(2)
    void sqlForgedTokenIsRefusedWithoutAnyKmsSign() {
        String token = com.vitalsshield.server.admin.webauthn.ProvisioningRecords.newToken();
        jdbc.update("INSERT INTO devices (device_id, hardware_model) VALUES ('dev_forged', 'sim')");
        jdbc.update("""
                INSERT INTO patient_device_assignments (assignment_id, device_id, patient_id, patient_birth_year,
                                                        max_renewal_horizon)
                VALUES (gen_random_uuid(), 'dev_forged', 'p', 1985, NOW() + INTERVAL '30 days')
                """);
        jdbc.update("""
                INSERT INTO device_bootstrap_tokens (token_id, device_id, token_hash, issued_by_clinician,
                    webauthn_cred_id_b64, webauthn_auth_data, webauthn_client_json, webauthn_signature, expires_at)
                VALUES (gen_random_uuid(), 'dev_forged', ?, 'dr_alice', ?, 'FAKE', 'FAKE', 'FAKE', NOW() + INTERVAL '15 minutes')
                """, WebAuthnBytes.sha256Hex(token.getBytes(java.nio.charset.StandardCharsets.US_ASCII)),
                ALICE.credentialIdB64url());
        long signsBefore = settledSignCount();

        SimulatorCli.Run r = sim().enroll("dev_forged", token);

        assertThat(r.exit()).as(r.out()).isNotZero();
        assertThat(r.out()).contains("403").contains("PROVISIONING_UNVERIFIED");
        assertThat(tokenStatus("dev_forged")).isEqualTo("REVOKED");
        assertThat(settledSignCount()).as("no KMS Sign call").isEqualTo(signsBefore);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM certificates WHERE device_id = 'dev_forged'", Integer.class))
                .isZero();
    }

    @Test
    @Order(3)
    void alteredClientJsonIsRefused() {
        String token = WebAuthnSteps.provision(alice, ALICE, "dev_reverify_tampered");
        String stored = jdbc.queryForObject(
                "SELECT webauthn_client_json FROM device_bootstrap_tokens WHERE device_id = 'dev_reverify_tampered'",
                String.class);
        String json = new String(WebAuthnBytes.fromB64url(stored), java.nio.charset.StandardCharsets.UTF_8);
        String altered = json.replace("\"crossOrigin\":false", "\"crossOrigin\":false,\"x\":1");
        assertThat(altered).isNotEqualTo(json);
        jdbc.update("UPDATE device_bootstrap_tokens SET webauthn_client_json = ? WHERE device_id = 'dev_reverify_tampered'",
                WebAuthnBytes.b64url(altered.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        long signsBefore = settledSignCount();

        SimulatorCli.Run r = sim().enroll("dev_reverify_tampered", token);

        assertThat(r.out()).contains("403").contains("PROVISIONING_UNVERIFIED");
        assertThat(tokenStatus("dev_reverify_tampered")).isEqualTo("REVOKED");
        assertThat(settledSignCount()).isEqualTo(signsBefore);
    }

    @Autowired RegistryAnchorKey anchorKey;
    @Autowired org.springframework.transaction.support.TransactionTemplate tx;

    @Test
    @Order(4)
    void devSeedTokensPassTheSameVerification() throws IOException {
        Path keyFile = dir.resolve("devseed/passkey.key");
        var first = com.vitalsshield.devtools.DevSeeder.seedWebAuthn(jdbc, tx, java.time.Clock.systemUTC(), anchorKey,
                keyFile, ports.admin(), java.util.Set.of("local"), com.vitalsshield.devtools.DevSeeder.Request.defaults("dev_seeded"));
        assertThat(java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(keyFile)))
                .isEqualTo("rw-------");
        SimulatorCli.Run r = sim().enroll("dev_seeded", first.token());
        assertThat(r.exit()).as(r.out()).isZero();

        // A second run reuses the stored passkey: still one dev-seed passkey, and it does not count as a clinician's.
        com.vitalsshield.devtools.DevSeeder.seedWebAuthn(jdbc, tx, java.time.Clock.systemUTC(), anchorKey, keyFile,
                ports.admin(), java.util.Set.of("local"), com.vitalsshield.devtools.DevSeeder.Request.defaults("dev_seeded_2"));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM clinician_passkeys WHERE purpose = 'DEV_SEED'",
                Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT issued_by_clinician FROM device_bootstrap_tokens WHERE device_id = 'dev_seeded_2'",
                String.class)).isEqualTo("dev-seed-clinician");
    }
}
