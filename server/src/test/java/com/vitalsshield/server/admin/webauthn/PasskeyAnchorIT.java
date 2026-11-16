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


/** The KMS Key #4 passkey anchor stops a database-only key swap (DECISIONS #56). */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PasskeyAnchorIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static final SoftwareAuthenticator ALICE = SoftwareAuthenticator.create();
    static final SoftwareAuthenticator BOB = SoftwareAuthenticator.create();

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-anchor-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired PasskeyRepository passkeys;
    @Autowired RegistryAnchorKey anchorKey;

    @Test
    @Order(1)
    void swappedPublicKeyFailsWithAnAnchorErrorAndUntouchedRowsVerify() {
        AdminHttp a = new AdminHttp(ports.admin());
        WebAuthnSteps.bootstrapClinician(a, ALICE, "dr_alice", ports.adminCodeFile());
        assertThat(WebAuthnSteps.register(a, BOB, "dr_bob", null).status()).isEqualTo(200);
        assertThat(WebAuthnSteps.signIn(new AdminHttp(ports.admin()), BOB).status()).isEqualTo(200);

        // A database-only attacker replaces Bob's public key with one they hold, keeping Bob's credential id.
        SoftwareAuthenticator mallory = SoftwareAuthenticator.impersonating(BOB);
        jdbc.update("UPDATE clinician_passkeys SET public_key_cose_der_b64 = ? WHERE credential_id_b64 = ?",
                java.util.Base64.getEncoder().encodeToString(mallory.coseKey()), BOB.credentialIdB64url());

        AdminHttp m = new AdminHttp(ports.admin());
        AdminHttp.Response r = WebAuthnSteps.signIn(m, mallory);
        assertThat(r.status()).as(r.body()).isEqualTo(401);
        assertThat(r.body()).contains("PASSKEY_ANCHOR_INVALID");
        assertThat(m.cookie()).isNull();

        PasskeyRepository.Row alice = passkeys.find(ALICE.credentialIdB64url()).orElseThrow();
        assertThat(PasskeyAnchor.verify(anchorKey, alice.credentialId(), alice.clinicianId(), alice.cose(),
                alice.anchorSig())).isTrue();
        assertThat(WebAuthnSteps.signIn(new AdminHttp(ports.admin()), ALICE).status()).isEqualTo(200);
    }

    @Test
    @Order(2)
    void reassignedClinicianFailsTheAnchor() {
        jdbc.update("UPDATE clinician_passkeys SET clinician_id = 'dr_root' WHERE credential_id_b64 = ?",
                ALICE.credentialIdB64url());
        AdminHttp.Response r = WebAuthnSteps.signIn(new AdminHttp(ports.admin()), ALICE);
        assertThat(r.status()).isEqualTo(401);
    }
}
