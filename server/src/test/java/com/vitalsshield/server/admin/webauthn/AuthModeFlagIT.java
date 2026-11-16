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

import com.vitalsshield.server.VitalsShieldServerApplication;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * vitalsshield.admin.auth: in bearer mode the Phase 5 admin plane is unchanged; in webauthn mode the setup code is
 * refused everywhere except registering the first passkey (DECISIONS #60).
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthModeFlagIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-mode-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry); // bearer mode
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired org.springframework.transaction.support.TransactionTemplate tx;

    String bearer() {
        return WebAuthnSteps.setupCode(ports.adminCodeFile());
    }

    @Test
    @Order(1)
    void bearerModeKeepsThePhase5Flows() {
        AdminHttp h = new AdminHttp(ports.admin());
        String code = bearer();
        assertThat(h.get("/api/v1/admin/auth/status").json()).containsEntry("mode", "bearer");
        assertThat(h.post("/api/v1/admin/devices/x/quarantine", "{}", null, null).status()).isEqualTo(401);

        // Dev seed token with fake WebAuthn fields enrolls (no re-verification in bearer mode), then the single-step
        // quarantine works with the bearer.
        String token = new com.vitalsshield.devtools.DevSeeder(jdbc, tx, java.time.Clock.systemUTC())
                .seed(com.vitalsshield.devtools.DevSeeder.Request.defaults("dev_mode_bearer")).token();
        SimulatorCli.Run e = new SimulatorCli(dir.resolve("sim"), dir.resolve("root-ca.pem"), ports)
                .enroll("dev_mode_bearer", token);
        assertThat(e.exit()).as(e.out()).isZero();
        AdminHttp.Response q = h.post("/api/v1/admin/devices/dev_mode_bearer/quarantine",
                AdminHttp.json(Map.of("lookback_minutes", 5, "reason", "bearer mode")), null, code);
        assertThat(q.status()).as(q.body()).isEqualTo(200);
        assertThat(q.json()).containsEntry("certs_revoked", 1);

        // The Phase 6 routes do not exist in bearer mode.
        assertThat(h.post("/api/v1/admin/session/begin", "{}", null, code).status()).isEqualTo(404);
        assertThat(h.post("/api/v1/admin/devices/provision/begin", "{}", null, code).status()).isEqualTo(404);
    }

    @Test
    @Order(2)
    void webauthnModeRefusesTheBearerExceptForTheFirstPasskey() {
        TestPorts.Listeners p2 = TestPorts.allocate();
        List<String> args = new ArrayList<>(List.of(
                "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "--spring.datasource.username=" + POSTGRES.getUsername(),
                "--spring.datasource.password=" + POSTGRES.getPassword(),
                "--vitalsshield.pki.trust-file=" + dir.resolve("root-ca-2.pem"),
                "--spring.main.keep-alive=false"));
        args.addAll(p2.asArgs("webauthn"));
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(VitalsShieldServerApplication.class)
                .profiles("local").run(args.toArray(String[]::new))) {
            AdminHttp h = new AdminHttp(p2.admin());
            String code = WebAuthnSteps.setupCode(p2.adminCodeFile());
            for (String path : List.of("/api/v1/admin/overview", "/api/v1/admin/session", "/api/v1/admin/audit")) {
                assertThat(h.post(path, "{}", h.origin(), code).status()).as("POST " + path).isIn(401, 405);
            }
            assertThat(h.post("/api/v1/admin/devices/dev_mode_bearer/quarantine",
                    AdminHttp.json(Map.of("lookback_minutes", 5, "reason", "x")), h.origin(), code).status())
                    .as("single-step quarantine does not exist in webauthn mode").isEqualTo(404);
            assertThat(h.post("/api/v1/admin/devices/provision/begin", "{}", h.origin(), code).status()).isEqualTo(401);
            AdminHttp.Response reg = WebAuthnSteps.register(h, SoftwareAuthenticator.create(), "dr_first", code);
            assertThat(reg.status()).as(reg.body()).isEqualTo(200);
            AdminHttp.Response second = WebAuthnSteps.register(h, SoftwareAuthenticator.create(), "dr_second", code);
            assertThat(second.status()).isEqualTo(401);
        }
    }
}
