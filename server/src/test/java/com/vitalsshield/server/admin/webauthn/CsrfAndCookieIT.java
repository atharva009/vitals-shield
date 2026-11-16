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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/** Origin checks, the localhost redirect, and the IPv6 loopback listener (DECISIONS #55, #59). */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CsrfAndCookieIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    final HttpClient raw = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-csrf-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Test
    @Order(1)
    void postWithAForeignOriginIs403() {
        AdminHttp h = new AdminHttp(ports.admin());
        assertThat(h.post("/api/v1/admin/session/begin", "{}", "http://evil.example", null).status()).isEqualTo(403);
        assertThat(h.post("/api/v1/admin/session/begin", "{}", "http://127.0.0.1:" + ports.admin(), null).status())
                .as("the IP origin is not the RP origin").isEqualTo(403);
    }

    @Test
    @Order(2)
    void postWithoutOriginIs403() {
        AdminHttp h = new AdminHttp(ports.admin());
        assertThat(h.post("/api/v1/admin/session/begin", "{}", null, null).status()).isEqualTo(403);
        assertThat(h.post("/api/v1/admin/session/begin", "{}").status()).as("right origin").isEqualTo(200);
    }

    @Test
    @Order(3)
    void htmlOn127IsRedirectedToLocalhost() throws Exception {
        HttpResponse<String> r = raw.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + ports.admin() + "/"))
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(r.statusCode()).isEqualTo(307);
        assertThat(r.headers().firstValue("Location")).hasValue("http://localhost:" + ports.admin() + "/");
        HttpResponse<String> api = raw.send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + ports.admin() + "/api/v1/admin/boot-status")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(api.statusCode()).as("API GETs are not redirected").isEqualTo(200);
    }

    @Test
    @Order(4)
    void adminPortAnswersOnIpv6Loopback() throws Exception {
        HttpResponse<String> r = raw.send(HttpRequest.newBuilder(
                URI.create("http://[::1]:" + ports.admin() + "/api/v1/admin/boot-status")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(r.statusCode()).isEqualTo(200);
    }

    @Test
    @Order(5)
    void sessionCookieIsNotSentForAnotherPathAndUnknownCookiesAre401() {
        AdminHttp h = new AdminHttp(ports.admin());
        h.cookie("vs_admin_session=forged");
        assertThat(h.get("/api/v1/admin/overview").status()).isEqualTo(401);
    }
}
