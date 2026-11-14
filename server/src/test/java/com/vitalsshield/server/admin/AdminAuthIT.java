package com.vitalsshield.server.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.testsupport.TestPorts;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** DECISIONS #41: the boot setup code guards /api/v1/admin/** except GET boot-status. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class AdminAuthIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-admin-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    final HttpClient http = HttpClient.newHttpClient();

    @Test
    void missingBearerIs401WithEmptyBody() throws Exception {
        HttpResponse<String> r = post(null);
        assertThat(r.statusCode()).isEqualTo(401);
        assertThat(r.body()).isEmpty();
    }

    @Test
    void wrongBearerIs401() throws Exception {
        assertThat(post("Bearer not-the-code").statusCode()).isEqualTo(401);
        assertThat(post("Basic " + code()).statusCode()).isEqualTo(401);
    }

    @Test
    void rightBearerPasses() throws Exception {
        // Auth passes; the quarantine controller then rejects the empty body with 400 (not 401).
        HttpResponse<String> r = post("Bearer " + code());
        assertThat(r.statusCode()).isEqualTo(400);
        assertThat(r.body()).contains("VALIDATION_FAILED");
    }

    @Test
    void bootStatusIsOpen() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + ports.admin() + "/api/v1/admin/boot-status")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(r.body()).contains("ADMIN_CODE_ISSUED").contains("LISTENERS_BOUND");
    }

    @Test
    void setupCodeFileIsOwnerReadWriteOnly() throws IOException {
        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(ports.adminCodeFile())))
                .isEqualTo("rw-------");
        assertThat(code()).hasSize(43);
    }

    private String code() throws IOException {
        return Files.readString(ports.adminCodeFile()).trim();
    }

    private HttpResponse<String> post(String authorization) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(
                        "http://127.0.0.1:" + ports.admin() + "/api/v1/admin/devices/dev_x/quarantine"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}"));
        if (authorization != null) {
            b.header("Authorization", authorization);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }
}
