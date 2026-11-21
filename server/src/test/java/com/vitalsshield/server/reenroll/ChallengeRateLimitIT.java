package com.vitalsshield.server.reenroll;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.testsupport.ReEnrolls;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.GatewayClient;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * DECISIONS #90 at the endpoint: with the local profile's limits (10 per minute per remote address), the 11th GET
 * /api/v1/devices/challenge within a minute from 127.0.0.1 is 429 RATE_LIMITED with a Retry-After. Its own context, so
 * no other test has spent from the bucket.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class ChallengeRateLimitIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-ratelimit-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    @Autowired ReEnrollProperties props;

    @Test
    void eleventhChallengeWithinAMinuteIs429WithRetryAfter() {
        assertThat(props.perAddressLimit()).as("local profile limit").isEqualTo(10);
        Path trust = dir.resolve("root-ca.pem");
        for (int i = 1; i <= 10; i++) {
            GatewayClient.Response r = ReEnrolls.get(ports, trust, "/api/v1/devices/challenge?device_id=dev_rl_" + i);
            assertThat(r.status()).as("request %d: %s", i, r.body()).isEqualTo(200);
        }

        GatewayClient.Response eleventh = ReEnrolls.get(ports, trust, "/api/v1/devices/challenge?device_id=dev_rl_11");

        assertThat(eleventh.status()).as(eleventh.body()).isEqualTo(429);
        assertThat(eleventh.body()).isEqualTo("{\"error\":\"RATE_LIMITED\"}");
        long retryAfter = Long.parseLong(eleventh.headers().firstValue("Retry-After").orElseThrow());
        assertThat(retryAfter).isBetween(1L, 60L);
    }
}
