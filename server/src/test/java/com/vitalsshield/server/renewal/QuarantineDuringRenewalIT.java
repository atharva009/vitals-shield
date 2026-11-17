package com.vitalsshield.server.renewal;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.quarantine.QuarantineService;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.Renewals;
import com.vitalsshield.simulator.CertIds;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.nio.file.Files;
import java.nio.file.Path;
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
 * Quarantine while one certificate is RENEWED in grace (A), one is ACTIVE (B) and one is ISSUED_PENDING_USE (C):
 * all three are revoked KEY_COMPROMISE, every live socket of each closes, and the CRL lists all three.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class QuarantineDuringRenewalIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-quar-renew-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        registry.add("vitalsshield.pki.renewal-grace", () -> "PT60S");
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;

    SpineFixture fx() {
        return new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
    }

    @Autowired CertificateActivationService activation;
    @Autowired QuarantineService quarantine;
    @Autowired CrlService crls;

    static boolean closed(MtlsTestClient.Connection c) {
        try {
            c.get("/api/v1/telemetry/ping");
            return false;
        } catch (IOException expected) {
            return true;
        }
    }

    @Test
    void quarantineRevokesRenewedActiveAndPending() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_quar_renew");
        Renewals.Identity a = Renewals.identity(d);
        Renewals.Identity b;
        try (MtlsTestClient.Connection c = Renewals.connect(ports.mtls(), anchors.root(), a)) {
            b = Renewals.renewOk(c, a, d.deviceId());
        }
        try (MtlsTestClient.Connection c = Renewals.connect(ports.mtls(), anchors.root(), b)) {
            assertThat(SpineFixture.ingest(c, SpineFixture.frame(b.as(d), 1, UUID.randomUUID())).status())
                    .isEqualTo(200);
        }
        assertThat(activation.awaitIdle(Duration.ofSeconds(10))).isTrue();
        Renewals.Identity cPending;
        try (MtlsTestClient.Connection c = Renewals.connect(ports.mtls(), anchors.root(), b)) {
            cPending = Renewals.renewOk(c, b, d.deviceId());
        }
        assertThat(jdbc.queryForList("SELECT status::text FROM certificates WHERE device_id = ? ORDER BY issued_at",
                String.class, d.deviceId())).containsExactly("RENEWED", "ACTIVE", "ISSUED_PENDING_USE");

        MtlsTestClient.Connection sa = Renewals.connect(ports.mtls(), anchors.root(), a);
        MtlsTestClient.Connection sb = Renewals.connect(ports.mtls(), anchors.root(), b);
        MtlsTestClient.Connection sc = Renewals.connect(ports.mtls(), anchors.root(), cPending);
        try {
            for (MtlsTestClient.Connection s : List.of(sa, sb, sc)) {
                assertThat(s.get("/api/v1/telemetry/ping").status()).isEqualTo(200);
            }
            QuarantineService.Result r = quarantine.quarantine(d.deviceId(), 10, "quarantine during renewal")
                    .block(Duration.ofSeconds(20));
            assertThat(r.certsRevoked()).isEqualTo(3);
            assertThat(r.channelsClosed()).isGreaterThanOrEqualTo(3);
            for (MtlsTestClient.Connection s : List.of(sa, sb, sc)) {
                assertThat(closed(s)).isTrue();
            }
        } finally {
            sa.close();
            sb.close();
            sc.close();
        }
        assertThat(jdbc.queryForList("""
                SELECT status::text || ' ' || revocation_reason FROM certificates WHERE device_id = ? ORDER BY issued_at
                """, String.class, d.deviceId())).containsOnly("REVOKED KEY_COMPROMISE");
        for (Renewals.Identity id : List.of(a, b, cPending)) {
            assertThat(Renewals.awaitOnCrl(crls, id.cert().getSerialNumber())).as(CertIds.serial(id.cert()))
                    .isNotNull();
            assertThat(MtlsTestClient.attempt(ports.mtls(), anchors.root(), id.key(), List.of(id.cert()),
                    "/api/v1/telemetry/ping").kind()).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);
        }
    }
}
