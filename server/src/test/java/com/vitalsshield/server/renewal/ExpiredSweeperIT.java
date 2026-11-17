package com.vitalsshield.server.renewal;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.Renewals;
import com.vitalsshield.simulator.CertIds;
import java.io.IOException;
import java.util.List;
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

/** DECISIONS #84: a certificate past not_after becomes EXPIRED and is deny-listed (handshake refused). */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class ExpiredSweeperIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-expired-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;

    SpineFixture fx() {
        return new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
    }

    @Autowired RenewalSweepers sweepers;
    @Autowired CertificateDenyList denyList;

    @Test
    void certPastNotAfterBecomesExpiredAndDenied() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_expired");
        SpineFixture.Device live = fx().enroll("dev_not_expired");
        Renewals.Identity id = Renewals.identity(d);
        CertKey key = CertKey.of(CertIds.issuerKeyHash(id.cert()), CertIds.serial(id.cert()));
        assertThat(MtlsTestClient.attempt(ports.mtls(), anchors.root(), id.key(), List.of(id.cert()),
                "/api/v1/telemetry/ping").is200()).isTrue();

        // The stored not_after is the sweeper's input; move it into the past (the X.509 notAfter is still ahead, so
        // only the deny-list entry can refuse the handshake below).
        jdbc.update("UPDATE certificates SET not_after = NOW() - INTERVAL '1 second' WHERE serial_number = ?",
                key.serial());
        List<RenewalSweepers.ExpiredCert> expired = sweepers.sweepExpired();

        assertThat(expired).extracting(RenewalSweepers.ExpiredCert::key).containsExactly(key);
        assertThat(jdbc.queryForObject("SELECT status::text FROM certificates WHERE serial_number = ?", String.class,
                key.serial())).isEqualTo("EXPIRED");
        assertThat(denyList.isDenied(key)).isTrue();
        assertThat(denyList.entry(key)).hasValueSatisfying(e -> assertThat(e.reason()).isEqualTo("EXPIRED"));
        assertThat(MtlsTestClient.attempt(ports.mtls(), anchors.root(), id.key(), List.of(id.cert()),
                "/api/v1/telemetry/ping").kind()).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);
        // Another device's certificate is untouched, and a second sweep finds nothing.
        assertThat(jdbc.queryForObject("SELECT status::text FROM certificates WHERE device_id = ?", String.class,
                live.deviceId())).isEqualTo("ACTIVE");
        assertThat(sweepers.sweepExpired()).isEmpty();
    }
}
