package com.vitalsshield.server.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.AdminHttp;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.WebAuthnSteps;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
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

/** With eviction off, a revoked certificate's next ingest on the same keep-alive connection is refused per request. */
@Tag("e2e")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest(properties = "vitalsshield.eviction.enabled=false")
class TelemetryPerRequest403E2E {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-403-e2e");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;

    @Test
    void ingestOnSameConnectionAfterRevokeIs403() throws Exception {
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, trustFile, stateRoot);
        AdminHttp admin = new AdminHttp(ports.admin());
        SoftwareAuthenticator clinician = SoftwareAuthenticator.create();
        WebAuthnSteps.bootstrapClinician(admin, clinician, "dr_403", ports.adminCodeFile());
        SpineFixture.Device d = fx.enrollWithToken("dev_e2e_403",
                WebAuthnSteps.provision(admin, clinician, "dev_e2e_403"));
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            assertThat(SpineFixture.ingest(c, SpineFixture.frame(d, 1, UUID.randomUUID())).status()).isEqualTo(200);

            // Step-up quarantine; eviction is off, so the connection stays open and the next request is refused
            // by the per-request status check.
            AdminHttp.Response q = WebAuthnSteps.quarantine(admin, clinician, "dev_e2e_403", 1, "per-request 403");
            assertThat(q.status()).as(q.body()).isEqualTo(200);
            assertThat(q.json()).containsEntry("approved_by", "dr_403").containsEntry("channels_closed", 0);

            MtlsTestClient.Response r = SpineFixture.ingest(c, SpineFixture.frame(d, 2, UUID.randomUUID()));
            assertThat(r.status()).isEqualTo(403);
            assertThat(r.body()).contains("CERT_NOT_ACCEPTED");
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM telemetry_records WHERE device_id = 'dev_e2e_403'",
                Integer.class)).as("only the first batch is stored (now quarantined)").isEqualTo(1);
    }
}
