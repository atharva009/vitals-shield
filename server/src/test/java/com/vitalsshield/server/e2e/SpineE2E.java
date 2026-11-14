package com.vitalsshield.server.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.vitalsshield.crypto.TelemetryJws;
import com.vitalsshield.server.pki.Pems;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.LedgerInvariant;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.GatewayClient;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
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

/** The thin spine end to end, 5 times: seed, enroll, stream, verify at rest, quarantine, evict, refuse, CRL. */
@Tag("e2e")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SpineE2E {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-spine-e2e");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;

    final List<Long> latencies = new ArrayList<>();

    @Test
    void spineFiveTimes() throws Exception {
        for (int run = 1; run <= 5; run++) {
            latencies.add(spine("dev_spine_" + run));
        }
        System.out.println("SPINE_REVOCATION_LATENCY_MICROS=" + latencies);
        assertThat(latencies).allSatisfy(l -> assertThat(l).isLessThan(500_000));
    }

    @AfterAll
    void ledgerInvariant() {
        assertThat(LedgerInvariant.violations(jdbc)).isZero();
    }

    private long spine(String dev) throws Exception {
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, trustFile, stateRoot);
        SpineFixture.Device d = fx.enroll(dev);

        // 1. Stream 20 batches with the in-process simulator.
        ByteArrayOutputStream log = new ByteArrayOutputStream();
        int exit = d.sim().stream(0, 20, new PrintStream(log, true, StandardCharsets.UTF_8));
        String out = log.toString(StandardCharsets.UTF_8);
        assertThat(exit).as(out).isZero();
        assertThat(out.lines().filter(l -> l.startsWith("SENT ")).toList()).hasSize(20)
                .allSatisfy(l -> assertThat(l).contains("status=200"));
        assertThat(count(dev, "ACCEPTED")).isEqualTo(20);

        // 2. At-rest integrity: re-verify one stored JWS against the stored certificate.
        Map<String, Object> row = jdbc.queryForList("""
                SELECT t.jws_compact, c.cert_pem, c.cert_thumbprint_s256 FROM telemetry_records t
                  JOIN certificates c USING (issuer_key_hash, serial_number) WHERE t.device_id = ? LIMIT 1
                """, dev).get(0);
        X509Certificate stored = Pems.parseCertificate((String) row.get("cert_pem"));
        TelemetryJws.parseAndVerify((String) row.get("jws_compact"), (String) row.get("cert_thumbprint_s256"),
                stored.getPublicKey());

        // 3. The device's keep-alive connection stays open while quarantine runs.
        long latency;
        try (MtlsTestClient.Connection live = fx.connect(d, anchors.root())) {
            assertThat(live.get("/api/v1/telemetry/ping").status()).isEqualTo(200);
            HttpResponse<String> q = quarantine(dev);
            assertThat(q.statusCode()).as(q.body()).isEqualTo(200);
            Map<String, Object> qr = JSONObjectUtils.parse(q.body());
            latency = ((Number) qr.get("revocation_latency_micros")).longValue();
            assertThat(((Number) qr.get("channels_closed")).intValue()).isGreaterThanOrEqualTo(1);

            // 4. Observed by the device: the connection closes ...
            assertThat(live.awaitClosedWithin(Duration.ofSeconds(2))).as("live socket closed").isTrue();
        }
        // ... and its reconnect is refused at the handshake.
        ByteArrayOutputStream after = new ByteArrayOutputStream();
        int exitAfter = d.sim().stream(0, 1, new PrintStream(after, true, StandardCharsets.UTF_8));
        assertThat(exitAfter).isEqualTo(3);
        assertThat(after.toString(StandardCharsets.UTF_8)).contains("REJECTED handshake_refused");

        assertThat(count(dev, "QUARANTINED")).isEqualTo(20);
        assertThat(jdbc.queryForMap("SELECT status::text AS s, revocation_reason AS r FROM certificates "
                + "WHERE device_id = ?", dev)).containsEntry("s", "REVOKED").containsEntry("r", "KEY_COMPROMISE");
        assertThat(onPublishedCrl(d.cert())).as("serial on the CRL over 8444").isTrue();
        Map<String, Object> device = jdbc.queryForMap("SELECT trust_state::text AS ts, dek_spki_der_b64 FROM devices "
                + "WHERE device_id = ?", dev);
        assertThat(device.get("ts")).isEqualTo("QUARANTINED");
        assertThat(device.get("dek_spki_der_b64")).isNull();
        assertThat(LedgerInvariant.violations(jdbc)).isZero();
        System.out.println("SPINE " + dev + " revocation_latency_micros=" + latency);
        return latency;
    }

    private int count(String dev, String trustState) {
        return jdbc.queryForObject("SELECT count(*) FROM telemetry_records WHERE device_id = ? AND trust_state = ?::telemetry_trust_state",
                Integer.class, dev, trustState);
    }

    private HttpResponse<String> quarantine(String dev) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + ports.admin()
                        + "/api/v1/admin/devices/" + dev + "/quarantine"))
                .header("Authorization", "Bearer " + Files.readString(ports.adminCodeFile()).trim())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"lookback_minutes\":60,\"reason\":\"spine e2e\"}")).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private boolean onPublishedCrl(X509Certificate cert) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            GatewayClient.Response r = GatewayClient.publicClient(trustFile)
                    .get(URI.create("https://127.0.0.1:" + ports.pub() + "/api/v1/pki/intermediate-crl.pem"));
            X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
                    .generateCRL(new ByteArrayInputStream(r.body().getBytes(StandardCharsets.US_ASCII)));
            if (crl.getRevokedCertificate(cert.getSerialNumber()) != null) {
                return true;
            }
            Thread.sleep(50);
        }
        return false;
    }
}
