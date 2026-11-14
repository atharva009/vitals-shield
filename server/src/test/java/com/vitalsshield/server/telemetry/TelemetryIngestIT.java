package com.vitalsshield.server.telemetry;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.util.Base64URL;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.crypto.TelemetryJws;
import com.vitalsshield.server.pki.Pems;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.TelemetryFrames;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
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

/** POST /api/v1/telemetry/ingest: binding, signature, payload, assignment, classification, storage. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class TelemetryIngestIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-ingest-it");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    SpineFixture fx;

    @BeforeEach
    void fixture() {
        fx = new SpineFixture(jdbc, tx, ports, trustFile, stateRoot);
    }

    @Test
    void happyPathStoresAcceptedRow() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_ingest_ok");
        UUID batch = UUID.randomUUID();
        String jws = SpineFixture.frame(d, 1, batch);
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            MtlsTestClient.Response r = SpineFixture.ingest(c, jws);
            assertThat(r.status()).as(r.body()).isEqualTo(200);
            assertThat(r.body()).contains("\"accepted\":true").contains("\"trust_state\":\"ACCEPTED\"")
                    .contains("\"idempotent_retry\":false").contains(batch.toString());
        }
        Map<String, Object> row = jdbc.queryForMap(
                "SELECT trust_state::text AS ts, payload_sha256, jws_compact, sequence_number, serial_number "
                        + "FROM telemetry_records WHERE batch_id = ?", batch);
        byte[] payload = new Base64URL(jws.split("\\.")[1]).decode();
        assertThat(row.get("ts")).isEqualTo("ACCEPTED");
        assertThat(row.get("payload_sha256"))
                .isEqualTo(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload)));
        assertThat(row.get("jws_compact")).isEqualTo(jws);
        assertThat(row.get("sequence_number")).isEqualTo(1L);
        assertThat(row.get("serial_number")).isEqualTo(d.cert().getSerialNumber().toString(16));
    }

    @Test
    void storedJwsReverifiesOfflineAgainstStoredCert() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_ingest_atrest");
        UUID batch = UUID.randomUUID();
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            assertThat(SpineFixture.ingest(c, SpineFixture.frame(d, 1, batch)).status()).isEqualTo(200);
        }
        // Offline: only the database row and the certificate stored for its (issuer, serial).
        Map<String, Object> row = jdbc.queryForMap("""
                SELECT t.jws_compact, c.cert_pem, c.cert_thumbprint_s256 FROM telemetry_records t
                  JOIN certificates c USING (issuer_key_hash, serial_number) WHERE t.batch_id = ?
                """, batch);
        X509Certificate cert = Pems.parseCertificate((String) row.get("cert_pem"));
        byte[] payload = TelemetryJws.parseAndVerify((String) row.get("jws_compact"),
                (String) row.get("cert_thumbprint_s256"), cert.getPublicKey());
        assertThat(new String(payload)).contains(batch.toString());
    }

    @Test
    void x5tOfAnotherCertIsCertMismatch() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_ingest_x5t");
        SpineFixture.Device other = fx.enroll("dev_ingest_x5t_other");
        byte[] payload = payload(d, 1);
        String jws = TelemetryJws.sign(payload, d.enrollment().olkKey(), other.cert().getEncoded());
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            MtlsTestClient.Response r = SpineFixture.ingest(c, jws);
            assertThat(r.status()).isEqualTo(401);
            assertThat(r.body()).contains("JWS_CERT_MISMATCH");
        }
    }

    @Test
    void differentKeyWithCorrectX5tIsSigInvalid() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_ingest_wrongkey");
        String jws = TelemetryJws.sign(payload(d, 1), EcKeys.generateP256().getPrivate(), d.cert().getEncoded());
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            MtlsTestClient.Response r = SpineFixture.ingest(c, jws);
            assertThat(r.status()).isEqualTo(401);
            assertThat(r.body()).contains("JWS_INVALID").contains("SIG_INVALID");
        }
    }

    @Test
    void otherDevicesIdIs403() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_ingest_mine");
        byte[] payload = TelemetryFrames.payload("dev_ingest_someone_else", d.assignmentId(), d.bootEpoch(), 1,
                UUID.randomUUID(), Instant.now(), Instant.now(), TelemetryFrames.Metrics.resting(new java.util.Random()));
        String jws = TelemetryJws.sign(payload, d.enrollment().olkKey(), d.cert().getEncoded());
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            MtlsTestClient.Response r = SpineFixture.ingest(c, jws);
            assertThat(r.status()).isEqualTo(403);
            assertThat(r.body()).contains("DEVICE_MISMATCH");
        }
    }

    @Test
    void staleAssignmentIs409WithCurrentId() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_ingest_assign");
        String jws = SpineFixture.frame(d, 1, UUID.randomUUID(), Instant.now(),
                TelemetryFrames.Metrics.resting(new java.util.Random()), UUID.randomUUID().toString(), d.bootEpoch());
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            MtlsTestClient.Response r = SpineFixture.ingest(c, jws);
            assertThat(r.status()).isEqualTo(409);
            assertThat(r.body()).contains("ASSIGNMENT_CHANGED").contains(d.assignmentId());
        }
    }

    @Test
    void wrongBootEpochIs409() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_ingest_epoch");
        String jws = SpineFixture.frame(d, 1, UUID.randomUUID(), Instant.now(),
                TelemetryFrames.Metrics.resting(new java.util.Random()), d.assignmentId(), d.bootEpoch() + 5);
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            MtlsTestClient.Response r = SpineFixture.ingest(c, jws);
            assertThat(r.status()).isEqualTo(409);
            assertThat(r.body()).contains("BOOT_EPOCH_MISMATCH");
        }
    }

    @Test
    void implausibleHrIsStoredAndConsumesItsSequence() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_ingest_implausible");
        UUID batch = UUID.randomUUID();
        String jws = SpineFixture.frame(d, 1, batch, Instant.now(),
                new TelemetryFrames.Metrics(400, 40.0, 98.0, 3.0, 0, 0.02), d.assignmentId(), d.bootEpoch());
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            MtlsTestClient.Response r = SpineFixture.ingest(c, jws);
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.body()).contains("REJECTED_IMPLAUSIBLE");

            MtlsTestClient.Response again = SpineFixture.ingest(c, SpineFixture.frame(d, 1, UUID.randomUUID()));
            assertThat(again.status()).isEqualTo(409);
            assertThat(again.body()).contains("DUPLICATE_SEQUENCE_REPLAY");
        }
        assertThat(jdbc.queryForObject("SELECT trust_state::text FROM telemetry_records WHERE batch_id = ?",
                String.class, batch)).isEqualTo("REJECTED_IMPLAUSIBLE");
    }

    @Test
    void signalDegradedStored() throws Exception {
        SpineFixture.Device d = fx.enroll("dev_ingest_degraded");
        String jws = SpineFixture.frame(d, 1, UUID.randomUUID(), Instant.now(),
                new TelemetryFrames.Metrics(70, 40.0, 98.0, 0.3, 0, 0.02), d.assignmentId(), d.bootEpoch());
        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            assertThat(SpineFixture.ingest(c, jws).body()).contains("SIGNAL_DEGRADED");
        }
    }

    private static byte[] payload(SpineFixture.Device d, long seq) {
        return TelemetryFrames.payload(d.deviceId(), d.assignmentId(), d.bootEpoch(), seq, UUID.randomUUID(),
                Instant.now(), Instant.now(), TelemetryFrames.Metrics.resting(new java.util.Random()));
    }
}
