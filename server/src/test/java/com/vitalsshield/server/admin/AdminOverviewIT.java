package com.vitalsshield.server.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.crypto.TelemetryJws;
import com.vitalsshield.devtools.DevSeeder;
import com.vitalsshield.server.pki.Pems;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.TelemetryFrames;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
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
import software.amazon.awssdk.services.kms.KmsClient;

/** GET /api/v1/admin/overview reflects the system as it changes. Ordered: KMS key loss runs last. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AdminOverviewIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-overview-it");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired KmsHealthMonitor kmsHealth;
    @Autowired AdminOverviewService overviewService;
    @Autowired KmsClient kms;

    final HttpClient http = HttpClient.newHttpClient();
    SpineFixture fx;
    SpineFixture.Device device;
    MtlsTestClient.Connection live;

    @Test
    @Order(1)
    void requiresBearer() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(uri("/api/v1/admin/overview")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(r.statusCode()).isEqualTo(401);
    }

    @Test
    @Order(2)
    void freshBoot() throws Exception {
        Map<String, Object> o = overview();
        Map<String, Object> kmsJson = map(o, "kms");
        assertThat(kmsJson.get("healthy")).isEqualTo(true);
        assertThat(kmsJson.get("state")).isEqualTo("HEALTHY");
        assertThat(list(kmsJson, "keys")).hasSize(4);
        assertThat(map(o, "ca")).containsKeys("root", "device_intermediate", "server_tls_ca");
        assertThat(map(map(o, "ca"), "device_intermediate")).containsKeys("crl_number", "crl_next_update", "crl_entries");
        assertThat(list(o, "boot_steps").stream().map(b -> (String) ((Map<?, ?>) b).get("step")).toList()).containsExactly(
                "RECONCILED", "SERIALS_SWEPT", "GATEWAY_TLS_ISSUED", "TRUST_ANCHORS_LOADED", "DENY_LIST_SEEDED",
                "CRLS_PUBLISHED", "ADMIN_CODE_ISSUED", "LISTENERS_BOUND");
        assertThat(num(map(o, "ledger"), "invariant_violations")).isZero();
    }

    @Test
    @Order(3)
    void liveSocketAndSerialMatchOpenssl() throws Exception {
        fx = new SpineFixture(jdbc, tx, ports, trustFile, stateRoot);
        device = fx.enroll("dev_overview");
        live = fx.connect(device, anchors.root());
        assertThat(live.get("/api/v1/telemetry/ping").status()).isEqualTo(200);

        Map<String, Object> o = overview();
        assertThat(num(map(o, "sessions"), "live_count")).isEqualTo(1);
        assertThat(num(map(map(o, "sessions"), "by_device"), "dev_overview")).isEqualTo(1);
        Map<String, Object> d = device(o, "dev_overview");
        assertThat(num(d, "live_sockets")).isEqualTo(1);
        assertThat(d.get("dev_seed")).isEqualTo(true);
        assertThat(d.get("dek_anchor_verified")).isEqualTo(true);
        String display = (String) map(d, "active_cert").get("serial_display");

        String openssl = opensslSerial(Pems.certificate(device.cert()));
        if (openssl != null) {
            assertThat(display).isEqualTo(openssl);
        }
        assertThat(display).isEqualTo(SerialDisplayFormat.toOpenSslHex(device.cert().getSerialNumber().toString(16)));
    }

    @Test
    @Order(4)
    void ingestsAreCounted() throws Exception {
        long acceptedBefore = num(map(overview(), "telemetry"), "accepted");
        long verifiedBefore = num(map(overview(), "telemetry"), "jws_verified");
        for (int seq = 1; seq <= 5; seq++) {
            assertThat(SpineFixture.ingest(live, SpineFixture.frame(device, seq, UUID.randomUUID())).status()).isEqualTo(200);
        }
        Map<String, Object> t = map(overview(), "telemetry");
        assertThat(num(t, "accepted") - acceptedBefore).isEqualTo(5);
        assertThat(num(t, "jws_verified") - verifiedBefore).isEqualTo(5);
    }

    @Test
    @Order(5)
    void badSignatureIsCountedByReason() throws Exception {
        byte[] payload = TelemetryFrames.payload("dev_overview", device.assignmentId(), device.bootEpoch(), 6,
                UUID.randomUUID(), Instant.now(), Instant.now(), TelemetryFrames.Metrics.resting(new Random()));
        String forged = TelemetryJws.sign(payload, EcKeys.generateP256().getPrivate(), device.cert().getEncoded());
        assertThat(SpineFixture.ingest(live, forged).status()).isEqualTo(401);

        assertThat(num(map(map(overview(), "telemetry"), "jws_rejected"), "SIG_INVALID")).isEqualTo(1);
    }

    @Test
    @Order(6)
    void quarantineShowsUpEverywhere() throws Exception {
        long denyBefore = num(overview(), "deny_list_size");
        HttpResponse<String> q = http.send(HttpRequest.newBuilder(uri("/api/v1/admin/devices/dev_overview/quarantine"))
                        .header("Authorization", bearer()).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{\"lookback_minutes\":10,\"reason\":\"overview it\"}"))
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(q.statusCode()).as(q.body()).isEqualTo(200);
        assertThat(live.awaitClosedWithin(java.time.Duration.ofSeconds(2))).isTrue();

        Map<String, Object> o = overview();
        Map<String, Object> rev = (Map<String, Object>) list(o, "revocations").get(0);
        assertThat(rev.get("serial_display"))
                .isEqualTo(SerialDisplayFormat.toOpenSslHex(device.cert().getSerialNumber().toString(16)));
        assertThat(rev.get("device_id")).isEqualTo("dev_overview");
        assertThat(rev.get("reason")).isEqualTo("KEY_COMPROMISE");
        assertThat(num(rev, "latency_micros")).isPositive();
        assertThat(num(rev, "channels_closed")).isEqualTo(1);

        Map<String, Object> qr = (Map<String, Object>) list(o, "quarantines").get(0);
        assertThat(qr.get("device_id")).isEqualTo("dev_overview");
        assertThat(num(qr, "certs_revoked")).isEqualTo(1);
        assertThat(num(qr, "batches_quarantined")).isEqualTo(5);
        assertThat(num(qr, "revocation_latency_micros")).isEqualTo(num(rev, "latency_micros"));

        assertThat(num(o, "deny_list_size")).isGreaterThan(denyBefore);
        assertThat(device(o, "dev_overview").get("trust_state")).isEqualTo("QUARANTINED");
        assertThat(num(map(o, "sessions"), "live_count")).isZero();

        List<?> rows = telemetry("dev_overview");
        assertThat(rows).hasSize(5).allSatisfy(r -> assertThat(((Map<?, ?>) r).get("trust_state")).isEqualTo("QUARANTINED"));
    }

    @Test
    @Order(7)
    void dekTamperShowsUnverified() throws Exception {
        fx.enroll("dev_overview_tamper");
        assertThat(device(overview(), "dev_overview_tamper").get("dek_anchor_verified")).isEqualTo(true);
        jdbc.update("UPDATE devices SET dek_spki_der_b64 = ? WHERE device_id = 'dev_overview_tamper'",
                Base64.getEncoder().encodeToString(EcKeys.generateP256().getPublic().getEncoded()));

        overviewService.clearDekCache(); // equivalent to waiting past the 30 s cache
        assertThat(device(overview(), "dev_overview_tamper").get("dek_anchor_verified")).isEqualTo(false);
    }

    @Test
    @Order(8)
    void devSeedBadgeAndLedger() throws Exception {
        new DevSeeder(jdbc, tx, Clock.systemUTC()).seed(DevSeeder.Request.defaults("dev_overview_seedonly"));
        Map<String, Object> o = overview();
        Map<String, Object> d = device(o, "dev_overview_seedonly");
        assertThat(d.get("dev_seed")).isEqualTo(true);
        assertThat(d.get("dek_anchor_verified")).isNull();
        assertThat(d.get("active_cert")).isNull();
        assertThat(num(map(o, "ledger"), "invariant_violations")).isZero();
        assertThat(num(map(o, "ledger"), "recorded")).isGreaterThanOrEqualTo(2);
    }

    @Test
    @Order(9)
    void overviewIsFastWithTenDevices() throws Exception {
        for (int i = 0; i < 7; i++) {
            new DevSeeder(jdbc, tx, Clock.systemUTC()).seed(DevSeeder.Request.defaults("dev_overview_fill_" + i));
        }
        assertThat(list(overview(), "devices")).hasSize(10);
        overview(); // warm
        List<Long> millis = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            long t0 = System.nanoTime();
            overview();
            millis.add((System.nanoTime() - t0) / 1_000_000);
        }
        millis.sort(Long::compare);
        System.out.println("OVERVIEW_MS min=" + millis.get(0) + " median=" + millis.get(10) + " max=" + millis.get(19));
        assertThat(millis.get(10)).as("median overview latency (ms)").isLessThan(100);
    }

    @Test
    @Order(10)
    void kmsKeyLossIsReported() throws Exception {
        String registryArn = jdbc.queryForObject(
                "SELECT kms_key_id FROM kms_keys WHERE purpose = 'REGISTRY_ANCHOR' AND status = 'ACTIVE'", String.class);
        kms.scheduleKeyDeletion(r -> r.keyId(registryArn).pendingWindowInDays(7));
        kmsHealth.checkNow(); // force a monitor run instead of waiting 30 s

        Map<String, Object> k = map(overview(), "kms");
        assertThat(k.get("healthy")).isEqualTo(false);
        assertThat(k.get("state")).isEqualTo("UNHEALTHY");
        Map<?, ?> registry = list(k, "keys").stream().map(x -> (Map<?, ?>) x)
                .filter(x -> "REGISTRY_ANCHOR".equals(x.get("purpose"))).findFirst().orElseThrow();
        assertThat(registry.get("enabled")).isEqualTo(false);
        assertThat(registryArn).endsWith((String) registry.get("arn_suffix"));
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + ports.admin() + path);
    }

    private String bearer() throws IOException {
        return "Bearer " + Files.readString(ports.adminCodeFile()).trim();
    }

    private Map<String, Object> overview() throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(uri("/api/v1/admin/overview"))
                .header("Authorization", bearer()).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(r.statusCode()).as(r.body()).isEqualTo(200);
        assertThat(r.headers().firstValue("cache-control")).hasValue("no-store");
        return JSONObjectUtils.parse(r.body());
    }

    private List<Object> telemetry(String dev) throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(uri("/api/v1/admin/devices/" + dev + "/telemetry?limit=30"))
                .header("Authorization", bearer()).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(r.statusCode()).isEqualTo(200);
        return JSONObjectUtils.parse("{\"rows\":" + r.body() + "}").get("rows") instanceof List<?> l
                ? new ArrayList<>(l) : List.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Map<String, Object> m, String key) {
        return (Map<String, Object>) m.get(key);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Map<String, Object> m, String key) {
        return (List<Object>) m.get(key);
    }

    private static long num(Map<String, Object> m, String key) {
        return ((Number) m.get(key)).longValue();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> device(Map<String, Object> o, String id) {
        return list(o, "devices").stream().map(x -> (Map<String, Object>) x)
                .filter(d -> id.equals(d.get("device_id"))).findFirst().orElseThrow();
    }

    /** {@code openssl x509 -serial} without the "serial=" prefix, or null if OpenSSL is not available. */
    private static String opensslSerial(String pem) throws Exception {
        String bin = System.getenv().getOrDefault("OPENSSL_BIN", "/opt/homebrew/opt/openssl@3/bin/openssl");
        if (!Files.isExecutable(Path.of(bin))) {
            return null;
        }
        Process p = new ProcessBuilder(bin, "x509", "-noout", "-serial").redirectErrorStream(true).start();
        p.getOutputStream().write(pem.getBytes(StandardCharsets.US_ASCII));
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        p.waitFor(10, TimeUnit.SECONDS);
        return out.startsWith("serial=") ? out.substring(7) : out;
    }
}
