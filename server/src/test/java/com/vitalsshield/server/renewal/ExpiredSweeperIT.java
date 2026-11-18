package com.vitalsshield.server.renewal;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.VitalsShieldServerApplication;
import com.vitalsshield.server.admin.AdminOverviewService;
import com.vitalsshield.server.boot.BootStep;
import com.vitalsshield.server.boot.BootStepCompleted;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.Renewals;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.CertIds;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * DECISIONS #84, #87: every ACTIVE, ISSUED_PENDING_USE or RENEWED certificate past not_after becomes EXPIRED, is
 * deny-listed from not_after, and loses its live sockets; the sweep also runs at boot before the listeners bind.
 *
 * <p>Leaf TTL PT80S: notBefore is backdated 60 s, so each leaf lives about 20 s after issuance (a PT20S leaf would be
 * born expired). The context is started by hand so the last test can restart it against the same database. The
 * periodic sweep is stopped after boot, so every sweep in these tests is an explicit call.
 */
@Tag("integration")
@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ExpiredSweeperIT {

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    /** Status of each watched serial when each boot step completed. */
    static final Map<String, Map<BootStep, String>> STATUS_AT_STEP = new ConcurrentHashMap<>();

    @Configuration(proxyBeanMethods = false)
    static class StepWatch {
        @Bean
        StepWatchListener stepWatchListener(JdbcTemplate jdbc) {
            return new StepWatchListener(jdbc);
        }
    }

    record StepWatchListener(JdbcTemplate jdbc) {
        @EventListener
        void on(BootStepCompleted e) {
            for (String serial : STATUS_AT_STEP.keySet()) {
                List<String> s = jdbc.queryForList("SELECT status::text FROM certificates WHERE serial_number = ?",
                        String.class, serial);
                STATUS_AT_STEP.get(serial).put(e.step(), s.isEmpty() ? "(none)" : s.get(0));
            }
        }
    }

    Path dir;
    ConfigurableApplicationContext ctx;
    TestPorts.Listeners ports;

    @BeforeAll
    void start() throws IOException {
        dir = Files.createTempDirectory("vs-expired-it");
        startServer();
    }

    @AfterAll
    void stop() {
        if (ctx != null) {
            ctx.close();
        }
    }

    void startServer() {
        ports = TestPorts.allocate();
        List<String> args = new ArrayList<>(List.of(
                "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "--spring.datasource.username=" + POSTGRES.getUsername(),
                "--spring.datasource.password=" + POSTGRES.getPassword(),
                "--vitalsshield.pki.trust-file=" + dir.resolve("root-ca.pem"),
                "--vitalsshield.pki.leaf-ttl=PT80S",
                "--spring.main.keep-alive=false"));
        args.addAll(ports.asArgs());
        ctx = new SpringApplicationBuilder(VitalsShieldServerApplication.class, StepWatch.class)
                .profiles("local").run(args.toArray(String[]::new));
        sweepers().shutdown(); // explicit sweeps only (the boot sweep has already run)
    }

    JdbcTemplate jdbc() {
        return ctx.getBean(JdbcTemplate.class);
    }

    RenewalSweepers sweepers() {
        return ctx.getBean(RenewalSweepers.class);
    }

    SpineFixture fx() {
        return new SpineFixture(jdbc(), ctx.getBean(TransactionTemplate.class), ports, dir.resolve("root-ca.pem"),
                dir.resolve("sim"));
    }

    MtlsTestClient.Connection connect(Renewals.Identity id) throws IOException {
        return Renewals.connect(ports.mtls(), ctx.getBean(TrustAnchors.class).root(), id);
    }

    MtlsTestClient.Attempt ping(Renewals.Identity id) {
        return MtlsTestClient.attempt(ports.mtls(), ctx.getBean(TrustAnchors.class).root(), id.key(),
                List.of(id.cert()), "/api/v1/telemetry/ping");
    }

    static CertKey key(Renewals.Identity id) {
        return CertKey.of(CertIds.issuerKeyHash(id.cert()), CertIds.serial(id.cert()));
    }

    String status(CertKey k) {
        return jdbc().queryForObject("SELECT status::text FROM certificates WHERE serial_number = ?", String.class,
                k.serial());
    }

    void expireInDb(CertKey k) {
        jdbc().update("UPDATE certificates SET not_after = NOW() - INTERVAL '1 second' WHERE serial_number = ?",
                k.serial());
    }

    /** The sweep's result for one device (leaves of earlier tests expire on their own after about 20 s). */
    List<RenewalSweepers.ExpiredCert> sweepFor(String deviceId) {
        return sweepers().sweepExpired().stream().filter(c -> c.deviceId().equals(deviceId)).toList();
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> overviewDevice(String deviceId) {
        List<Map<String, Object>> devices = (List<Map<String, Object>>) ctx.getBean(AdminOverviewService.class)
                .snapshot().get("devices");
        return devices.stream().filter(d -> deviceId.equals(d.get("device_id"))).findFirst().orElseThrow();
    }

    @Test
    @Order(1)
    void sweepDoesNotTouchValidCerts() {
        Renewals.Identity id = Renewals.identity(fx().enroll("dev_valid"));
        assertThat(sweepFor("dev_valid")).isEmpty();
        assertThat(status(key(id))).isEqualTo("ACTIVE");
        assertThat(ctx.getBean(CertificateDenyList.class).isDenied(key(id))).isFalse();
        assertThat(ping(id).is200()).isTrue();
        assertThat(overviewDevice("dev_valid").get("needs_attention")).isNull();
    }

    @Test
    @Order(2)
    void pendingCertExpiresUnused() throws Exception {
        Renewals.Identity cur = Renewals.identity(fx().enroll("dev_pending_exp"));
        Renewals.Identity next;
        try (MtlsTestClient.Connection c = connect(cur)) {
            next = Renewals.renewOk(c, cur, "dev_pending_exp");
        }
        assertThat(status(key(next))).isEqualTo("ISSUED_PENDING_USE");
        expireInDb(key(next));

        List<RenewalSweepers.ExpiredCert> swept = sweepFor("dev_pending_exp");
        assertThat(swept).extracting(RenewalSweepers.ExpiredCert::key).containsExactly(key(next));
        assertThat(swept.get(0).previousStatus()).isEqualTo("ISSUED_PENDING_USE");
        assertThat(status(key(next))).isEqualTo("EXPIRED");
        assertThat(ctx.getBean(CertificateDenyList.class).isDenied(key(next))).isTrue();
        // The current certificate is untouched, so the device does not need attention.
        assertThat(status(key(cur))).isEqualTo("ACTIVE");
        assertThat(overviewDevice("dev_pending_exp").get("needs_attention")).isNull();
    }

    @Test
    @Order(3)
    void renewedCertExpires() throws Exception {
        Renewals.Identity cur = Renewals.identity(fx().enroll("dev_renewed_exp"));
        Renewals.Identity next;
        try (MtlsTestClient.Connection c = connect(cur)) {
            next = Renewals.renewOk(c, cur, "dev_renewed_exp");
        }
        assertThat(ctx.getBean(CertificateActivationService.class).activate("dev_renewed_exp", key(next)))
                .isPresent();
        assertThat(status(key(cur))).isEqualTo("RENEWED");
        expireInDb(key(cur));

        List<RenewalSweepers.ExpiredCert> swept = sweepFor("dev_renewed_exp");
        assertThat(swept).extracting(RenewalSweepers.ExpiredCert::key).containsExactly(key(cur));
        assertThat(swept.get(0).previousStatus()).isEqualTo("RENEWED");
        assertThat(status(key(cur))).isEqualTo("EXPIRED");
        assertThat(status(key(next))).isEqualTo("ACTIVE");
        assertThat(overviewDevice("dev_renewed_exp").get("needs_attention")).isNull();
    }

    @Test
    @Order(4)
    void certPastNotAfterBecomesExpiredAndDenied() {
        SpineFixture.Device d = fx().enroll("dev_expired");
        SpineFixture.Device live = fx().enroll("dev_not_expired");
        Renewals.Identity id = Renewals.identity(d);
        CertKey key = key(id);
        assertThat(ping(id).is200()).isTrue();

        // The stored not_after is the sweeper's input; move it into the past (the X.509 notAfter is still ahead, so
        // only the deny-list entry can refuse the handshake below).
        expireInDb(key);
        assertThat(sweepFor("dev_expired")).extracting(RenewalSweepers.ExpiredCert::key).containsExactly(key);
        assertThat(status(key)).isEqualTo("EXPIRED");
        CertificateDenyList denyList = ctx.getBean(CertificateDenyList.class);
        assertThat(denyList.isDenied(key)).isTrue();
        assertThat(denyList.entry(key)).hasValueSatisfying(e -> assertThat(e.reason()).isEqualTo("EXPIRED"));
        assertThat(ping(id).kind()).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);
        // Another device's certificate is untouched, and a second sweep finds nothing for this device.
        assertThat(jdbc().queryForObject("SELECT status::text FROM certificates WHERE device_id = ?", String.class,
                live.deviceId())).isEqualTo("ACTIVE");
        assertThat(sweepFor("dev_expired")).isEmpty();
    }

    @Test
    @Order(5)
    void activeCertExpiresWithoutSuccessor() throws Exception {
        String dev = "dev_active_exp";
        Renewals.Identity id = Renewals.identity(fx().enroll(dev));
        CertKey key = key(id);
        ActiveSessionRegistry sessions = ctx.getBean(ActiveSessionRegistry.class);
        try (MtlsTestClient.Connection c = connect(id)) {
            assertThat(c.get("/api/v1/telemetry/ping").status()).isEqualTo(200);
            Instant notAfter = id.cert().getNotAfter().toInstant();
            Thread.sleep(Math.max(0, Duration.between(Instant.now(), notAfter).toMillis()) + 1000);

            // Expired but not yet swept: still ACTIVE, and the kept-alive socket is still registered and open.
            assertThat(status(key)).isEqualTo("ACTIVE");
            assertThat(sessions.liveSocketsFor(key)).hasSize(1);

            List<RenewalSweepers.ExpiredCert> swept = sweepFor(dev);
            assertThat(swept).extracting(RenewalSweepers.ExpiredCert::key).containsExactly(key);
            assertThat(swept.get(0).previousStatus()).isEqualTo("ACTIVE");
            assertThat(status(key)).isEqualTo("EXPIRED");
            // The sweep closed the socket; nothing was sent on it after the expiry.
            assertThat(c.awaitClosedWithin(Duration.ofSeconds(5))).as("socket closed by the sweep").isTrue();
            assertThat(sessions.liveSocketsFor(key)).isEmpty();
        }
        assertThat(ping(id).kind()).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);

        Map<String, Object> d = overviewDevice(dev);
        @SuppressWarnings("unchecked")
        Map<String, Object> cert = (Map<String, Object>) d.get("active_cert");
        assertThat(cert.get("status")).isEqualTo("EXPIRED");
        assertThat(d.get("needs_attention")).isEqualTo("CERT_EXPIRED_NO_SUCCESSOR");
    }

    @Test
    @Order(6)
    void expiredWhileServerDown() {
        Renewals.Identity id = Renewals.identity(fx().enroll("dev_down_exp"));
        CertKey key = key(id);
        assertThat(ping(id).is200()).isTrue();
        ctx.close();
        ctx = null;

        // While the server is down, the certificate's not_after passes.
        DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        new JdbcTemplate(ds).update(
                "UPDATE certificates SET not_after = NOW() - INTERVAL '1 second' WHERE serial_number = ?", key.serial());
        STATUS_AT_STEP.put(key.serial(), new ConcurrentHashMap<>());

        startServer();
        Map<BootStep, String> seen = STATUS_AT_STEP.get(key.serial());
        assertThat(seen.get(BootStep.TRUST_ANCHORS_LOADED)).as("before the deny-list step").isEqualTo("ACTIVE");
        assertThat(seen.get(BootStep.DENY_LIST_SEEDED)).as("at DENY_LIST_SEEDED").isEqualTo("EXPIRED");
        assertThat(seen.get(BootStep.LISTENERS_BOUND)).as("at LISTENERS_BOUND").isEqualTo("EXPIRED");
        assertThat(ctx.getBean(CertificateDenyList.class).isDenied(key)).isTrue();
        assertThat(ping(id).kind()).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);
        assertThat(overviewDevice("dev_down_exp").get("needs_attention")).isEqualTo("CERT_EXPIRED_NO_SUCCESSOR");
    }
}
