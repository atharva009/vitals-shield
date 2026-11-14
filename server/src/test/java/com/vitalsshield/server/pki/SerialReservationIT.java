package com.vitalsshield.server.pki;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.vitalsshield.crypto.CsrFactory;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.devtools.DevSeeder;
import com.vitalsshield.server.VitalsShieldServerApplication;
import com.vitalsshield.server.enrollment.EnrollmentHooks;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.testsupport.LedgerInvariant;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.GatewayClient;
import com.vitalsshield.simulator.Simulator;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.flywaydb.core.Flyway;
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** DECISIONS #38: every device serial the CA signs ends up RECORDED, or VOIDED and on the CRL and deny-list. */
@Tag("integration")
@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SerialReservationIT {

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    /** Controllable hook: pause or crash the first enrollment of a chosen device right after KMS signs the leaf. */
    static final class Hooks implements EnrollmentHooks {
        volatile String targetDevice;
        volatile String mode = "NONE";
        final AtomicReference<CountDownLatch> signed = new AtomicReference<>(new CountDownLatch(1));
        final AtomicReference<CountDownLatch> release = new AtomicReference<>(new CountDownLatch(1));

        @Override
        public void afterLeafSigned(String deviceId) {
            if (!deviceId.equals(targetDevice) || "NONE".equals(mode)) {
                return;
            }
            String m = mode;
            mode = "NONE"; // only the first enrollment for the target device
            if ("CRASH".equals(m)) {
                throw new SimulatedCrash();
            }
            signed.get().countDown();
            try {
                release.get().await(60, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** An Error, so it bypasses every RuntimeException cleanup path: nothing after Tx 1 is persisted. */
    static final class SimulatedCrash extends Error {
        SimulatedCrash() {
            super("simulated crash after KMS Sign");
        }
    }

    static final Hooks HOOKS = new Hooks();

    @Configuration(proxyBeanMethods = false)
    static class HookConfig {
        @Bean
        EnrollmentHooks testEnrollmentHooks() {
            return HOOKS;
        }
    }

    Path trustFile;
    Path stateRoot;
    ConfigurableApplicationContext ctx;
    TestPorts.Listeners ports;

    @BeforeAll
    void start() throws IOException {
        Path dir = Files.createTempDirectory("vs-serials-it");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
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
                "--vitalsshield.pki.trust-file=" + trustFile,
                "--spring.main.keep-alive=false"));
        args.addAll(ports.asArgs());
        ctx = new SpringApplicationBuilder(VitalsShieldServerApplication.class, HookConfig.class)
                .profiles("local").run(args.toArray(String[]::new));
    }

    JdbcTemplate jdbc() {
        return ctx.getBean(JdbcTemplate.class);
    }

    @Test
    @Order(1)
    void reclaimRaceLoserIsVoidedAndOnCrl() throws Exception {
        String dev = "dev_serial_race";
        DevSeeder.Result seed = seed(dev);
        HOOKS.targetDevice = dev;
        HOOKS.mode = "PAUSE";
        HOOKS.signed.set(new CountDownLatch(1));
        HOOKS.release.set(new CountDownLatch(1));

        CompletableFuture<GatewayClient.Response> a = CompletableFuture.supplyAsync(() -> post(body(dev, seed.token())));
        assertThat(HOOKS.signed.get().await(30, TimeUnit.SECONDS)).as("A signed its leaf").isTrue();
        BigInteger serialA = new BigInteger(jdbc().queryForObject(
                "SELECT serial_number FROM issued_serials WHERE device_id = ? AND status = 'RESERVED'", String.class, dev), 16);

        // A looks dead: age its claim past 2 minutes, then B reclaims the token and wins.
        jdbc().update("UPDATE device_bootstrap_tokens SET claimed_at = NOW() - INTERVAL '3 minutes' WHERE token_id = ?",
                seed.tokenId());
        GatewayClient.Response b = post(body(dev, seed.token()));
        assertThat(b.status()).as(b.body()).isEqualTo(201);
        HOOKS.release.get().countDown();

        GatewayClient.Response loser = a.get(30, TimeUnit.SECONDS);
        assertThat(loser.status()).isEqualTo(409);
        assertThat(loser.body()).contains("ENROLLMENT_SUPERSEDED");

        assertThat(ledgerStatus(serialA)).isEqualTo("VOIDED");
        Map<String, Object> aRow = jdbc().queryForMap(
                "SELECT status::text AS s, revocation_reason AS r FROM certificates WHERE serial_number = ?",
                serialA.toString(16));
        assertThat(aRow).containsEntry("s", "REVOKED").containsEntry("r", "REPLACED_BEFORE_USE");

        BigInteger serialB = new BigInteger((String) jdbc().queryForObject(
                "SELECT serial_number FROM certificates WHERE device_id = ? AND status = 'ACTIVE'", String.class, dev), 16);
        assertThat(ledgerStatus(serialB)).isEqualTo("RECORDED");

        X509CRLEntry entry = awaitCrlEntry(serialA);
        assertThat(entry).as("A's serial on the CRL").isNotNull();
        assertThat(entry.getRevocationReason()).isEqualTo(java.security.cert.CRLReason.SUPERSEDED);
    }

    @Test
    @Order(2)
    void crashAfterSignIsVoidedByBootSweep() throws Exception {
        String dev = "dev_serial_crash";
        DevSeeder.Result seed = seed(dev);
        HOOKS.targetDevice = dev;
        HOOKS.mode = "CRASH";

        GatewayClient.Response crashed = post(body(dev, seed.token()));
        assertThat(crashed.status()).isEqualTo(500);
        String serialHex = jdbc().queryForObject(
                "SELECT serial_number FROM issued_serials WHERE device_id = ? AND status = 'RESERVED'", String.class, dev);
        assertThat(jdbc().queryForObject("SELECT count(*) FROM certificates WHERE device_id = ?", Integer.class, dev))
                .as("the signed leaf was lost").isZero();
        String issuer = jdbc().queryForObject(
                "SELECT issuer_key_hash FROM issued_serials WHERE serial_number = ?", String.class, serialHex);
        jdbc().update("UPDATE issued_serials SET reserved_at = NOW() - INTERVAL '3 minutes' WHERE serial_number = ?",
                serialHex);

        ctx.close();
        startServer();

        assertThat(ledgerStatus(new BigInteger(serialHex, 16))).isEqualTo("VOIDED");
        X509CRLEntry entry = awaitCrlEntry(new BigInteger(serialHex, 16));
        assertThat(entry).as("voided serial on the boot-published CRL").isNotNull();
        assertThat(entry.getRevocationReason()).isEqualTo(java.security.cert.CRLReason.SUPERSEDED);
        assertThat(ctx.getBean(CertificateDenyList.class).isDenied(CertKey.of(issuer, serialHex))).isTrue();
    }

    @Test
    @Order(3)
    void everyCertificateHasLedgerRow() {
        assertThat(LedgerInvariant.violations(jdbc())).isZero();
    }

    @Test
    @Order(4)
    void backfillCoversExistingRows() {
        try (PostgreSQLContainer pg = new PostgreSQLContainer("postgres:16")) {
            pg.start();
            Flyway.configure().dataSource(pg.getJdbcUrl(), pg.getUsername(), pg.getPassword()).target("1").load().migrate();
            JdbcTemplate j = new JdbcTemplate(new DriverManagerDataSource(pg.getJdbcUrl(), pg.getUsername(), pg.getPassword()));
            j.update("INSERT INTO ca_issuers (issuer_key_hash, subject_dn, kms_primary_arn, cert_pem, status) "
                    + "VALUES ('iss', 'CN=x', 'arn', 'PEM', 'ACTIVE')");
            j.update("INSERT INTO devices (device_id, hardware_model) VALUES ('dev_pre_v2', 'sim')");
            for (String[] row : List.of(new String[] {"0a", "REVOKED"}, new String[] {"0b", "ACTIVE"})) {
                j.update("""
                        INSERT INTO certificates (issuer_key_hash, serial_number, device_id, cert_thumbprint_s256,
                                                  cert_pem, not_before, not_after, status)
                        VALUES ('iss', ?, 'dev_pre_v2', 't', 'PEM', NOW(), NOW() + INTERVAL '12 hours',
                                ?::cert_status)
                        """, row[0], row[1]);
            }
            Flyway.configure().dataSource(pg.getJdbcUrl(), pg.getUsername(), pg.getPassword()).load().migrate();

            assertThat(LedgerInvariant.violations(j)).isZero();
            assertThat(j.queryForObject("SELECT count(*) FROM issued_serials WHERE status = 'RECORDED'", Integer.class))
                    .isEqualTo(2);
        }
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    private DevSeeder.Result seed(String dev) {
        return new DevSeeder(jdbc(), ctx.getBean(TransactionTemplate.class), Clock.systemUTC())
                .seed(DevSeeder.Request.defaults(dev));
    }

    private static Map<String, Object> body(String dev, String token) {
        return Simulator.enrollmentBody(dev, token, EcKeys.generateP256(), CsrFactory.create(EcKeys.generateP256(), dev));
    }

    private GatewayClient.Response post(Map<String, Object> body) {
        try {
            return GatewayClient.publicClient(trustFile).postJson(
                    URI.create("https://127.0.0.1:" + ports.pub() + "/api/v1/devices/enroll"),
                    JSONObjectUtils.toJSONString(body));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String ledgerStatus(BigInteger serial) {
        return jdbc().queryForObject("SELECT status::text FROM issued_serials WHERE serial_number = ?", String.class,
                serial.toString(16));
    }

    /** Fetches the published intermediate CRL over 8444 until it lists {@code serial} (or 5 s pass). */
    private X509CRLEntry awaitCrlEntry(BigInteger serial) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            GatewayClient.Response r = GatewayClient.publicClient(trustFile).get(
                    URI.create("https://127.0.0.1:" + ports.pub() + "/api/v1/pki/intermediate-crl.pem"));
            X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
                    .generateCRL(new ByteArrayInputStream(r.body().getBytes(StandardCharsets.US_ASCII)));
            X509CRLEntry e = crl.getRevokedCertificate(serial);
            if (e != null) {
                return e;
            }
            Thread.sleep(50);
        }
        return null;
    }
}
