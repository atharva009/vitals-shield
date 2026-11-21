package com.vitalsshield.server.reenroll;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.server.kms.KmsSigner;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.LedgerInvariant;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.ReEnrolls;
import com.vitalsshield.server.testsupport.Renewals;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.GatewayClient;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * Spec claims that had no test before Phase 10b.1: renewal (Protocol B) and re-enrollment (Protocol C) answer a KMS
 * signing failure with 503 and a Retry-After of 3 to 8 s and VOID the reserved serial (DECISIONS #34, #38), and
 * re-enrollment of a device with no ACTIVE assignment is 409 DEVICE_UNASSIGNED.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@Import(RenewReEnrollRefusalsIT.FlakyKms.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RenewReEnrollRefusalsIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-refusals-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    /** Wraps the real signer; fails the next N Sign calls on demand (the same test hook as EnrollmentIT). */
    static class FlakyKmsSigner extends KmsSigner {
        final AtomicInteger failNext = new AtomicInteger();

        FlakyKmsSigner(KmsClient kms) {
            super(kms);
        }

        @Override
        public byte[] signDigestBlocking(String keyArn, byte[] sha256Digest) {
            if (failNext.getAndUpdate(n -> n > 0 ? n - 1 : 0) > 0) {
                throw SdkClientException.create("injected KMS outage");
            }
            return super.signDigestBlocking(keyArn, sha256Digest);
        }
    }

    @TestConfiguration
    static class FlakyKms {
        @Bean
        @Primary
        FlakyKmsSigner flakyKmsSigner(KmsClient kms) {
            return new FlakyKmsSigner(kms);
        }
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired FlakyKmsSigner flaky;

    @AfterAll
    void ledgerInvariantHolds() {
        assertThat(LedgerInvariant.violations(jdbc)).isZero();
    }

    SpineFixture.Device enroll(String deviceId) {
        return new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim")).enroll(deviceId);
    }

    /** The device's most recent serial reservation. */
    Map<String, Object> lastReservation(String deviceId) {
        return jdbc.queryForMap("""
                SELECT serial_number, status::text AS status, voided_at FROM issued_serials
                 WHERE device_id = ? ORDER BY reserved_at DESC, serial_number LIMIT 1
                """, deviceId);
    }

    List<String> certStatuses(String deviceId) {
        return jdbc.queryForList("SELECT status::text FROM certificates WHERE device_id = ? ORDER BY not_before",
                String.class, deviceId);
    }

    static void assertRetryAfter3to8(String value) {
        assertThat(value).isNotNull();
        assertThat(Integer.parseInt(value)).isBetween(3, 8);
    }

    @Test
    void renewalKmsFailureIs503WithRetryAfterAndTheSerialIsVoided() throws Exception {
        String dev = "dev_renew_kmsdown";
        SpineFixture.Device d = enroll(dev);
        Renewals.Identity current = Renewals.identity(d);
        try (MtlsTestClient.Connection c = Renewals.connect(ports.mtls(), anchors.root(), current)) {
            Renewals.Challenge ch = Renewals.challenge(c);
            flaky.failNext.set(1);                              // the leaf Sign is renewal's first KMS call
            MtlsTestClient.Response r = Renewals.post(c,
                    Renewals.body(current.cert(), current.key(), ch, EcKeys.generateP256(), dev));

            assertThat(r.status()).as(r.body()).isEqualTo(503);
            assertThat(Renewals.error(r)).isEqualTo("TEMPORARILY_UNAVAILABLE");
            assertRetryAfter3to8(r.header("Retry-After"));
            assertThat(flaky.failNext.get()).as("the injected failure was consumed").isZero();

            Map<String, Object> reservation = lastReservation(dev);
            assertThat(reservation.get("status")).isEqualTo("VOIDED");
            assertThat(reservation.get("voided_at")).isNotNull();
            assertThat(certStatuses(dev)).containsExactly("ACTIVE");

            // KMS is back: the same connection renews normally.
            Renewals.Identity next = Renewals.renewOk(c, current, dev);
            assertThat(next.cert().getSerialNumber().toString(16)).isNotEqualTo(reservation.get("serial_number"));
        }
    }

    @Test
    void reEnrollKmsFailureIs503WithRetryAfterAndTheSerialIsVoided() {
        String dev = "dev_reenroll_kmsdown";
        SpineFixture.Device d = enroll(dev);
        Path trust = dir.resolve("root-ca.pem");
        Map<String, Object> body = ReEnrolls.body(d, ReEnrolls.challenge(ports, trust, dev), 1);
        flaky.failNext.set(1);                                  // the leaf Sign is Protocol C's first KMS call
        GatewayClient.Response r = ReEnrolls.post(ports, trust, body);

        assertThat(r.status()).as(r.body()).isEqualTo(503);
        assertThat(ReEnrolls.error(r)).isEqualTo("TEMPORARILY_UNAVAILABLE");
        assertRetryAfter3to8(r.headers().firstValue("Retry-After").orElse(null));
        assertThat(flaky.failNext.get()).as("the injected failure was consumed").isZero();

        Map<String, Object> reservation = lastReservation(dev);
        assertThat(reservation.get("status")).isEqualTo("VOIDED");
        assertThat(reservation.get("voided_at")).isNotNull();
        assertThat(certStatuses(dev)).containsExactly("ACTIVE");

        // KMS is back: a fresh challenge re-enrolls.
        GatewayClient.Response ok = ReEnrolls.post(ports, trust,
                ReEnrolls.body(d, ReEnrolls.challenge(ports, trust, dev), 1));
        assertThat(ok.status()).as(ok.body()).isEqualTo(200);
        assertThat(certStatuses(dev)).containsExactlyInAnyOrder("REVOKED", "ACTIVE");
    }

    @Test
    void reEnrollWithNoActiveAssignmentIs409DeviceUnassigned() {
        String dev = "dev_reenroll_unassigned";
        SpineFixture.Device d = enroll(dev);
        int closed = jdbc.update("""
                UPDATE patient_device_assignments SET status = 'CLOSED', active_until = GREATEST(NOW(), active_from)
                 WHERE device_id = ? AND status = 'ACTIVE'
                """, dev);
        assertThat(closed).isEqualTo(1);
        Path trust = dir.resolve("root-ca.pem");
        long reservationsBefore = jdbc.queryForObject("SELECT count(*) FROM issued_serials WHERE device_id = ?",
                Long.class, dev);

        GatewayClient.Response r = ReEnrolls.post(ports, trust,
                ReEnrolls.body(d, ReEnrolls.challenge(ports, trust, dev), 1));

        assertThat(r.status()).as(r.body()).isEqualTo(409);
        assertThat(r.body()).isEqualTo("{\"error\":\"DEVICE_UNASSIGNED\"}");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM issued_serials WHERE device_id = ?", Long.class, dev))
                .as("no serial reserved").isEqualTo(reservationsBefore);
        assertThat(certStatuses(dev)).containsExactly("ACTIVE");
    }
}
