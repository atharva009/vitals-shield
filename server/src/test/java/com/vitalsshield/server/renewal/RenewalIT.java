package com.vitalsshield.server.renewal;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.crypto.CsrFactory;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.testsupport.LedgerInvariant;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.Renewals;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.CertIds;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CRLReason;
import java.security.cert.X509CRLEntry;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Protocol B against the real listeners (TTL PT2M, grace PT3S): pending, first-use activation, grace and eviction,
 * the lost-response case, every rejection code, and the ledger invariant (DECISIONS #38) after each case.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class RenewalIT {

    static volatile String crashDevice = null;

    static final class SimulatedCrash extends Error {
        SimulatedCrash() {
            super("simulated crash after KMS Sign");
        }
    }

    @TestConfiguration
    static class Hooks {
        @Bean
        RenewalHooks crashAfterSign() {
            return new RenewalHooks() {
                @Override
                public void afterLeafSigned(String deviceId) {
                    if (deviceId.equals(crashDevice)) {
                        throw new SimulatedCrash();
                    }
                }
            };
        }
    }

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-renewal-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        registry.add("vitalsshield.pki.leaf-ttl", () -> "PT2M");
        registry.add("vitalsshield.pki.renewal-grace", () -> "PT3S");
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired CertificateActivationService activation;
    @Autowired RenewalSweepers sweepers;
    @Autowired RenewalChallenge challenges;
    @Autowired CrlService crls;

    SpineFixture fx() {
        return new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
    }

    MtlsTestClient.Connection connect(Renewals.Identity id) throws IOException {
        return Renewals.connect(ports.mtls(), anchors.root(), id);
    }

    MtlsTestClient.Attempt ping(Renewals.Identity id) {
        return MtlsTestClient.attempt(ports.mtls(), anchors.root(), id.key(), List.of(id.cert()),
                "/api/v1/telemetry/ping");
    }

    String status(Renewals.Identity id) {
        CertKey k = CertKey.of(CertIds.issuerKeyHash(id.cert()), CertIds.serial(id.cert()));
        return jdbc.queryForObject("SELECT status::text FROM certificates WHERE issuer_key_hash = ? AND serial_number = ?",
                String.class, k.issuerKeyHash(), k.serial());
    }

    Map<String, Object> row(Renewals.Identity id) {
        return jdbc.queryForMap("""
                SELECT status::text AS status, superseded_serial, grace_expires_at, activated_at, revocation_reason
                  FROM certificates WHERE serial_number = ?
                """, CertIds.serial(id.cert()));
    }

    @AfterEach
    void ledgerInvariantHolds() {
        assertThat(LedgerInvariant.violations(jdbc)).as("DECISIONS #38 invariant").isZero();
    }

    @Test
    void happyPathPendingActivationGraceAndEviction() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_renew_happy");
        Renewals.Identity old = Renewals.identity(d);
        Renewals.Identity next;
        try (MtlsTestClient.Connection c = connect(old)) {
            next = Renewals.renewOk(c, old, d.deviceId());
        }
        // Pending; the old certificate is still ACTIVE.
        assertThat(row(next)).containsEntry("status", "ISSUED_PENDING_USE")
                .containsEntry("superseded_serial", CertIds.serial(old.cert()));
        assertThat(status(old)).isEqualTo("ACTIVE");
        // Both pass the handshake and the ping.
        assertThat(ping(old).is200()).isTrue();
        assertThat(ping(next).is200()).isTrue();

        try (MtlsTestClient.Connection oldKeepAlive = connect(old);
             MtlsTestClient.Connection newConn = connect(next)) {
            assertThat(oldKeepAlive.get("/api/v1/telemetry/ping").status()).isEqualTo(200);

            // The first batch signed by the new certificate activates it (off the response path).
            SpineFixture.Device asNext = next.as(d);
            MtlsTestClient.Response b = SpineFixture.ingest(newConn, SpineFixture.frame(asNext, 1, UUID.randomUUID()));
            assertThat(b.status()).as(b.body()).isEqualTo(200);
            assertThat(activation.awaitIdle(Duration.ofSeconds(10))).isTrue();
            Map<String, Object> newRow = row(next);
            Map<String, Object> oldRow = row(old);
            assertThat(newRow).containsEntry("status", "ACTIVE");
            assertThat(newRow.get("activated_at")).isNotNull();
            assertThat(oldRow).containsEntry("status", "RENEWED");
            Instant grace = ((java.sql.Timestamp) oldRow.get("grace_expires_at")).toInstant();
            Instant activatedAt = ((java.sql.Timestamp) newRow.get("activated_at")).toInstant();
            assertThat(Duration.between(activatedAt, grace)).isEqualTo(Duration.ofSeconds(3));

            // Within grace the old certificate still works, on the kept-alive socket and on a new one.
            assertThat(oldKeepAlive.get("/api/v1/telemetry/ping").status()).isEqualTo(200);
            assertThat(ping(old).is200()).isTrue();
            // Batches with the new certificate keep flowing.
            assertThat(SpineFixture.ingest(newConn, SpineFixture.frame(asNext, 2, UUID.randomUUID())).status())
                    .isEqualTo(200);

            // After grace (3.5 s): GraceEviction closed the kept-alive socket and the handshake is refused.
            Thread.sleep(Math.max(0, Duration.between(Instant.now(), grace).toMillis()) + 500);
            boolean closed;
            try {
                oldKeepAlive.get("/api/v1/telemetry/ping");
                closed = false;
            } catch (IOException expected) {
                closed = true;
            }
            assertThat(closed).as("old keep-alive socket closed by GraceEviction").isTrue();
            CertKey oldKey = CertKey.of(CertIds.issuerKeyHash(old.cert()), CertIds.serial(old.cert()));
            assertThat(activation.graceEviction(oldKey)).hasValueSatisfying(
                    e -> assertThat(e.socketsClosed()).isGreaterThanOrEqualTo(1));
            MtlsTestClient.Attempt after = ping(old);
            assertThat(after.kind()).as(String.valueOf(after)).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);
            // The new certificate is unaffected.
            assertThat(SpineFixture.ingest(newConn, SpineFixture.frame(asNext, 3, UUID.randomUUID())).status())
                    .isEqualTo(200);
        }
    }

    @Test
    void perRequestCheckRefusesRenewedCertOnceTheStoredGraceHasPassed() throws Exception {
        // The handshake deny-list entry and the eviction both fire at grace_expires_at, so no socket of the old
        // certificate survives to show the per-request layer. Moving grace_expires_at back in the DB only shows it:
        // the in-memory deny-list still has the original instant, so the open socket is not refused at the TLS layer,
        // but CertStatusResolver reads the row on every request.
        SpineFixture.Device d = fx().enroll("dev_renew_403");
        Renewals.Identity old = Renewals.identity(d);
        Renewals.Identity next;
        try (MtlsTestClient.Connection c = connect(old)) {
            next = Renewals.renewOk(c, old, d.deviceId());
        }
        try (MtlsTestClient.Connection oldConn = connect(old); MtlsTestClient.Connection newConn = connect(next)) {
            assertThat(SpineFixture.ingest(newConn, SpineFixture.frame(next.as(d), 1, UUID.randomUUID())).status())
                    .isEqualTo(200);
            assertThat(activation.awaitIdle(Duration.ofSeconds(10))).isTrue();
            assertThat(oldConn.get("/api/v1/telemetry/ping").status()).isEqualTo(200);
            jdbc.update("UPDATE certificates SET grace_expires_at = NOW() - INTERVAL '1 second' WHERE serial_number = ?",
                    CertIds.serial(old.cert()));
            MtlsTestClient.Response r = oldConn.get("/api/v1/telemetry/ping");
            assertThat(r.status()).isEqualTo(403);
            assertThat(r.body()).contains("SUPERSEDED");
        }
    }

    @Test
    void lostResponseRenewTwiceBeforeUse() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_renew_lost");
        Renewals.Identity old = Renewals.identity(d);
        Renewals.Identity first;
        Renewals.Identity second;
        try (MtlsTestClient.Connection c = connect(old)) {
            first = Renewals.renewOk(c, old, d.deviceId());   // response "lost": the device never uses it
            second = Renewals.renewOk(c, old, d.deviceId());
        }
        assertThat(row(first)).containsEntry("status", "REVOKED").containsEntry("revocation_reason", "REPLACED_BEFORE_USE");
        assertThat(row(second)).containsEntry("status", "ISSUED_PENDING_USE");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM certificates WHERE device_id = ? AND status = 'ISSUED_PENDING_USE'",
                Integer.class, d.deviceId())).isEqualTo(1);
        X509CRLEntry entry = Renewals.awaitOnCrl(crls, first.cert().getSerialNumber());
        assertThat(entry).as("first pending on the CRL").isNotNull();
        assertThat(entry.getRevocationReason()).isEqualTo(CRLReason.SUPERSEDED);
        assertThat(ping(first).kind()).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);

        try (MtlsTestClient.Connection c2 = connect(second)) {
            assertThat(SpineFixture.ingest(c2, SpineFixture.frame(second.as(d), 1, UUID.randomUUID())).status())
                    .isEqualTo(200);
        }
        assertThat(activation.awaitIdle(Duration.ofSeconds(10))).isTrue();
        assertThat(status(second)).isEqualTo("ACTIVE");
        assertThat(status(old)).isEqualTo("RENEWED");
    }

    @Test
    void challengeAndBindingRejections() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_renew_chk");
        SpineFixture.Device other = fx().enroll("dev_renew_chk_other");
        Renewals.Identity cur = Renewals.identity(d);
        Renewals.Identity otherId = Renewals.identity(other);
        try (MtlsTestClient.Connection c = connect(cur); MtlsTestClient.Connection oc = connect(otherId)) {
            // Replay: a challenge already consumed by a successful renewal.
            Renewals.Challenge ch = Renewals.challenge(c);
            MtlsTestClient.Response ok = Renewals.post(c, Renewals.body(cur.cert(), cur.key(), ch,
                    EcKeys.generateP256(), d.deviceId()));
            assertThat(ok.status()).as(ok.body()).isEqualTo(200);
            MtlsTestClient.Response replay = Renewals.post(c, Renewals.body(cur.cert(), cur.key(), ch,
                    EcKeys.generateP256(), d.deviceId()));
            assertThat(replay.status()).isEqualTo(409);
            assertThat(Renewals.error(replay)).isEqualTo("CHALLENGE_REPLAYED");

            // 61 s old: a genuine tag (minted with the boot key) for an issued_at 61 s ago.
            byte[] nonce = new byte[16];
            new java.security.SecureRandom().nextBytes(nonce);
            long stale = System.currentTimeMillis() - 61_000;
            String issuer = CertIds.issuerKeyHash(cur.cert());
            String serial = CertIds.serial(cur.cert());
            Renewals.Challenge old = new Renewals.Challenge(stale, nonce,
                    Base64.getEncoder().encodeToString(challenges.tag(issuer, serial, stale, nonce)));
            MtlsTestClient.Response tooOld = Renewals.post(c, Renewals.body(cur.cert(), cur.key(), old,
                    EcKeys.generateP256(), d.deviceId()));
            assertThat(tooOld.status()).isEqualTo(401);
            assertThat(Renewals.error(tooOld)).isEqualTo("CHALLENGE_INVALID");

            // A tag minted for another serial: the other device's challenge, used by this device for its own cert.
            Renewals.Challenge foreign = Renewals.challenge(oc);
            MtlsTestClient.Response wrongSerial = Renewals.post(c, Renewals.body(cur.cert(), cur.key(), foreign,
                    EcKeys.generateP256(), d.deviceId()));
            assertThat(wrongSerial.status()).isEqualTo(401);
            assertThat(Renewals.error(wrongSerial)).isEqualTo("CHALLENGE_INVALID");

            // Body names another device's certificate: refused before the challenge is looked at.
            MtlsTestClient.Response mismatch = Renewals.post(c, Renewals.body(otherId.cert(), cur.key(),
                    Renewals.challenge(c), EcKeys.generateP256(), d.deviceId()));
            assertThat(mismatch.status()).isEqualTo(403);
            assertThat(Renewals.error(mismatch)).isEqualTo("RENEWAL_CERT_MISMATCH");
        }
    }

    @Test
    void pendingCertCannotRenew() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_renew_pending");
        Renewals.Identity cur = Renewals.identity(d);
        Renewals.Identity next;
        try (MtlsTestClient.Connection c = connect(cur)) {
            next = Renewals.renewOk(c, cur, d.deviceId());
        }
        try (MtlsTestClient.Connection pc = connect(next)) {
            MtlsTestClient.Response r = Renewals.renew(pc, next, EcKeys.generateP256(), d.deviceId());
            assertThat(r.status()).isEqualTo(409);
            assertThat(Renewals.error(r)).isEqualTo("CERT_NOT_RENEWABLE");
        }
    }

    @Test
    void proofRejections() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_renew_proof");
        Renewals.Identity cur = Renewals.identity(d);
        try (MtlsTestClient.Connection c = connect(cur)) {
            // Proof signed by the wrong key.
            MtlsTestClient.Response wrongKey = Renewals.post(c, Renewals.body(cur.cert(),
                    EcKeys.generateP256().getPrivate(), Renewals.challenge(c), EcKeys.generateP256(), d.deviceId()));
            assertThat(wrongKey.status()).isEqualTo(400);
            assertThat(Renewals.error(wrongKey)).isEqualTo("PROOF_INVALID");

            // CSR key equal to the current OLK.
            KeyPair currentOlk = new KeyPair(cur.cert().getPublicKey(), cur.key());
            MtlsTestClient.Response sameOlk = Renewals.post(c, Renewals.body(cur.cert(), cur.key(),
                    Renewals.challenge(c), currentOlk, d.deviceId()));
            assertThat(sameOlk.status()).isEqualTo(400);
            assertThat(Renewals.error(sameOlk)).isEqualTo("PROOF_INVALID");

            // CSR key equal to the stored DEK.
            KeyPair dek = d.sim().store().loadOrCreateDek();
            MtlsTestClient.Response dekKey = Renewals.post(c, Renewals.body(cur.cert(), cur.key(),
                    Renewals.challenge(c), dek, d.deviceId()));
            assertThat(dekKey.status()).isEqualTo(400);
            assertThat(Renewals.error(dekKey)).isEqualTo("PROOF_INVALID");

            // A CSR whose self-signature is broken.
            Map<String, Object> body = Renewals.body(cur.cert(), cur.key(), Renewals.challenge(c),
                    EcKeys.generateP256(), d.deviceId());
            byte[] csr = CsrFactory.create(EcKeys.generateP256(), d.deviceId());
            csr[csr.length - 5] ^= 1;
            body.put("olk_new_csr_der_b64", Base64.getEncoder().encodeToString(csr));
            MtlsTestClient.Response badCsr = Renewals.post(c, body);
            assertThat(badCsr.status()).isEqualTo(400);
            assertThat(Renewals.error(badCsr)).isEqualTo("PROOF_INVALID");
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM certificates WHERE device_id = ?", Integer.class,
                d.deviceId())).as("no certificate issued by a rejected request").isEqualTo(1);
    }

    @Test
    void deviceAndAssignmentRejections() throws Exception {
        SpineFixture.Device q = fx().enroll("dev_renew_quar");
        jdbc.update("UPDATE devices SET trust_state = 'QUARANTINED' WHERE device_id = ?", q.deviceId());
        try (MtlsTestClient.Connection c = connect(Renewals.identity(q))) {
            MtlsTestClient.Response r = Renewals.renew(c, Renewals.identity(q), EcKeys.generateP256(), q.deviceId());
            assertThat(r.status()).isEqualTo(403);
            assertThat(Renewals.error(r)).isEqualTo("DEVICE_NOT_ACTIVE");
        }

        SpineFixture.Device u = fx().enroll("dev_renew_unassigned");
        jdbc.update("UPDATE patient_device_assignments SET status = 'CLOSED', active_until = NOW() WHERE device_id = ?",
                u.deviceId());
        try (MtlsTestClient.Connection c = connect(Renewals.identity(u))) {
            MtlsTestClient.Response r = Renewals.renew(c, Renewals.identity(u), EcKeys.generateP256(), u.deviceId());
            assertThat(r.status()).isEqualTo(409);
            assertThat(Renewals.error(r)).isEqualTo("DEVICE_UNASSIGNED");
        }

        SpineFixture.Device h = fx().enroll("dev_renew_horizon");
        jdbc.update("UPDATE patient_device_assignments SET max_renewal_horizon = NOW() - INTERVAL '1 minute' "
                + "WHERE device_id = ?", h.deviceId());
        try (MtlsTestClient.Connection c = connect(Renewals.identity(h))) {
            MtlsTestClient.Response r = Renewals.renew(c, Renewals.identity(h), EcKeys.generateP256(), h.deviceId());
            assertThat(r.status()).isEqualTo(409);
            assertThat(Renewals.error(r)).isEqualTo("RENEWAL_HORIZON_EXCEEDED");
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM issued_serials WHERE device_id IN (?, ?, ?) "
                        + "AND status <> 'RECORDED'", Integer.class, q.deviceId(), u.deviceId(), h.deviceId()))
                .as("no serial reserved for a request refused in Tx 1").isZero();
    }

    @Test
    void crashAfterSignIsVoidedBySweepAndListed() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_renew_crash");
        crashDevice = d.deviceId();
        try (MtlsTestClient.Connection c = connect(Renewals.identity(d))) {
            MtlsTestClient.Response r = Renewals.renew(c, Renewals.identity(d), EcKeys.generateP256(), d.deviceId());
            assertThat(r.status()).isGreaterThanOrEqualTo(500);
        } finally {
            crashDevice = null;
        }
        String serial = jdbc.queryForObject(
                "SELECT serial_number FROM issued_serials WHERE device_id = ? AND status = 'RESERVED'", String.class,
                d.deviceId());
        // The process "restarts" 3 minutes later: the reservation is stale, and the sweep voids it.
        jdbc.update("UPDATE issued_serials SET reserved_at = NOW() - INTERVAL '3 minutes' WHERE serial_number = ?",
                serial);
        List<CertKey> voided = sweepers.sweepStaleReservations();
        assertThat(voided).extracting(CertKey::serial).contains(serial);
        assertThat(jdbc.queryForObject("SELECT status::text FROM issued_serials WHERE serial_number = ?", String.class,
                serial)).isEqualTo("VOIDED");
        X509CRLEntry entry = Renewals.awaitOnCrl(crls, new BigInteger(serial, 16));
        assertThat(entry).as("voided serial on the CRL").isNotNull();
        assertThat(entry.getRevocationReason()).isEqualTo(CRLReason.SUPERSEDED);
    }
}
