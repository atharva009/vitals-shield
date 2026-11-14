package com.vitalsshield.server.enrollment;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.vitalsshield.crypto.CsrFactory;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.devtools.DevSeeder;
import com.vitalsshield.server.kms.KmsSigner;
import com.vitalsshield.server.pki.CertificateProfiles;
import com.vitalsshield.server.pki.Pems;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.GatewayClient;
import com.vitalsshield.simulator.Simulator;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
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

/** Protocol A end to end: seeded via DevSeeder, real listeners, the simulator classes as the client. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@Import(EnrollmentIT.FlakyKms.class)
class EnrollmentIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-enroll-it");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim-state");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.register(registry);
    }

    /** Wraps the real signer; fails the next N Sign calls on demand (simulated KMS outage). */
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
    @Autowired DekAnchorVerifier anchorVerifier;
    @Autowired TrustAnchors anchors;
    @Autowired FlakyKmsSigner flaky;

    // ---- happy path ---------------------------------------------------------------------------------------------

    @Test
    void happyPathEnrolls() throws Exception {
        DevSeeder.Result seed = seed("dev_happy");
        Simulator sim = sim("dev_happy");

        Simulator.EnrollOutcome outcome = sim.enroll(seed.token());

        assertThat(outcome).isInstanceOf(Simulator.EnrollOutcome.Enrolled.class);
        X509Certificate cert = ((Simulator.EnrollOutcome.Enrolled) outcome).cert();
        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=dev_happy,O=VitalsShield Devices");
        assertThat(cert.getSubjectAlternativeNames()).containsExactly(List.of(6, "urn:vitalsshield:device:dev_happy"));
        assertThat(CertificateProfiles.authorityKeyIdentifier(cert))
                .isEqualTo(CertificateProfiles.subjectKeyIdentifier(anchors.deviceIntermediate()));
        assertThat(Duration.between(cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant()))
                .isEqualTo(Duration.ofHours(12));

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT status::text AS status, cert_thumbprint_s256 FROM certificates WHERE device_id = 'dev_happy'");
        assertThat(row.get("status")).isEqualTo("ACTIVE");
        String expectedThumb = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        assertThat(row.get("cert_thumbprint_s256")).isEqualTo(expectedThumb);
        assertThat((String) row.get("cert_thumbprint_s256")).hasSize(43);

        Map<String, Object> device = jdbc.queryForMap("SELECT * FROM devices WHERE device_id = 'dev_happy'");
        assertThat(device.get("trust_state")).hasToString("ACTIVE");
        assertThat(device.get("boot_epoch")).isEqualTo(1L);
        assertThat(device.get("dek_spki_der_b64")).isNotNull();
        assertThat(device.get("dek_registry_kms_sig")).isNotNull();
        assertThat(device.get("provisioned_at")).isNotNull();
        byte[] spki = Base64.getDecoder().decode((String) device.get("dek_spki_der_b64"));
        assertThat(device.get("dek_spki_sha256"))
                .isEqualTo(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(spki)));

        assertThat(tokenStatus(seed)).isEqualTo("CONSUMED");
        assertThat(anchorVerifier.verify("dev_happy")).isTrue();
    }

    @Test
    void dekAnchorDetectsTamper() throws Exception {
        DevSeeder.Result seed = seed("dev_tamper");
        assertThat(sim("dev_tamper").enroll(seed.token())).isInstanceOf(Simulator.EnrollOutcome.Enrolled.class);
        assertThat(anchorVerifier.verify("dev_tamper")).isTrue();

        jdbc.update("UPDATE devices SET dek_spki_der_b64 = ? WHERE device_id = 'dev_tamper'",
                Base64.getEncoder().encodeToString(EcKeys.generateP256().getPublic().getEncoded()));

        assertThat(anchorVerifier.verify("dev_tamper")).isFalse();
    }

    @Test
    void enrolledCertPingsImmediately() throws Exception {
        DevSeeder.Result seed = seed("dev_pingnow");
        Simulator sim = sim("dev_pingnow");
        X509Certificate cert = ((Simulator.EnrollOutcome.Enrolled) sim.enroll(seed.token())).cert();

        GatewayClient.Response ping = sim.ping();

        assertThat(ping.status()).isEqualTo(200);
        assertThat(ping.body()).contains("\"serial\":\"" + cert.getSerialNumber().toString(16) + "\"");
    }

    // ---- token handling -----------------------------------------------------------------------------------------

    @Test
    void tokenSingleUse() throws Exception {
        DevSeeder.Result seed = seed("dev_single");
        assertThat(sim("dev_single").enroll(seed.token())).isInstanceOf(Simulator.EnrollOutcome.Enrolled.class);

        GatewayClient.Response again = post(freshBody("dev_single", seed.token()));

        assertThat(again.status()).isEqualTo(401);
        assertThat(again.body()).isEqualTo("{\"error\":\"INVALID_BOOTSTRAP\"}");
    }

    @Test
    void concurrentEnrollSameToken() throws Exception {
        DevSeeder.Result seed = seed("dev_race");
        Map<String, Object> a = freshBody("dev_race", seed.token());
        Map<String, Object> b = freshBody("dev_race", seed.token());

        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch go = new CountDownLatch(1);
        try {
            Future<GatewayClient.Response> fa = pool.submit(() -> {
                go.await();
                return post(a);
            });
            Future<GatewayClient.Response> fb = pool.submit(() -> {
                go.await();
                return post(b);
            });
            go.countDown();
            List<Integer> statuses = List.of(fa.get(30, TimeUnit.SECONDS).status(), fb.get(30, TimeUnit.SECONDS).status());
            assertThat(statuses).containsExactlyInAnyOrder(201, 401);
        } finally {
            pool.shutdownNow();
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM certificates WHERE device_id = 'dev_race'", Integer.class))
                .isEqualTo(1);
    }

    @Test
    void invalidTokensLookIdentical() throws Exception {
        DevSeeder.Result mine = seed("dev_oracle");
        DevSeeder.Result other = seed("dev_oracle_other");
        DevSeeder.Result expired = seed("dev_oracle");
        jdbc.update("UPDATE device_bootstrap_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE token_id = ?",
                expired.tokenId());
        DevSeeder.Result consumed = seed("dev_oracle_used");
        assertThat(sim("dev_oracle_used").enroll(consumed.token())).isInstanceOf(Simulator.EnrollOutcome.Enrolled.class);

        List<GatewayClient.Response> responses = List.of(
                post(freshBody("dev_oracle", "unknown-token-" + System.nanoTime())),
                post(freshBody("dev_oracle", other.token())),
                post(freshBody("dev_oracle", expired.token())),
                post(freshBody("dev_oracle_used", consumed.token())));

        for (GatewayClient.Response r : responses) {
            assertThat(r.status()).isEqualTo(401);
            assertThat(r.body()).isEqualTo(responses.get(0).body());
        }
        assertThat(responses.get(0).body()).isEqualTo("{\"error\":\"INVALID_BOOTSTRAP\"}");
        assertThat(tokenStatus(mine)).isEqualTo("ISSUED");
    }

    // ---- proofs -------------------------------------------------------------------------------------------------

    @Test
    void badDekProofRevokesToken() throws Exception {
        DevSeeder.Result seed = seed("dev_badproof");
        KeyPair dek = EcKeys.generateP256();
        byte[] csr = CsrFactory.create(EcKeys.generateP256(), "dev_badproof");
        byte[] otherCsr = CsrFactory.create(EcKeys.generateP256(), "dev_badproof");
        Map<String, Object> body = Simulator.enrollmentBody("dev_badproof", seed.token(), dek, otherCsr);
        body.put("olk_csr_der_b64", Base64.getEncoder().encodeToString(csr)); // proof was over a different CSR

        assertProofInvalid(seed, "dev_badproof", post(body));
    }

    @Test
    void badCsrSignatureRevokesToken() throws Exception {
        DevSeeder.Result seed = seed("dev_badcsr");
        byte[] csr = CsrFactory.create(EcKeys.generateP256(), "dev_badcsr");
        csr[csr.length - 1] ^= 0x01; // corrupt the CSR self-signature
        // The DEK proof is valid over the tampered bytes, so only the CSR signature is wrong.
        Map<String, Object> body = Simulator.enrollmentBody("dev_badcsr", seed.token(), EcKeys.generateP256(), csr);

        assertProofInvalid(seed, "dev_badcsr", post(body));
    }

    @Test
    void dekEqualsOlkRejected() throws Exception {
        DevSeeder.Result seed = seed("dev_samekey");
        KeyPair one = EcKeys.generateP256();
        Map<String, Object> body = Simulator.enrollmentBody("dev_samekey", seed.token(), one,
                CsrFactory.create(one, "dev_samekey"));

        assertProofInvalid(seed, "dev_samekey", post(body));
    }

    @Test
    void csrAttributesIgnored() throws Exception {
        DevSeeder.Result seed = seed("dev_attrs");
        KeyPair olk = EcKeys.generateP256();
        ExtensionsGenerator ext = new ExtensionsGenerator();
        ext.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "attacker.example")));
        ext.addExtension(Extension.basicConstraints, true, new org.bouncycastle.asn1.x509.BasicConstraints(true));
        byte[] evilCsr = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=evil-device"), olk.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext.generate())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(olk.getPrivate())).getEncoded();

        GatewayClient.Response r = post(Simulator.enrollmentBody("dev_attrs", seed.token(), EcKeys.generateP256(), evilCsr));

        assertThat(r.status()).isEqualTo(201);
        X509Certificate cert = Pems.parseCertificate((String) JSONObjectUtils.parse(r.body()).get("new_cert_pem"));
        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=dev_attrs,O=VitalsShield Devices");
        assertThat(cert.getSubjectAlternativeNames()).containsExactly(List.of(6, "urn:vitalsshield:device:dev_attrs"));
        assertThat(cert.getBasicConstraints()).isEqualTo(-1);
        assertThat(cert.getPublicKey().getEncoded()).isEqualTo(olk.getPublic().getEncoded());
    }

    // ---- device and assignment state ----------------------------------------------------------------------------

    @Test
    void noAssignment409() throws Exception {
        DevSeeder.Result seed = seed("dev_unassigned");
        jdbc.update("UPDATE patient_device_assignments SET status = 'CLOSED', active_until = NOW() "
                + "WHERE device_id = 'dev_unassigned'");

        GatewayClient.Response r = post(freshBody("dev_unassigned", seed.token()));

        assertThat(r.status()).isEqualTo(409);
        assertThat(r.body()).isEqualTo("{\"error\":\"DEVICE_UNASSIGNED\"}");
        assertThat(tokenStatus(seed)).isEqualTo("ISSUED");
        assertThat(certCount("dev_unassigned")).isZero();
    }

    @Test
    void decommissionedRejected() throws Exception {
        DevSeeder.Result seed = seed("dev_decom");
        jdbc.update("UPDATE devices SET trust_state = 'DECOMMISSIONED' WHERE device_id = 'dev_decom'");

        GatewayClient.Response r = post(freshBody("dev_decom", seed.token()));

        assertThat(r.status()).isEqualTo(403);
        assertThat(r.body()).isEqualTo("{\"error\":\"DEVICE_DECOMMISSIONED\"}");
        assertThat(tokenStatus(seed)).isEqualTo("REVOKED");
        assertThat(certCount("dev_decom")).isZero();
    }

    @Test
    void reprovisionRevokesPriorEvictsAndBumpsEpoch() throws Exception {
        DevSeeder.Result first = seed("dev_reprov");
        Simulator sim = sim("dev_reprov");
        X509Certificate oldCert = ((Simulator.EnrollOutcome.Enrolled) sim.enroll(first.token())).cert();
        var oldEnrollment = sim.store().load().orElseThrow();
        String oldSpki = jdbc.queryForObject("SELECT dek_spki_der_b64 FROM devices WHERE device_id = 'dev_reprov'",
                String.class);

        try (MtlsTestClient.Connection live = MtlsTestClient.connect(ports.mtls(), anchors.root(),
                oldEnrollment.olkKey(), List.of(oldCert))) {
            assertThat(live.get("/api/v1/telemetry/ping").status()).isEqualTo(200);

            DevSeeder.Result second = seed("dev_reprov");
            sim.store().factoryWipe();
            Simulator.EnrollOutcome again = sim.enroll(second.token());
            assertThat(again).isInstanceOf(Simulator.EnrollOutcome.Enrolled.class);
            assertThat(((Simulator.EnrollOutcome.Enrolled) again).bootEpoch()).isEqualTo(2);

            assertThat(live.awaitClosedWithin(Duration.ofSeconds(2))).as("old keep-alive socket closed").isTrue();
        }

        Map<String, Object> old = jdbc.queryForMap(
                "SELECT status::text AS status, revocation_reason FROM certificates WHERE device_id = 'dev_reprov' "
                        + "AND serial_number = ?", oldCert.getSerialNumber().toString(16));
        assertThat(old).containsEntry("status", "REVOKED").containsEntry("revocation_reason", "SUPERSEDED_BY_REPROVISION");

        MtlsTestClient.Attempt reuse = MtlsTestClient.attempt(ports.mtls(), anchors.root(), oldEnrollment.olkKey(),
                List.of(oldCert), "/api/v1/telemetry/ping");
        assertThat(reuse.kind()).as(reuse.detail()).isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);

        Map<String, Object> device = jdbc.queryForMap("SELECT * FROM devices WHERE device_id = 'dev_reprov'");
        assertThat(device.get("boot_epoch")).isEqualTo(2L);
        assertThat(device.get("last_sequence_num")).isEqualTo(0L);
        assertThat(device.get("replay_bitmap")).isEqualTo(0L);
        assertThat(device.get("dek_spki_der_b64")).isNotEqualTo(oldSpki);
        assertThat(anchorVerifier.verify("dev_reprov")).isTrue();
    }

    // ---- failure handling ---------------------------------------------------------------------------------------

    @Test
    void kmsFailureReturnsToken() throws Exception {
        DevSeeder.Result seed = seed("dev_kmsdown");
        flaky.failNext.set(1); // the DEK anchor Sign is the first KMS call in enrollment

        GatewayClient.Response r = post(freshBody("dev_kmsdown", seed.token()));

        assertThat(r.status()).isEqualTo(503);
        assertThat(r.headers().firstValue("Retry-After")).isPresent();
        assertThat(tokenStatus(seed)).isEqualTo("ISSUED");
        assertThat(certCount("dev_kmsdown")).isZero();

        // The returned token still works once KMS is back.
        assertThat(post(freshBody("dev_kmsdown", seed.token())).status()).isEqualTo(201);
    }

    @Test
    void staleClaimingReclaimed() throws Exception {
        DevSeeder.Result seed = seed("dev_stale");
        jdbc.update("UPDATE device_bootstrap_tokens SET status = 'CLAIMING', claimed_at = NOW() - INTERVAL '5 minutes' "
                + "WHERE token_id = ?", seed.tokenId());

        assertThat(post(freshBody("dev_stale", seed.token())).status()).isEqualTo(201);
        assertThat(tokenStatus(seed)).isEqualTo("CONSUMED");
    }

    @Test
    void freshClaimingNotReclaimed() throws Exception {
        DevSeeder.Result seed = seed("dev_busy");
        jdbc.update("UPDATE device_bootstrap_tokens SET status = 'CLAIMING', claimed_at = NOW() WHERE token_id = ?",
                seed.tokenId());

        assertThat(post(freshBody("dev_busy", seed.token())).status()).isEqualTo(401);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    private DevSeeder.Result seed(String deviceId) {
        return new DevSeeder(jdbc, tx, Clock.systemUTC()).seed(DevSeeder.Request.defaults(deviceId));
    }

    private Simulator sim(String deviceId) {
        return new Simulator(new Simulator.Config(deviceId, stateRoot, trustFile,
                URI.create("https://127.0.0.1:" + ports.pub()), URI.create("https://127.0.0.1:" + ports.mtls())),
                Clock.systemUTC());
    }

    private static Map<String, Object> freshBody(String deviceId, String token) {
        KeyPair olk = EcKeys.generateP256();
        return Simulator.enrollmentBody(deviceId, token, EcKeys.generateP256(), CsrFactory.create(olk, deviceId));
    }

    private static GatewayClient.Response post(Map<String, Object> body) throws Exception {
        return GatewayClient.publicClient(trustFile).postJson(
                URI.create("https://127.0.0.1:" + ports.pub() + "/api/v1/devices/enroll"),
                JSONObjectUtils.toJSONString(body));
    }

    private void assertProofInvalid(DevSeeder.Result seed, String deviceId, GatewayClient.Response r) {
        assertThat(r.status()).isEqualTo(400);
        assertThat(r.body()).isEqualTo("{\"error\":\"PROOF_INVALID\"}");
        assertThat(tokenStatus(seed)).isEqualTo("REVOKED");
        assertThat(certCount(deviceId)).isZero();
    }

    private String tokenStatus(DevSeeder.Result seed) {
        return jdbc.queryForObject("SELECT status::text FROM device_bootstrap_tokens WHERE token_id = ?", String.class,
                seed.tokenId());
    }

    private int certCount(String deviceId) {
        return jdbc.queryForObject("SELECT count(*) FROM certificates WHERE device_id = ?", Integer.class, deviceId);
    }
}
