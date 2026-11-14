package com.vitalsshield.server.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.VitalsShieldServerApplication;
import com.vitalsshield.server.boot.BootStatusTracker;
import com.vitalsshield.server.boot.BootStep;
import com.vitalsshield.server.pki.CaIssuer;
import com.vitalsshield.server.pki.CaIssuerRepository;
import com.vitalsshield.server.pki.CertificateProfiles;
import com.vitalsshield.server.pki.KeyPurpose;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import com.vitalsshield.server.signer.RevocationResult;
import com.vitalsshield.server.signer.SignerRevocationService;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.MtlsTestClient.Attempt;
import com.vitalsshield.server.testsupport.MtlsTestClient.Connection;
import com.vitalsshield.server.testsupport.MtlsTestClient.Kind;
import com.vitalsshield.server.testsupport.MtlsTestClient.Response;
import com.vitalsshield.server.testsupport.TestDevices;
import com.vitalsshield.server.testsupport.TestDevices.Leaf;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * Real listeners on ephemeral ports against Testcontainers Postgres and the Compose LocalStack. Contexts are started
 * by hand so tests can restart them against the same database. No test sleeps.
 */
@Tag("integration")
@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class MtlsListenerIT {

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    Path trustFile;
    Server server;

    record Server(ConfigurableApplicationContext ctx, TestPorts.Listeners ports) {
        <T> T bean(Class<T> type) {
            return ctx.getBean(type);
        }

        X509Certificate root() {
            return bean(TrustAnchors.class).root();
        }
    }

    @BeforeAll
    void start() throws IOException {
        trustFile = Files.createTempDirectory("vs-mtls-it").resolve("root-ca.pem");
        server = startServer();
    }

    @AfterAll
    void stop() {
        if (server != null) {
            server.ctx().close();
        }
    }

    Server startServer(String... extraArgs) {
        TestPorts.Listeners ports = TestPorts.allocate();
        List<String> args = new ArrayList<>(List.of(
                "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "--spring.datasource.username=" + POSTGRES.getUsername(),
                "--spring.datasource.password=" + POSTGRES.getPassword(),
                "--vitalsshield.pki.trust-file=" + trustFile,
                "--spring.main.keep-alive=false"));
        args.addAll(ports.asArgs());
        args.addAll(List.of(extraArgs));
        ConfigurableApplicationContext ctx = new SpringApplicationBuilder(VitalsShieldServerApplication.class)
                .profiles("local")
                .run(args.toArray(String[]::new));
        return new Server(ctx, ports);
    }

    // ---- boot and binding ---------------------------------------------------------------------------------------

    @Test
    @Order(1)
    void bootStepsInOrder() {
        assertThat(server.bean(BootStatusTracker.class).completed())
                .extracting(BootStatusTracker.Completed::step)
                .containsExactly(BootStep.RECONCILED, BootStep.SERIALS_SWEPT, BootStep.GATEWAY_TLS_ISSUED, BootStep.TRUST_ANCHORS_LOADED,
                        BootStep.DENY_LIST_SEEDED, BootStep.CRLS_PUBLISHED, BootStep.ADMIN_CODE_ISSUED, BootStep.LISTENERS_BOUND);
    }

    @Test
    @Order(2)
    void bootDisabledBindsNothing() {
        Server noBoot = startServer("--vitalsshield.boot.enabled=false");
        try {
            for (int port : new int[] {noBoot.ports().mtls(), noBoot.ports().pub(), noBoot.ports().admin()}) {
                assertThat(connectRefused(port)).as("port %d refused", port).isTrue();
            }
            assertThat(noBoot.bean(ListenerManager.class).boundAddresses()).isEmpty();
        } finally {
            noBoot.ctx().close();
        }
    }

    @Test
    @Order(3)
    void allListenersOnLoopback() {
        List<InetSocketAddress> bound = server.bean(ListenerManager.class).boundAddresses();
        assertThat(bound).hasSize(3);
        assertThat(bound).allSatisfy(a -> assertThat(a.getAddress().getHostAddress()).isEqualTo("127.0.0.1"));
        assertThat(bound).extracting(InetSocketAddress::getPort).containsExactly(
                server.ports().mtls(), server.ports().pub(), server.ports().admin());
    }

    // ---- handshake ----------------------------------------------------------------------------------------------

    @Test
    @Order(10)
    void noClientCertFailsHandshake() {
        Attempt a = MtlsTestClient.attempt(server.ports().mtls(), server.root(), null, List.of(),
                "/api/v1/telemetry/ping");
        assertThat(a.kind()).as(a.detail()).isEqualTo(Kind.TLS_REJECTED);
    }

    @Test
    @Order(11)
    void tls12Refused() {
        Leaf leaf = TestDevices.enroll(server.ctx(), "dev_tls12");
        for (int port : new int[] {server.ports().mtls(), server.ports().pub()}) {
            Attempt a = MtlsTestClient.attempt(port, server.root(), leaf.keyPair().getPrivate(), leaf.chain(),
                    "/api/v1/telemetry/ping", "TLSv1.2");
            assertThat(a.kind()).as("port %d: %s", port, a.detail()).isEqualTo(Kind.TLS_REJECTED);
        }
    }

    @Test
    @Order(12)
    void validLeafPings() throws IOException {
        Leaf leaf = TestDevices.enroll(server.ctx(), "dev_ping");
        try (Connection c = connect(leaf)) {
            Response r = c.get("/api/v1/telemetry/ping");
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.body()).contains("\"serial\":\"" + leaf.key().serial() + "\"")
                    .contains("\"issuer_key_hash\":\"" + leaf.key().issuerKeyHash() + "\"")
                    .contains("\"device_id\":\"dev_ping\"")
                    .contains("\"status\":\"ACTIVE\"");
        }
    }

    @Test
    @Order(13)
    void newlyIssuedLeafConnectsImmediately() throws IOException {
        Leaf leaf = TestDevices.enroll(server.ctx(), "dev_fresh");
        try (Connection c = connect(leaf)) {
            assertThat(c.get("/api/v1/telemetry/ping").status()).isEqualTo(200);
        }
    }

    @Test
    @Order(14)
    void unknownCertPassesHandshakeButGets403() throws IOException {
        Leaf leaf = TestDevices.issueOnly(server.ctx(), "dev_unknown");
        try (Connection c = connect(leaf)) {
            Response r = c.get("/api/v1/telemetry/ping");
            assertThat(r.status()).isEqualTo(403);
            assertThat(r.body()).isEqualTo("{\"error\":\"CERT_NOT_ACCEPTED\",\"reason\":\"UNKNOWN\"}");
        }
    }

    // ---- revocation ---------------------------------------------------------------------------------------------

    @Test
    @Order(20)
    void revokedLeafRejectedOnImmediateReconnect() throws IOException {
        Leaf leaf = TestDevices.enroll(server.ctx(), "dev_reconnect");
        try (Connection c = connect(leaf)) {
            assertThat(c.get("/api/v1/telemetry/ping").status()).isEqualTo(200);
        }
        revoke(server, leaf);

        Attempt again = MtlsTestClient.attempt(server.ports().mtls(), server.root(), leaf.keyPair().getPrivate(),
                leaf.chain(), "/api/v1/telemetry/ping");
        assertThat(again.kind()).as(again.detail()).isEqualTo(Kind.TLS_REJECTED);
    }

    @Test
    @Order(21)
    void revokeClosesLiveKeepAliveSocket() throws IOException {
        ActiveSessionRegistry sessions = server.bean(ActiveSessionRegistry.class);
        long maxMicros = 0;
        for (int i = 0; i < 5; i++) {
            Leaf leaf = TestDevices.enroll(server.ctx(), "dev_evict_" + i);
            try (Connection c = connect(leaf)) {
                assertThat(c.get("/api/v1/telemetry/ping").status()).isEqualTo(200);
                int liveBefore = sessions.liveSocketCount();
                assertThat(sessions.liveSocketsFor(leaf.key())).hasSize(1);

                long start = System.nanoTime();
                RevocationResult result = revoke(server, leaf);
                long remainingMs = 500 - (System.nanoTime() - start) / 1_000_000;

                assertThat(c.awaitClosedWithin(Duration.ofMillis(Math.max(remainingMs, 1))))
                        .as("client sees close within 500 ms of revoke").isTrue();
                assertThat(result.channelsClosed()).isEqualTo(1);
                assertThat(sessions.liveSocketCount()).isEqualTo(liveBefore - 1);
                maxMicros = Math.max(maxMicros, result.evictionLatencyMicros());
                System.out.printf("EVICTION run %d: evictionLatencyMicros=%d%n", i, result.evictionLatencyMicros());
            }
        }
        System.out.println("MAX_EVICTION_LATENCY_MICROS=" + maxMicros);
        writeResult("eviction-latency.txt", "MAX_EVICTION_LATENCY_MICROS=" + maxMicros + "\n");
        assertThat(maxMicros).isLessThan(500_000);
    }

    @Test
    @Order(22)
    void perRequest403WhenEvictionDisabled() throws IOException {
        Server noEvict = startServer("--vitalsshield.eviction.enabled=false");
        try {
            Leaf leaf = TestDevices.enroll(noEvict.ctx(), "dev_noevict");
            try (Connection c = connectTo(noEvict, leaf)) {
                assertThat(c.get("/api/v1/telemetry/ping").status()).isEqualTo(200);

                RevocationResult result = revoke(noEvict, leaf);
                assertThat(result.channelsClosed()).isZero();

                Response r = c.get("/api/v1/telemetry/ping");
                assertThat(r.status()).isEqualTo(403);
                assertThat(r.body()).isEqualTo("{\"error\":\"CERT_NOT_ACCEPTED\",\"reason\":\"REVOKED\"}");
            }
        } finally {
            noEvict.ctx().close();
        }
    }

    /** No per-request cache: a status change made directly in the DB (deny-list unaware) is seen by the next request. */
    @Test
    @Order(23)
    void dbStatusChangeVisibleToNextRequestOnSameConnection() throws IOException {
        Leaf leaf = TestDevices.enroll(server.ctx(), "dev_dbonly");
        try (Connection c = connect(leaf)) {
            assertThat(c.get("/api/v1/telemetry/ping").status()).isEqualTo(200);
            server.bean(JdbcTemplate.class).update(
                    "UPDATE certificates SET status = 'EXPIRED' WHERE issuer_key_hash = ? AND serial_number = ?",
                    leaf.key().issuerKeyHash(), leaf.key().serial());

            Response r = c.get("/api/v1/telemetry/ping");
            assertThat(r.status()).isEqualTo(403);
            assertThat(r.body()).contains("\"reason\":\"EXPIRED\"");
        }
    }

    // ---- ports and CRLs -----------------------------------------------------------------------------------------

    @Test
    @Order(30)
    void wrongPortReturns404() throws IOException {
        Leaf leaf = TestDevices.enroll(server.ctx(), "dev_ports");
        X509Certificate root = server.root();

        try (Connection pub = MtlsTestClient.connect(server.ports().pub(), root, null, List.of())) {
            assertEmpty404(pub.get("/api/v1/telemetry/ping"));
            assertEmpty404(pub.get("/api/v1/admin/boot-status"));
        }
        try (Connection mtls = connect(leaf)) {
            assertEmpty404(mtls.get("/api/v1/pki/intermediate-crl.pem"));
            assertEmpty404(mtls.get("/api/v1/admin/boot-status"));
        }
    }

    @Test
    @Order(31)
    void crlsServedOnPublicPort() throws Exception {
        CaIssuerRepository issuers = server.bean(CaIssuerRepository.class);
        JdbcTemplate jdbc = server.bean(JdbcTemplate.class);
        try (Connection pub = MtlsTestClient.connect(server.ports().pub(), server.root(), null, List.of())) {
            for (String path : List.of("/api/v1/pki/intermediate-crl.pem", "/api/v1/pki/root-crl.pem")) {
                Response r = pub.get(path);
                assertThat(r.status()).as(path).isEqualTo(200);
                assertThat(r.body()).startsWith("-----BEGIN X509 CRL-----");

                X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(
                        new ByteArrayInputStream(r.body().getBytes(StandardCharsets.US_ASCII)));
                // Find the issuer by key ID (CRL AKI), never by DN.
                String akiHex = HexFormat.of().formatHex(AuthorityKeyIdentifier.getInstance(
                        new X509CRLHolder(crl.getEncoded()).getExtension(Extension.authorityKeyIdentifier)
                                .getParsedValue()).getKeyIdentifierOctets());
                String pem = jdbc.queryForObject("SELECT cert_pem FROM ca_issuers WHERE issuer_key_hash = ?",
                        String.class, akiHex);
                X509Certificate issuer = com.vitalsshield.server.pki.Pems.parseCertificate(pem);
                crl.verify(issuer.getPublicKey());
            }
        }
        // Sanity: the intermediate CRL is signed by the ACTIVE Device Intermediate.
        CaIssuer deviceInt = issuers.requireActive(KeyPurpose.DEVICE_INTERMEDIATE);
        assertThat(deviceInt.issuerKeyHash()).isEqualTo(
                CertificateProfiles.issuerKeyHash(server.bean(TrustAnchors.class).deviceIntermediate()));
    }

    // ---- CRL caching and republication (Phase 2.1) ---------------------------------------------------------------

    @Test
    @Order(32)
    void crlGetsDoNotSign() throws Exception {
        awaitCrlSettled(server);
        com.vitalsshield.server.kms.KmsSigner signer = server.bean(com.vitalsshield.server.kms.KmsSigner.class);
        long signsBefore = signer.signCount();
        long numberBefore = deviceIntCrlNumber(server);

        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(16);
        try {
            List<java.util.concurrent.Future<String>> bodies = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                bodies.add(pool.submit(() -> {
                    try (Connection c = MtlsTestClient.connect(server.ports().pub(), server.root(), null, List.of())) {
                        Response r = c.get("/api/v1/pki/intermediate-crl.pem");
                        assertThat(r.status()).isEqualTo(200);
                        return r.body();
                    }
                }));
            }
            java.util.Set<String> distinct = new java.util.HashSet<>();
            for (java.util.concurrent.Future<String> f : bodies) {
                distinct.add(f.get(30, java.util.concurrent.TimeUnit.SECONDS));
            }
            assertThat(distinct).as("all 100 bodies identical").hasSize(1);
        } finally {
            pool.shutdownNow();
        }
        assertThat(signer.signCount()).as("KMS Sign calls").isEqualTo(signsBefore);
        assertThat(deviceIntCrlNumber(server)).as("crl_number").isEqualTo(numberBefore);
    }

    @Test
    @Order(33)
    void crlRepublishedOnRevoke() throws Exception {
        awaitCrlSettled(server);
        // Newest CRL Number issued by anyone is crl_number - 1 (other servers in this class share the DB).
        long nextNumber = deviceIntCrlNumber(server);
        Leaf leaf = TestDevices.enroll(server.ctx(), "dev_crl_one");

        revoke(server, leaf);

        long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
        X509CRL crl = fetchIntermediateCrl(server);
        while (crl.getRevokedCertificate(leaf.cert().getSerialNumber()) == null && System.nanoTime() < deadline) {
            Thread.sleep(25);
            crl = fetchIntermediateCrl(server);
        }
        assertThat(crl.getRevokedCertificate(leaf.cert().getSerialNumber())).as("serial listed within 2 s").isNotNull();
        assertThat(crlNumberOf(crl)).as("exactly one higher than the newest CRL")
                .isEqualTo(java.math.BigInteger.valueOf(nextNumber));
        awaitCrlSettled(server);
        assertThat(deviceIntCrlNumber(server)).as("one regeneration").isEqualTo(nextNumber + 1);
    }

    @Test
    @Order(34)
    void crlBurstCoalesced() throws Exception {
        awaitCrlSettled(server);
        long numberBefore = deviceIntCrlNumber(server);
        List<Leaf> leaves = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            leaves.add(TestDevices.enroll(server.ctx(), "dev_burst_" + i));
        }

        SignerRevocationService svc = server.bean(SignerRevocationService.class);
        reactor.core.publisher.Flux.fromIterable(leaves)
                .flatMap(l -> svc.revoke(l.key(), "KEY_COMPROMISE"), 10)
                .collectList()
                .block(Duration.ofSeconds(30));

        awaitCrlSettled(server);
        X509CRL crl = fetchIntermediateCrl(server);
        for (Leaf l : leaves) {
            assertThat(crl.getRevokedCertificate(l.cert().getSerialNumber())).as(l.deviceId()).isNotNull();
        }
        long rose = deviceIntCrlNumber(server) - numberBefore;
        System.out.println("CRL_BURST crl_number rose by " + rose + " for 10 concurrent revocations");
        assertThat(rose).isBetween(1L, 3L);
    }

    // ---- restarts (last: they replace the running server) -------------------------------------------------------

    @Test
    @Order(90)
    void denyListSurvivesRestart() {
        Leaf leaf = TestDevices.enroll(server.ctx(), "dev_restart");
        revoke(server, leaf);

        server.ctx().close();
        server = startServer();

        Attempt a = MtlsTestClient.attempt(server.ports().mtls(), server.root(), leaf.keyPair().getPrivate(),
                leaf.chain(), "/api/v1/telemetry/ping");
        assertThat(a.kind()).as(a.detail()).isEqualTo(Kind.TLS_REJECTED);
    }

    @Test
    @Order(91)
    void oldHierarchyLeafRejected() {
        Leaf oldLeaf = TestDevices.enroll(server.ctx(), "dev_oldhier");
        CaIssuer oldInt = server.bean(CaIssuerRepository.class).requireActive(KeyPurpose.DEVICE_INTERMEDIATE);
        server.bean(KmsClient.class).scheduleKeyDeletion(r -> r.keyId(oldInt.kmsArn()).pendingWindowInDays(7));

        server.ctx().close();
        server = startServer();

        X509Certificate newInt = server.bean(TrustAnchors.class).deviceIntermediate();
        assertThat(newInt.getSubjectX500Principal()).isEqualTo(oldLeaf.cert().getIssuerX500Principal());
        assertThat(CertificateProfiles.issuerKeyHash(newInt)).isNotEqualTo(oldInt.issuerKeyHash());

        Attempt a = MtlsTestClient.attempt(server.ports().mtls(), server.root(), oldLeaf.keyPair().getPrivate(),
                List.of(oldLeaf.cert()), "/api/v1/telemetry/ping");
        assertThat(a.kind()).as(a.detail()).isEqualTo(Kind.TLS_REJECTED);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    /** DB crl_number of the ACTIVE Device Intermediate: the next number CrlService will use. */
    private static long deviceIntCrlNumber(Server s) {
        return s.bean(JdbcTemplate.class).queryForObject("""
                SELECT ci.crl_number FROM ca_issuers ci JOIN kms_keys k ON k.kms_key_id = ci.kms_primary_arn
                 WHERE k.purpose = 'DEVICE_INTERMEDIATE' AND k.status = 'ACTIVE' AND ci.status = 'ACTIVE'
                """, Long.class);
    }

    /**
     * Waits until no CRL regeneration is running or pending in this server. (Not "cached number == DB - 1": other
     * servers started by this class against the same DB also publish CRLs and advance crl_number.)
     */
    private static void awaitCrlSettled(Server s) throws InterruptedException {
        com.vitalsshield.server.pki.CrlService crls = s.bean(com.vitalsshield.server.pki.CrlService.class);
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (System.nanoTime() < deadline) {
            if (crls.isIdle() && crls.cachedIntermediate().isPresent()) {
                Thread.sleep(50);
                if (crls.isIdle()) {
                    return;
                }
            }
            Thread.sleep(25);
        }
        throw new AssertionError("CRL cache did not settle within 10 s");
    }

    private static X509CRL fetchIntermediateCrl(Server s) throws Exception {
        try (Connection c = MtlsTestClient.connect(s.ports().pub(), s.root(), null, List.of())) {
            Response r = c.get("/api/v1/pki/intermediate-crl.pem");
            assertThat(r.status()).isEqualTo(200);
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(
                    new ByteArrayInputStream(r.body().getBytes(StandardCharsets.US_ASCII)));
        }
    }

    private static java.math.BigInteger crlNumberOf(X509CRL crl) throws Exception {
        return org.bouncycastle.asn1.x509.CRLNumber.getInstance(new X509CRLHolder(crl.getEncoded())
                .getExtension(Extension.cRLNumber).getParsedValue()).getCRLNumber();
    }

    private Connection connect(Leaf leaf) throws IOException {
        return connectTo(server, leaf);
    }

    private static Connection connectTo(Server s, Leaf leaf) throws IOException {
        return MtlsTestClient.connect(s.ports().mtls(), s.root(), leaf.keyPair().getPrivate(), leaf.chain());
    }

    private static RevocationResult revoke(Server s, Leaf leaf) {
        return s.bean(SignerRevocationService.class).revoke(leaf.key(), "KEY_COMPROMISE").block(Duration.ofSeconds(10));
    }

    private static void assertEmpty404(Response r) {
        assertThat(r.status()).isEqualTo(404);
        assertThat(r.body()).isEmpty();
    }

    private static boolean connectRefused(int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 1000);
            return false;
        } catch (ConnectException e) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static void writeResult(String name, String content) throws IOException {
        Path dir = Path.of(System.getProperty("vitalsshield.repoRoot", "..")).resolve("build/mtls-out");
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(name), content);
    }
}
