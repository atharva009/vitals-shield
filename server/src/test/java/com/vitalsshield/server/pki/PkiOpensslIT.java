package com.vitalsshield.server.pki;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Cross-checks the KMS-built hierarchy, leaves and CRLs with OpenSSL (-x509_strict). BootSequence runs during context
 * startup. PEMs are left in {repo}/build/pki-out/ for manual inspection.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PkiOpensslIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-openssl-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        // Phase 2: boot now binds listeners; use free ports so tests never clash with a running bootRun.
        com.vitalsshield.server.testsupport.TestPorts.register(registry);
    }

    @Autowired CertificateIssuer issuer;
    @Autowired CaIssuerRepository issuers;
    @Autowired GatewayTlsMaterial gatewayTls;
    @Autowired CrlService crls;
    @Autowired JdbcTemplate jdbc;

    String openssl;
    Path out;

    @BeforeAll
    void materialize() throws Exception {
        openssl = findOpenssl();
        Assumptions.assumeTrue(openssl != null,
                "OpenSSL 3 not found: set OPENSSL_BIN or `brew install openssl@3`; skipping PkiOpensslIT");

        out = Path.of(System.getProperty("vitalsshield.repoRoot", "..")).resolve("build/pki-out");
        Files.createDirectories(out);

        CaIssuer root = issuers.requireActive(KeyPurpose.ROOT_CA);
        CaIssuer deviceInt = issuers.requireActive(KeyPurpose.DEVICE_INTERMEDIATE);
        CaIssuer serverCa = issuers.requireActive(KeyPurpose.SERVER_TLS_CA);
        write("root.pem", root.certPem());
        write("device-int.pem", deviceInt.certPem());
        write("device-int-chain.pem", deviceInt.certPem() + root.certPem());
        write("server-ca.pem", serverCa.certPem());
        write("gateway-leaf.pem", Pems.certificate(gatewayTls.certificateChain().get(0)));

        X509Certificate leaf = issuer.issueDeviceLeaf("dev_wearable_019", localSpki(), Duration.ofHours(12), new com.vitalsshield.server.pki.SerialAllocator().next());
        write("device-leaf.pem", Pems.certificate(leaf));
        write("intermediate-crl.pem", crls.publishIntermediateCrl().pem());
        write("root-crl.pem", crls.publishRootCrl().pem());
    }

    @Test
    @Order(1)
    void deviceLeafVerifiesForClientAuthOnly() throws Exception {
        assertThat(run("verify", "-x509_strict", "-purpose", "sslclient", "-CAfile", "root.pem",
                "-untrusted", "device-int.pem", "device-leaf.pem").exit()).isZero();
        assertThat(run("verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", "root.pem",
                "-untrusted", "device-int.pem", "device-leaf.pem").exit()).isNotZero();
    }

    @Test
    @Order(2)
    void gatewayLeafVerifiesForServerAuthOnly() throws Exception {
        assertThat(run("verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", "root.pem",
                "-untrusted", "server-ca.pem", "gateway-leaf.pem").exit()).isZero();
        assertThat(run("verify", "-x509_strict", "-purpose", "sslclient", "-CAfile", "root.pem",
                "-untrusted", "server-ca.pem", "gateway-leaf.pem").exit()).isNotZero();
    }

    @Test
    @Order(3)
    void crlsVerify() throws Exception {
        Result intermediate = run("crl", "-in", "intermediate-crl.pem", "-CAfile", "device-int-chain.pem",
                "-noout", "-verify");
        assertThat(intermediate.exit()).isZero();
        assertThat(intermediate.output()).contains("verify OK");

        Result root = run("crl", "-in", "root-crl.pem", "-CAfile", "root.pem", "-noout", "-verify");
        assertThat(root.exit()).isZero();
        assertThat(root.output()).contains("verify OK");
    }

    @Test
    @Order(4)
    void revokedLeafAppearsOnIntermediateCrl() throws Exception {
        BigInteger before = crlNumber(Files.readString(out.resolve("intermediate-crl.pem")));
        CaIssuer deviceInt = issuers.requireActive(KeyPurpose.DEVICE_INTERMEDIATE);

        X509Certificate leaf = issuer.issueDeviceLeaf("dev_revoked_01", localSpki(), Duration.ofHours(12), new com.vitalsshield.server.pki.SerialAllocator().next());
        BigInteger serial = leaf.getSerialNumber();
        jdbc.update("INSERT INTO devices (device_id, hardware_model) VALUES ('dev_revoked_01', 'sim-v1')");
        jdbc.update("""
                INSERT INTO certificates (issuer_key_hash, serial_number, device_id, cert_thumbprint_s256, cert_pem,
                                          not_before, not_after, status, revocation_reason, revoked_at)
                VALUES (?, ?, 'dev_revoked_01', 'thumb', ?, ?, ?, 'REVOKED', 'KEY_COMPROMISE', ?)
                """, deviceInt.issuerKeyHash(), SerialNumbers.toHex(serial), Pems.certificate(leaf),
                Timestamp.from(leaf.getNotBefore().toInstant()), Timestamp.from(leaf.getNotAfter().toInstant()),
                Timestamp.from(Instant.now()));

        String crlPem = crls.publishIntermediateCrl().pem();
        write("intermediate-crl.pem", crlPem);

        X509CRLHolder crl = parseCrl(crlPem);
        assertThat(crlNumber(crlPem)).isEqualTo(before.add(BigInteger.ONE));
        X509CRLEntryHolder entry = crl.getRevokedCertificate(serial);
        assertThat(entry).as("serial %s on CRL", serial.toString(16)).isNotNull();
        assertThat(ASN1Enumerated.getInstance(entry.getExtensions().getExtensionParsedValue(Extension.reasonCode))
                .intValueExact()).isEqualTo(CRLReason.keyCompromise);

        Result text = run("crl", "-in", "intermediate-crl.pem", "-noout", "-text");
        assertThat(text.exit()).isZero();
        assertThat(serialsIn(text.output())).contains(serial);
        assertThat(text.output()).contains("Key Compromise");

        Result verify = run("crl", "-in", "intermediate-crl.pem", "-CAfile", "device-int-chain.pem",
                "-noout", "-verify");
        assertThat(verify.output()).contains("verify OK");
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    record Result(int exit, String output) {
    }

    private Result run(String... args) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(openssl);
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).directory(out.toFile()).redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(p.waitFor(30, TimeUnit.SECONDS)).isTrue();
        return new Result(p.exitValue(), output);
    }

    private void write(String name, String content) throws IOException {
        Files.writeString(out.resolve(name), content, StandardCharsets.US_ASCII);
    }

    private static String findOpenssl() {
        String env = System.getenv("OPENSSL_BIN");
        if (env != null && !env.isBlank()) {
            return Files.isExecutable(Path.of(env)) ? env : null;
        }
        try {
            Process p = new ProcessBuilder("brew", "--prefix", "openssl@3").redirectErrorStream(true).start();
            String prefix = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0) {
                Path bin = Path.of(prefix, "bin", "openssl");
                return Files.isExecutable(bin) ? bin.toString() : null;
            }
        } catch (IOException | InterruptedException e) {
            // brew not installed
        }
        return null;
    }

    private static X509CRLHolder parseCrl(String pem) throws IOException {
        try (PEMParser parser = new PEMParser(new java.io.InputStreamReader(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)), StandardCharsets.US_ASCII))) {
            return (X509CRLHolder) parser.readObject();
        }
    }

    private static BigInteger crlNumber(String pem) throws IOException {
        return CRLNumber.getInstance(parseCrl(pem).getExtension(Extension.cRLNumber).getParsedValue()).getCRLNumber();
    }

    private static List<BigInteger> serialsIn(String opensslText) {
        Matcher m = Pattern.compile("Serial Number:\\s*([0-9A-Fa-f]+)").matcher(opensslText);
        List<BigInteger> out = new ArrayList<>();
        while (m.find()) {
            out.add(new BigInteger(m.group(1), 16));
        }
        return out;
    }

    private static SubjectPublicKeyInfo localSpki() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return SubjectPublicKeyInfo.getInstance(gen.generateKeyPair().getPublic().getEncoded());
    }
}
