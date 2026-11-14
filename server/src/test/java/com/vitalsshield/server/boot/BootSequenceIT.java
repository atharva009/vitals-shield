package com.vitalsshield.server.boot;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.CaIssuer;
import com.vitalsshield.server.pki.CaIssuerRepository;
import com.vitalsshield.server.pki.CertificateProfiles;
import com.vitalsshield.server.pki.GatewayTlsMaterial;
import com.vitalsshield.server.pki.KeyPurpose;
import com.vitalsshield.server.pki.ReconcileResult;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import software.amazon.awssdk.services.kms.KmsClient;

/** The ApplicationRunner boot sequence, run for real during context startup against Postgres + LocalStack. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@Import(BootSequenceIT.StepCapture.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class BootSequenceIT {

    /** Captured before the Spring context (and therefore the boot sequence) starts. */
    static final Instant TEST_START = Instant.now().minusSeconds(1);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static Path trustDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        trustDir = Files.createTempDirectory("vs-boot-it");
        registry.add("vitalsshield.pki.trust-file", () -> trustDir.resolve("root-ca.pem").toString());
        // Phase 2: boot now binds listeners; use free ports so tests never clash with a running bootRun.
        com.vitalsshield.server.testsupport.TestPorts.register(registry);
    }

    @TestConfiguration
    static class StepCapture {
        final List<BootStep> steps = new CopyOnWriteArrayList<>();

        @Bean
        StepCaptureListener stepCaptureListener() {
            return new StepCaptureListener(steps);
        }
    }

    record StepCaptureListener(List<BootStep> steps) {
        @EventListener
        void on(BootStepCompleted event) {
            steps.add(event.step());
        }
    }

    @Autowired StepCaptureListener capture;
    @Autowired BootSequence bootSequence;
    @Autowired GatewayTlsMaterial gatewayTls;
    @Autowired CaIssuerRepository issuers;
    @Autowired JdbcTemplate jdbc;
    @Autowired KmsClient kms;

    @Test
    @Order(1)
    void stepsRunInOrder() {
        assertThat(capture.steps()).containsExactly(
                BootStep.RECONCILED, BootStep.SERIALS_SWEPT, BootStep.GATEWAY_TLS_ISSUED, BootStep.TRUST_ANCHORS_LOADED,
                BootStep.DENY_LIST_SEEDED, BootStep.CRLS_PUBLISHED, BootStep.ADMIN_CODE_ISSUED, BootStep.LISTENERS_BOUND);
    }

    @Test
    @Order(2)
    void gatewayCertIssuedByCurrentServerCa() throws Exception {
        CaIssuer oldServerCa = issuers.requireActive(KeyPurpose.SERVER_TLS_CA);
        CaIssuer deviceInt = issuers.requireActive(KeyPurpose.DEVICE_INTERMEDIATE);
        kms.scheduleKeyDeletion(r -> r.keyId(deviceInt.kmsArn()).pendingWindowInDays(7));
        capture.steps().clear();

        assertThat(bootSequence.runBoot()).isEqualTo(ReconcileResult.REBUILT);
        assertThat(capture.steps()).containsExactly(
                BootStep.RECONCILED, BootStep.SERIALS_SWEPT, BootStep.GATEWAY_TLS_ISSUED, BootStep.TRUST_ANCHORS_LOADED,
                BootStep.DENY_LIST_SEEDED, BootStep.CRLS_PUBLISHED, BootStep.ADMIN_CODE_ISSUED, BootStep.LISTENERS_BOUND);

        CaIssuer activeServerCa = issuers.requireActive(KeyPurpose.SERVER_TLS_CA);
        assertThat(activeServerCa.issuerKeyHash()).isNotEqualTo(oldServerCa.issuerKeyHash());
        assertThat(jdbc.queryForObject("SELECT status::text FROM ca_issuers WHERE issuer_key_hash = ?",
                String.class, oldServerCa.issuerKeyHash())).isEqualTo("REVOKED");

        X509Certificate leaf = gatewayTls.certificateChain().get(0);
        assertThat(java.util.HexFormat.of().formatHex(CertificateProfiles.authorityKeyIdentifier(leaf)))
                .isEqualTo(activeServerCa.issuerKeyHash())
                .isNotEqualTo(oldServerCa.issuerKeyHash());
        leaf.verify(activeServerCa.certificate().getPublicKey());
        assertThat(gatewayTls.certificateChain().get(1)).isEqualTo(activeServerCa.certificate());

        assertThat(leaf.getExtendedKeyUsage()).containsExactly("1.3.6.1.5.5.7.3.1");
        assertThat(leaf.getSubjectAlternativeNames()).containsExactlyInAnyOrder(
                List.of(2, "localhost"), List.of(7, "127.0.0.1"));
    }

    @Test
    @Order(3)
    void noPrivateKeyOnDisk() throws IOException {
        assertThat(gatewayTls.isIssued()).isTrue();
        assertThat(gatewayTls.toString()).doesNotContain("PRIVATE").doesNotContain("privateKey=");

        Path repoVar = Path.of(System.getProperty("vitalsshield.repoRoot", "..")).resolve("var");
        Path tmp = Path.of(System.getProperty("java.io.tmpdir"));
        List<Path> scanned = new ArrayList<>();
        List<Path> offenders = new ArrayList<>();
        for (Path root : List.of(repoVar, tmp)) {
            scan(root, scanned, offenders);
        }

        assertThat(scanned).as("files created during the test").contains(trustDir.resolve("root-ca.pem"));
        assertThat(offenders).as("files containing PRIVATE KEY").isEmpty();
    }

    private static void scan(Path root, List<Path> scanned, List<Path> offenders) throws IOException {
        if (!Files.isDirectory(root)) {
            return;
        }
        byte[] needle = "PRIVATE KEY".getBytes(StandardCharsets.US_ASCII);
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (!attrs.isRegularFile() || attrs.size() > 10_000_000
                        || attrs.lastModifiedTime().toInstant().isBefore(TEST_START)) {
                    return FileVisitResult.CONTINUE;
                }
                try {
                    scanned.add(file);
                    if (contains(Files.readAllBytes(file), needle)) {
                        offenders.add(file);
                    }
                } catch (IOException e) {
                    // unreadable (permissions, deleted mid-walk): skip
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
