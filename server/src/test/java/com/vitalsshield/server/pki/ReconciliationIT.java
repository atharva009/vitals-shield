package com.vitalsshield.server.pki;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vitalsshield.server.kms.KmsKeyAdmin;
import com.vitalsshield.server.kms.KmsSigner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
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

/**
 * HierarchyReconciler against a fresh Testcontainers Postgres and the Compose LocalStack. BootSequence is disabled so
 * each test drives reconcile() itself. Ordered: each test builds on the hierarchy left by the previous one.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest(properties = "vitalsshield.boot.enabled=false")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ReconciliationIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static Path trustFile;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws Exception {
        trustFile = Files.createTempDirectory("vs-reconcile-it").resolve("trust/root-ca.pem");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
    }

    @Autowired HierarchyReconciler reconciler;
    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired KmsClient kms;
    @Autowired KmsKeyAdmin keyAdmin;
    @Autowired KmsSigner kmsSigner;
    @Autowired CertificateProfiles profiles;
    @Autowired CaIssuerRepository issuers;
    @Autowired CertificateIssuer certificateIssuer;
    @Autowired PkiProperties props;

    @Test
    @Order(1)
    void firstBootBuildsHierarchy() throws Exception {
        assertThat(count("kms_keys")).isZero();

        assertThat(reconciler.reconcile()).isEqualTo(ReconcileResult.REBUILT);

        List<String> purposes = jdbc.queryForList(
                "SELECT purpose::text FROM kms_keys WHERE status = 'ACTIVE'", String.class);
        assertThat(purposes).containsExactlyInAnyOrder(
                "ROOT_CA", "DEVICE_INTERMEDIATE", "SERVER_TLS_CA", "REGISTRY_ANCHOR");
        assertThat(jdbc.queryForList("SELECT kms_key_id FROM kms_keys", String.class))
                .allMatch(arn -> arn.startsWith("arn:aws:kms:"));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ca_issuers WHERE status = 'ACTIVE'", Integer.class))
                .isEqualTo(3);

        assertThat(trustFile).exists();
        assertThat(Files.readString(trustFile)).isEqualTo(issuers.requireActive(KeyPurpose.ROOT_CA).certPem());
    }

    @Test
    @Order(2)
    void secondBootIsNoOp() {
        int keys = count("kms_keys");
        int cas = count("ca_issuers");

        assertThat(reconciler.reconcile()).isEqualTo(ReconcileResult.NO_CHANGE);

        assertThat(count("kms_keys")).isEqualTo(keys);
        assertThat(count("ca_issuers")).isEqualTo(cas);
    }

    @Test
    @Order(3)
    void pendingDeletionKeyTriggersFullRebuild() throws Exception {
        Map<String, String> oldKeys = activeKeysByPurpose();
        List<String> oldIssuerHashes = jdbc.queryForList(
                "SELECT issuer_key_hash FROM ca_issuers WHERE status = 'ACTIVE'", String.class);
        String oldRootPem = Files.readString(trustFile);
        CaIssuer oldDeviceInt = issuers.requireActive(KeyPurpose.DEVICE_INTERMEDIATE);

        jdbc.update("""
                INSERT INTO devices (device_id, hardware_model, dek_spki_der_b64, dek_spki_sha256,
                                     dek_registry_kms_sig, provisioned_at, trust_state)
                VALUES ('dev_reconcile_01', 'sim-v1', 'AAAA', ?, 'c2ln', NOW(), 'ACTIVE')
                """, "b".repeat(64));
        X509Certificate leaf = certificateIssuer.issueDeviceLeaf("dev_reconcile_01", localSpki(), Duration.ofHours(12));
        String serial = SerialNumbers.toHex(leaf.getSerialNumber());
        jdbc.update("""
                INSERT INTO certificates (issuer_key_hash, serial_number, device_id, cert_thumbprint_s256, cert_pem,
                                          not_before, not_after, status)
                VALUES (?, ?, 'dev_reconcile_01', ?, ?, ?, ?, 'ACTIVE')
                """, oldDeviceInt.issuerKeyHash(), serial, sha256Hex(leaf.getEncoded()), Pems.certificate(leaf),
                Timestamp.from(leaf.getNotBefore().toInstant()), Timestamp.from(leaf.getNotAfter().toInstant()));

        kms.scheduleKeyDeletion(r -> r.keyId(oldKeys.get("REGISTRY_ANCHOR")).pendingWindowInDays(7));

        assertThat(reconciler.reconcile()).isEqualTo(ReconcileResult.REBUILT);

        // Old four RETIRED (with retired_at), four new ACTIVE.
        for (String arn : oldKeys.values()) {
            assertThat(jdbc.queryForMap("SELECT status::text AS status, retired_at FROM kms_keys WHERE kms_key_id = ?", arn))
                    .containsEntry("status", "RETIRED")
                    .extractingByKey("retired_at").isNotNull();
        }
        Map<String, String> newKeys = activeKeysByPurpose();
        assertThat(newKeys).hasSize(4);
        assertThat(newKeys.values()).doesNotContainAnyElementsOf(oldKeys.values());

        // Old three ca_issuers REVOKED and still present.
        for (String hash : oldIssuerHashes) {
            assertThat(jdbc.queryForObject("SELECT status::text FROM ca_issuers WHERE issuer_key_hash = ?",
                    String.class, hash)).isEqualTo("REVOKED");
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ca_issuers WHERE status = 'ACTIVE'", Integer.class))
                .isEqualTo(3);

        // Seeded certificate revoked; its issuer still resolves.
        Map<String, Object> cert = jdbc.queryForMap("""
                SELECT c.status::text AS status, c.revocation_reason, c.revoked_at, ci.issuer_key_hash AS issuer
                  FROM certificates c JOIN ca_issuers ci ON ci.issuer_key_hash = c.issuer_key_hash
                 WHERE c.serial_number = ?
                """, serial);
        assertThat(cert).containsEntry("status", "REVOKED")
                .containsEntry("revocation_reason", "HIERARCHY_REBUILD")
                .containsEntry("issuer", oldDeviceInt.issuerKeyHash());
        assertThat(cert.get("revoked_at")).isNotNull();

        // Device back to PROVISIONED with its DEK anchor cleared.
        Map<String, Object> device = jdbc.queryForMap("SELECT * FROM devices WHERE device_id = 'dev_reconcile_01'");
        assertThat(device.get("trust_state")).hasToString("PROVISIONED");
        assertThat(device).containsEntry("dek_spki_der_b64", null)
                .containsEntry("dek_spki_sha256", null)
                .containsEntry("dek_registry_kms_sig", null)
                .containsEntry("provisioned_at", null);

        // Trust file now holds the new Root.
        String newRootPem = Files.readString(trustFile);
        assertThat(newRootPem).isEqualTo(issuers.requireActive(KeyPurpose.ROOT_CA).certPem());
        assertThat(newRootPem).isNotEqualTo(oldRootPem);
    }

    @Test
    @Order(4)
    void prodProfileFailsClosed() {
        PkiProperties prodProps = new PkiProperties(props.publicBaseUrl(), false, props.trustFile(),
                props.deviceLeafTtl(), props.gatewayLeafTtl());
        HierarchyReconciler prod = new HierarchyReconciler(
                jdbc, tx, keyAdmin, kmsSigner, profiles, issuers, prodProps);
        kms.scheduleKeyDeletion(r -> r.keyId(activeKeysByPurpose().get("ROOT_CA")).pendingWindowInDays(7));

        int kmsRows = count("kms_keys");
        long kmsKeys = listKeysCount();

        assertThatThrownBy(prod::reconcile)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("KMS hierarchy incomplete; refusing to regenerate CA keys outside the local profile");

        assertThat(count("kms_keys")).isEqualTo(kmsRows);
        assertThat(listKeysCount()).isEqualTo(kmsKeys);
    }

    private Map<String, String> activeKeysByPurpose() {
        Map<String, String> out = new java.util.HashMap<>();
        jdbc.query("SELECT purpose::text AS purpose, kms_key_id FROM kms_keys WHERE status = 'ACTIVE'",
                rs -> {
                    out.put(rs.getString("purpose"), rs.getString("kms_key_id"));
                });
        return out;
    }

    private long listKeysCount() {
        return kms.listKeysPaginator(r -> r.limit(1000)).keys().stream().count();
    }

    private int count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM " + table, Integer.class);
    }

    private static SubjectPublicKeyInfo localSpki() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return SubjectPublicKeyInfo.getInstance(gen.generateKeyPair().getPublic().getEncoded());
    }

    private static String sha256Hex(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }
}
