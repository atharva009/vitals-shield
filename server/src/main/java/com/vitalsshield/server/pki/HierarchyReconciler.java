package com.vitalsshield.server.pki;

import com.vitalsshield.server.kms.KmsKeyAdmin;
import com.vitalsshield.server.kms.KmsSigner;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Startup check that the KMS-backed CA hierarchy recorded in Postgres still exists in KMS (spec Section 3, "Local KMS
 * Profile"). If any of the four ACTIVE keys is missing or not Enabled, the local profile rebuilds the whole hierarchy;
 * every other profile fails closed before creating anything.
 *
 * <p>Rebuild never deletes kms_keys or ca_issuers rows: old rows are RETIRED / REVOKED so historical certificates
 * still resolve their issuer.
 */
@Component
public class HierarchyReconciler {

    private static final Logger log = LoggerFactory.getLogger(HierarchyReconciler.class);

    static final String FAIL_CLOSED_MESSAGE =
            "KMS hierarchy incomplete; refusing to regenerate CA keys outside the local profile";

    /** Keys created for a rebuild that did not commit are scheduled for deletion with the minimum window. */
    private static final int ORPHAN_DELETION_WINDOW_DAYS = 7;

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final KmsKeyAdmin keyAdmin;
    private final KmsSigner kmsSigner;
    private final CertificateProfiles profiles;
    private final CaIssuerRepository issuers;
    private final PkiProperties props;

    public HierarchyReconciler(JdbcTemplate jdbc, TransactionTemplate tx, KmsKeyAdmin keyAdmin, KmsSigner kmsSigner,
                               CertificateProfiles profiles, CaIssuerRepository issuers, PkiProperties props) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.keyAdmin = keyAdmin;
        this.kmsSigner = kmsSigner;
        this.profiles = profiles;
        this.issuers = issuers;
        this.props = props;
    }

    public ReconcileResult reconcile() {
        Map<KeyPurpose, String> active = activeKeys();
        List<String> problems = new ArrayList<>();
        for (KeyPurpose purpose : KeyPurpose.values()) {
            String arn = active.get(purpose);
            if (arn == null) {
                problems.add(purpose + ": no ACTIVE kms_keys row");
            } else if (!keyAdmin.describeEnabled(arn)) {
                problems.add(purpose + ": " + arn + " missing or not Enabled in KMS");
            }
        }
        if (problems.isEmpty()) {
            issuers.findActive(KeyPurpose.ROOT_CA).ifPresent(root -> syncTrustFile(root.certPem()));
            log.info("Hierarchy reconciliation: NO_CHANGE");
            return ReconcileResult.NO_CHANGE;
        }
        if (!props.allowHierarchyRebuild()) {
            log.error("Hierarchy check failed: {}", problems);
            throw new IllegalStateException(FAIL_CLOSED_MESSAGE);
        }
        log.warn("Hierarchy check failed, rebuilding (local profile): {}", problems);
        rebuild(active);
        log.info("Hierarchy reconciliation: REBUILT");
        return ReconcileResult.REBUILT;
    }

    private void rebuild(Map<KeyPurpose, String> observedActive) {
        Map<KeyPurpose, String> created = new EnumMap<>(KeyPurpose.class);
        boolean committed = false;
        String rootPem;
        try {
            // 1. KMS work, outside any DB transaction.
            for (KeyPurpose purpose : KeyPurpose.values()) {
                created.put(purpose, keyAdmin.createP256SigningKey("VitalsShield " + purpose));
            }
            KmsContentSigner rootSigner = signer(created.get(KeyPurpose.ROOT_CA));
            X509Certificate root = profiles.root(spki(created.get(KeyPurpose.ROOT_CA)), rootSigner);
            X509Certificate deviceInt = profiles.deviceIntermediate(
                    spki(created.get(KeyPurpose.DEVICE_INTERMEDIATE)), root, signer(created.get(KeyPurpose.ROOT_CA)));
            X509Certificate serverCa = profiles.serverTlsCa(
                    spki(created.get(KeyPurpose.SERVER_TLS_CA)), root, signer(created.get(KeyPurpose.ROOT_CA)));
            rootPem = Pems.certificate(root);

            // 2. One DB transaction for every row change.
            tx.executeWithoutResult(status -> {
                jdbc.queryForObject("SELECT pg_advisory_xact_lock(hashtext('vitalsshield.hierarchy-rebuild'))",
                        Object.class);
                if (!activeKeys().equals(observedActive)) {
                    throw new IllegalStateException("kms_keys changed concurrently during rebuild; aborting");
                }
                jdbc.update("UPDATE kms_keys SET status = 'RETIRED', retired_at = NOW() WHERE status = 'ACTIVE'");
                created.forEach((purpose, arn) -> jdbc.update(
                        "INSERT INTO kms_keys (kms_key_id, purpose, status) VALUES (?, ?::kms_key_purpose, 'ACTIVE')",
                        arn, purpose.name()));

                jdbc.update("UPDATE ca_issuers SET status = 'REVOKED' WHERE status <> 'REVOKED'");
                // Reservations under the old issuers can never be activated now (DECISIONS #38).
                jdbc.update("UPDATE issued_serials SET status = 'VOIDED', voided_at = NOW() WHERE status = 'RESERVED'");
                insertIssuer(root, created.get(KeyPurpose.ROOT_CA));
                insertIssuer(deviceInt, created.get(KeyPurpose.DEVICE_INTERMEDIATE));
                insertIssuer(serverCa, created.get(KeyPurpose.SERVER_TLS_CA));

                int revoked = jdbc.update("""
                        UPDATE certificates
                           SET status = 'REVOKED', revocation_reason = 'HIERARCHY_REBUILD', revoked_at = NOW()
                         WHERE status <> 'REVOKED'
                        """);
                // DEK anchors were signed by the old registry key, so every device must re-provision. QUARANTINED
                // and DECOMMISSIONED are clinician decisions and keep their state; their DEK is still cleared.
                int devices = jdbc.update("""
                        UPDATE devices
                           SET dek_spki_der_b64 = NULL, dek_spki_sha256 = NULL, dek_registry_kms_sig = NULL,
                               provisioned_at = NULL,
                               trust_state = CASE WHEN trust_state IN ('QUARANTINED', 'DECOMMISSIONED')
                                                  THEN trust_state ELSE 'PROVISIONED' END,
                               updated_at = NOW()
                        """);
                log.warn("Hierarchy rebuild revoked {} certificates (HIERARCHY_REBUILD) and reset {} devices",
                        revoked, devices);
            });
            committed = true;
        } finally {
            if (!committed) {
                created.values().forEach(this::scheduleOrphanDeletion);
            }
        }

        // 3. After commit: publish the new Root.
        TrustFileWriter.write(props.trustFile(), rootPem);
    }

    private void insertIssuer(X509Certificate cert, String kmsArn) {
        jdbc.update("""
                INSERT INTO ca_issuers (issuer_key_hash, subject_dn, kms_primary_arn, cert_pem, status)
                VALUES (?, ?, ?, ?, 'ACTIVE')
                """,
                CertificateProfiles.issuerKeyHash(cert),
                cert.getSubjectX500Principal().getName(),
                kmsArn,
                Pems.certificate(cert));
    }

    private Map<KeyPurpose, String> activeKeys() {
        Map<KeyPurpose, String> out = new EnumMap<>(KeyPurpose.class);
        jdbc.query("SELECT purpose::text AS purpose, kms_key_id FROM kms_keys WHERE status = 'ACTIVE'",
                rs -> {
                    out.put(KeyPurpose.valueOf(rs.getString("purpose")), rs.getString("kms_key_id"));
                });
        return out;
    }

    private void syncTrustFile(String rootPem) {
        if (!TrustFileWriter.matches(props.trustFile(), rootPem)) {
            log.info("Trust file {} missing or stale; republishing current Root", props.trustFile());
            TrustFileWriter.write(props.trustFile(), rootPem);
        }
    }

    private KmsContentSigner signer(String arn) {
        return KmsContentSigner.forKmsKey(kmsSigner, arn);
    }

    private SubjectPublicKeyInfo spki(String arn) {
        return SubjectPublicKeyInfo.getInstance(keyAdmin.publicKeySpki(arn));
    }

    private void scheduleOrphanDeletion(String arn) {
        try {
            keyAdmin.scheduleDeletion(arn, ORPHAN_DELETION_WINDOW_DAYS);
            log.warn("Scheduled deletion of uncommitted KMS key {}", arn);
        } catch (RuntimeException e) {
            log.warn("Could not schedule deletion of uncommitted KMS key {}: {}", arn, e.toString());
        }
    }
}
