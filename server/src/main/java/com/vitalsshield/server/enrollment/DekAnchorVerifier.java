package com.vitalsshield.server.enrollment;

import com.vitalsshield.crypto.DerSignatures;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import com.vitalsshield.server.kms.KmsKeyAdmin;
import com.vitalsshield.server.pki.ActiveKmsKeys;
import com.vitalsshield.server.pki.KeyPurpose;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Re-checks a device's DEK registry anchor: recomputes dekAnchorBytes from the stored columns and verifies
 * dek_registry_kms_sig with the REGISTRY_ANCHOR (KMS Key #4) public key. Detects SQL edits to dek_spki_der_b64 or
 * provisioned_at made without access to Key #4. Blocking (JDBC, KMS GetPublicKey on first use per ARN).
 */
@Component
public class DekAnchorVerifier {

    private final JdbcTemplate jdbc;
    private final ActiveKmsKeys kmsKeys;
    private final KmsKeyAdmin keyAdmin;
    private final Map<String, PublicKey> publicKeys = new ConcurrentHashMap<>();

    public DekAnchorVerifier(JdbcTemplate jdbc, ActiveKmsKeys kmsKeys, KmsKeyAdmin keyAdmin) {
        this.jdbc = jdbc;
        this.kmsKeys = kmsKeys;
        this.keyAdmin = keyAdmin;
    }

    public boolean verify(String deviceId) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT dek_spki_der_b64, dek_registry_kms_sig, provisioned_at FROM devices WHERE device_id = ?",
                deviceId);
        if (rows.isEmpty()) {
            return false;
        }
        Map<String, Object> r = rows.get(0);
        if (r.get("dek_spki_der_b64") == null || r.get("dek_registry_kms_sig") == null
                || r.get("provisioned_at") == null) {
            return false;
        }
        try {
            byte[] spki = Base64.getDecoder().decode((String) r.get("dek_spki_der_b64"));
            byte[] sig = Base64.getDecoder().decode((String) r.get("dek_registry_kms_sig"));
            long provisionedMs = ((Timestamp) r.get("provisioned_at")).toInstant().toEpochMilli();
            byte[] bytes = CanonicalEncodings.dekAnchorBytes(deviceId, spki, provisionedMs);
            String arn = kmsKeys.requireArn(KeyPurpose.REGISTRY_ANCHOR);
            PublicKey anchorKey = publicKeys.computeIfAbsent(arn,
                    a -> EcKeys.publicKeyFromSpki(keyAdmin.publicKeySpki(a)));
            // KMS signed SHA-256(bytes) with ECDSA_SHA_256, which is exactly SHA256withECDSA over bytes.
            return DerSignatures.verify(anchorKey, bytes, sig);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
