package com.vitalsshield.server.admin.webauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * {@code clinician_passkeys}. {@code credential_id_b64} holds the credential id as base64url (no padding),
 * {@code public_key_cose_der_b64} the COSE public key bytes as standard base64. The WebAuthn username is the
 * clinician id; the user handle is derived ({@link WebAuthnBytes#userHandle}). All methods block (JDBC).
 */
@Component
public class PasskeyRepository implements CredentialRepository {

    /** The dev seed tool's clinician (DECISIONS #51, #57). Not counted for the first-passkey rule (DECISIONS #64). */
    public static final String DEV_SEED_CLINICIAN = "dev-seed-clinician";

    public record Row(String credentialId, String clinicianId, byte[] cose, String anchorSig, long signCount) {
        public byte[] credentialIdBytes() {
            return WebAuthnBytes.fromB64url(credentialId);
        }
    }

    private final JdbcTemplate jdbc;

    public PasskeyRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Passkeys of real clinicians (the dev seed passkey is excluded). Zero means the setup code may register. */
    public long countClinicianPasskeys() {
        Long n = jdbc.queryForObject(
                "SELECT count(*) FROM clinician_passkeys WHERE clinician_id <> ?", Long.class, DEV_SEED_CLINICIAN);
        return n == null ? 0 : n;
    }

    public Optional<Row> find(String credentialIdB64url) {
        List<Row> rows = jdbc.query("""
                SELECT credential_id_b64, clinician_id, public_key_cose_der_b64, passkey_registry_kms_sig, sign_count
                  FROM clinician_passkeys WHERE credential_id_b64 = ?
                """, (rs, i) -> new Row(rs.getString(1), rs.getString(2), decodeCose(rs.getString(3)),
                rs.getString(4), rs.getLong(5)), credentialIdB64url);
        return rows.stream().findFirst();
    }

    public List<Row> forClinician(String clinicianId) {
        return jdbc.query("""
                SELECT credential_id_b64, clinician_id, public_key_cose_der_b64, passkey_registry_kms_sig, sign_count
                  FROM clinician_passkeys WHERE clinician_id = ?
                """, (rs, i) -> new Row(rs.getString(1), rs.getString(2), decodeCose(rs.getString(3)),
                rs.getString(4), rs.getLong(5)), clinicianId);
    }

    public void insert(String credentialIdB64url, String clinicianId, byte[] cose, String anchorSig, long signCount) {
        jdbc.update("""
                INSERT INTO clinician_passkeys (credential_id_b64, clinician_id, public_key_cose_der_b64,
                                                passkey_registry_kms_sig, sign_count)
                VALUES (?, ?, ?, ?, ?)
                """, credentialIdB64url, clinicianId, Base64.getEncoder().encodeToString(cose), anchorSig, signCount);
    }

    public void updateSignCount(String credentialIdB64url, long signCount) {
        jdbc.update("UPDATE clinician_passkeys SET sign_count = ? WHERE credential_id_b64 = ?", signCount,
                credentialIdB64url);
    }

    /** Legacy (Phase 3 to 5) fake rows hold text that is not base64; treat them as an empty key. */
    private static byte[] decodeCose(String b64) {
        try {
            return Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return new byte[0];
        }
    }

    // ---- Yubico CredentialRepository --------------------------------------------------------------------------

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        Set<PublicKeyCredentialDescriptor> out = new HashSet<>();
        for (Row r : forClinician(username)) {
            try {
                out.add(PublicKeyCredentialDescriptor.builder().id(new ByteArray(r.credentialIdBytes())).build());
            } catch (IllegalArgumentException ignored) {
                // legacy non-base64url id
            }
        }
        return out;
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return Optional.of(new ByteArray(WebAuthnBytes.userHandle(username)));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        List<String> clinicians = jdbc.queryForList("SELECT DISTINCT clinician_id FROM clinician_passkeys", String.class);
        return clinicians.stream()
                .filter(c -> Arrays.equals(WebAuthnBytes.userHandle(c), userHandle.getBytes()))
                .findFirst();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return find(credentialId.getBase64Url())
                .filter(r -> Arrays.equals(WebAuthnBytes.userHandle(r.clinicianId()), userHandle.getBytes()))
                .map(PasskeyRepository::registered);
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        Set<RegisteredCredential> out = new HashSet<>();
        find(credentialId.getBase64Url()).map(PasskeyRepository::registered).ifPresent(out::add);
        return out;
    }

    private static RegisteredCredential registered(Row r) {
        return RegisteredCredential.builder()
                .credentialId(new ByteArray(r.credentialIdBytes()))
                .userHandle(new ByteArray(WebAuthnBytes.userHandle(r.clinicianId())))
                .publicKeyCose(new ByteArray(r.cose()))
                .signatureCount(r.signCount())
                .build();
    }
}
