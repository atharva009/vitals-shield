package com.vitalsshield.server.admin.webauthn;

import com.vitalsshield.crypto.DerSignatures;
import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import java.util.Base64;

/**
 * Passkey registry anchor (spec Section 3 encoding 1, DECISIONS #56): KMS Key #4 signs
 * {@code PasskeyAnchorBytes(cred_id, clinician_id, cose_pub_key)}. Without Key #4, an SQL edit to a passkey row (a
 * swapped public key or clinician) cannot produce a matching signature.
 */
public final class PasskeyAnchor {

    private PasskeyAnchor() {
    }

    /** Base64 DER signature for {@code passkey_registry_kms_sig}. Calls KMS Sign (blocking). */
    public static String sign(RegistryAnchorKey key, String credentialIdB64url, String clinicianId, byte[] cose) {
        byte[] bytes = CanonicalEncodings.passkeyAnchorBytes(credentialIdB64url, clinicianId, cose);
        return Base64.getEncoder().encodeToString(key.signDigest(WebAuthnBytes.sha256(bytes)));
    }

    /** KMS signed SHA-256(bytes) with ECDSA_SHA_256, which is exactly SHA256withECDSA over the bytes. */
    public static boolean verify(RegistryAnchorKey key, String credentialIdB64url, String clinicianId, byte[] cose,
                                 String signatureB64) {
        try {
            byte[] bytes = CanonicalEncodings.passkeyAnchorBytes(credentialIdB64url, clinicianId, cose);
            return DerSignatures.verify(key.publicKey(), bytes, Base64.getDecoder().decode(signatureB64));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
