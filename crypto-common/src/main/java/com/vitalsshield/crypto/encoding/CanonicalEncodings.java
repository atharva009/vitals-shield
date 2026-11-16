package com.vitalsshield.crypto.encoding;

import com.vitalsshield.crypto.CanonicalBytes;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * The signed byte layouts from spec Section 3 ("Canonical Binary Encodings") and Section 4 Protocol C step 2.
 * Every layout is built only through {@link CanonicalBytes}. Golden vectors: {@code scripts/golden_vectors.py}.
 */
public final class CanonicalEncodings {

    /** Raw challenge nonces are written without a length prefix, so their width is fixed. */
    public static final int NONCE_LENGTH = 16;

    private CanonicalEncodings() {
    }

    /** 1. {@code uint32_be(len(cred_id)) || utf8(cred_id) || uint32_be(len(clinician_id)) || utf8(clinician_id) || sha256(cose_pub_key_der)} */
    public static byte[] passkeyAnchorBytes(String credId, String clinicianId, byte[] coseKeyDer) {
        return new CanonicalBytes()
                .utf8WithLength(credId)
                .utf8WithLength(clinicianId)
                .sha256(coseKeyDer)
                .toByteArray();
    }

    /** 2. {@code SHA256(uint32_be(len(device_id)) || utf8(device_id) || sha256(bootstrap_token_ascii) || int64_be(expires_at_epoch_ms))}; returns the 32-byte digest. */
    public static byte[] provisioningDigest(String deviceId, String bootstrapTokenAscii, long expiresAtEpochMs) {
        byte[] preimage = new CanonicalBytes()
                .utf8WithLength(deviceId)
                .sha256(ascii(bootstrapTokenAscii))
                .int64Be(expiresAtEpochMs)
                .toByteArray();
        return new CanonicalBytes().sha256(preimage).toByteArray();
    }

    /** 3. {@code uint32_be(len(device_id)) || utf8(device_id) || sha256(bootstrap_token_ascii) || sha256(olk_csr_der)} */
    public static byte[] dekEnrollmentProofBytes(String deviceId, String bootstrapTokenAscii, byte[] olkCsrDer) {
        return new CanonicalBytes()
                .utf8WithLength(deviceId)
                .sha256(ascii(bootstrapTokenAscii))
                .sha256(olkCsrDer)
                .toByteArray();
    }

    /** 4. {@code uint32_be(len(device_id)) || utf8(device_id) || sha256(dek_spki_der) || int64_be(provisioned_at_epoch_ms)} */
    public static byte[] dekAnchorBytes(String deviceId, byte[] dekSpkiDer, long provisionedAtEpochMs) {
        return new CanonicalBytes()
                .utf8WithLength(deviceId)
                .sha256(dekSpkiDer)
                .int64Be(provisionedAtEpochMs)
                .toByteArray();
    }

    /**
     * 5. {@code uint32_be(len(issuer_key_hash)) || utf8(issuer_key_hash) || uint32_be(len(serial_number)) || utf8(serial_number)
     * || int64_be(issued_at_ms) || random_nonce (16B) || sha256(olk_new_csr_der)}
     *
     * @throws IllegalArgumentException if {@code nonce16} is not exactly 16 bytes
     */
    public static byte[] olkRenewalProofBytes(
            String issuerKeyHash, String serialNumber, long issuedAtMs, byte[] nonce16, byte[] olkNewCsrDer) {
        return new CanonicalBytes()
                .utf8WithLength(issuerKeyHash)
                .utf8WithLength(serialNumber)
                .int64Be(issuedAtMs)
                .raw(requireNonce(nonce16))
                .sha256(olkNewCsrDer)
                .toByteArray();
    }

    /**
     * Protocol C step 2: {@code uint32_be(len(device_id)) || utf8(device_id) || int64_be(issued_at_ms) || random_nonce
     * || int64_be(boot_epoch) || sha256(olk_csr_der)}.
     *
     * <p>The spec does not state the nonce width here; it is the same 16-byte HMAC challenge nonce as Protocol B, and
     * because it carries no length prefix it must be fixed-width, so 16 bytes is enforced.
     *
     * @throws IllegalArgumentException if {@code nonce} is not exactly 16 bytes
     */
    public static byte[] reEnrollProofBytes(
            String deviceId, long issuedAtMs, byte[] nonce, long bootEpoch, byte[] olkCsrDer) {
        return new CanonicalBytes()
                .utf8WithLength(deviceId)
                .int64Be(issuedAtMs)
                .raw(requireNonce(nonce))
                .int64Be(bootEpoch)
                .sha256(olkCsrDer)
                .toByteArray();
    }

    /**
     * Step-up approval for quarantine (DECISIONS #58): {@code SHA256(utf8WithLength("vitalsshield.quarantine.v1") ||
     * utf8WithLength(device_id) || uint32_be(lookback_minutes) || utf8WithLength(reason) || raw(nonce16))}; the 32-byte
     * digest is the WebAuthn challenge.
     */
    public static byte[] quarantineApprovalDigest(String deviceId, int lookbackMinutes, String reason, byte[] nonce16) {
        byte[] preimage = new CanonicalBytes()
                .utf8WithLength("vitalsshield.quarantine.v1")
                .utf8WithLength(deviceId)
                .uint32Be(lookbackMinutes)
                .utf8WithLength(reason)
                .raw(requireNonce(nonce16))
                .toByteArray();
        return new CanonicalBytes().sha256(preimage).toByteArray();
    }

    /**
     * Step-up approval for restore-active (DECISIONS #58): {@code SHA256(utf8WithLength("vitalsshield.restore-active.v1")
     * || utf8WithLength(device_id) || raw(nonce16))}.
     */
    public static byte[] restoreApprovalDigest(String deviceId, byte[] nonce16) {
        byte[] preimage = new CanonicalBytes()
                .utf8WithLength("vitalsshield.restore-active.v1")
                .utf8WithLength(deviceId)
                .raw(requireNonce(nonce16))
                .toByteArray();
        return new CanonicalBytes().sha256(preimage).toByteArray();
    }

    private static byte[] requireNonce(byte[] nonce) {
        Objects.requireNonNull(nonce, "nonce");
        if (nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException(
                    "nonce must be exactly " + NONCE_LENGTH + " bytes, got " + nonce.length);
        }
        return nonce;
    }

    private static byte[] ascii(String value) {
        Objects.requireNonNull(value, "bootstrapTokenAscii");
        if (!StandardCharsets.US_ASCII.newEncoder().canEncode(value)) {
            throw new IllegalArgumentException("bootstrap token must be ASCII");
        }
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
