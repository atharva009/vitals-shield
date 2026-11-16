package com.vitalsshield.server.admin.webauthn;

import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * Protocol A re-verification of the clinician's stored provisioning approval (spec Section 4 step 3, DECISIONS #57).
 * Runs without the WebAuthn library, from the token row alone:
 * <ol>
 *   <li>the passkey row's KMS Key #4 anchor verifies;</li>
 *   <li>clientDataJSON: type webauthn.get, challenge = base64url(ProvisioningDigest(device_id, presented token,
 *       expires_at)), origin allowed;</li>
 *   <li>authenticatorData: rpIdHash = SHA-256("localhost"), UP and UV set;</li>
 *   <li>ES256 signature over authenticatorData || SHA-256(clientDataJSON) with the stored COSE key.</li>
 * </ol>
 * Blocking (JDBC, KMS GetPublicKey on first use).
 */
@Component
public class ProvisioningAssertionVerifier {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    static final int FLAG_UP = 0x01;
    static final int FLAG_UV = 0x04;

    /** The stored approval as it sits in device_bootstrap_tokens (base64url columns). */
    public record StoredApproval(String credentialId, String authDataB64url, String clientJsonB64url,
                                 String signatureB64url, Instant expiresAt) {
    }

    private final PasskeyRepository passkeys;
    private final RegistryAnchorKey anchorKey;
    private final WebAuthnOrigins origins;

    private final DevSeedPolicy devSeed;

    public ProvisioningAssertionVerifier(PasskeyRepository passkeys, RegistryAnchorKey anchorKey,
                                         WebAuthnOrigins origins, DevSeedPolicy devSeed) {
        this.devSeed = devSeed;
        this.passkeys = passkeys;
        this.anchorKey = anchorKey;
        this.origins = origins;
    }

    /** Empty if the approval verifies; otherwise the reason (for the log; the client only sees the error code). */
    @SuppressWarnings("unchecked")
    public Optional<String> verify(String deviceId, String presentedToken, StoredApproval a) {
        try {
            PasskeyRepository.Row row = passkeys.find(a.credentialId()).orElse(null);
            if (row == null) {
                return Optional.of("unknown passkey " + a.credentialId());
            }
            if (row.devSeed() && !devSeed.allowed()) {
                return Optional.of("DEV_SEED approval outside the local profile (DECISIONS #66)");
            }
            if (!PasskeyAnchor.verify(anchorKey, row.credentialId(), row.clinicianId(), row.cose(), row.anchorSig())) {
                return Optional.of("passkey anchor does not verify");
            }
            byte[] authData = WebAuthnBytes.fromB64url(a.authDataB64url());
            byte[] clientJson = WebAuthnBytes.fromB64url(a.clientJsonB64url());
            byte[] signature = WebAuthnBytes.fromB64url(a.signatureB64url());

            Map<String, Object> client = JSON.readValue(new String(clientJson, StandardCharsets.UTF_8), Map.class);
            if (!"webauthn.get".equals(client.get("type"))) {
                return Optional.of("clientDataJSON type is not webauthn.get");
            }
            String expected = WebAuthnBytes.b64url(CanonicalEncodings.provisioningDigest(deviceId, presentedToken,
                    a.expiresAt().toEpochMilli()));
            if (!expected.equals(client.get("challenge"))) {
                return Optional.of("challenge is not the ProvisioningDigest of this token");
            }
            if (!(client.get("origin") instanceof String origin) || !origins.origins().contains(origin)) {
                return Optional.of("origin not allowed: " + client.get("origin"));
            }
            if (authData.length < 37) {
                return Optional.of("authenticatorData too short");
            }
            byte[] rpIdHash = WebAuthnBytes.sha256(origins.rpId().getBytes(StandardCharsets.UTF_8));
            if (!Arrays.equals(Arrays.copyOfRange(authData, 0, 32), rpIdHash)) {
                return Optional.of("rpIdHash is not SHA-256(\"" + origins.rpId() + "\")");
            }
            int flags = authData[32] & 0xff;
            if ((flags & FLAG_UP) == 0 || (flags & FLAG_UV) == 0) {
                return Optional.of("UP or UV flag not set (flags 0x" + Integer.toHexString(flags) + ")");
            }
            PublicKey key = CoseKeys.es256PublicKey(row.cose());
            Signature v = Signature.getInstance("SHA256withECDSA");
            v.initVerify(key);
            v.update(WebAuthnBytes.concat(authData, WebAuthnBytes.sha256(clientJson)));
            if (!v.verify(signature)) {
                return Optional.of("assertion signature does not verify");
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.of("malformed approval: " + e.getClass().getSimpleName() + " " + e.getMessage());
        }
    }
}
