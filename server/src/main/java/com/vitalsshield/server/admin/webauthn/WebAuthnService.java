package com.vitalsshield.server.admin.webauthn;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import com.vitalsshield.server.audit.AuditLog;
import java.io.IOException;
import org.springframework.transaction.support.TransactionTemplate;
import java.time.Clock;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Registration and assertion ceremonies on the Yubico library (DECISIONS #54). Relying party "localhost",
 * attestation "none" (DECISIONS #63), user verification and discoverable credentials required. The library's own
 * counter check is off; {@link CounterRule} applies DECISIONS #61. Every assertion verifies the credential's KMS
 * anchor first (DECISIONS #56). All methods block (JDBC, KMS): call them on boundedElastic.
 *
 * <p>Options are exchanged as JSON strings (the library's {@code toCredentials*Json} and {@code parse*ResponseJson}),
 * so no application class touches the library's Jackson 2.
 */
@Service
public class WebAuthnService {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnService.class);
    static final long TIMEOUT_MS = 120_000;

    public record Registered(String credentialId, String clinicianId) {
    }

    /** A verified assertion, with the raw signed material (stored for provisioning, hashed for audit). */
    public record VerifiedAssertion(String clinicianId, String credentialId, byte[] authenticatorData,
                                    byte[] clientDataJson, byte[] signature, long signCount) {
        public String sha256Hex() {
            return WebAuthnBytes.sha256Hex(WebAuthnBytes.concat(authenticatorData, clientDataJson, signature));
        }
    }

    private record PendingRegistration(PublicKeyCredentialCreationOptions options, String clinicianId,
                                       PasskeyRepository.Purpose purpose) {
    }

    /** What an assertion is for (DECISIONS #66): a DEV_SEED credential may only answer SEED_PROVISION, in local. */
    public enum Use { SIGN_IN, STEP_UP, PROVISION, SEED_PROVISION }

    private final RelyingParty rp;
    private final PasskeyRepository passkeys;
    private final RegistryAnchorKey anchorKey;
    private final WebAuthnOrigins origins;
    private final CeremonyStore<PendingRegistration> registrations;
    private final CeremonyStore<AssertionRequest> signIns;

    private final TransactionTemplate tx;
    private final AuditLog audit;

    private final DevSeedPolicy devSeed;

    public WebAuthnService(PasskeyRepository passkeys, RegistryAnchorKey anchorKey, WebAuthnOrigins origins,
                           TransactionTemplate tx, AuditLog audit, DevSeedPolicy devSeed, Clock clock) {
        this.devSeed = devSeed;
        this.tx = tx;
        this.audit = audit;
        this.passkeys = passkeys;
        this.anchorKey = anchorKey;
        this.origins = origins;
        this.registrations = new CeremonyStore<>(clock);
        this.signIns = new CeremonyStore<>(clock);
        this.rp = RelyingParty.builder()
                .identity(RelyingPartyIdentity.builder().id(origins.rpId()).name("VitalsShield").build())
                .credentialRepository(passkeys)
                .origins(origins.origins())
                .attestationConveyancePreference(AttestationConveyancePreference.NONE)
                .allowUntrustedAttestation(true)
                .validateSignatureCounter(false)
                .clock(clock)
                .build();
    }

    public WebAuthnOrigins origins() {
        return origins;
    }

    // ---- registration -----------------------------------------------------------------------------------------

    /** Creation options JSON ({@code {"publicKey":{...}}}) for navigator.credentials.create. A CLINICIAN passkey. */
    public String registerBegin(String clinicianId, String displayName) {
        return registerBegin(clinicianId, displayName, PasskeyRepository.Purpose.CLINICIAN);
    }

    /** The dev seed tool's registration (no HTTP route reaches this). Refused outside the local profile. */
    public String registerBeginDevSeed(String clinicianId, String displayName) {
        if (!devSeed.allowed()) {
            throw new WebAuthnFailure(403, "DEV_SEED_NOT_ALLOWED", "dev seed passkeys need the local profile");
        }
        return registerBegin(clinicianId, displayName, PasskeyRepository.Purpose.DEV_SEED);
    }

    private String registerBegin(String clinicianId, String displayName, PasskeyRepository.Purpose purpose) {
        PublicKeyCredentialCreationOptions options = rp.startRegistration(StartRegistrationOptions.builder()
                .user(UserIdentity.builder()
                        .name(clinicianId)
                        .displayName(displayName)
                        .id(new ByteArray(WebAuthnBytes.userHandle(clinicianId)))
                        .build())
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                        .residentKey(ResidentKeyRequirement.REQUIRED)
                        .userVerification(UserVerificationRequirement.REQUIRED)
                        .build())
                .timeout(TIMEOUT_MS)
                .build());
        registrations.put(options.getChallenge().getBase64Url(), new PendingRegistration(options, clinicianId, purpose));
        return json(() -> options.toCredentialsCreateJson());
    }

    /** Verifies the attestation response, signs the passkey anchor with KMS Key #4, and stores the passkey. */
    public Registered registerFinish(String credentialJson) {
        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc;
        try {
            pkc = PublicKeyCredential.parseRegistrationResponseJson(credentialJson);
        } catch (IOException | RuntimeException e) {
            throw new WebAuthnFailure(400, "MALFORMED_CREDENTIAL", e.getMessage());
        }
        PendingRegistration pending = registrations.take(pkc.getResponse().getClientData().getChallenge().getBase64Url())
                .orElseThrow(WebAuthnFailure::gone);
        RegistrationResult result;
        try {
            result = rp.finishRegistration(FinishRegistrationOptions.builder()
                    .request(pending.options()).response(pkc).build());
        } catch (RegistrationFailedException e) {
            log.info("Passkey registration rejected for {}: {}", pending.clinicianId(), e.getMessage());
            throw new WebAuthnFailure(401, "REGISTRATION_REJECTED", e.getMessage());
        }
        byte[] cose = result.getPublicKeyCose().getBytes();
        CoseKeys.es256PublicKey(cose); // only ES256 passkeys are stored (Protocol A re-verifies with them)
        String credentialId = result.getKeyId().getId().getBase64Url();
        String anchor = PasskeyAnchor.sign(anchorKey, credentialId, pending.clinicianId(), cose);
        tx.executeWithoutResult(s -> {
            passkeys.insert(credentialId, pending.clinicianId(), cose, anchor, result.getSignatureCount(),
                    pending.purpose());
            audit.append("PASSKEY_REGISTERED", pending.clinicianId(), java.util.Map.of("credential_id", credentialId,
                    "cose_key_sha256", WebAuthnBytes.sha256Hex(cose),
                    "attestation_object_sha256",
                    WebAuthnBytes.sha256Hex(pkc.getResponse().getAttestationObject().getBytes())));
        });
        log.info("Passkey registered for {} (credential {}..., anchor signed with KMS Key #4)", pending.clinicianId(),
                credentialId.substring(0, Math.min(8, credentialId.length())));
        return new Registered(credentialId, pending.clinicianId());
    }

    // ---- assertions -------------------------------------------------------------------------------------------

    /** Usernameless sign-in: empty allowCredentials, user verification required. */
    public String signInBegin() {
        AssertionRequest request = rp.startAssertion(StartAssertionOptions.builder()
                .userVerification(UserVerificationRequirement.REQUIRED)
                .timeout(TIMEOUT_MS)
                .build());
        signIns.put(request.getPublicKeyCredentialRequestOptions().getChallenge().getBase64Url(), request);
        return json(request::toCredentialsGetJson);
    }

    public VerifiedAssertion signInFinish(String credentialJson) {
        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc = parseAssertion(credentialJson);
        AssertionRequest request = signIns.take(pkc.getResponse().getClientData().getChallenge().getBase64Url())
                .orElseThrow(WebAuthnFailure::gone);
        return finishAssertion(request, pkc, Use.SIGN_IN);
    }

    /**
     * An assertion request with a caller-chosen 32-byte challenge (an action digest or the ProvisioningDigest),
     * restricted to one credential of one clinician. The caller keeps the request in its own ceremony store.
     */
    public AssertionRequest boundAssertion(byte[] challenge, String credentialId, String clinicianId) {
        return AssertionRequest.builder()
                .publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions.builder()
                        .challenge(new ByteArray(challenge))
                        .rpId(origins.rpId())
                        .allowCredentials(List.of(PublicKeyCredentialDescriptor.builder()
                                .id(new ByteArray(WebAuthnBytes.fromB64url(credentialId))).build()))
                        .userVerification(UserVerificationRequirement.REQUIRED)
                        .timeout(TIMEOUT_MS)
                        .build())
                .username(clinicianId)
                .build();
    }

    public static String requestJson(AssertionRequest request) {
        return json(request::toCredentialsGetJson);
    }

    public PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> parseAssertion(String json) {
        try {
            return PublicKeyCredential.parseAssertionResponseJson(json);
        } catch (IOException | RuntimeException e) {
            throw new WebAuthnFailure(400, "MALFORMED_CREDENTIAL", e.getMessage());
        }
    }

    /**
     * Anchor first (an SQL-swapped key fails here, before its signature is even checked), then the library's checks
     * (challenge, origin, rpIdHash, UP, UV, signature, allowCredentials), then the counter rule.
     */
    public VerifiedAssertion finishAssertion(AssertionRequest request,
                                             PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc,
                                             Use use) {
        String credentialId = pkc.getId().getBase64Url();
        PasskeyRepository.Row row = passkeys.find(credentialId)
                .orElseThrow(() -> new WebAuthnFailure(401, "UNKNOWN_CREDENTIAL", credentialId));
        // DECISIONS #66: checked before anything else, so a refused DEV_SEED assertion changes nothing (not even
        // sign_count).
        if (row.devSeed() && !(use == Use.SEED_PROVISION && devSeed.allowed())) {
            log.warn("DEV_SEED credential {} refused for {} (local profile: {})", credentialId, use, devSeed.allowed());
            throw new WebAuthnFailure(403, "DEV_SEED_NOT_ALLOWED", use.name());
        }
        if (!PasskeyAnchor.verify(anchorKey, row.credentialId(), row.clinicianId(), row.cose(), row.anchorSig())) {
            log.error("Passkey anchor INVALID for credential {} (clinician {}): row changed without KMS Key #4",
                    credentialId, row.clinicianId());
            throw new WebAuthnFailure(401, "PASSKEY_ANCHOR_INVALID", credentialId);
        }
        AssertionResult result;
        try {
            result = rp.finishAssertion(FinishAssertionOptions.builder().request(request).response(pkc).build());
        } catch (AssertionFailedException | RuntimeException e) {
            log.info("Assertion rejected for credential {}: {}", credentialId, e.getMessage());
            throw new WebAuthnFailure(401, "ASSERTION_REJECTED", e.getMessage());
        }
        if (!result.isSuccess()) {
            throw new WebAuthnFailure(401, "ASSERTION_REJECTED", "not successful");
        }
        long presented = result.getSignatureCount();
        if (!CounterRule.accept(row.signCount(), presented)) {
            log.warn("Signature counter regression for credential {} (clinician {}): stored {}, presented {}",
                    credentialId, row.clinicianId(), row.signCount(), presented);
            throw new WebAuthnFailure(401, "COUNTER_REGRESSION", "stored " + row.signCount() + ", got " + presented);
        }
        passkeys.updateSignCount(credentialId, CounterRule.next(row.signCount(), presented));
        AuthenticatorAssertionResponse r = pkc.getResponse();
        return new VerifiedAssertion(row.clinicianId(), credentialId, r.getAuthenticatorData().getBytes(),
                r.getClientDataJSON().getBytes(), r.getSignature().getBytes(), presented);
    }

    private interface JsonSupplier {
        String get() throws IOException;
    }

    private static String json(JsonSupplier s) {
        try {
            return s.get();
        } catch (IOException e) {
            throw new IllegalStateException("cannot serialize WebAuthn options", e);
        }
    }
}
