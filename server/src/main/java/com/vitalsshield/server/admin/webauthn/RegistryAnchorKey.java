package com.vitalsshield.server.admin.webauthn;

import java.security.PublicKey;

/** KMS Key #4 (REGISTRY_ANCHOR): signs registry anchors and exposes its public key for verification. Blocking. */
public interface RegistryAnchorKey {

    /** ECDSA P-256 DER signature over a SHA-256 digest (KMS DIGEST mode). */
    byte[] signDigest(byte[] sha256Digest);

    PublicKey publicKey();
}
