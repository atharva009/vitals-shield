package com.vitalsshield.server.pki;

/** Signs a 32-byte SHA-256 digest and returns a DER ECDSA signature. KMS in production, a local key in unit tests. */
@FunctionalInterface
public interface DigestSigner {

    byte[] signSha256Digest(byte[] digest);
}
