package com.vitalsshield.server.pki;

import com.vitalsshield.server.kms.KmsSigner;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.ContentSigner;

/**
 * BouncyCastle {@link ContentSigner} that hashes the TBS bytes locally and signs the SHA-256 digest through
 * {@link DigestSigner} (KMS {@code MessageType.DIGEST}). Single use, like every BC ContentSigner.
 */
public final class KmsContentSigner implements ContentSigner {

    /** ecdsa-with-SHA256 (1.2.840.10045.4.3.2) with the parameters field absent, per RFC 5758 section 3.2. */
    static final AlgorithmIdentifier ECDSA_WITH_SHA256 = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);

    private final DigestSigner digestSigner;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public KmsContentSigner(DigestSigner digestSigner) {
        this.digestSigner = Objects.requireNonNull(digestSigner, "digestSigner");
    }

    public static KmsContentSigner forKmsKey(KmsSigner kmsSigner, String keyArn) {
        return new KmsContentSigner(digest -> kmsSigner.signDigestBlocking(keyArn, digest));
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return ECDSA_WITH_SHA256;
    }

    @Override
    public OutputStream getOutputStream() {
        return buffer;
    }

    @Override
    public byte[] getSignature() {
        byte[] digest = sha256().digest(buffer.toByteArray());
        buffer.reset();
        return digestSigner.signSha256Digest(digest);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
