package com.vitalsshield.server.kms;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * Signs precomputed SHA-256 digests with a KMS {@code ECC_NIST_P256} key ({@code MessageType.DIGEST}), so the
 * 4096-byte RAW message limit never applies. Output is a DER {@code ECDSA-Sig-Value}.
 */
@Component
public class KmsSigner {

    static final int SHA256_LENGTH = 32;

    private final KmsClient kms;
    private final AtomicLong signCount = new AtomicLong();

    public KmsSigner(KmsClient kms) {
        this.kms = kms;
    }

    /**
     * Blocking KMS Sign call. Call only from {@code boundedElastic} or the boot runner thread; calling from a
     * non-blocking (event loop / parallel) thread is rejected.
     */
    public byte[] signDigestBlocking(String keyArn, byte[] sha256Digest) {
        Objects.requireNonNull(keyArn, "keyArn");
        Objects.requireNonNull(sha256Digest, "sha256Digest");
        if (sha256Digest.length != SHA256_LENGTH) {
            throw new IllegalArgumentException("expected a 32-byte SHA-256 digest, got " + sha256Digest.length);
        }
        if (Schedulers.isInNonBlockingThread()) {
            throw new IllegalStateException("KMS Sign is blocking and must not run on non-blocking thread "
                    + Thread.currentThread().getName() + "; use signDigest(...)");
        }
        signCount.incrementAndGet();
        return kms.sign(r -> r.keyId(keyArn)
                        .message(SdkBytes.fromByteArray(sha256Digest))
                        .messageType(MessageType.DIGEST)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256))
                .signature()
                .asByteArray();
    }

    /** Number of KMS Sign calls made by this signer (tests and metrics). */
    public long signCount() {
        return signCount.get();
    }

    /** Reactive variant: the blocking call is shifted onto {@code boundedElastic}. */
    public Mono<byte[]> signDigest(String keyArn, byte[] sha256Digest) {
        return Mono.fromCallable(() -> signDigestBlocking(keyArn, sha256Digest))
                .subscribeOn(Schedulers.boundedElastic());
    }
}
