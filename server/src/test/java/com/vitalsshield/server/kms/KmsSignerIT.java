package com.vitalsshield.server.kms;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.test.StepVerifier;

/** KmsSigner against the Compose LocalStack: MessageType.DIGEST signing, verified with JCA. */
@Tag("integration")
@ActiveProfiles("local")
@SpringBootTest(classes = {KmsConfig.class, KmsSigner.class, KmsKeyAdmin.class})
@EnableConfigurationProperties(KmsProperties.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class KmsSignerIT {

    @Autowired
    KmsSigner signer;

    @Autowired
    KmsKeyAdmin keyAdmin;

    String keyArn;
    PublicKey publicKey;

    @BeforeAll
    void createKey() throws Exception {
        keyArn = keyAdmin.createP256SigningKey("KmsSignerIT");
        publicKey = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(keyAdmin.publicKeySpki(keyArn)));
        assertThat(keyArn).startsWith("arn:aws:kms:");
        assertThat(keyAdmin.describeEnabled(keyArn)).isTrue();
    }

    @Test
    void signsSha256DigestAndVerifiesWithJca() throws Exception {
        byte[] message = "vitalsshield digest signing".getBytes(StandardCharsets.UTF_8);

        byte[] signature = signer.signDigestBlocking(keyArn, sha256(message));

        assertThat(verify(message, signature)).isTrue();
    }

    @Test
    void signsDigestOf10000ByteMessage() throws Exception {
        // RAW signing is capped at 4096 bytes; DIGEST mode only ever sends 32 bytes.
        byte[] message = new byte[10_000];
        new SecureRandom().nextBytes(message);

        byte[] signature = signer.signDigestBlocking(keyArn, sha256(message));

        assertThat(verify(message, signature)).isTrue();
    }

    @Test
    void tenParallelSignaturesOnBoundedElastic() {
        record Result(byte[] message, byte[] signature, String thread) {
        }

        Mono<java.util.List<Result>> all = Flux.range(0, 10)
                .flatMap(i -> {
                    byte[] message = ("parallel-" + i).getBytes(StandardCharsets.UTF_8);
                    return signer.signDigest(keyArn, sha256(message))
                            .map(sig -> new Result(message, sig, Thread.currentThread().getName()));
                }, 10)
                .collectList();

        StepVerifier.create(all)
                .assertNext(results -> {
                    assertThat(results).hasSize(10);
                    for (Result r : results) {
                        assertThat(verify(r.message(), r.signature())).isTrue();
                        assertThat(r.thread()).startsWith("boundedElastic");
                    }
                })
                .expectComplete()
                .verify(Duration.ofSeconds(30));
    }

    @Test
    void blockingSignIsRejectedOnNonBlockingThread() {
        Mono<byte[]> onParallel = Mono.fromCallable(() -> signer.signDigestBlocking(keyArn, sha256(new byte[] {1})))
                .subscribeOn(Schedulers.parallel());

        StepVerifier.create(onParallel)
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("non-blocking thread"))
                .verify(Duration.ofSeconds(10));
    }

    private boolean verify(byte[] message, byte[] derSignature) {
        try {
            Signature v = Signature.getInstance("SHA256withECDSA");
            v.initVerify(publicKey);
            v.update(message);
            return v.verify(derSignature);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
