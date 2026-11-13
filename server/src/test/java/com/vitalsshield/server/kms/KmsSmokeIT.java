package com.vitalsshield.server.kms;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/** Talks to the Compose LocalStack on :4566 through the real {@link KmsAsyncClient} bean. */
@Tag("integration")
@ActiveProfiles("local")
@SpringBootTest(classes = KmsConfig.class)
@EnableConfigurationProperties(KmsProperties.class)
class KmsSmokeIT {

    private static final byte[] MESSAGE = "vitalsshield-kms-smoke".getBytes(StandardCharsets.UTF_8);

    @Autowired
    KmsAsyncClient kms;

    @Test
    void createSignVerify() throws Exception {
        String keyId = createKey();
        byte[] signature = sign(keyId);

        byte[] spkiDer = kms.getPublicKey(r -> r.keyId(keyId)).join().publicKey().asByteArray();
        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spkiDer));

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(MESSAGE);
        assertThat(verifier.verify(signature)).isTrue();
    }

    @Test
    void signatureIsDer() throws Exception {
        byte[] signature = sign(createKey());

        ASN1Primitive parsed = ASN1Primitive.fromByteArray(signature);
        assertThat(parsed).isInstanceOf(ASN1Sequence.class);
        ASN1Sequence seq = (ASN1Sequence) parsed;
        assertThat(seq.size()).isEqualTo(2);
        assertThat(seq.getObjectAt(0)).isInstanceOf(ASN1Integer.class);
        assertThat(seq.getObjectAt(1)).isInstanceOf(ASN1Integer.class);
        // Strict DER: re-encoding yields the identical bytes (rules out BER and trailing data).
        assertThat(seq.getEncoded(ASN1Encoding.DER)).containsExactly(signature);
    }

    private String createKey() {
        return kms.createKey(r -> r.keySpec(KeySpec.ECC_NIST_P256).keyUsage(KeyUsageType.SIGN_VERIFY))
                .join().keyMetadata().keyId();
    }

    private byte[] sign(String keyId) {
        return kms.sign(r -> r.keyId(keyId)
                        .message(SdkBytes.fromByteArray(MESSAGE))
                        .messageType(MessageType.RAW)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256))
                .join().signature().asByteArray();
    }
}
