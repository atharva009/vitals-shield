package com.vitalsshield.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.Test;

class EcKeysTest {

    @Test
    void pemRoundTrip() {
        KeyPair kp = EcKeys.generateP256();
        String pem = EcKeys.toPkcs8Pem(kp.getPrivate());

        assertThat(pem).startsWith("-----BEGIN PRIVATE KEY-----\n").endsWith("-----END PRIVATE KEY-----\n");
        PrivateKey back = EcKeys.fromPkcs8Pem(pem);
        assertThat(back.getEncoded()).isEqualTo(kp.getPrivate().getEncoded());
        // The restored key still signs verifiably.
        byte[] sig = DerSignatures.sign(back, new byte[] {1});
        assertThat(DerSignatures.verify(kp.getPublic(), new byte[] {1}, sig)).isTrue();
    }

    @Test
    void spkiRoundTrip() {
        KeyPair kp = EcKeys.generateP256();
        assertThat(EcKeys.publicKeyFromSpki(EcKeys.spkiDer(kp.getPublic())).getEncoded())
                .isEqualTo(kp.getPublic().getEncoded());
    }

    @Test
    void p384SpkiRejected() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp384r1"));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> EcKeys.publicKeyFromSpki(g.generateKeyPair().getPublic().getEncoded()));
    }

    @Test
    void rsaSpkiRejected() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        assertThatIllegalArgumentException()
                .isThrownBy(() -> EcKeys.publicKeyFromSpki(g.generateKeyPair().getPublic().getEncoded()));
    }

    @Test
    void p384PrivateKeyPemRejected() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp384r1"));
        String pem = EcKeys.toPkcs8Pem(g.generateKeyPair().getPrivate());
        assertThatIllegalArgumentException().isThrownBy(() -> EcKeys.fromPkcs8Pem(pem));
    }

    @Test
    void garbageSpkiRejected() {
        assertThatIllegalArgumentException().isThrownBy(() -> EcKeys.publicKeyFromSpki(new byte[] {0x30, 0x00}));
    }
}
