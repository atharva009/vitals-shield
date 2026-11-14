package com.vitalsshield.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;

class CsrFactoryTest {

    @Test
    void roundTripReturnsTheCsrPublicKey() throws Exception {
        KeyPair olk = EcKeys.generateP256();
        byte[] csr = CsrFactory.create(olk, "dev_wearable_019");

        SubjectPublicKeyInfo spki = CsrFactory.parseAndVerify(csr);

        assertThat(spki.getEncoded()).isEqualTo(olk.getPublic().getEncoded());
    }

    @Test
    void tamperedCsrFails() {
        byte[] csr = CsrFactory.create(EcKeys.generateP256(), "dev_wearable_019");
        // Flip a byte inside the subject CN (well inside the signed CertificationRequestInfo).
        int idx = new String(csr, java.nio.charset.StandardCharsets.ISO_8859_1).indexOf("dev_wearable_019");
        csr[idx] ^= 0x01;

        assertThatIllegalArgumentException().isThrownBy(() -> CsrFactory.parseAndVerify(csr));
    }

    @Test
    void rsaCsrRejected() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair rsa = g.generateKeyPair();
        byte[] csr = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=rsa"), rsa.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(rsa.getPrivate())).getEncoded();

        assertThatIllegalArgumentException().isThrownBy(() -> CsrFactory.parseAndVerify(csr))
                .withMessageContaining("not EC");
    }

    @Test
    void p384CsrRejected() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair p384 = g.generateKeyPair();
        byte[] csr = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=p384"), p384.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(p384.getPrivate())).getEncoded();

        assertThatIllegalArgumentException().isThrownBy(() -> CsrFactory.parseAndVerify(csr))
                .withMessageContaining("P-256");
    }

    @Test
    void garbageRejected() {
        assertThatIllegalArgumentException().isThrownBy(() -> CsrFactory.parseAndVerify(new byte[] {1, 2, 3}));
    }
}
