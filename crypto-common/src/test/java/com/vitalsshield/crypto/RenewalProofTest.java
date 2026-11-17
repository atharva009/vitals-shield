package com.vitalsshield.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import java.security.KeyPair;
import java.util.Arrays;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Test;

/**
 * Protocol B end to end with crypto-common only: the device signs encoding 5 with its current OLK over a CSR for the
 * new OLK; the verifier checks the signature with the current key and the CSR's self-signature for the new key.
 */
class RenewalProofTest {

    @Test
    void renewalProofSignsAndVerifies() throws Exception {
        KeyPair current = EcKeys.generateP256();
        KeyPair next = EcKeys.generateP256();
        byte[] csr = CsrFactory.create(next, "dev_renew_proof");
        byte[] nonce = new byte[16];
        Arrays.fill(nonce, (byte) 0x5a);
        String issuer = "9f2c0e7d4b1a8c3e5f60718293a4b5c6d7e8f901";
        String serial = "2ed4e9af9446efdb6e9f66e21a6d47bc4c0907";
        long issuedAt = 1_794_830_400_000L;

        byte[] message = CanonicalEncodings.olkRenewalProofBytes(issuer, serial, issuedAt, nonce, csr);
        byte[] sig = DerSignatures.sign(current.getPrivate(), message);

        assertThat(DerSignatures.verify(current.getPublic(), message, sig)).isTrue();
        SubjectPublicKeyInfo spki = CsrFactory.parseAndVerify(csr);
        assertThat(spki.getEncoded()).isEqualTo(next.getPublic().getEncoded());

        // The new key cannot stand in for the current one, and every covered field is bound.
        assertThat(DerSignatures.verify(next.getPublic(), message, sig)).isFalse();
        assertThat(DerSignatures.verify(current.getPublic(),
                CanonicalEncodings.olkRenewalProofBytes(issuer, serial, issuedAt + 1, nonce, csr), sig)).isFalse();
        assertThat(DerSignatures.verify(current.getPublic(),
                CanonicalEncodings.olkRenewalProofBytes(issuer, serial + "0", issuedAt, nonce, csr), sig)).isFalse();
        byte[] otherCsr = CsrFactory.create(EcKeys.generateP256(), "dev_renew_proof");
        assertThat(DerSignatures.verify(current.getPublic(),
                CanonicalEncodings.olkRenewalProofBytes(issuer, serial, issuedAt, nonce, otherCsr), sig)).isFalse();
    }
}
