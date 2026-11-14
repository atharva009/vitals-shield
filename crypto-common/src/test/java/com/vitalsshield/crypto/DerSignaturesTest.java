package com.vitalsshield.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.Test;

class DerSignaturesTest {

    static final byte[] MESSAGE = "dek proof bytes".getBytes(StandardCharsets.UTF_8);

    @Test
    void roundTrip() {
        KeyPair kp = EcKeys.generateP256();
        byte[] sig = DerSignatures.sign(kp.getPrivate(), MESSAGE);

        assertThat(sig[0]).isEqualTo((byte) 0x30);
        assertThat(DerSignatures.verify(kp.getPublic(), MESSAGE, sig)).isTrue();
    }

    @Test
    void tamperedMessageFails() {
        KeyPair kp = EcKeys.generateP256();
        byte[] sig = DerSignatures.sign(kp.getPrivate(), MESSAGE);
        byte[] other = Arrays.copyOf(MESSAGE, MESSAGE.length);
        other[0] ^= 0x01;

        assertThat(DerSignatures.verify(kp.getPublic(), other, sig)).isFalse();
    }

    @Test
    void wrongKeyFails() {
        byte[] sig = DerSignatures.sign(EcKeys.generateP256().getPrivate(), MESSAGE);
        assertThat(DerSignatures.verify(EcKeys.generateP256().getPublic(), MESSAGE, sig)).isFalse();
    }

    @Test
    void raw64ByteRsSignatureRejected() throws Exception {
        KeyPair kp = EcKeys.generateP256();
        ASN1Sequence der = ASN1Sequence.getInstance(DerSignatures.sign(kp.getPrivate(), MESSAGE));
        byte[] raw = new byte[64];
        copyFixed(((ASN1Integer) der.getObjectAt(0)).getValue(), raw, 0);
        copyFixed(((ASN1Integer) der.getObjectAt(1)).getValue(), raw, 32);

        assertThat(DerSignatures.verify(kp.getPublic(), MESSAGE, raw)).isFalse();
    }

    @Test
    void trailingBytesRejected() {
        KeyPair kp = EcKeys.generateP256();
        byte[] sig = DerSignatures.sign(kp.getPrivate(), MESSAGE);
        byte[] padded = Arrays.copyOf(sig, sig.length + 1);

        assertThat(DerSignatures.verify(kp.getPublic(), MESSAGE, padded)).isFalse();
    }

    private static void copyFixed(BigInteger v, byte[] out, int offset) {
        byte[] b = v.toByteArray();
        int start = b.length > 32 ? b.length - 32 : 0;
        int len = b.length - start;
        System.arraycopy(b, start, out, offset + 32 - len, len);
    }
}
