package com.vitalsshield.crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * SHA256withECDSA signatures in DER form (SEQUENCE of two INTEGERs), used for every signature outside JWS (DEK proofs,
 * KMS anchors). JWS uses raw R||S instead (DECISIONS #33).
 */
public final class DerSignatures {

    private DerSignatures() {
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(key);
            s.update(message);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    /**
     * True only if {@code derSig} is a strict DER ECDSA signature (no BER variants, no trailing bytes, not raw R||S)
     * that verifies over {@code message}.
     */
    public static boolean verify(PublicKey key, byte[] message, byte[] derSig) {
        if (!isStrictDerEcdsa(derSig)) {
            return false;
        }
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(key);
            s.update(message);
            return s.verify(derSig);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    static boolean isStrictDerEcdsa(byte[] sig) {
        try {
            ASN1Primitive p = ASN1Primitive.fromByteArray(sig);
            if (!(p instanceof ASN1Sequence seq) || seq.size() != 2
                    || !(seq.getObjectAt(0) instanceof ASN1Integer r) || !(seq.getObjectAt(1) instanceof ASN1Integer s)
                    || r.getValue().signum() <= 0 || s.getValue().signum() <= 0) {
                return false;
            }
            return Arrays.equals(seq.getEncoded(ASN1Encoding.DER), sig);
        } catch (Exception e) {
            return false;
        }
    }
}
