package com.vitalsshield.simulator;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

/** Recomputes the public key Q = d*G from a stored P-256 private key (PKCS#8 holds only d). */
final class DekPublic {

    private DekPublic() {
    }

    static PublicKey derive(PrivateKey key) {
        ECPrivateKey ec = (ECPrivateKey) key;
        ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256r1");
        org.bouncycastle.math.ec.ECPoint q = curve.getG().multiply(ec.getS()).normalize();
        ECParameterSpec params = ec.getParams();
        ECPoint w = new ECPoint(q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger());
        try {
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

}
