package com.vitalsshield.simulator;

import com.vitalsshield.crypto.EcKeys;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** A throwaway self-signed P-256 certificate for persistence tests. */
final class TestCert {

    static final String PEM = build();

    private TestCert() {
    }

    private static String build() {
        try {
            KeyPair kp = EcKeys.generateP256();
            X500Name name = new X500Name("CN=test");
            byte[] der = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, new Date(),
                    new Date(System.currentTimeMillis() + 3_600_000L), name, kp.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate())).getEncoded();
            return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                    + "\n-----END CERTIFICATE-----\n";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
