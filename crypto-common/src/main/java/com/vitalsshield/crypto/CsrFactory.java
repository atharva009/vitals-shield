package com.vitalsshield.crypto;

import java.io.IOException;
import java.security.KeyPair;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * PKCS#10 certificate signing requests. The CSR's self-signature proves the requester holds the private key for the
 * public key inside it (proof of possession). Everything else in a CSR (subject, SANs, extensions) is a request the CA
 * is free to ignore, and ours does (spec Section 3).
 */
public final class CsrFactory {

    private CsrFactory() {
    }

    /** A DER PKCS#10 request for {@code olk}, signed SHA256withECDSA. */
    public static byte[] create(KeyPair olk, String subjectCn) {
        try {
            return new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=" + subjectCn), olk.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withECDSA").build(olk.getPrivate()))
                    .getEncoded();
        } catch (OperatorCreationException | IOException e) {
            throw new IllegalStateException("cannot build CSR", e);
        }
    }

    /**
     * Parses a DER CSR, requires an EC P-256 key and an ecdsa-with-SHA256 self-signature that verifies, and returns the
     * public key. Throws IllegalArgumentException on anything else.
     */
    public static SubjectPublicKeyInfo parseAndVerify(byte[] der) {
        PKCS10CertificationRequest csr;
        try {
            csr = new PKCS10CertificationRequest(der);
        } catch (IOException | RuntimeException e) {
            throw new IllegalArgumentException("not a DER PKCS#10 request", e);
        }
        SubjectPublicKeyInfo spki = csr.getSubjectPublicKeyInfo();
        EcKeys.requireP256(spki);
        if (!X9ObjectIdentifiers.ecdsa_with_SHA256.equals(csr.getSignatureAlgorithm().getAlgorithm())) {
            throw new IllegalArgumentException("CSR is not signed ecdsa-with-SHA256");
        }
        try {
            if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(spki))) {
                throw new IllegalArgumentException("CSR self-signature does not verify");
            }
        } catch (OperatorCreationException | PKCSException e) {
            throw new IllegalArgumentException("CSR self-signature does not verify", e);
        }
        return spki;
    }
}
