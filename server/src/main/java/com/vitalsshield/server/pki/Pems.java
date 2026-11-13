package com.vitalsshield.server.pki;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/** PEM helpers for certificates and CRLs (public material only). */
public final class Pems {

    private static final Base64.Encoder MIME = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII));

    private Pems() {
    }

    public static String certificate(X509Certificate cert) {
        try {
            return encode("CERTIFICATE", cert.getEncoded());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot encode certificate", e);
        }
    }

    public static String crl(byte[] der) {
        return encode("X509 CRL", der);
    }

    public static X509Certificate parseCertificate(String pem) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot parse certificate PEM", e);
        }
    }

    private static String encode(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + MIME.encodeToString(der) + "\n-----END " + type + "-----\n";
    }
}
