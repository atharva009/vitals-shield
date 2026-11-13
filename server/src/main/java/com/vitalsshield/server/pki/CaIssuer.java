package com.vitalsshield.server.pki;

import java.security.cert.X509Certificate;

/** A ca_issuers row joined to its kms_keys purpose. */
public record CaIssuer(KeyPurpose purpose, String issuerKeyHash, String subjectDn, String kmsArn, String certPem) {

    public X509Certificate certificate() {
        return Pems.parseCertificate(certPem);
    }
}
