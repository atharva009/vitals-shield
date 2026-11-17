package com.vitalsshield.simulator;

import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Locale;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;

/**
 * The (issuer_key_hash, serial_number) pair the server keys certificates by: the leaf's AKI keyIdentifier as
 * lowercase hex, and the serial as lowercase hex without leading zeros (DECISIONS #50 storage form). The renewal
 * request must name exactly the certificate of its TLS connection (DECISIONS #81).
 */
public final class CertIds {

    private CertIds() {
    }

    public static String issuerKeyHash(X509Certificate cert) {
        byte[] ext = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (ext == null) {
            throw new IllegalArgumentException("certificate has no AuthorityKeyIdentifier");
        }
        byte[] aki = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(ext).getOctets())
                .getKeyIdentifierOctets();
        return HexFormat.of().formatHex(aki);
    }

    public static String serial(X509Certificate cert) {
        return cert.getSerialNumber().toString(16);
    }

    /** As {@code openssl x509 -serial} prints it: uppercase, whole bytes. */
    public static String serialDisplay(X509Certificate cert) {
        String hex = serial(cert).toUpperCase(Locale.ROOT);
        return hex.length() % 2 == 1 ? "0" + hex : hex;
    }
}
