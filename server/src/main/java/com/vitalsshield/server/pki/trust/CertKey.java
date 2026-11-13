package com.vitalsshield.server.pki.trust;

import com.vitalsshield.server.pki.CertificateProfiles;
import com.vitalsshield.server.pki.SerialNumbers;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;

/**
 * Identifies a leaf by issuer key and serial: (issuer_key_hash, serial_number), the certificates primary key.
 * Both are normalized the Phase 1 way: lowercase hex, serial without leading zeros. Never keyed by DN.
 */
public record CertKey(String issuerKeyHash, String serial) {

    public CertKey {
        Objects.requireNonNull(issuerKeyHash, "issuerKeyHash");
        Objects.requireNonNull(serial, "serial");
    }

    public static CertKey of(String issuerKeyHash, String serialHex) {
        return new CertKey(issuerKeyHash.toLowerCase(Locale.ROOT),
                SerialNumbers.toHex(new BigInteger(serialHex, 16)));
    }

    /** From a leaf: issuer key hash = the leaf's AKI keyIdentifier in hex. */
    public static CertKey from(X509Certificate leaf) {
        byte[] aki = CertificateProfiles.authorityKeyIdentifier(leaf);
        if (aki == null) {
            throw new IllegalArgumentException("certificate has no AuthorityKeyIdentifier");
        }
        return new CertKey(HexFormat.of().formatHex(aki), SerialNumbers.toHex(leaf.getSerialNumber()));
    }
}
