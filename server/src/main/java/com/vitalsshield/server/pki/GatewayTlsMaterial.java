package com.vitalsshield.server.pki;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * The gateway's TLS server key and chain [gateway leaf, Server TLS CA]. The P-256 private key is generated in memory
 * and lives only in this object: it is never written to disk, logged, or included in {@link #toString()}.
 */
@Component
public class GatewayTlsMaterial {

    private static final Logger log = LoggerFactory.getLogger(GatewayTlsMaterial.class);

    private final CertificateIssuer issuer;
    private final CaIssuerRepository issuers;
    private final PkiProperties props;

    private volatile Material current;

    public GatewayTlsMaterial(CertificateIssuer issuer, CaIssuerRepository issuers, PkiProperties props) {
        this.issuer = issuer;
        this.issuers = issuers;
        this.props = props;
    }

    public void issue() {
        KeyPair keyPair = generateP256();
        X509Certificate leaf = issuer.issueGatewayLeaf(keyPair.getPublic(), props.gatewayLeafTtl());
        X509Certificate serverCa = issuers.requireActive(KeyPurpose.SERVER_TLS_CA).certificate();
        if (!Arrays.equals(CertificateProfiles.authorityKeyIdentifier(leaf),
                CertificateProfiles.subjectKeyIdentifier(serverCa))) {
            throw new IllegalStateException("gateway leaf was not issued by the current Server TLS CA");
        }
        current = new Material(keyPair.getPrivate(), List.of(leaf, serverCa));
        log.info("Issued gateway TLS leaf serial {} valid until {}",
                SerialNumbers.toHex(leaf.getSerialNumber()), leaf.getNotAfter().toInstant());
    }

    public PrivateKey privateKey() {
        return require().privateKey;
    }

    /** [gateway leaf, Server TLS CA certificate]. */
    public List<X509Certificate> certificateChain() {
        return require().chain;
    }

    public boolean isIssued() {
        return current != null;
    }

    @Override
    public String toString() {
        Material m = current;
        return m == null ? "GatewayTlsMaterial[not issued]"
                : "GatewayTlsMaterial[leafSerial=" + SerialNumbers.toHex(m.chain.get(0).getSerialNumber())
                + ", notAfter=" + m.chain.get(0).getNotAfter().toInstant() + "]";
    }

    private Material require() {
        Material m = current;
        if (m == null) {
            throw new IllegalStateException("gateway TLS material has not been issued yet");
        }
        return m;
    }

    private static KeyPair generateP256() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            return gen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot generate P-256 key", e);
        }
    }

    /** Not a record: a record's generated toString would print the private key. */
    private static final class Material {
        private final PrivateKey privateKey;
        private final List<X509Certificate> chain;

        Material(PrivateKey privateKey, List<X509Certificate> chain) {
            this.privateKey = privateKey;
            this.chain = List.copyOf(chain);
        }

        @Override
        public String toString() {
            return "Material[chainLength=" + chain.size() + "]";
        }
    }
}
