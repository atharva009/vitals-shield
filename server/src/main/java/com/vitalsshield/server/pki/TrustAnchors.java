package com.vitalsshield.server.pki;

import java.security.cert.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** Current Root and Device Intermediate certificates from ca_issuers. Read by the Phase 2 mTLS trust manager. */
@Component
public class TrustAnchors {

    private static final Logger log = LoggerFactory.getLogger(TrustAnchors.class);

    private final CaIssuerRepository issuers;
    private volatile Anchors current;

    public TrustAnchors(CaIssuerRepository issuers) {
        this.issuers = issuers;
    }

    public void reload() {
        X509Certificate root = issuers.requireActive(KeyPurpose.ROOT_CA).certificate();
        X509Certificate deviceInt = issuers.requireActive(KeyPurpose.DEVICE_INTERMEDIATE).certificate();
        current = new Anchors(root, deviceInt);
        log.info("Trust anchors loaded: root {} / device intermediate {}",
                CertificateProfiles.issuerKeyHash(root), CertificateProfiles.issuerKeyHash(deviceInt));
    }

    public X509Certificate root() {
        return require().root();
    }

    public X509Certificate deviceIntermediate() {
        return require().deviceIntermediate();
    }

    private Anchors require() {
        Anchors a = current;
        if (a == null) {
            throw new IllegalStateException("trust anchors not loaded; call reload()");
        }
        return a;
    }

    private record Anchors(X509Certificate root, X509Certificate deviceIntermediate) {
    }
}
