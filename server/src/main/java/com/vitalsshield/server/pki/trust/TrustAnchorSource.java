package com.vitalsshield.server.pki.trust;

import java.security.cert.X509Certificate;

/** The current Root and Device Intermediate. Implemented by {@link com.vitalsshield.server.pki.TrustAnchors}. */
public interface TrustAnchorSource {

    X509Certificate root();

    X509Certificate deviceIntermediate();
}
