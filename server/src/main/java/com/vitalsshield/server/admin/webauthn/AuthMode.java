package com.vitalsshield.server.admin.webauthn;

/** {@code vitalsshield.admin.auth}. */
public enum AuthMode {
    /** Passkey sessions and step-up approvals (Phase 6). The setup code only registers the first passkey. */
    WEBAUTHN,
    /** Phase 5 behavior: the setup code is the bearer on every admin route. */
    BEARER
}
