package com.vitalsshield.server.admin.webauthn;

/**
 * Whether DEV_SEED passkeys may be used at all (DECISIONS #66): only with the {@code local} profile. Outside it, every
 * assertion from a DEV_SEED credential is rejected, including at Protocol A re-verification.
 */
public record DevSeedPolicy(boolean allowed) {
}
