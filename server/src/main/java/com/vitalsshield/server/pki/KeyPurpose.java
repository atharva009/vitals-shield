package com.vitalsshield.server.pki;

/** Mirrors the {@code kms_key_purpose} Postgres enum. */
public enum KeyPurpose {
    ROOT_CA,
    DEVICE_INTERMEDIATE,
    SERVER_TLS_CA,
    REGISTRY_ANCHOR
}
