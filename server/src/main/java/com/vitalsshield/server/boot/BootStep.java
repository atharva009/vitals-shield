package com.vitalsshield.server.boot;

public enum BootStep {
    RECONCILED,
    SERIALS_SWEPT,
    GATEWAY_TLS_ISSUED,
    TRUST_ANCHORS_LOADED,
    DENY_LIST_SEEDED,
    CRLS_PUBLISHED,
    ADMIN_CODE_ISSUED,
    /** Always last: nothing accepts connections before every earlier step has completed. */
    LISTENERS_BOUND
}
