package com.vitalsshield.server.boot;

public enum BootStep {
    RECONCILED,
    GATEWAY_TLS_ISSUED,
    TRUST_ANCHORS_LOADED,
    DENY_LIST_SEEDED,
    /** Always last: nothing accepts connections before every earlier step has completed. */
    LISTENERS_BOUND
}
