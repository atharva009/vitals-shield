package com.vitalsshield.server.boot;

public enum BootStep {
    RECONCILED,
    GATEWAY_TLS_ISSUED,
    TRUST_ANCHORS_LOADED
    // PHASE 2: add BIND_LISTENERS here.
}
