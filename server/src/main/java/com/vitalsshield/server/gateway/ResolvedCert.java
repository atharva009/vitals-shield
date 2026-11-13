package com.vitalsshield.server.gateway;

/** The certificates row accepted for this request; set as an exchange attribute by {@link CertStatusResolver}. */
public record ResolvedCert(String issuerKeyHash, String serial, String deviceId, String status) {

    public static final String ATTRIBUTE = ResolvedCert.class.getName();
}
