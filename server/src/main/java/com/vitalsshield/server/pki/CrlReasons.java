package com.vitalsshield.server.pki;

import org.bouncycastle.asn1.x509.CRLReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Maps certificates.revocation_reason to an RFC 5280 section 5.3.1 CRLReason code. */
public final class CrlReasons {

    private static final Logger log = LoggerFactory.getLogger(CrlReasons.class);

    private CrlReasons() {
    }

    public static int toCrlReason(String revocationReason) {
        if (revocationReason == null) {
            log.warn("Revoked certificate has no revocation_reason; using unspecified (0)");
            return CRLReason.unspecified;
        }
        return switch (revocationReason) {
            case "KEY_COMPROMISE", "SUSPECTED_CLONE" -> CRLReason.keyCompromise; // DECISIONS #92
            case "CA_COMPROMISE" -> CRLReason.cACompromise;
            case "SUPERSEDED_BY_REPROVISION", "SUPERSEDED_BY_REENROLL", "REPLACED_BEFORE_USE" -> CRLReason.superseded;
            case "HIERARCHY_REBUILD" -> CRLReason.cessationOfOperation;
            default -> {
                log.warn("Unknown revocation_reason '{}'; using unspecified (0)", revocationReason);
                yield CRLReason.unspecified;
            }
        };
    }
}
