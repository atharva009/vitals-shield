package com.vitalsshield.server.pki;

import static org.assertj.core.api.Assertions.assertThat;

import org.bouncycastle.asn1.x509.CRLReason;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;

class CrlReasonMappingTest {

    @ParameterizedTest
    @CsvSource({
            "KEY_COMPROMISE, 1",
            "CA_COMPROMISE, 2",
            "SUPERSEDED_BY_REPROVISION, 4",
            "SUPERSEDED_BY_REENROLL, 4",
            "REPLACED_BEFORE_USE, 4",
            "HIERARCHY_REBUILD, 5",
            "SOMETHING_NEW, 0",
            "'', 0",
    })
    void mapsRevocationReasonToRfc5280Code(String reason, int expectedCode) {
        assertThat(CrlReasons.toCrlReason(reason)).isEqualTo(expectedCode);
    }

    @ParameterizedTest
    @NullSource
    void nullReasonIsUnspecified(String reason) {
        assertThat(CrlReasons.toCrlReason(reason)).isEqualTo(CRLReason.unspecified);
    }

    @ParameterizedTest
    @CsvSource({"1, keyCompromise", "2, cACompromise", "4, superseded", "5, cessationOfOperation", "0, unspecified"})
    void codesMatchBouncyCastleConstants(int code, String bcName) throws Exception {
        assertThat(CRLReason.class.getField(bcName).getInt(null)).isEqualTo(code);
    }
}
