package com.vitalsshield.server.enrollment;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class BootEpochRuleTest {

    @Test
    void firstTimeDeviceKeepsStoredEpoch() {
        assertThat(BootEpochRule.afterEnrollment(1, false).bootEpoch()).isEqualTo(1);
    }

    @Test
    void deviceWithPriorCertificateGetsNextEpoch() {
        assertThat(BootEpochRule.afterEnrollment(1, true).bootEpoch()).isEqualTo(2);
        assertThat(BootEpochRule.afterEnrollment(7, true).bootEpoch()).isEqualTo(8);
    }

    @Test
    void sequenceAndBitmapAlwaysReset() {
        for (boolean prior : new boolean[] {false, true}) {
            BootEpochRule.DeviceCounters c = BootEpochRule.afterEnrollment(3, prior);
            assertThat(c.lastSequenceNum()).isZero();
            assertThat(c.replayBitmap()).isZero();
        }
    }
}
