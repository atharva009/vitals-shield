package com.vitalsshield.server.reenroll;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Spec Section 4 epoch handling and DECISIONS #97, every branch. */
class EpochRulesTest {

    @Test
    void presentedAboveStoredIsInvalidEvenWithResync() {
        assertThat(EpochRules.decide(3, 4, false).kind()).isEqualTo(EpochRules.Kind.INVALID);
        assertThat(EpochRules.decide(3, 4, true).kind()).isEqualTo(EpochRules.Kind.INVALID);
    }

    @Test
    void resyncWithPresentedBelowOrEqualAssignsStoredPlusOne() {
        assertThat(EpochRules.decide(3, 1, true)).isEqualTo(new EpochRules.Decision(EpochRules.Kind.RESYNC, 4));
        assertThat(EpochRules.decide(3, 3, true)).isEqualTo(new EpochRules.Decision(EpochRules.Kind.RESYNC, 4));
    }

    @Test
    void presentedBelowStoredWithoutResyncIsRegression() {
        assertThat(EpochRules.decide(3, 2, false).kind()).isEqualTo(EpochRules.Kind.REGRESSION);
    }

    @Test
    void equalWithoutResyncKeepsTheEpoch() {
        assertThat(EpochRules.decide(3, 3, false)).isEqualTo(new EpochRules.Decision(EpochRules.Kind.SAME, 3));
    }
}
