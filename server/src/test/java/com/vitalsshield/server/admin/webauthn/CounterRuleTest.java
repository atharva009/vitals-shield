package com.vitalsshield.server.admin.webauthn;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** DECISIONS #61. */
class CounterRuleTest {

    @ParameterizedTest(name = "stored={0} presented={1} -> {2}")
    @CsvSource({
            "0, 0, true",      // synced passkey, always 0
            "7, 0, true",      // a 0 is accepted even after non-zero values
            "0, 1, true",
            "7, 8, true",
            "7, 7, false",     // equal is a replay or clone
            "7, 6, false",     // regression
            "4294967295, 4294967294, false"})
    void rule(long stored, long presented, boolean accepted) {
        assertThat(CounterRule.accept(stored, presented)).isEqualTo(accepted);
    }

    @ParameterizedTest
    @CsvSource({"0, 0, 0", "7, 0, 7", "7, 9, 9"})
    void storedValueNeverGoesDown(long stored, long presented, long next) {
        assertThat(CounterRule.next(stored, presented)).isEqualTo(next);
    }
}
