package com.vitalsshield.devtools;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SeedDemoDeviceTest {

    @Test
    void localComposeAccepted() {
        assertThatCode(() -> SeedDemoDevice.requireLocalCompose("jdbc:postgresql://localhost:5433/vitalsshield"))
                .doesNotThrowAnyException();
        assertThatCode(() -> SeedDemoDevice.requireLocalCompose("jdbc:postgresql://127.0.0.1:5433/vitalsshield"))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "jdbc:postgresql://localhost:5432/vitalsshield",
            "jdbc:postgresql://db.example.com:5433/vitalsshield",
            "jdbc:postgresql://10.0.0.5:5433/vitalsshield",
            "jdbc:postgresql://localhost/vitalsshield",
            "jdbc:mysql://localhost:5433/vitalsshield"})
    void anythingElseRefused(String url) {
        assertThatIllegalStateException().isThrownBy(() -> SeedDemoDevice.requireLocalCompose(url));
    }
}
