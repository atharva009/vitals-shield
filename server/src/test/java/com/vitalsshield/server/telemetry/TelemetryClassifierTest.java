package com.vitalsshield.server.telemetry;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class TelemetryClassifierTest {

    @ParameterizedTest
    @CsvSource({
            "14, 98.0, 3.0, REJECTED_IMPLAUSIBLE",
            "15, 98.0, 3.0, ACCEPTED",
            "300, 98.0, 3.0, ACCEPTED",
            "301, 98.0, 3.0, REJECTED_IMPLAUSIBLE",
            "70, 39.9, 3.0, REJECTED_IMPLAUSIBLE",
            "70, 40.0, 3.0, ACCEPTED",
            "70, 100.0, 3.0, ACCEPTED",
            "70, 100.1, 3.0, REJECTED_IMPLAUSIBLE",
            "70, 98.0, 0.49, SIGNAL_DEGRADED",
            "70, 98.0, 0.5, ACCEPTED",
            "14, 98.0, 0.1, REJECTED_IMPLAUSIBLE",
    })
    void boundaries(int hr, double spo2, double perfusion, String expected) {
        assertThat(TelemetryClassifier.classify(new TelemetryPayload.Metrics(hr, 45.0, spo2, perfusion, 0, 0.02)))
                .isEqualTo(expected);
    }
}
