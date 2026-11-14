package com.vitalsshield.server.telemetry;

import java.time.Duration;
import java.time.Instant;
import java.util.regex.Pattern;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Strict parsing and validation of the JWS payload. Unknown fields, missing fields, nulls, trailing tokens, and
 * float-to-int coercion are all rejected (DECISIONS #43). Rules (DECISIONS #40): sequence_number and boot_epoch >= 1;
 * transmitted_at within 5 minutes of server time; measured_at no later than transmitted_at + 1 minute; firmware hash
 * format; every metric present and finite. A device_id that is not the TLS certificate's device is 403.
 */
public final class TelemetryPayloadValidator {

    static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(5);
    static final Duration MAX_MEASURED_AHEAD = Duration.ofMinutes(1);
    static final Pattern FIRMWARE_HASH = Pattern.compile("^sha256:[0-9a-f]{64}$");

    private static final JsonMapper STRICT = JsonMapper.builder()
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
            // "98" is not a number: no string-to-number (or number-to-string) coercion.
            .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
            .build();

    private TelemetryPayloadValidator() {
    }

    /** Parses the exact signed bytes; any structural problem is 400 PAYLOAD_INVALID. */
    public static TelemetryPayload parse(byte[] payloadBytes) {
        try {
            return STRICT.readValue(payloadBytes, TelemetryPayload.class);
        } catch (JacksonException e) {
            throw IngestRejection.of(400, "PAYLOAD_INVALID", "UNPARSEABLE_OR_UNKNOWN_FIELD");
        }
    }

    public static void validate(TelemetryPayload p, String certDeviceId, Instant now) {
        if (p.batchId() == null || p.deviceId() == null || p.assignmentId() == null || p.bootEpoch() == null
                || p.sequenceNumber() == null || p.measuredAt() == null || p.transmittedAt() == null
                || p.firmwareHash() == null || p.metrics() == null) {
            throw IngestRejection.of(400, "PAYLOAD_INVALID", "MISSING_FIELD");
        }
        if (!p.deviceId().equals(certDeviceId)) {
            throw IngestRejection.of(403, "DEVICE_MISMATCH");
        }
        if (p.sequenceNumber() < 1) {
            throw IngestRejection.of(400, "PAYLOAD_INVALID", "SEQUENCE_NUMBER");
        }
        if (p.bootEpoch() < 1) {
            throw IngestRejection.of(400, "PAYLOAD_INVALID", "BOOT_EPOCH");
        }
        if (Duration.between(p.transmittedAt(), now).abs().compareTo(MAX_CLOCK_SKEW) > 0) {
            throw IngestRejection.of(400, "PAYLOAD_INVALID", "TRANSMITTED_AT_SKEW");
        }
        if (p.measuredAt().isAfter(p.transmittedAt().plus(MAX_MEASURED_AHEAD))) {
            throw IngestRejection.of(400, "PAYLOAD_INVALID", "MEASURED_AT_AFTER_TRANSMITTED_AT");
        }
        if (!FIRMWARE_HASH.matcher(p.firmwareHash()).matches()) {
            throw IngestRejection.of(400, "PAYLOAD_INVALID", "FIRMWARE_HASH");
        }
        TelemetryPayload.Metrics m = p.metrics();
        if (m.heartRateBpm() == null || m.stepCadenceSpm() == null
                || !finite(m.hrvRmssdMs()) || !finite(m.spo2Pct()) || !finite(m.signalPerfusionIndex())
                || !finite(m.motionGRms())) {
            throw IngestRejection.of(400, "PAYLOAD_INVALID", "METRIC");
        }
    }

    private static boolean finite(Double d) {
        return d != null && Double.isFinite(d);
    }
}
