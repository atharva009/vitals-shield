package com.vitalsshield.simulator;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Contents of state/state.json: what a wearable keeps in flash across power cycles (spec Section 4).
 * {@code lastMeasuredAt} (Phase 7, DECISIONS #74) is the compressed-clock measured_at of the last batch, null before
 * the first batch; it is written together with sequence_number before the batch is sent.
 */
public record SimulatorState(String deviceId, long bootEpoch, long sequenceNumber, String assignmentId,
                             String assignmentActiveFrom, String enrolledAt, String lastMeasuredAt) {

    public SimulatorState(String deviceId, long bootEpoch, long sequenceNumber, String assignmentId,
                          String assignmentActiveFrom, String enrolledAt) {
        this(deviceId, bootEpoch, sequenceNumber, assignmentId, assignmentActiveFrom, enrolledAt, null);
    }

    public SimulatorState withSequenceNumber(long seq) {
        return new SimulatorState(deviceId, bootEpoch, seq, assignmentId, assignmentActiveFrom, enrolledAt,
                lastMeasuredAt);
    }

    public SimulatorState withNextBatch(long seq, String measuredAt) {
        return new SimulatorState(deviceId, bootEpoch, seq, assignmentId, assignmentActiveFrom, enrolledAt, measuredAt);
    }

    String toJson() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("device_id", deviceId);
        m.put("boot_epoch", bootEpoch);
        m.put("sequence_number", sequenceNumber);
        m.put("assignment_id", assignmentId);
        m.put("assignment_active_from", assignmentActiveFrom);
        m.put("enrolled_at", enrolledAt);
        if (lastMeasuredAt != null) {
            m.put("last_measured_at", lastMeasuredAt);
        }
        return JSONObjectUtils.toJSONString(m);
    }

    static SimulatorState fromJson(String json) {
        try {
            Map<String, Object> m = JSONObjectUtils.parse(json);
            return new SimulatorState((String) m.get("device_id"), ((Number) m.get("boot_epoch")).longValue(),
                    ((Number) m.get("sequence_number")).longValue(), (String) m.get("assignment_id"),
                    (String) m.get("assignment_active_from"), (String) m.get("enrolled_at"),
                    (String) m.get("last_measured_at"));
        } catch (ParseException | RuntimeException e) {
            throw new IllegalStateException("corrupt state.json", e);
        }
    }
}
