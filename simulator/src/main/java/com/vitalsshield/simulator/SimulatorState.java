package com.vitalsshield.simulator;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

/** Contents of state/state.json: what a wearable keeps in flash across power cycles (spec Section 4). */
public record SimulatorState(String deviceId, long bootEpoch, long sequenceNumber, String assignmentId,
                             String assignmentActiveFrom, String enrolledAt) {

    public SimulatorState withSequenceNumber(long seq) {
        return new SimulatorState(deviceId, bootEpoch, seq, assignmentId, assignmentActiveFrom, enrolledAt);
    }

    String toJson() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("device_id", deviceId);
        m.put("boot_epoch", bootEpoch);
        m.put("sequence_number", sequenceNumber);
        m.put("assignment_id", assignmentId);
        m.put("assignment_active_from", assignmentActiveFrom);
        m.put("enrolled_at", enrolledAt);
        return JSONObjectUtils.toJSONString(m);
    }

    static SimulatorState fromJson(String json) {
        try {
            Map<String, Object> m = JSONObjectUtils.parse(json);
            return new SimulatorState((String) m.get("device_id"), ((Number) m.get("boot_epoch")).longValue(),
                    ((Number) m.get("sequence_number")).longValue(), (String) m.get("assignment_id"),
                    (String) m.get("assignment_active_from"), (String) m.get("enrolled_at"));
        } catch (ParseException | RuntimeException e) {
            throw new IllegalStateException("corrupt state.json", e);
        }
    }
}
