package com.vitalsshield.server.clinical;

// LOCK ORDER (DECISIONS #70), in every transaction: devices -> telemetry_records -> patient_device_assignments
// -> clinical_alerts -> audit advisory lock LAST. This class: the clinical_alerts row FOR UPDATE, then the audit lock.

import com.vitalsshield.server.audit.AuditLog;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** Acknowledge and resolve (DECISIONS #76). Blocking; the controller runs it on boundedElastic. */
@Service
public class AlertService {

    public enum Action {
        ACKNOWLEDGE("ACKNOWLEDGED", "ALERT_ACKNOWLEDGED"),
        RESOLVE("RESOLVED", "ALERT_RESOLVED");

        final String target;
        final String auditEvent;

        Action(String target, String auditEvent) {
            this.target = target;
            this.auditEvent = auditEvent;
        }
    }

    /** {@code status}: 200, 404 ALERT_NOT_FOUND, or 409 ILLEGAL_TRANSITION (with the current status). */
    public record Result(int status, Map<String, Object> body) {
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final AuditLog audit;

    public AlertService(JdbcTemplate jdbc, TransactionTemplate tx, AuditLog audit) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.audit = audit;
    }

    public Result apply(UUID alertId, Action action, String clinicianId) {
        return tx.execute(status -> {
            List<Map<String, Object>> rows = jdbc.queryForList("""
                    SELECT device_id, alert_type::text AS alert_type, alert_status::text AS alert_status
                      FROM clinical_alerts WHERE alert_id = ? FOR UPDATE
                    """, alertId);
            if (rows.isEmpty()) {
                return new Result(404, Map.of("error", "ALERT_NOT_FOUND"));
            }
            Map<String, Object> row = rows.get(0);
            String from = (String) row.get("alert_status");
            if (!AlertTransitions.allowed(from, action.target)) {
                return new Result(409, Map.of("error", "ILLEGAL_TRANSITION", "alert_status", from));
            }
            jdbc.update("UPDATE clinical_alerts SET alert_status = ?::alert_lifecycle_status WHERE alert_id = ?",
                    action.target, alertId);
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("alert_id", alertId.toString());
            payload.put("device_id", row.get("device_id"));
            payload.put("alert_type", row.get("alert_type"));
            payload.put("from", from);
            payload.put("to", action.target);
            audit.append(action.auditEvent, clinicianId, payload); // last (DECISIONS #67, #70)
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("alert_id", alertId.toString());
            body.put("alert_status", action.target);
            body.put("by", clinicianId);
            return new Result(200, body);
        });
    }
}
