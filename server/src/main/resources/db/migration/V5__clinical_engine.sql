-- Phase 7: clinical engine state (DECISIONS #68) and an append-only audit log (DECISIONS #75).

-- Per-assignment streak state, updated by the clinical evaluator under the assignment row lock (DECISIONS #69, #70).
ALTER TABLE patient_device_assignments
    ADD COLUMN resting_since               TIMESTAMPTZ,
    ADD COLUMN degraded_critical_streak    INT    NOT NULL DEFAULT 0,
    ADD COLUMN degraded_critical_batch_ids UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN drift_breach_streak         INT    NOT NULL DEFAULT 0,
    ADD COLUMN drift_breach_batch_ids      UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN last_evaluated_measured_at  TIMESTAMPTZ;

-- Activity context is NULL until the batch is evaluated; clinical_evaluated_at NULL means "not evaluated".
ALTER TABLE telemetry_records
    ADD COLUMN activity_context      VARCHAR(16)
        CONSTRAINT telemetry_records_activity_context_check CHECK (activity_context IN ('RESTING', 'EXERTION')),
    ADD COLUMN clinical_evaluated_at TIMESTAMPTZ;

-- Which rule fired (RESTING_HR_HIGH, SPO2_LOW, LOW_PERFUSION_CRITICAL, DRIFT, ...); the acute dedupe key.
ALTER TABLE clinical_alerts
    ADD COLUMN condition_code VARCHAR(32);

-- Append-only audit log. Rows can be inserted and read; UPDATE, DELETE and TRUNCATE fail for every role that does
-- not first disable the trigger (only the table owner or a superuser can). The hash chain detects edits by those.
CREATE FUNCTION security_audit_log_append_only() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION 'security_audit_log is append-only';
END;
$$;

CREATE TRIGGER security_audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON security_audit_log
    FOR EACH ROW EXECUTE FUNCTION security_audit_log_append_only();

CREATE TRIGGER security_audit_log_no_truncate
    BEFORE TRUNCATE ON security_audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION security_audit_log_append_only();
