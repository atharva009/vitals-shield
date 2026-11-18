-- Phase 9: Protocol C re-enrollment, split-brain traps, backstop poller (DECISIONS #89 to #98).

-- Backstop poller (DECISIONS #96) under the same-clock rule (DECISIONS #89): revoked_at is written by the JVM in every
-- in-process path, but a revocation made outside it (direct SQL) may set any value, or none. revoked_db_at is stamped
-- by Postgres itself whenever a row becomes REVOKED, so the poller compares a Postgres time with Postgres now().
ALTER TABLE certificates
    ADD COLUMN revoked_db_at TIMESTAMPTZ,
    -- How the certificate was issued: ENROLL (Protocol A), RENEW (Protocol B), REENROLL (Protocol C).
    ADD COLUMN issued_via    VARCHAR(16),
    -- Protocol C only: why the device re-enrolled, derived by the server (cert_expired, epoch_resync, no_usable_cert).
    ADD COLUMN reenroll_reason VARCHAR(32);

UPDATE certificates SET revoked_db_at = COALESCE(revoked_at, NOW()) WHERE status = 'REVOKED';
UPDATE certificates SET issued_via = CASE WHEN superseded_serial IS NULL THEN 'ENROLL' ELSE 'RENEW' END;

CREATE FUNCTION certificates_stamp_revoked_db_at() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF NEW.status = 'REVOKED' AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM 'REVOKED') THEN
        NEW.revoked_db_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificates_revoked_db_at
    BEFORE INSERT OR UPDATE OF status ON certificates
    FOR EACH ROW EXECUTE FUNCTION certificates_stamp_revoked_db_at();

CREATE INDEX idx_certs_revoked_db_at ON certificates(revoked_db_at) WHERE status = 'REVOKED';
