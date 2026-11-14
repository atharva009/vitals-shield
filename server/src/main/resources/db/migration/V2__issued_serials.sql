-- Serial reservation ledger (DECISIONS #38). Every device leaf serial is reserved here before any KMS call.
CREATE TYPE issued_serial_status AS ENUM ('RESERVED', 'RECORDED', 'VOIDED');

CREATE TABLE issued_serials (
    issuer_key_hash VARCHAR(64) NOT NULL REFERENCES ca_issuers(issuer_key_hash),
    serial_number   VARCHAR(64) NOT NULL,
    device_id       VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    reserved_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          issued_serial_status NOT NULL DEFAULT 'RESERVED',
    voided_at       TIMESTAMPTZ,
    PRIMARY KEY (issuer_key_hash, serial_number)
);

CREATE INDEX idx_issued_serials_reserved ON issued_serials(reserved_at) WHERE status = 'RESERVED';

-- Backfill: every certificate that already exists is RECORDED.
INSERT INTO issued_serials (issuer_key_hash, serial_number, device_id, reserved_at, status)
SELECT issuer_key_hash, serial_number, device_id, not_before, 'RECORDED' FROM certificates;
