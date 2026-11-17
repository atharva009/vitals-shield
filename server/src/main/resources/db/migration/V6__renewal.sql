-- Phase 8: Protocol B renewal with first-use activation (DECISIONS #81 to #85).

-- When the CA signed the row's leaf, and when a renewed leaf was first used (ISSUED_PENDING_USE to ACTIVE). Rows that
-- exist before this migration get the migration time as issued_at; only renewals made after it are shown in the
-- dashboard's renewal log, so the backfill value is never displayed.
ALTER TABLE certificates
    ADD COLUMN issued_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN activated_at TIMESTAMPTZ;

-- The renewal log and activation look a renewed leaf's predecessor up by (device_id, superseded_serial).
CREATE INDEX idx_certs_device_superseded ON certificates(device_id, superseded_serial)
    WHERE superseded_serial IS NOT NULL;

-- The nonce sweeper deletes rows past expires_at every 5 minutes.
CREATE INDEX idx_consumed_nonces_expires ON consumed_challenge_nonces(expires_at);

-- The expiry sweeper finds live certificates past not_after.
CREATE INDEX idx_certs_live_not_after ON certificates(not_after)
    WHERE status IN ('ACTIVE', 'ISSUED_PENDING_USE', 'RENEWED');
