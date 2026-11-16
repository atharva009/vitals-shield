-- Phase 6.1 (DECISIONS #66): mark what a passkey may be used for. CLINICIAN: sign-in, step-up, provisioning.
-- DEV_SEED: only the dev seed tool's provisioning path, and only in the local profile.
-- (Versions are not contiguous: there is no V3. Flyway only requires increasing versions.)
ALTER TABLE clinician_passkeys
    ADD COLUMN purpose VARCHAR(32) NOT NULL DEFAULT 'CLINICIAN'
        CONSTRAINT clinician_passkeys_purpose_check CHECK (purpose IN ('CLINICIAN', 'DEV_SEED'));

-- One-time backfill of the dev seed credentials written before this column existed: the Phase 3 fake row
-- ('dev-seed') and any Phase 6 software passkey registered by the seed tool. From now on the seed tool writes
-- purpose = 'DEV_SEED' itself and runtime checks read only this column.
UPDATE clinician_passkeys SET purpose = 'DEV_SEED'
 WHERE credential_id_b64 = 'dev-seed' OR clinician_id = 'dev-seed-clinician';
