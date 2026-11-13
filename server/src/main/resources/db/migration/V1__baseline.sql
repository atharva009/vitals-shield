CREATE EXTENSION IF NOT EXISTS btree_gist;

CREATE TYPE ca_status AS ENUM ('ACTIVE', 'STANDBY', 'REVOKED');
CREATE TYPE cert_status AS ENUM ('ISSUED_PENDING_USE', 'ACTIVE', 'RENEWED', 'REVOKED', 'EXPIRED');
CREATE TYPE device_trust_state AS ENUM (
    'PROVISIONED',
    'ACTIVE',
    'REAUTH_REQUIRED',
    'QUARANTINED',
    'DECOMMISSIONED'
);
CREATE TYPE token_status AS ENUM ('ISSUED', 'CLAIMING', 'CONSUMED', 'EXPIRED', 'REVOKED');
CREATE TYPE assignment_status AS ENUM ('ACTIVE', 'CLOSED');
CREATE TYPE baseline_lock_state AS ENUM ('CALIBRATING', 'LOCKED');
CREATE TYPE telemetry_trust_state AS ENUM (
    'ACCEPTED',
    'SIGNAL_DEGRADED',
    'REJECTED_IMPLAUSIBLE',
    'QUARANTINED',
    'REVIEWED'
);
CREATE TYPE alert_severity_type AS ENUM (
    'ACUTE_PHYSIOLOGICAL_ALERT',
    'LOW_PERFUSION_CRITICAL_ALERT',
    'POTENTIAL_PHYSIOLOGICAL_DRIFT',
    'SECURITY_ANOMALY_ALERT'
);
CREATE TYPE alert_lifecycle_status AS ENUM (
    'ACTIVE',
    'ACKNOWLEDGED',
    'RETRACTED_BY_QUARANTINE',
    'RESOLVED'
);

CREATE TABLE clinician_passkeys (
    credential_id_b64        VARCHAR(256) PRIMARY KEY,
    clinician_id             VARCHAR(128) NOT NULL,
    public_key_cose_der_b64  TEXT NOT NULL,
    passkey_registry_kms_sig TEXT NOT NULL,
    sign_count               BIGINT NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ca_issuers (
    issuer_key_hash          VARCHAR(64) PRIMARY KEY,
    subject_dn               TEXT NOT NULL,
    kms_primary_arn          TEXT NOT NULL,
    kms_replica_arn          TEXT,
    cert_pem                 TEXT NOT NULL,
    crl_number               BIGINT NOT NULL DEFAULT 1,
    status                   ca_status NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE devices (
    device_id                VARCHAR(64) PRIMARY KEY,
    hardware_model           VARCHAR(64) NOT NULL,
    dek_spki_der_b64         TEXT,
    dek_spki_sha256          VARCHAR(64),
    dek_registry_kms_sig     TEXT,
    provisioned_at           TIMESTAMPTZ,
    boot_epoch               BIGINT NOT NULL DEFAULT 1,
    epoch_resync_allowed     BOOLEAN NOT NULL DEFAULT FALSE,
    last_sequence_num        BIGINT NOT NULL DEFAULT 0,
    replay_bitmap            BIGINT NOT NULL DEFAULT 0,
    last_ingested_at         TIMESTAMPTZ,
    trust_state              device_trust_state NOT NULL DEFAULT 'PROVISIONED',
    quarantine_reason        VARCHAR(128),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE device_bootstrap_tokens (
    token_id                 UUID PRIMARY KEY,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    token_hash               VARCHAR(64) NOT NULL,
    status                   token_status NOT NULL DEFAULT 'ISSUED',
    issued_by_clinician      VARCHAR(128) NOT NULL,
    webauthn_cred_id_b64     VARCHAR(256) NOT NULL REFERENCES clinician_passkeys(credential_id_b64),
    webauthn_auth_data       TEXT NOT NULL,
    webauthn_client_json     TEXT NOT NULL,
    webauthn_signature       TEXT NOT NULL,
    expires_at               TIMESTAMPTZ NOT NULL,
    claimed_at               TIMESTAMPTZ,
    consumed_at              TIMESTAMPTZ
);

CREATE TABLE consumed_challenge_nonces (
    nonce_b64                VARCHAR(64) PRIMARY KEY,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    consumed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at               TIMESTAMPTZ NOT NULL
);

CREATE TABLE certificates (
    issuer_key_hash          VARCHAR(64) NOT NULL REFERENCES ca_issuers(issuer_key_hash),
    serial_number            VARCHAR(64) NOT NULL,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    cert_thumbprint_s256     VARCHAR(64) NOT NULL,
    cert_pem                 TEXT NOT NULL,
    superseded_serial        VARCHAR(64),
    not_before               TIMESTAMPTZ NOT NULL,
    not_after                TIMESTAMPTZ NOT NULL,
    grace_expires_at         TIMESTAMPTZ,
    status                   cert_status NOT NULL DEFAULT 'ACTIVE',
    revocation_reason        VARCHAR(64),
    revoked_at               TIMESTAMPTZ,
    PRIMARY KEY (issuer_key_hash, serial_number)
);

CREATE UNIQUE INDEX idx_one_active_cert_per_device
    ON certificates(device_id) WHERE status = 'ACTIVE';

CREATE UNIQUE INDEX idx_one_pending_cert_per_device
    ON certificates(device_id) WHERE status = 'ISSUED_PENDING_USE';

CREATE INDEX idx_certs_revoked_at_poll
    ON certificates(revoked_at) WHERE status = 'REVOKED';

CREATE TABLE patient_device_assignments (
    assignment_id            UUID PRIMARY KEY,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    patient_id               VARCHAR(64) NOT NULL,
    patient_birth_year       INTEGER NOT NULL,
    active_from              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active_until             TIMESTAMPTZ,
    max_renewal_horizon      TIMESTAMPTZ NOT NULL,
    baseline_state           baseline_lock_state NOT NULL DEFAULT 'CALIBRATING',
    baseline_version         INTEGER NOT NULL DEFAULT 1,
    calibration_batch_ids    UUID[] NOT NULL DEFAULT '{}',
    ref_hr_mean              DOUBLE PRECISION,
    ref_hr_sd                DOUBLE PRECISION,
    ref_hrv_mean             DOUBLE PRECISION,
    ref_hrv_sd               DOUBLE PRECISION,
    ref_spo2_mean            DOUBLE PRECISION,
    ref_spo2_sd              DOUBLE PRECISION,
    status                   assignment_status NOT NULL DEFAULT 'ACTIVE',
    EXCLUDE USING gist (
        device_id WITH =,
        tstzrange(active_from, active_until, '[)') WITH &&
    )
);

CREATE UNIQUE INDEX idx_one_active_assignment_per_device
    ON patient_device_assignments(device_id) WHERE status = 'ACTIVE';

CREATE TABLE telemetry_records (
    batch_id                 UUID NOT NULL,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    assignment_id            UUID NOT NULL REFERENCES patient_device_assignments(assignment_id),
    issuer_key_hash          VARCHAR(64) NOT NULL,
    serial_number            VARCHAR(64) NOT NULL,
    boot_epoch               BIGINT NOT NULL,
    sequence_number          BIGINT NOT NULL,
    measured_at              TIMESTAMPTZ NOT NULL,
    transmitted_at           TIMESTAMPTZ NOT NULL,
    ingested_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    heart_rate_bpm           INTEGER NOT NULL,
    hrv_rmssd_ms             DOUBLE PRECISION NOT NULL,
    spo2_pct                 DOUBLE PRECISION NOT NULL,
    perfusion_index          DOUBLE PRECISION NOT NULL,
    step_cadence_spm         INTEGER NOT NULL DEFAULT 0,
    motion_g_rms             DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    firmware_hash_meta       VARCHAR(128),
    payload_sha256           VARCHAR(64) NOT NULL,
    jws_compact              TEXT NOT NULL,
    trust_state              telemetry_trust_state NOT NULL,
    PRIMARY KEY (device_id, batch_id),
    UNIQUE (device_id, boot_epoch, sequence_number)
);

CREATE INDEX idx_telemetry_quarantine_window
    ON telemetry_records(device_id, ingested_at, measured_at);

CREATE TABLE clinical_alerts (
    alert_id                 UUID PRIMARY KEY,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    assignment_id            UUID REFERENCES patient_device_assignments(assignment_id),
    baseline_version         INTEGER,
    alert_type               alert_severity_type NOT NULL,
    alert_status             alert_lifecycle_status NOT NULL DEFAULT 'ACTIVE',
    triggering_batch_ids     UUID[] NOT NULL,
    explanation_summary      TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retracted_at             TIMESTAMPTZ,
    CONSTRAINT chk_alert_baseline_lineage CHECK (
        (alert_type = 'POTENTIAL_PHYSIOLOGICAL_DRIFT' AND baseline_version IS NOT NULL)
        OR (alert_type <> 'POTENTIAL_PHYSIOLOGICAL_DRIFT' AND baseline_version IS NULL)
    )
);

CREATE INDEX idx_alerts_triggering_batches
    ON clinical_alerts USING gin (triggering_batch_ids);

CREATE TABLE security_audit_log (
    sequence_id              BIGSERIAL PRIMARY KEY,
    event_type               VARCHAR(64) NOT NULL,
    actor_id                 VARCHAR(128) NOT NULL,
    payload_json             JSONB NOT NULL,
    prev_entry_hash          VARCHAR(64) NOT NULL,
    entry_hash               VARCHAR(64) NOT NULL,
    s3_anchor_version_id     VARCHAR(128),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TYPE kms_key_purpose AS ENUM ('ROOT_CA', 'DEVICE_INTERMEDIATE', 'SERVER_TLS_CA', 'REGISTRY_ANCHOR');
CREATE TYPE kms_key_status AS ENUM ('ACTIVE', 'RETIRED');

CREATE TABLE kms_keys (
    kms_key_id   TEXT PRIMARY KEY,
    purpose      kms_key_purpose NOT NULL,
    status       kms_key_status NOT NULL DEFAULT 'ACTIVE',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at   TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_one_active_key_per_purpose
    ON kms_keys(purpose) WHERE status = 'ACTIVE';
