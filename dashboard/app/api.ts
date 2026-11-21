// Types mirror GET /api/v1/admin/overview exactly (field names are a contract with AdminOverviewService).

export type KmsKey = { purpose: string; arn_suffix: string; enabled: boolean | null; checked_at: string; error?: string };

export type CaEntry = {
  subject: string;
  ski_hex: string;
  not_after: string;
  crl_number?: number;
  crl_next_update?: string;
  crl_entries?: number;
};

export type Device = {
  device_id: string;
  trust_state: string;
  boot_epoch: number;
  last_sequence_num: number;
  last_ingested_at: string | null;
  dev_seed: boolean;
  dek_anchor_verified: boolean | null;
  assignment: Assignment | null;
  active_cert: {
    serial_display: string;
    not_before: string;
    not_after: string;
    status: string;
    thumbprint_s256: string;
    /** DECISIONS #83: not_before + 2/3 of the validity. */
    renewal_due_at: string;
  } | null;
  /** Protocol B: renewed, waiting for its first accepted batch. */
  pending_cert: LifecycleCert | null;
  /** Protocol B: superseded, accepted until grace_expires_at. */
  renewed_cert: LifecycleCert | null;
  live_sockets: number;
  /** DECISIONS #92: the newest SECURITY_ANOMALY_ALERT, set while the device is REAUTH_REQUIRED. */
  anomaly: { alert_id: string; condition_code: string; explanation: string; created_at: string } | null;
  /**
   * DECISIONS #77: certificate revoked but the quarantine transaction did not commit.
   * DECISIONS #87: newest certificate EXPIRED with no ACTIVE or pending successor.
   */
  needs_attention: "CERT_REVOKED_STATE_ACTIVE" | "CERT_EXPIRED_NO_SUCCESSOR" | null;
};

export type LifecycleCert = {
  serial_display: string;
  issued_at: string;
  not_after: string;
  grace_expires_at: string | null;
  grace_ended?: boolean;
};

/** One Protocol B renewal (GET /api/v1/admin/overview renewals[], newest first). */
export type Renewal = {
  device_id: string;
  /** RENEW (Protocol B) or REENROLL (Protocol C, "RE-ENROLLED via DEK"). */
  kind: "RENEW" | "REENROLL";
  /** Protocol C only: cert_expired, epoch_resync or no_usable_cert. */
  reenroll_reason: string | null;
  old_serial_display: string | null;
  new_serial_display: string;
  new_status: string;
  new_revocation_reason: string | null;
  issued_at: string;
  activated_at: string | null;
  grace_expires_at: string | null;
  grace_ended_at: string | null;
  grace_sockets_closed: number | null;
  /** The predecessor's current status (RENEWED during grace; REVOKED or EXPIRED once it is final). */
  old_status: string | null;
  old_revocation_reason: string | null;
};

export type Baseline = {
  hr_mean: number;
  hr_sd: number;
  hrv_mean: number;
  hrv_sd: number;
  spo2_mean: number;
  spo2_sd: number;
};

export type Assignment = {
  assignment_id: string;
  patient_id: string;
  baseline_state: "CALIBRATING" | "LOCKED";
  baseline_version: number;
  calibration_count: number;
  calibration_size: number;
  ref: Baseline | null;
  degraded_critical_streak: number;
  drift_breach_streak: number;
  resting_since: string | null;
};

export type Alert = {
  alert_id: string;
  device_id: string;
  assignment_id: string | null;
  alert_type: string;
  condition_code: string | null;
  alert_status: "ACTIVE" | "ACKNOWLEDGED" | "RETRACTED_BY_QUARANTINE" | "RESOLVED";
  explanation: string;
  triggering_batch_count: number;
  triggering_batch_ids_short: string[];
  baseline_version: number | null;
  created_at: string;
  retracted_at: string | null;
};

export type Revocation = {
  serial_display: string;
  device_id: string | null;
  reason: string;
  revoked_at: string;
  channels_closed: number;
  latency_micros: number;
};

export type Quarantine = {
  device_id: string;
  at: string;
  certs_revoked: number;
  channels_closed: number;
  revocation_latency_micros: number;
  batches_quarantined: number;
  baselines_reset: number;
  alerts_retracted: number;
  approved_by?: string;
};

export type AuditEntry = {
  sequence_id: number;
  event_type: string;
  actor_id: string;
  payload: Record<string, unknown>;
  entry_hash: string;
  created_at: string;
};

export type Audit = { chain_valid: boolean; first_broken_sequence_id: number | null; total_entries: number; entries: AuditEntry[] };

export type Overview = {
  server_time: string;
  /** Postgres now(): relative times of Postgres-stamped columns use it (DECISIONS #89). */
  db_time: string;
  /** DECISIONS #98: Postgres clock_timestamp() minus the JVM clock. */
  clock: { skew_ms: number | null; checked_at: string | null; state: "UNKNOWN" | "GREEN" | "AMBER" | "RED"; error: string | null };
  boot_steps: { step: string; at: string }[];
  kms: { healthy: boolean; state: "HEALTHY" | "UNHEALTHY" | "UNKNOWN"; keys: KmsKey[] };
  ca: { root?: CaEntry; device_intermediate?: CaEntry; server_tls_ca?: CaEntry };
  sessions: { live_count: number; by_device: Record<string, number> };
  deny_list_size: number;
  telemetry: {
    jws_verified: number;
    jws_rejected: Record<string, number>;
    accepted: number;
    idempotent_retries: number;
    conflicts: Record<string, number>;
  };
  ledger: { recorded: number; voided: number; reserved: number; invariant_violations: number };
  revocations: Revocation[];
  quarantines: Quarantine[];
  devices: Device[];
  renewals: Renewal[];
  alerts: { active: number; acknowledged: number; retracted_by_quarantine: number; resolved: number };
  clinical: {
    evaluations: number;
    evaluation_failures: number;
    dedupe_suppressed: number;
    alerts_created: Record<string, number>;
    calibration_size: number;
    /** DECISIONS #79: queue overflow and evaluations lost to a restart. */
    unevaluated_count: number;
    queue_overflows: number;
    queue_capacity: number;
  };
};

export type TelemetryRow = {
  batch_id_short: string;
  sequence_number: number;
  measured_at: string;
  ingested_at: string;
  trust_state: string;
  heart_rate_bpm: number;
  spo2_pct: number;
  hrv_rmssd_ms: number;
  perfusion_index: number;
  step_cadence_spm: number;
  motion_g_rms: number;
  boot_epoch: number;
  activity_context: "RESTING" | "EXERTION" | null;
  clinical_evaluated: boolean;
  z: { hr: number; hrv: number; spo2: number } | null;
};

export const ALL_BOOT_STEPS = [
  "RECONCILED",
  "SERIALS_SWEPT",
  "GATEWAY_TLS_ISSUED",
  "TRUST_ANCHORS_LOADED",
  "DENY_LIST_SEEDED",
  "CRLS_PUBLISHED",
  "ADMIN_CODE_ISSUED",
  "LISTENERS_BOUND",
];

export class Unauthorized extends Error {}

/** Stored in place of a setup code in webauthn mode: the HttpOnly session cookie authenticates (DECISIONS #59). */
export const SESSION = "__passkey_session__";

export type AuthStatus = { mode: "webauthn" | "bearer"; passkeys_registered?: number; clinician_id?: string | null };

export type Ceremony = { ceremony_id: string; options: Record<string, unknown> };

export async function api<T>(code: string, path: string, init?: RequestInit): Promise<T> {
  const auth: Record<string, string> = code === SESSION ? {} : { Authorization: `Bearer ${code}` };
  const json: Record<string, string> = init?.body ? { "Content-Type": "application/json" } : {};
  const res = await fetch(path, {
    ...init,
    cache: "no-store",
    credentials: "same-origin",
    headers: { ...json, ...(init?.headers ?? {}), ...auth },
  });
  if (res.status === 401) {
    throw new Unauthorized("unauthorized");
  }
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw Object.assign(new Error(`HTTP ${res.status}`), { status: res.status, body });
  }
  return body as T;
}
