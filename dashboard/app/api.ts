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
  assignment: { assignment_id: string; patient_id: string; baseline_state: string; baseline_version: number } | null;
  active_cert: { serial_display: string; not_before: string; not_after: string; status: string; thumbprint_s256: string } | null;
  live_sockets: number;
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
