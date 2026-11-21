"use client";

import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { ALL_BOOT_STEPS, api, AuthStatus, Device, Overview, Quarantine, SESSION, TelemetryRow, Unauthorized } from "./api";
import { AlertsPanel } from "./alerts";
import { AuditPanel, PasskeySignIn, ProvisionPanel, stepUp } from "./passkeys";
import s from "./page.module.css";
import { read, subscribe, UNKNOWN, write } from "./storage";

const CODE_KEY = "vitalsshield.adminCode"; // sessionStorage, until WebAuthn (DECISIONS #47)
const CONTRAST_KEY = "vitalsshield.highContrast"; // localStorage
const CRL_URL = "https://127.0.0.1:8444/api/v1/pki/intermediate-crl.pem";
const ATTENTION_HINT: Record<NonNullable<Device["needs_attention"]>, string> = {
  CERT_REVOKED_STATE_ACTIVE: "Certificate revoked but quarantine incomplete: retry quarantine", // DECISIONS #77
  CERT_EXPIRED_NO_SUCCESSOR: "Device must re-enroll (Protocol C) or be re-provisioned", // DECISIONS #87
};

// ---- small helpers ----------------------------------------------------------------------------------------------

function ms(iso: string | null | undefined): number | null {
  return iso ? Date.parse(iso) : null;
}

function ago(iso: string | null, nowMs: number): string {
  const t = ms(iso);
  if (t === null) return "never";
  const sec = Math.max(0, Math.round((nowMs - t) / 1000));
  if (sec < 60) return `${sec} s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)} min ago`;
  return `${Math.floor(sec / 3600)} h ago`;
}

function countdown(iso: string | undefined, nowMs: number): string {
  const t = ms(iso);
  if (t === null) return "";
  const sec = Math.round((t - nowMs) / 1000);
  if (sec <= 0) return "expired";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return h > 0 ? `${h} h ${m} min left` : `${m} min left`;
}

/** "1 min 40 s", "40 s", or the fallback once the instant has passed. */
function secondsLeft(iso: string | null | undefined, nowMs: number, passed: string): string {
  const t = ms(iso);
  if (t === null) return "";
  const sec = Math.ceil((t - nowMs) / 1000);
  if (sec <= 0) return passed;
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const r = sec % 60;
  if (h > 0) return `${h} h ${m} min`;
  return m > 0 ? `${m} min ${r} s` : `${r} s`;
}

function latency(micros: number | undefined): { big: string; small: string } {
  if (micros === undefined) return { big: "n/a", small: "" };
  return { big: `${(micros / 1000).toFixed(1)} ms`, small: `${micros.toLocaleString()} µs` };
}

function short(hex: string | undefined, n = 16): string {
  if (!hex) return "";
  return hex.length > n ? `${hex.slice(0, n)}…` : hex;
}

function time(iso: string | undefined): string {
  return iso ? new Date(iso).toLocaleTimeString() : "";
}

function dateTime(iso: string | undefined): string {
  return iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "";
}

function stateClass(state: string): string {
  switch (state) {
    case "ACTIVE":
    case "ACCEPTED":
    case "HEALTHY":
    case "LOCKED":
    case "RESTING":
      return s.chipOk;
    case "CALIBRATING":
      return s.chipWarn;
    case "QUARANTINED":
    case "REJECTED_IMPLAUSIBLE":
    case "UNHEALTHY":
    case "REVOKED":
    case "DECOMMISSIONED":
      return s.chipDanger;
    case "SIGNAL_DEGRADED":
    case "REAUTH_REQUIRED":
    case "PROVISIONED":
      return s.chipWarn;
    default:
      return s.chipMuted;
  }
}

/** Re-keys its content when the value changes so a 600 ms background flash replays, without layout shift. */
function Flash({ value, children, className }: { value: unknown; children: React.ReactNode; className?: string }) {
  const key = JSON.stringify(value);
  const first = useRef(true);
  const [gen, setGen] = useState(0);
  const prev = useRef(key);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    if (prev.current !== key) {
      prev.current = key;
      setGen((g) => g + 1);
    }
  }, [key]);
  return (
    <span key={gen} className={`${gen > 0 ? s.flash : ""} ${className ?? ""}`}>
      {children}
    </span>
  );
}

function z(v: number | undefined): string {
  return v === undefined ? "" : `${v >= 0 ? "+" : ""}${v.toFixed(1)}`;
}

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return <svg className={s.spark} viewBox="0 0 240 48" aria-hidden />;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = Math.max(1, max - min);
  const pts = values
    .map((v, i) => `${(i / (values.length - 1)) * 236 + 2},${46 - ((v - min) / span) * 42}`)
    .join(" ");
  return (
    <svg className={s.spark} viewBox="0 0 240 48" role="img" aria-label={`heart rate ${min} to ${max} bpm`}>
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
    </svg>
  );
}

// ---- sign-in ----------------------------------------------------------------------------------------------------

function SignIn({ onCode, error }: { onCode: (c: string) => void; error: string | null }) {
  const [value, setValue] = useState("");
  return (
    <main className={s.signin}>
      <form
        className={s.signinCard}
        onSubmit={(e) => {
          e.preventDefault();
          if (value.trim()) onCode(value.trim());
        }}
      >
        <h1>VitalsShield Operator</h1>
        <label htmlFor="code">Admin setup code</label>
        <input
          id="code"
          name="code"
          type="password"
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className={s.input}
          autoFocus
        />
        <p className={s.hint}>
          from <code>var/admin/setup-code</code>
        </p>
        {error && <p className={s.error}>{error}</p>}
        <button type="submit" className={s.primary}>
          Sign in
        </button>
      </form>
    </main>
  );
}

// ---- page -------------------------------------------------------------------------------------------------------

export default function Page() {
  const code = useSyncExternalStore(subscribe, () => read("session", CODE_KEY), () => UNKNOWN);
  const contrastPref = useSyncExternalStore(subscribe, () => read("local", CONTRAST_KEY), () => UNKNOWN);
  const highContrast = contrastPref === "1";
  const [signInError, setSignInError] = useState<string | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [lastOk, setLastOk] = useState<number>(0);
  const [now, setNow] = useState<number>(() => Date.now());
  const [selected, setSelected] = useState<string | null>(null);
  const [rows, setRows] = useState<TelemetryRow[]>([]);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [lookback, setLookback] = useState(10);
  const [reason, setReason] = useState("operator quarantine");
  const [result, setResult] = useState<Quarantine | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [clinician, setClinician] = useState<string | null>(null);
  const overviewInFlight = useRef(false);
  const telemetryInFlight = useRef(false);

  useEffect(() => {
    document.documentElement.dataset.contrast = highContrast ? "high" : "normal";
  }, [highContrast]);

  const setHighContrast = (on: boolean) => write("local", CONTRAST_KEY, on ? "1" : "0");

  // Which admin plane is this (DECISIONS #60)? In webauthn mode a live session cookie skips the sign-in screen.
  const [statusVersion, setStatusVersion] = useState(0);
  const reloadStatus = useCallback(() => setStatusVersion((v) => v + 1), []);
  useEffect(() => {
    let cancelled = false;
    fetch("/api/v1/admin/auth/status", { cache: "no-store", credentials: "same-origin" })
      .then((r) => r.json() as Promise<AuthStatus>)
      .then((st) => {
        if (cancelled) return;
        setAuthStatus(st);
        const stored = read("session", CODE_KEY);
        if (st.mode === "webauthn") {
          if (st.clinician_id) {
            setClinician(st.clinician_id);
            write("session", CODE_KEY, SESSION);
          } else if (stored) {
            write("session", CODE_KEY, null);
          }
        } else if (stored === SESSION) {
          write("session", CODE_KEY, null);
        }
      })
      .catch(() => setAuthStatus({ mode: "bearer" }));
    return () => {
      cancelled = true;
    };
  }, [statusVersion]);

  const signOut = useCallback((message: string | null = null) => {
    if (read("session", CODE_KEY) === SESSION) {
      // Re-read the status after logout: the passkey count may have changed since the page loaded.
      void fetch("/api/v1/admin/session/logout", { method: "POST", credentials: "same-origin" }).finally(reloadStatus);
      setClinician(null);
    }
    write("session", CODE_KEY, null);
    setOverview(null);
    setSelected(null);
    setSignInError(message);
  }, [reloadStatus]);

  const onCode = useCallback((c: string) => {
    setSignInError(null);
    write("session", CODE_KEY, c);
  }, []);

  // Overview poll: every 500 ms while visible, never overlapping (DECISIONS #48).
  useEffect(() => {
    if (!code || code === UNKNOWN) return;
    const tick = async () => {
      setNow(Date.now());
      if (document.visibilityState !== "visible" || overviewInFlight.current) return;
      overviewInFlight.current = true;
      try {
        const o = await api<Overview>(code, "/api/v1/admin/overview");
        setOverview(o);
        setLastOk(Date.now());
      } catch (e) {
        if (e instanceof Unauthorized) signOut("That code was not accepted. Check var/admin/setup-code.");
      } finally {
        overviewInFlight.current = false;
      }
    };
    void tick();
    const id = window.setInterval(tick, 500);
    return () => window.clearInterval(id);
  }, [code, signOut]);

  // Selected device telemetry: every 1 s.
  useEffect(() => {
    if (!code || code === UNKNOWN || !selected) return;
    const tick = async () => {
      if (document.visibilityState !== "visible" || telemetryInFlight.current) return;
      telemetryInFlight.current = true;
      try {
        setRows(await api<TelemetryRow[]>(code, `/api/v1/admin/devices/${encodeURIComponent(selected)}/telemetry?limit=30`));
      } catch (e) {
        if (e instanceof Unauthorized) signOut("Session expired.");
      } finally {
        telemetryInFlight.current = false;
      }
    };
    void tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [code, selected, signOut]);

  const serverNow = useMemo(() => {
    // Relative times use the server clock so a skewed laptop clock cannot mislead.
    if (!overview) return now;
    return ms(overview.server_time)! + (now - lastOk);
  }, [overview, now, lastOk]);

  const dbNow = useMemo(() => {
    // DECISIONS #89: ingested_at and last_ingested_at are stamped by Postgres, so they are compared with its clock.
    if (!overview) return now;
    return ms(overview.db_time)! + (now - lastOk);
  }, [overview, now, lastOk]);

  const device = overview?.devices.find((d) => d.device_id === selected) ?? null;

  const quarantine = async () => {
    if (!code || code === UNKNOWN || !selected) return;
    setBusy(true);
    setActionError(null);
    try {
      const path = `/api/v1/admin/devices/${encodeURIComponent(selected)}/quarantine`;
      // Webauthn mode: begin -> Touch ID over the action digest -> finish (DECISIONS #58). Bearer mode: Phase 5.
      const r =
        code === SESSION
          ? await stepUp<Quarantine>(`${path}/begin`, { lookback_minutes: lookback, reason }, `${path}/finish`)
          : await api<Quarantine>(code, path, {
              method: "POST",
              body: JSON.stringify({ lookback_minutes: lookback, reason }),
            });
      setResult(r);
      setConfirmOpen(false);
    } catch (e) {
      if (e instanceof Unauthorized) signOut("Session expired.");
      const body = (e as { body?: { error?: string } }).body;
      setActionError(body?.error ?? (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const auditUnauthorized = useCallback(() => signOut("Session expired."), [signOut]);

  const restore = async (deviceId: string) => {
    setBusy(true);
    setActionError(null);
    try {
      const path = `/api/v1/admin/devices/${encodeURIComponent(deviceId)}/restore-active`;
      await stepUp(`${path}/begin`, {}, `${path}/finish`);
    } catch (e) {
      if (e instanceof Unauthorized) signOut("Session expired.");
      const body = (e as { body?: { error?: string } }).body;
      setActionError(body?.error ?? (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (code === UNKNOWN || !authStatus) return null; // prerender and hydration: storage is not readable yet
  if (authStatus.mode === "webauthn" && code !== SESSION) {
    return (
      <PasskeySignIn
        status={authStatus}
        error={signInError}
        onSignedIn={(c) => {
          setClinician(c);
          setSignInError(null);
          write("session", CODE_KEY, SESSION);
          reloadStatus();
        }}
      />
    );
  }
  if (!code) return <SignIn onCode={onCode} error={signInError} />;

  const o = overview;
  const stale = !lastOk || now - lastOk > 3000;
  const bootOk = !!o && ALL_BOOT_STEPS.every((st) => o.boot_steps.some((b) => b.step === st));
  const rejectedTotal = o ? Object.values(o.telemetry.jws_rejected).reduce((a, b) => a + b, 0) : 0;
  const rejectedBreakdown = o
    ? Object.entries(o.telemetry.jws_rejected).map(([k, v]) => `${k}: ${v}`).join("\n") || "none"
    : "";
  const lastRev = o?.revocations[0];
  const lat = latency(lastRev?.latency_micros);
  const kmsTitle =
    o?.kms.state === "UNHEALTHY"
      ? "KMS keys missing or disabled: restart the server to rebuild the hierarchy (this revokes every device)"
      : o?.kms.keys.map((k) => `${k.purpose} …${k.arn_suffix}: ${k.enabled === null ? k.error : k.enabled ? "enabled" : "NOT ENABLED"}`).join("\n");

  return (
    <div className={s.page}>
      <header className={s.header}>
        <div className={s.brand}>VitalsShield Operator</div>
        <span className={`${s.pill} ${bootOk ? s.pillOk : s.pillWarn}`} title={o?.boot_steps.map((b) => b.step).join(" → ")}>
          {bootOk ? "Boot complete" : "Booting"}
        </span>
        <span
          className={`${s.pill} ${o?.kms.state === "HEALTHY" ? s.pillOk : o?.kms.state === "UNHEALTHY" ? s.pillDanger : s.pillMuted}`}
          title={kmsTitle}
        >
          KMS {o?.kms.state ?? "…"}
        </span>
        {stale && <span className={`${s.pill} ${s.pillWarn}`}>stale</span>}
        <span className={s.spacer} />
        <span className={s.clock}>{o ? new Date(o.server_time).toLocaleTimeString() : ""}</span>
        <label className={s.toggle}>
          <input type="checkbox" checked={highContrast} onChange={(e) => setHighContrast(e.target.checked)} /> High contrast
        </label>
        {clinician && <span className={s.clock}>signed in as {clinician}</span>}
        <button className={s.ghost} onClick={() => signOut()}>
          Sign out
        </button>
      </header>

      {o && !o.kms.healthy && o.kms.state === "UNHEALTHY" && (
        <div className={s.banner}>KMS keys missing. Restart the server to rebuild the hierarchy. This revokes every device.</div>
      )}

      <section className={s.tiles}>
        <div className={s.tile}>
          <div className={s.tileLabel}>Live mTLS sockets</div>
          <Flash value={o?.sessions.live_count} className={s.tileValue}>{o?.sessions.live_count ?? "…"}</Flash>
        </div>
        <div className={s.tile}>
          <div className={s.tileLabel}>JWS verified</div>
          <Flash value={o?.telemetry.jws_verified} className={s.tileValue}>{o?.telemetry.jws_verified ?? "…"}</Flash>
        </div>
        <div className={s.tile} title={rejectedBreakdown}>
          <div className={s.tileLabel}>JWS rejected</div>
          <Flash value={rejectedTotal} className={s.tileValue}>{o ? rejectedTotal : "…"}</Flash>
        </div>
        <div className={s.tile}>
          <div className={s.tileLabel}>Last revocation latency</div>
          <Flash value={lastRev?.latency_micros} className={s.tileValue}>{lat.big}</Flash>
          <div className={s.tileSub}>{lat.small}</div>
        </div>
        <div className={`${s.tile} ${o && o.alerts.active > 0 ? s.tileDanger : ""}`} title={o ? `acknowledged ${o.alerts.acknowledged} · resolved ${o.alerts.resolved} · dedupe suppressed ${o.clinical.dedupe_suppressed} · unevaluated batches ${o.clinical.unevaluated_count}` : ""}>
          <div className={s.tileLabel}>Active alerts</div>
          <Flash value={o?.alerts.active} className={s.tileValue}>{o?.alerts.active ?? "…"}</Flash>
          <div className={s.tileSub}>{o ? `${o.alerts.acknowledged} acknowledged` : ""}</div>
        </div>
        <div
          className={`${s.tile} ${o && o.clinical.queue_overflows > 0 ? s.tileDanger : ""}`}
          title="DECISIONS #79: batches whose evaluation overflowed the queue or was lost to a restart stay unevaluated and are never replayed"
        >
          <div className={s.tileLabel}>Clinical engine</div>
          <Flash value={o?.clinical.unevaluated_count} className={s.tileValue}>{o?.clinical.unevaluated_count ?? "…"}</Flash>
          <div className={s.tileSub}>
            {o ? `unevaluated · ${o.clinical.queue_overflows} queue overflows (cap ${o.clinical.queue_capacity}) · ${o.clinical.evaluations} evaluated` : ""}
          </div>
        </div>
        <div className={s.tile}>
          <div className={s.tileLabel}>Retracted alerts</div>
          <Flash value={o?.alerts.retracted_by_quarantine} className={s.tileValue}>{o?.alerts.retracted_by_quarantine ?? "…"}</Flash>
          <div className={s.tileSub}>by quarantine</div>
        </div>
        <div className={s.tile}>
          <div className={s.tileLabel}>Deny-list size</div>
          <Flash value={o?.deny_list_size} className={s.tileValue}>{o?.deny_list_size ?? "…"}</Flash>
        </div>
        <div className={`${s.tile} ${o && o.ledger.invariant_violations > 0 ? s.tileDanger : ""}`}>
          <div className={s.tileLabel}>Serial ledger</div>
          <Flash value={o ? [o.ledger.recorded, o.ledger.voided] : null} className={s.tileValue}>
            {o ? `${o.ledger.recorded} / ${o.ledger.voided}` : "…"}
          </Flash>
          <div className={s.tileSub}>
            recorded / voided{o && o.ledger.invariant_violations > 0 ? ` · ${o.ledger.invariant_violations} VIOLATIONS` : ""}
          </div>
        </div>
        <div
          className={`${s.tile} ${o?.clock.state === "RED" ? s.tileDanger : o?.clock.state === "AMBER" ? s.tileWarn : ""}`}
          data-testid="clock-skew"
          title="DECISIONS #98: Postgres clock_timestamp() minus the JVM clock, checked every 60 s. Amber above 2 s, red above 10 s: after a laptop sleep, restart Docker Desktop."
        >
          <div className={s.tileLabel}>Clock skew (DB vs server)</div>
          <Flash value={o?.clock.skew_ms} className={s.tileValue}>
            {o ? (o.clock.skew_ms === null ? "?" : `${o.clock.skew_ms > 0 ? "+" : ""}${o.clock.skew_ms} ms`) : "…"}
          </Flash>
          <div className={s.tileSub}>
            {o ? (
              <span className={`${s.chip} ${o.clock.state === "GREEN" ? s.chipOk : o.clock.state === "AMBER" ? s.chipWarn : o.clock.state === "RED" ? s.chipDanger : s.chipMuted}`} data-testid="clock-skew-state">
                {o.clock.state}
              </span>
            ) : null}
            {o?.clock.checked_at ? ` checked ${time(o.clock.checked_at)}` : ""}
          </div>
        </div>
      </section>

      <section className={s.panel}>
        <h2>Trust chain</h2>
        <div className={s.chain}>
          {(
            [
              ["Root CA", o?.ca.root],
              ["Device Intermediate", o?.ca.device_intermediate],
              ["Server TLS CA", o?.ca.server_tls_ca],
            ] as const
          ).map(([label, c]) => (
            <div key={label} className={s.caCard}>
              <div className={s.caLabel}>{label}</div>
              <div className={s.caSubject}>{c?.subject ?? "…"}</div>
              <div className={s.mono} title={c?.ski_hex}>
                SKI <Flash value={c?.ski_hex}>{short(c?.ski_hex)}</Flash>
              </div>
              <div className={s.muted}>until {c ? new Date(c.not_after).toLocaleDateString() : ""}</div>
            </div>
          ))}
        </div>
        <div className={s.chainNote}>Root → Device Intermediate → device leaves · Root → Server TLS CA → gateway leaf</div>
        {o?.ca.device_intermediate && (
          <div className={s.crlLine}>
            CRL #<Flash value={o.ca.device_intermediate.crl_number}>{o.ca.device_intermediate.crl_number}</Flash>
            {" · "}next update {dateTime(o.ca.device_intermediate.crl_next_update)}
            {" · "}
            <Flash value={o.ca.device_intermediate.crl_entries}>{o.ca.device_intermediate.crl_entries} entries</Flash>
            {" · "}
            <a href={CRL_URL} target="_blank" rel="noreferrer noopener">
              intermediate-crl.pem
            </a>
          </div>
        )}
      </section>

      <section className={s.panel}>
        <h2>Devices</h2>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Device</th>
              <th>State</th>
              <th className={s.num}>Epoch</th>
              <th className={s.num}>Last seq</th>
              <th>Last ingested</th>
              <th>Active cert serial</th>
              <th>DEK anchor</th>
              <th className={s.num}>Sockets</th>
            </tr>
          </thead>
          <tbody>
            {o?.devices.map((d) => (
              <tr
                key={d.device_id}
                className={d.device_id === selected ? s.rowSelected : s.row}
                onClick={() => {
                  setSelected(d.device_id);
                  setRows([]);
                  setResult(null);
                }}
              >
                <td>
                  {d.device_id} {d.dev_seed && <span className={s.badge}>DEV SEED</span>}
                </td>
                <td>
                  <Flash value={d.trust_state}>
                    <span className={`${s.chip} ${stateClass(d.trust_state)}`}>{d.trust_state}</span>
                  </Flash>{" "}
                  {d.needs_attention && (
                    <span
                      className={`${s.chip} ${s.chipWarn}`}
                      data-testid="needs-attention"
                      title={ATTENTION_HINT[d.needs_attention]}
                    >
                      {d.needs_attention === "CERT_EXPIRED_NO_SUCCESSOR" ? d.needs_attention : "NEEDS ATTENTION"}
                    </span>
                  )}
                </td>
                <td className={s.num}>{d.boot_epoch}</td>
                <td className={s.num}>
                  <Flash value={d.last_sequence_num}>{d.last_sequence_num}</Flash>
                </td>
                <td>{ago(d.last_ingested_at, dbNow)}</td>
                <td className={s.mono}>
                  {d.active_cert ? (
                    <>
                      <span title={d.active_cert.serial_display}>{short(d.active_cert.serial_display, 20)}</span>
                      <span className={s.certMeta}>
                        {" "}
                        <span className={`${s.chip} ${stateClass(d.active_cert.status)}`}>{d.active_cert.status}</span>{" "}
                        {d.active_cert.status === "ACTIVE" ? countdown(d.active_cert.not_after, serverNow) : ""}
                      </span>
                    </>
                  ) : (
                    "–"
                  )}
                </td>
                <td>
                  {d.dek_anchor_verified === null ? (
                    <span className={s.muted}>–</span>
                  ) : d.dek_anchor_verified ? (
                    <span className={s.okText}>✓</span>
                  ) : (
                    <span className={s.dangerText}>✗</span>
                  )}
                </td>
                <td className={s.num}>
                  <Flash value={d.live_sockets}>{d.live_sockets}</Flash>
                </td>
              </tr>
            ))}
            {o && o.devices.length === 0 && (
              <tr>
                <td colSpan={8} className={s.muted}>
                  No devices yet. Seed one with ./gradlew :server:seedDemoDevice
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      {device && (
        <section className={s.panel}>
          <div className={s.deviceHead}>
            <h2>
              {device.device_id} {device.dev_seed && <span className={s.badge}>DEV SEED</span>}
            </h2>
            <button
              className={s.danger}
              disabled={device.trust_state !== "ACTIVE" && device.trust_state !== "REAUTH_REQUIRED"}
              onClick={() => {
                setActionError(null);
                setConfirmOpen(true);
              }}
            >
              Quarantine
            </button>
          </div>
          {device.trust_state === "REAUTH_REQUIRED" && (
            <div className={s.reauth} data-testid="reauth-panel">
              <div>
                <span className={`${s.chip} ${s.chipDanger}`}>REAUTH_REQUIRED</span>{" "}
                {device.anomaly ? (
                  <span className={`${s.mono} ${s.code}`} data-testid="reauth-condition">{device.anomaly.condition_code}</span>
                ) : null}
              </div>
              <p className={s.reauthText}>
                {device.anomaly
                  ? device.anomaly.explanation.replace(/([^.!?])$/, "$1.")
                  : "A split-brain trap fired for this device."}{" "}
                Every certificate was revoked and telemetry is untouched. Decide which it is:
              </p>
              <div className={s.reauthActions}>
                <button
                  className={s.primary}
                  disabled={busy || code !== SESSION}
                  title={code === SESSION ? "Passkey step-up: trust_state ACTIVE and epoch_resync_allowed, so the device can re-enroll with a new epoch" : "Needs a passkey session"}
                  onClick={() => void restore(device.device_id)}
                  data-testid="reauth-restore"
                >
                  {busy ? "Waiting for Touch ID…" : "Restore (benign reset)"}
                </button>
                <button
                  className={s.danger}
                  disabled={busy}
                  onClick={() => {
                    setActionError(null);
                    setConfirmOpen(true);
                  }}
                  data-testid="reauth-quarantine"
                >
                  Quarantine (confirmed compromise)
                </button>
              </div>
            </div>
          )}
          <div className={s.certGrid} data-testid="cert-card">
            <div>
              <div className={s.muted}>Current certificate</div>
              {device.active_cert && device.active_cert.status === "ACTIVE" ? (
                <Flash value={device.active_cert.serial_display}>
                  <div className={s.mono} data-testid="cert-active">{device.active_cert.serial_display}</div>
                </Flash>
              ) : (
                <div className={s.muted}>none ACTIVE</div>
              )}
            </div>
            <div>
              <div className={s.muted}>Next renewal due</div>
              <div data-testid="cert-renewal-due">
                {device.active_cert && device.active_cert.status === "ACTIVE"
                  ? `${time(device.active_cert.renewal_due_at)} (${secondsLeft(device.active_cert.renewal_due_at, serverNow, "due now")})`
                  : "–"}
              </div>
            </div>
            <div>
              <div className={s.muted}>Pending</div>
              {device.pending_cert ? (
                <div data-testid="cert-pending">
                  <span className={s.mono}>{short(device.pending_cert.serial_display, 20)}</span>{" "}
                  <span className={`${s.chip} ${s.chipWarn}`}>awaiting first batch</span>
                </div>
              ) : (
                <div className={s.muted}>none</div>
              )}
            </div>
            <div>
              <div className={s.muted}>Renewed (previous)</div>
              {device.renewed_cert ? (
                <div data-testid="cert-renewed">
                  <span className={s.mono}>{short(device.renewed_cert.serial_display, 20)}</span>{" "}
                  {device.renewed_cert.grace_expires_at && ms(device.renewed_cert.grace_expires_at)! > serverNow ? (
                    <span className={`${s.chip} ${s.chipWarn}`}>
                      grace {secondsLeft(device.renewed_cert.grace_expires_at, serverNow, "0 s")}
                    </span>
                  ) : (
                    <span className={`${s.chip} ${s.chipMuted}`}>superseded</span>
                  )}
                </div>
              ) : (
                <div className={s.muted}>none</div>
              )}
            </div>
          </div>
          {device.active_cert && (
            <div className={s.certGrid}>
              {device.active_cert.status !== "ACTIVE" && (
                <div>
                  <div className={s.muted}>Last certificate</div>
                  <div>
                    <span className={s.mono}>{short(device.active_cert.serial_display, 20)}</span>{" "}
                    <span className={`${s.chip} ${stateClass(device.active_cert.status)}`}>{device.active_cert.status}</span>
                  </div>
                </div>
              )}
              <div>
                <div className={s.muted}>x5t#S256</div>
                <div className={s.mono}>{device.active_cert.thumbprint_s256}</div>
              </div>
              <div>
                <div className={s.muted}>Validity</div>
                <div>
                  {dateTime(device.active_cert.not_before)} → {dateTime(device.active_cert.not_after)}
                </div>
              </div>
            </div>
          )}
          {device.needs_attention && (
            <div className={s.attention} data-testid="attention-hint">
              {device.needs_attention === "CERT_EXPIRED_NO_SUCCESSOR" && (
                <span className={`${s.chip} ${s.chipWarn}`}>CERT_EXPIRED_NO_SUCCESSOR</span>
              )}{" "}
              {ATTENTION_HINT[device.needs_attention]}
            </div>
          )}
          {device.assignment && (
            <Flash value={[device.assignment.baseline_state, device.assignment.baseline_version]}>
              <div className={s.baseline}>
                <div>
                  <div className={s.muted}>Baseline</div>
                  <div>
                    <span className={`${s.chip} ${stateClass(device.assignment.baseline_state)}`}>
                      {device.assignment.baseline_state}
                    </span>{" "}
                    v{device.assignment.baseline_version}
                  </div>
                </div>
                {device.assignment.baseline_state === "CALIBRATING" && (
                  <div>
                    <div className={s.muted}>Calibration</div>
                    <div>
                      {device.assignment.calibration_count} / {device.assignment.calibration_size} resting batches
                    </div>
                  </div>
                )}
                {device.assignment.ref && (
                  <>
                    <div>
                      <div className={s.muted}>HR ref</div>
                      <div>
                        {device.assignment.ref.hr_mean.toFixed(1)} ± {device.assignment.ref.hr_sd.toFixed(1)} bpm
                      </div>
                    </div>
                    <div>
                      <div className={s.muted}>HRV ref</div>
                      <div>
                        {device.assignment.ref.hrv_mean.toFixed(1)} ± {device.assignment.ref.hrv_sd.toFixed(1)} ms
                      </div>
                    </div>
                    <div>
                      <div className={s.muted}>SpO2 ref</div>
                      <div>
                        {device.assignment.ref.spo2_mean.toFixed(1)} ± {device.assignment.ref.spo2_sd.toFixed(2)} %
                      </div>
                    </div>
                  </>
                )}
                <div>
                  <div className={s.muted}>Streaks</div>
                  <div>
                    drift {device.assignment.drift_breach_streak} · low perfusion {device.assignment.degraded_critical_streak}
                  </div>
                </div>
              </div>
            </Flash>
          )}
          {result && result.device_id === device.device_id && (
            <div className={s.result}>
              <div className={s.resultBig}>{latency(result.revocation_latency_micros).big}</div>
              <div>
                revocation latency · {result.certs_revoked} cert(s) revoked · {result.channels_closed} socket(s) closed ·{" "}
                {result.batches_quarantined} batches quarantined · {result.baselines_reset} baselines reset ·{" "}
                {result.alerts_retracted} alerts retracted
              </div>
              {result.approved_by && <div className={s.approved}>approved by {result.approved_by} (passkey step-up)</div>}
            </div>
          )}
          <div className={s.sparkRow}>
            <span className={s.muted}>Heart rate</span>
            <Sparkline values={rows.slice().reverse().map((r) => r.heart_rate_bpm)} />
          </div>
          <table className={s.table}>
            <thead>
              <tr>
                <th className={s.num}>Seq</th>
                <th>State</th>
                <th>Activity</th>
                <th className={s.num}>HR</th>
                <th className={s.num}>SpO2</th>
                <th className={s.num}>HRV</th>
                <th className={s.num}>Perfusion</th>
                <th className={s.num}>z HR / HRV / SpO2</th>
                <th>Measured</th>
                <th>Ingested</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.sequence_number}-${r.batch_id_short}`} className={r.trust_state === "QUARANTINED" ? s.rowQuarantined : ""}>
                  <td className={s.num}>{r.sequence_number}</td>
                  <td>
                    <span className={`${s.chip} ${stateClass(r.trust_state)}`}>{r.trust_state}</span>
                  </td>
                  <td>
                    {r.activity_context ? (
                      <span className={`${s.chip} ${stateClass(r.activity_context)}`}>{r.activity_context}</span>
                    ) : (
                      <span className={s.muted}>–</span>
                    )}
                    {!r.clinical_evaluated && (r.trust_state === "ACCEPTED" || r.trust_state === "SIGNAL_DEGRADED") && (
                      <span className={s.unevaluated} title="clinical_evaluated_at is NULL">unevaluated</span>
                    )}
                  </td>
                  <td className={s.num}>{r.heart_rate_bpm}</td>
                  <td className={s.num}>{r.spo2_pct.toFixed(1)}</td>
                  <td className={s.num}>{r.hrv_rmssd_ms.toFixed(1)}</td>
                  <td className={s.num}>{r.perfusion_index.toFixed(2)}</td>
                  <td className={s.num}>{r.z ? `${z(r.z.hr)} / ${z(r.z.hrv)} / ${z(r.z.spo2)}` : "–"}</td>
                  <td>{time(r.measured_at)}</td>
                  <td>{ago(r.ingested_at, dbNow)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <AlertsPanel code={code} selected={selected} onUnauthorized={auditUnauthorized} />

      {code === SESSION && <ProvisionPanel onUnauthorized={() => signOut("Session expired.")} />}

      <section className={s.panel}>
        <h2>Revocation log</h2>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Time</th>
              <th>Device</th>
              <th>Serial</th>
              <th>Reason</th>
              <th className={s.num}>Sockets closed</th>
              <th className={s.num}>Latency</th>
            </tr>
          </thead>
          <tbody>
            {o?.revocations.map((r) => (
              <tr key={`${r.serial_display}-${r.revoked_at}`}>
                <td>{time(r.revoked_at)}</td>
                <td>{r.device_id ?? "–"}</td>
                <td className={s.mono} title={r.serial_display}>
                  {short(r.serial_display, 20)}
                </td>
                <td>{r.reason}</td>
                <td className={s.num}>{r.channels_closed}</td>
                <td className={s.num}>{latency(r.latency_micros).big}</td>
              </tr>
            ))}
            {o && o.revocations.length === 0 && (
              <tr>
                <td colSpan={6} className={s.muted}>
                  No revocations since boot.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      <section className={s.panel}>
        <h2>Renewal log</h2>
        <p className={s.muted}>Protocol B renewals and Protocol C re-enrollments, newest first.</p>
        <table className={s.table} data-testid="renewal-log">
          <thead>
            <tr>
              <th>Device</th>
              <th>Old serial</th>
              <th>New serial</th>
              <th>Issued</th>
              <th>Activated</th>
              <th>Grace ended</th>
            </tr>
          </thead>
          <tbody>
            {o?.renewals.map((r) => (
              <tr key={r.new_serial_display}>
                <td>{r.device_id}</td>
                {r.kind === "REENROLL" ? (
                  <td data-testid="renewal-reenroll">
                    <span className={`${s.chip} ${s.chipWarn}`}>RE-ENROLLED via DEK</span>{" "}
                    <span className={s.muted}>{r.reenroll_reason}</span>
                  </td>
                ) : (
                  <td className={s.mono} title={r.old_serial_display ?? ""}>{short(r.old_serial_display ?? "–", 16)}</td>
                )}
                <td className={s.mono} title={r.new_serial_display}>
                  {short(r.new_serial_display, 16)}
                  {r.new_status === "REVOKED" && (
                    <span className={`${s.chip} ${s.chipDanger}`} title={r.new_revocation_reason ?? ""}>
                      {r.new_revocation_reason === "REPLACED_BEFORE_USE" ? "replaced before use" : "revoked"}
                    </span>
                  )}
                </td>
                <td>{time(r.issued_at)}</td>
                <td>{r.activated_at ? time(r.activated_at) : r.new_status === "ISSUED_PENDING_USE" ? "awaiting first batch" : "–"}</td>
                <td>
                  {r.old_status === "REVOKED" || r.old_status === "EXPIRED" ? (
                    // Phase 10a.1: a predecessor that is final (quarantined, swept) shows its status, never a countdown.
                    <span data-testid="renewal-final-status">
                      <span className={`${s.chip} ${r.old_status === "REVOKED" ? s.chipDanger : s.chipMuted}`} title={r.old_revocation_reason ?? ""}>
                        {r.old_status}
                      </span>
                      {r.old_status === "EXPIRED" && r.grace_ended_at ? ` grace ended ${time(r.grace_ended_at)}` : ""}
                    </span>
                  ) : r.grace_ended_at ? (
                    `${time(r.grace_ended_at)}${r.grace_sockets_closed !== null ? ` · ${r.grace_sockets_closed} socket(s) closed` : ""}`
                  ) : r.grace_expires_at ? (
                    `in ${secondsLeft(r.grace_expires_at, serverNow, "0 s")}`
                  ) : (
                    "–"
                  )}
                </td>
              </tr>
            ))}
            {o && o.renewals.length === 0 && (
              <tr>
                <td colSpan={6} className={s.muted}>
                  No renewals yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      {code === SESSION && <AuditPanel onUnauthorized={auditUnauthorized} />}

      {confirmOpen && device && (
        <div className={s.modalBack} role="dialog" aria-modal="true" aria-label="Confirm quarantine">
          <div className={s.modal}>
            <h2>Quarantine {device.device_id}?</h2>
            <p className={s.muted}>
              Revokes every certificate of this device, closes its sockets, clears its DEK, and quarantines recent telemetry.
            </p>
            <label htmlFor="lookback">Lookback minutes</label>
            <input
              id="lookback"
              type="number"
              min={1}
              max={1440}
              value={lookback}
              onChange={(e) => setLookback(Number(e.target.value))}
              className={s.input}
            />
            <label htmlFor="reason">Reason</label>
            <input id="reason" value={reason} maxLength={128} onChange={(e) => setReason(e.target.value)} className={s.input} />
            {actionError && <p className={s.error}>{actionError}</p>}
            <div className={s.modalActions}>
              <button className={s.ghost} onClick={() => setConfirmOpen(false)} disabled={busy}>
                Cancel
              </button>
              <button className={s.danger} onClick={quarantine} disabled={busy || !reason.trim() || lookback < 1 || lookback > 1440}>
                {busy ? (code === SESSION ? "Waiting for Touch ID…" : "Quarantining…") : code === SESSION ? "Approve quarantine with passkey" : "Quarantine now"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
