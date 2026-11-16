"use client";

import { useEffect, useState } from "react";
import { api, Audit, AuthStatus, Ceremony, SESSION, Unauthorized } from "./api";
import s from "./page.module.css";
import { createPasskey, getAssertion } from "./webauthn";

function message(e: unknown): string {
  const body = (e as { body?: { error?: string } }).body;
  if (body?.error) return body.error;
  if (e instanceof DOMException && e.name === "NotAllowedError") return "Passkey prompt was cancelled or timed out.";
  return (e as Error).message;
}

/** begin -> Touch ID -> finish, for the ceremony-id steps (provision, quarantine, restore). */
export async function stepUp<T>(beginPath: string, beginBody: unknown, finishPath: string): Promise<T> {
  const begun = await api<Ceremony>(SESSION, beginPath, { method: "POST", body: JSON.stringify(beginBody ?? {}) });
  const credential = await getAssertion(begun.options);
  return api<T>(SESSION, finishPath, {
    method: "POST",
    body: JSON.stringify({ ceremony_id: begun.ceremony_id, credential }),
  });
}

async function signInWithPasskey(): Promise<string> {
  const begun = await api<{ options: Record<string, unknown> }>(SESSION, "/api/v1/admin/session/begin", { method: "POST", body: "{}" });
  const credential = await getAssertion(begun.options);
  const r = await api<{ clinician_id: string }>(SESSION, "/api/v1/admin/session/finish", {
    method: "POST",
    body: JSON.stringify({ credential }),
  });
  return r.clinician_id;
}

/** Webauthn-mode sign-in. With zero clinician passkeys: the first-run registration form (setup code once). */
export function PasskeySignIn({ status, onSignedIn, error }: { status: AuthStatus; onSignedIn: (c: string) => void; error: string | null }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(error);
  const [clinicianId, setClinicianId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [setupCode, setSetupCode] = useState("");
  const firstRun = status.passkeys_registered === 0;

  const signIn = async () => {
    setBusy(true);
    setErr(null);
    try {
      onSignedIn(await signInWithPasskey());
    } catch (e) {
      setErr(e instanceof Unauthorized ? "Passkey not accepted." : message(e));
    } finally {
      setBusy(false);
    }
  };

  const register = async () => {
    setBusy(true);
    setErr(null);
    try {
      const begun = await api<{ options: Record<string, unknown> }>(setupCode.trim(), "/api/v1/admin/passkeys/register/begin", {
        method: "POST",
        body: JSON.stringify({ clinician_id: clinicianId.trim(), display_name: displayName.trim() }),
      });
      const credential = await createPasskey(begun.options);
      await api(SESSION, "/api/v1/admin/passkeys/register/finish", { method: "POST", body: JSON.stringify({ credential }) });
      onSignedIn(await signInWithPasskey());
    } catch (e) {
      setErr(e instanceof Unauthorized ? "Setup code not accepted, or a passkey already exists." : message(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className={s.signin}>
      <form
        className={s.signinCard}
        onSubmit={(e) => {
          e.preventDefault();
          if (firstRun) void register();
          else void signIn();
        }}
      >
        <h1>VitalsShield Operator</h1>
        {firstRun ? (
          <>
            <p className={s.hint}>No clinician passkey yet. Register the first one with the setup code.</p>
            <label htmlFor="clinician">Clinician id</label>
            <input id="clinician" value={clinicianId} onChange={(e) => setClinicianId(e.target.value)} className={s.input} autoFocus />
            <label htmlFor="display">Display name</label>
            <input id="display" value={displayName} onChange={(e) => setDisplayName(e.target.value)} className={s.input} />
            <label htmlFor="code">Admin setup code</label>
            <input id="code" type="password" autoComplete="off" value={setupCode} onChange={(e) => setSetupCode(e.target.value)} className={s.input} />
            <p className={s.hint}>
              from <code>var/admin/setup-code</code>; only works while no passkey exists
            </p>
          </>
        ) : (
          <p className={s.hint}>Sign in with the passkey on this Mac (Touch ID).</p>
        )}
        {err && <p className={s.error}>{err}</p>}
        <button
          type="submit"
          className={s.primary}
          disabled={busy || (firstRun && (!clinicianId.trim() || !displayName.trim() || !setupCode.trim()))}
        >
          {busy ? "Waiting for passkey…" : firstRun ? "Register passkey" : "Sign in with passkey"}
        </button>
      </form>
    </main>
  );
}

type Provisioned = { device_id: string; bootstrap_token: string; expires_at: string; assignment_id: string; approved_by: string };

/** Provision a device: Touch ID approves the ProvisioningDigest; the token is shown once. */
export function ProvisionPanel({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [deviceId, setDeviceId] = useState("");
  const [patientId, setPatientId] = useState("");
  const [birthYear, setBirthYear] = useState(1985);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<Provisioned | null>(null);
  const [copied, setCopied] = useState(false);

  const provision = async () => {
    setBusy(true);
    setErr(null);
    setDone(null);
    setCopied(false);
    try {
      setDone(
        await stepUp<Provisioned>(
          "/api/v1/admin/devices/provision/begin",
          { device_id: deviceId.trim(), patient_id: patientId.trim(), patient_birth_year: birthYear },
          "/api/v1/admin/devices/provision/finish",
        ),
      );
    } catch (e) {
      if (e instanceof Unauthorized) onUnauthorized();
      setErr(message(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={s.panel}>
      <h2>Provision device</h2>
      <form
        className={s.provisionForm}
        onSubmit={(e) => {
          e.preventDefault();
          void provision();
        }}
      >
        <label>
          Device id
          <input value={deviceId} onChange={(e) => setDeviceId(e.target.value)} className={s.input} placeholder="dev_touchid_001" />
        </label>
        <label>
          Patient id
          <input value={patientId} onChange={(e) => setPatientId(e.target.value)} className={s.input} placeholder="patient-001" />
        </label>
        <label>
          Birth year
          <input type="number" min={1900} max={2100} value={birthYear} onChange={(e) => setBirthYear(Number(e.target.value))} className={s.input} />
        </label>
        <button type="submit" className={s.primary} disabled={busy || !deviceId.trim() || !patientId.trim()}>
          {busy ? "Waiting for Touch ID…" : "Approve with passkey"}
        </button>
      </form>
      {err && <p className={s.error}>{err}</p>}
      {done && (
        <div className={s.tokenBox}>
          <div className={s.muted}>
            Bootstrap token for {done.device_id}, approved by {done.approved_by}. Shown once; expires {new Date(done.expires_at).toLocaleTimeString()}.
          </div>
          <div className={s.tokenRow}>
            <code className={s.mono}>{done.bootstrap_token}</code>
            <button
              className={s.ghost}
              onClick={() => {
                void navigator.clipboard.writeText(done.bootstrap_token).then(() => setCopied(true));
              }}
            >
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

/** The hash-chained audit log (DECISIONS #62), re-verified server-side on every fetch. */
export function AuditPanel({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [audit, setAudit] = useState<Audit | null>(null);
  useEffect(() => {
    let stop = false;
    const tick = async () => {
      if (document.visibilityState !== "visible") return;
      try {
        const a = await api<Audit>(SESSION, "/api/v1/admin/audit?limit=20");
        if (!stop) setAudit(a);
      } catch (e) {
        if (e instanceof Unauthorized) onUnauthorized();
      }
    };
    void tick();
    const id = window.setInterval(tick, 5000);
    return () => {
      stop = true;
      window.clearInterval(id);
    };
  }, [onUnauthorized]);

  return (
    <section className={s.panel}>
      <h2>
        Audit log{" "}
        {audit && (
          <span className={`${s.pill} ${audit.chain_valid ? s.pillOk : s.pillDanger}`}>
            {audit.chain_valid ? `chain valid · ${audit.total_entries} entries` : `chain BROKEN at #${audit.first_broken_sequence_id}`}
          </span>
        )}
      </h2>
      <table className={s.table}>
        <thead>
          <tr>
            <th>#</th>
            <th>Time</th>
            <th>Event</th>
            <th>Actor</th>
            <th>Device</th>
            <th>Entry hash</th>
          </tr>
        </thead>
        <tbody>
          {audit?.entries.map((e) => (
            <tr key={e.sequence_id}>
              <td>{e.sequence_id}</td>
              <td>{new Date(e.created_at).toLocaleTimeString()}</td>
              <td>{e.event_type}</td>
              <td>{e.actor_id}</td>
              <td>{(e.payload.device_id as string) ?? "–"}</td>
              <td className={s.mono}>{e.entry_hash.slice(0, 16)}…</td>
            </tr>
          ))}
          {audit && audit.entries.length === 0 && (
            <tr>
              <td colSpan={6} className={s.muted}>
                No entries yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}
