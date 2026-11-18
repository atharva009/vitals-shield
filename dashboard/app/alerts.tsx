"use client";

import { useEffect, useState } from "react";
import { Alert, api, SESSION, Unauthorized } from "./api";
import s from "./page.module.css";

const TYPE_LABEL: Record<string, string> = {
  ACUTE_PHYSIOLOGICAL_ALERT: "ACUTE",
  LOW_PERFUSION_CRITICAL_ALERT: "LOW PERFUSION",
  POTENTIAL_PHYSIOLOGICAL_DRIFT: "DRIFT",
  SECURITY_ANOMALY_ALERT: "SECURITY",
};

/** SECURITY_ANOMALY_ALERT rows first (DECISIONS #92), each group newest first as the server sent it. */
function pinned(alerts: Alert[]): Alert[] {
  const security = alerts.filter((a) => a.alert_type === "SECURITY_ANOMALY_ALERT");
  return [...security, ...alerts.filter((a) => a.alert_type !== "SECURITY_ANOMALY_ALERT")];
}

function statusClass(status: Alert["alert_status"]): string {
  switch (status) {
    case "ACTIVE":
      return s.chipDanger;
    case "ACKNOWLEDGED":
      return s.chipWarn;
    case "RESOLVED":
      return s.chipOk;
    default:
      return s.chipMuted;
  }
}

/**
 * Clinical alerts, newest first, polled every second. Acknowledge and Resolve need a passkey session (DECISIONS #76);
 * a RETRACTED_BY_QUARANTINE alert is shown struck through with its retraction time and cannot change.
 */
export function AlertsPanel({
  code,
  selected,
  onUnauthorized,
}: {
  code: string;
  selected: string | null;
  onUnauthorized: () => void;
}) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [onlySelected, setOnlySelected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const filter = onlySelected && selected ? selected : null;

  useEffect(() => {
    let stop = false;
    let inFlight = false;
    const tick = async () => {
      if (document.visibilityState !== "visible" || inFlight) return;
      inFlight = true;
      try {
        const q = filter ? `?device_id=${encodeURIComponent(filter)}&limit=100` : "?limit=100";
        const a = await api<Alert[]>(code, `/api/v1/admin/alerts${q}`);
        if (!stop) setAlerts(a);
      } catch (e) {
        if (e instanceof Unauthorized) onUnauthorized();
      } finally {
        inFlight = false;
      }
    };
    void tick();
    const id = window.setInterval(tick, 1000);
    return () => {
      stop = true;
      window.clearInterval(id);
    };
  }, [code, filter, onUnauthorized]);

  const act = async (a: Alert, action: "acknowledge" | "resolve") => {
    setBusy(a.alert_id);
    setError(null);
    try {
      await api(code, `/api/v1/admin/alerts/${a.alert_id}/${action}`, { method: "POST", body: "{}" });
    } catch (e) {
      if (e instanceof Unauthorized) onUnauthorized();
      const body = (e as { body?: { error?: string; alert_status?: string } }).body;
      setError(body?.error ? `${body.error}${body.alert_status ? ` (now ${body.alert_status})` : ""}` : (e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className={s.panel}>
      <div className={s.deviceHead}>
        <h2>Clinical alerts</h2>
        <label className={s.toggle}>
          <input
            type="checkbox"
            checked={onlySelected}
            disabled={!selected}
            onChange={(e) => setOnlySelected(e.target.checked)}
          />{" "}
          {selected ? `only ${selected}` : "select a device to filter"}
        </label>
      </div>
      {error && <p className={s.error}>{error}</p>}
      <table className={s.table}>
        <thead>
          <tr>
            <th>Created</th>
            <th>Device</th>
            <th>Type</th>
            <th>Condition</th>
            <th>Explanation</th>
            <th className={s.num}>Batches</th>
            <th>Baseline</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {pinned(alerts).map((a) => {
            const retracted = a.alert_status === "RETRACTED_BY_QUARANTINE";
            const security = a.alert_type === "SECURITY_ANOMALY_ALERT";
            return (
              <tr
                key={a.alert_id}
                className={`${retracted ? s.rowRetracted : ""} ${security ? s.rowPinned : ""}`}
                data-testid={security ? "alert-security" : undefined}
              >
                <td>
                  {security && (
                    <span className={`${s.chip} ${s.chipDanger}`} title="Security anomalies are pinned to the top">
                      PINNED
                    </span>
                  )}{" "}
                  {new Date(a.created_at).toLocaleTimeString()}
                </td>
                <td>{a.device_id}</td>
                <td>
                  <span className={`${s.chip} ${s.chipMuted}`}>{TYPE_LABEL[a.alert_type] ?? a.alert_type}</span>
                </td>
                <td className={`${s.mono} ${s.code}`}>{a.condition_code ?? "–"}</td>
                <td>{a.explanation}</td>
                <td className={s.num} title={a.triggering_batch_ids_short.join("\n")}>
                  {a.triggering_batch_count}
                </td>
                <td>{a.baseline_version !== null ? `v${a.baseline_version}` : "–"}</td>
                <td>
                  <span className={`${s.chip} ${statusClass(a.alert_status)}`}>{a.alert_status}</span>
                  {retracted && a.retracted_at && (
                    <div className={s.approved}>retracted {new Date(a.retracted_at).toLocaleTimeString()}</div>
                  )}
                </td>
                <td className={s.alertActions}>
                  {code === SESSION && a.alert_status === "ACTIVE" && (
                    <button className={s.ghost} disabled={busy === a.alert_id} onClick={() => void act(a, "acknowledge")}>
                      Acknowledge
                    </button>
                  )}
                  {code === SESSION && (a.alert_status === "ACTIVE" || a.alert_status === "ACKNOWLEDGED") && (
                    <button className={s.ghost} disabled={busy === a.alert_id} onClick={() => void act(a, "resolve")}>
                      Resolve
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
          {alerts.length === 0 && (
            <tr>
              <td colSpan={9} className={s.muted}>
                No clinical alerts{filter ? ` for ${filter}` : ""}.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}
