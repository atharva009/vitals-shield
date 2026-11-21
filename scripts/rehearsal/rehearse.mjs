// Timed rehearsal of docs/DEMO_RUNBOOK.md (Phase 10a): headless Chrome over the DevTools protocol (Node 22 built-in
// WebSocket) with a virtual authenticator for every Touch ID step, driving the real scripts/stage/*.sh against the
// demo profile on 8443 to 8445. Run it right after scripts/stage/01-reset.sh and a demo-profile boot (it registers the
// first passkey with the setup code). Screenshots: 1440x900, normal and high contrast, bootstrap tokens blanked.
//   node scripts/rehearsal/rehearse.mjs docs/learning/img "$(cat var/admin/setup-code)" "$PWD" <artifactDir>
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const outDir = process.argv[2];
const ADMIN = process.argv[5] || "9445";
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const port = 9333;
const profile = mkdtempSync(join(tmpdir(), "vs-chrome-"));
const chrome = spawn(CHROME, ["--headless=new", `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
  "--window-size=1440,900", "--force-device-scale-factor=1", "--no-first-run", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function json(path, method = "GET") {
  for (let i = 0; i < 50; i++) {
    try { return await (await fetch(`http://127.0.0.1:${port}${path}`, { method })).json(); } catch { await sleep(200); }
  }
  throw new Error("chrome not reachable");
}

const target = await json(`/json/new?about:blank`, "PUT");
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
let id = 0;
const pending = new Map();
const events = [];
ws.addEventListener("message", (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  else if (msg.method) events.push(msg);
});
const send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
const evaluate = async (expr) => (await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true })).result?.result?.value;
const shot = async (name) => {
  // Never commit a bootstrap token, even a consumed one (DECISIONS 101): blank it before every capture.
  await evaluate(`document.querySelectorAll('[class*=tokenRow] code, [class*=tokenBox] code').forEach(e => { e.textContent = '<bootstrap token redacted>'; })`);
  const r = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false,
    clip: { x: 0, y: await evaluate("window.scrollY"), width: 1440, height: 900, scale: 1 } });
  writeFileSync(join(outDir, name), Buffer.from(r.result.data, "base64"));
  console.log(`SCREENSHOT ${name}`);
};
const waitFor = async (expr, ms = 8000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await evaluate(expr)) return true; await sleep(150); }
  return false;
};

await send("Page.enable"); await send("Runtime.enable"); await send("Log.enable");
// ---- Phase 10a rehearsal: the 5-minute script end to end, timed, against the demo profile on 8443 to 8445 ---------
// Usage: node rehearse.mjs <shotDir> <setupCode> <repoRoot> <artifactDir>
const [, setupCode, repoRoot, artDir] = process.argv.slice(2);
const ADMIN_URL = `http://127.0.0.1:8445`;
const { execFileSync, spawn: sp } = await import("node:child_process");
const { appendFileSync } = await import("node:fs");
const stage = (n) => join(repoRoot, "scripts/stage", n);
const run = (cmd, args, opts = {}) => { try { return execFileSync(cmd, args, { cwd: repoRoot, ...opts }).toString(); }
  catch (e) { return `EXIT ${e.status}\n` + (e.stdout?.toString() ?? "") + (e.stderr?.toString() ?? ""); } };
const save = (name, text) => { writeFileSync(join(artDir, name), text); console.log(`ARTIFACT ${name}`); };
const psql = (sql) => run("docker", ["exec", "vitals-shield-postgres-1", "psql", "-U", "vitalsshield", "-d", "vitalsshield", "-c", sql]);
await send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
await send("WebAuthn.enable", { enableUI: false });
await send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true,
  hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
const setInput = (sel, value) => evaluate(`(() => { const el=document.querySelector(${JSON.stringify(sel)});
  const set=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set; set.call(el, ${JSON.stringify(String(value))});
  el.dispatchEvent(new Event('input',{bubbles:true})); return true })()`);
const clickText = (tag, text) => evaluate(`(() => { const b=[...document.querySelectorAll(${JSON.stringify(tag)})].find(x=>x.textContent.trim()===${JSON.stringify(text)}); if(!b) return false; b.click(); return true })()`);
const bodyHas = (t) => `document.body.innerText.includes(${JSON.stringify(t)})`;
const scrollTo = (expr) => evaluate(`(() => { const el=${expr}; if(!el) return false; el.scrollIntoView({block:'start'}); window.scrollBy(0,-92); return true })()`);
const h2 = (t) => `[...document.querySelectorAll('h2')].find(x=>x.textContent.trim().startsWith(${JSON.stringify(t)}))?.closest('section')`;
const selectDevice = (dev) => evaluate(`(() => { const r=[...document.querySelectorAll('tbody tr')].find(t=>t.children[0]?.textContent.includes('${dev}')); r?.click(); return !!r })()`);
const contrast = (on) => evaluate(`(() => { const l=[...document.querySelectorAll('label')].find(x=>x.textContent.includes('High contrast')); const c=l?.querySelector('input'); if(c && c.checked !== ${on}) c.click(); return !!c })()`);
const overflow = [];
async function shots(name) { await sleep(300);
  const w = await evaluate("document.documentElement.scrollWidth");
  if (w > 1440) overflow.push(`${name}: page scrollWidth ${w}`);
  // Phase 10a.1: every panel's own bounds, not just the page: no section scrolls sideways and no table or row
  // reaches past its panel's border.
  const panels = await evaluate(`[...document.querySelectorAll('section')].flatMap(sec => {
    const r = sec.getBoundingClientRect(); const out = [];
    if (sec.scrollWidth > sec.clientWidth + 1) out.push((sec.querySelector('h2')?.textContent || 'section') + ': scrollWidth ' + sec.scrollWidth + ' > ' + sec.clientWidth);
    sec.querySelectorAll('table, tr').forEach(t => { const b = t.getBoundingClientRect();
      if (b.width > 0 && b.right > r.right - 1) out.push((sec.querySelector('h2')?.textContent || 'section') + ': ' + t.tagName + ' right ' + Math.round(b.right) + ' > panel ' + Math.round(r.right)); });
    return out; }).filter((v, i, a) => a.indexOf(v) === i)`);
  for (const p of panels ?? []) overflow.push(`${name}: ${p}`);
  await shot(`stage-${name}.png`); await contrast(true); await sleep(400);
  await shot(`stage-${name}-hc.png`); await contrast(false); await sleep(200); }
async function provision(dev, patient) {
  await scrollTo(h2("Provision device"));
  await setInput("input[placeholder='dev_touchid_001']", dev);
  await setInput("input[placeholder='patient-001']", patient);
  await clickText("button", "Approve with passkey");
  await waitFor(`document.querySelector('[class*=tokenRow] code')?.textContent?.length > 20 && document.body.innerText.includes(${JSON.stringify("for " + dev)})`, 15000);
  return evaluate("document.querySelector('[class*=tokenRow] code')?.textContent");
}
const beats = []; const assertions = []; let T0 = 0;
const t = () => ((Date.now() - T0) / 1000);
const fmt = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
async function beat(n, title, planned, fn) {
  const start = t(); console.log(`BEAT ${n} ${title} start=${fmt(start)}`);
  const note = await fn();
  const end = t(); beats.push({ n, title, planned, start: fmt(start), end: fmt(end), seconds: Math.round(end - start), note });
  console.log(`BEAT ${n} done=${fmt(end)} (${Math.round(end - start)} s) ${note ?? ""}`);
}

// ---- T-15 (before the clock starts): passkey, precheck device, the clone-drill device --------------------------
await send("Page.navigate", { url: `${ADMIN_URL}/` });
await waitFor(`location.href.startsWith('http://localhost:8445') && !!document.querySelector('form')`, 15000);
await setInput("#clinician", "dr_stage"); await setInput("#display", "Dr Stage");
await setInput("#code", setupCode);
await evaluate("document.querySelector('form').requestSubmit()");
const signedIn = await waitFor(bodyHas("signed in as dr_stage"), 15000);
const pre = await provision("dev_precheck_001", "patient-precheck-001");
save("t15-precheck.txt", run(stage("02-enroll.sh"), ["dev_precheck_001", pre]) +
  run(join(repoRoot, "simulator/build/install/simulator/bin/simulator"), ["run", "--device-id", "dev_precheck_001", "--count", "5", "--interval-ms", "300"]));
const tok2 = await provision("dev_stage_002", "patient-stage-002");
save("t15-enroll-dev_stage_002.txt", run(stage("02-enroll.sh"), ["dev_stage_002", tok2]));
save("prestage.txt", run(stage("00-prestage.sh"), []));

// ---- The 5-minute script ------------------------------------------------------------------------------------------
await evaluate("window.scrollTo(0,0)");
T0 = Date.now();
let stream = null, streamLog = "";
await beat(1, "problem", "0:00", async () => { await sleep(3000); await shots("01-problem"); return "dashboard landing, signed in"; });
await beat(2, "trust chain on KMS", "0:15", async () => {
  await scrollTo(h2("Trust chain")); await shots("02-trust-chain");
  save("crl-text.txt", run("bash", ["-c", "curl -sk https://127.0.0.1:8444/api/v1/pki/intermediate-crl.pem | openssl crl -noout -text"]));
  save("kms-keys.txt", psql("SELECT purpose, status, right(kms_key_id, 12) AS key_id_suffix FROM kms_keys ORDER BY purpose, status"));
  await sleep(8000); return null; });
await beat(3, "Touch ID provisioning + enroll", "0:35", async () => {
  const tok = await provision("dev_stage_001", "patient-stage-001");
  await shots("03-provisioned");
  const out = run(stage("02-enroll.sh"), ["dev_stage_001", tok]); save("enroll-dev_stage_001.txt", out.replace(tok, "<token>"));
  return out.split("\n").find((l) => l.startsWith("ENROLLED")); });
await beat(4, "streaming", "1:15", async () => {
  stream = sp(stage("03-stream.sh"), ["dev_stage_001"], { cwd: repoRoot }); stream.stdout.on("data", (d) => (streamLog += d));
  await waitFor(`!!document.querySelector('tbody tr')`, 5000); await selectDevice("dev_stage_001");
  const ok = await waitFor(bodyHas("LOCKED"), 40000);
  await scrollTo(h2("Devices")); await shots("04-streaming");
  return `baseline LOCKED=${ok}, ${streamLog.split("\n").filter((l) => l.startsWith("SENT")).length} batches`; });
await beat(5, "rollover", "1:45", async () => {
  const ok = await waitFor(`!!document.querySelector('[data-testid=renewal-log] tbody tr td')?.textContent.includes('dev_stage_001')`, 150000);
  await waitFor(`(() => { const r=document.querySelector('[data-testid=renewal-log] tbody tr'); return r && !r.innerText.includes('awaiting'); })()`, 15000);
  await scrollTo(`document.querySelector('[data-testid=renewal-log]')?.closest('section')`); await shots("05-rollover");
  return `renewal row=${ok}; ` + streamLog.split("\n").filter((l) => l.startsWith("RENEWED") || l.startsWith("ACTIVATED")).join(" | "); });
await beat(6, "drift alert", "2:05", async () => {
  run(stage("04-drift.sh"), ["dev_stage_001"]);
  const ok = await waitFor(bodyHas("Drift vs baseline"), 60000);
  await scrollTo(h2("Clinical alerts")); await shots("06-drift");
  return `drift alert=${ok}`; });
await beat(7, "Touch ID quarantine", "2:45", async () => {
  await evaluate("window.scrollTo(0,0)"); await selectDevice("dev_stage_001");
  await clickText("button", "Quarantine"); await waitFor("!!document.querySelector('[role=dialog]')", 5000);
  await clickText("button", "Approve quarantine with passkey");
  const ok = await waitFor(bodyHas("(passkey step-up)"), 15000);
  await sleep(1500);
  const q = await evaluate(`fetch('/api/v1/admin/overview',{credentials:'include'}).then(r=>r.json()).then(o=>JSON.stringify(o.quarantines[0], null, 2))`);
  save("quarantine.json", q);
  await waitFor(bodyHas("RETRACTED_BY_QUARANTINE"), 8000);
  await scrollTo(h2("dev_stage_001")); await shots("07-quarantine");
  // Phase 10a.1: the renewal log row of the quarantined device shows the predecessor's final status, no countdown.
  await sleep(1500);
  const renewalRow = await evaluate(`[...document.querySelectorAll('[data-testid=renewal-log] tbody tr')].find(r => r.children[0]?.textContent.includes('dev_stage_001'))?.innerText.replace(/\\s+/g,' ')`);
  assertions.push({ check: "revoked predecessor shows its final status, no grace countdown", row: renewalRow,
    pass: !!renewalRow && renewalRow.includes("REVOKED") && !/\bin \d/.test(renewalRow) });
  await scrollTo(`document.querySelector('[data-testid=renewal-log]')?.closest('section')`); await shots("07b-renewal-log-after-quarantine");
  await scrollTo(h2("Clinical alerts")); await shots("07c-alerts-after-quarantine");
  await new Promise((r) => (stream.exitCode !== null ? r() : stream.on("exit", r)));
  save("stream-dev_stage_001.txt", streamLog);
  return `approved=${ok} simulator: ${streamLog.trim().split("\n").slice(-2).join(" | ")}`; });
await beat(8, "clone drill + Touch ID restore", "3:45", async () => {
  const out = run(stage("05-clone.sh"), ["dev_stage_002"]); save("clone-drill.txt", out);
  await selectDevice("dev_stage_002");
  const panel = await waitFor(`!!document.querySelector('[data-testid=reauth-panel]')`, 10000);
  await scrollTo(`document.querySelector('[data-testid=reauth-panel]')`); await shots("08a-reauth");
  await scrollTo(h2("Clinical alerts")); await shots("08b-pinned-alert");
  await scrollTo(`document.querySelector('[data-testid=reauth-panel]')`);
  await clickText("button", "Restore (benign reset)");
  const restored = await waitFor(`!document.querySelector('[data-testid=reauth-panel]')`, 15000);
  const rec = run(stage("06-recover.sh"), ["dev_stage_002"]); save("recover.txt", rec);
  await sleep(1500); await scrollTo(`document.querySelector('[data-testid=renewal-log]')?.closest('section')`); await shots("08c-recovered");
  return `panel=${panel} restored=${restored} ${rec.split("\n").find((l) => l.startsWith("RE-ENROLLED"))}`; });
await beat(9, "honest close", "4:30", async () => {
  await scrollTo(h2("Audit log")); await shots("09-close"); await sleep(10000); return null; });

save("psql-after.txt", psql("SELECT device_id, trust_state, boot_epoch, last_sequence_num FROM devices ORDER BY device_id") +
  psql("SELECT device_id, alert_type, condition_code, alert_status FROM clinical_alerts ORDER BY created_at") +
  psql("SELECT device_id, left(serial_number, 12) AS serial, status, revocation_reason, issued_via, reenroll_reason FROM certificates ORDER BY device_id, issued_at") +
  psql("SELECT device_id, trust_state, count(*) FROM telemetry_records GROUP BY 1, 2 ORDER BY 1, 2") +
  psql("SELECT sequence_id, event_type, actor_id, payload_json->>'device_id' AS device FROM security_audit_log ORDER BY sequence_id"));
const consoleMsgs = events.filter((e) => e.method === "Runtime.consoleAPICalled").map((e) => `${e.params.type}: ${e.params.args.map((a) => a.value ?? a.description).join(" ")}`);
const exceptions = events.filter((e) => e.method === "Runtime.exceptionThrown").map((e) => e.params.exceptionDetails.exception?.description ?? e.params.exceptionDetails.text);
console.log("REPORT " + JSON.stringify({ signedIn, total: fmt(t()), beats, overflow, assertions, console: consoleMsgs, exceptions }, null, 2));
ws.close(); chrome.kill();
process.exit(0);
