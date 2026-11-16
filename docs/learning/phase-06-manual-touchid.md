# Phase 6: manual Touch ID check

Every automated test uses a software authenticator, and the dashboard flow was also driven in headless Chrome with a
DevTools virtual authenticator. This checklist is the part only a person can do: a real passkey in the Secure Enclave,
synced through iCloud Keychain, approved with Touch ID in Chrome. Each step lists what to do and what you should see.

Terminals: **A** server, **B** simulator, **C** commands. Run everything from the repo root.

## 0. Prepare

1. **C**: start the stack if it is not running.
   `docker compose up -d`
   Expect: `postgres` and `localstack` healthy (`docker compose ps`).
2. **C**: build the dashboard and the simulator binary.
   `cd dashboard && npm run build && cd .. && ./gradlew -q :simulator:installDist`
   Expect: `○  (Static)  prerendered as static content`, and `simulator/build/install/simulator/bin/simulator` exists.
3. **A**: start the server (webauthn mode is the default).
   `./gradlew :server:bootRun --args='--spring.profiles.active=local'`
   Expect in the log: `Listener admin bound on /127.0.0.1:8445` and `Listener admin-ipv6 bound on /[0:0:0:0:0:0:0:1]:8445`.
4. **C**: confirm the mode and the passkey count.
   `curl -s http://localhost:8445/api/v1/admin/auth/status`
   Expect: `{"mode":"webauthn","passkeys_registered":0,"clinician_id":null}`.

## 1. Reset the passkey table (only if `passkeys_registered` is not 0)

Changed in Phase 7: for a full clean slate, stop the server and run `scripts/reset-demo-state.sh` instead (it drops the
Compose Postgres volume; audit rows can no longer be deleted, DECISIONS #75). The SQL below still works for passkeys
only.

The setup code registers a passkey only while no clinician passkey exists (DECISIONS #60). DEV_SEED passkeys
(`purpose = 'DEV_SEED'`) do not count (DECISIONS #64, #66) and are kept.

**C**:
```
docker compose exec -T postgres psql -U vitalsshield -d vitalsshield \
  -c "DELETE FROM device_bootstrap_tokens WHERE webauthn_cred_id_b64 IN (SELECT credential_id_b64 FROM clinician_passkeys WHERE purpose = 'CLINICIAN');" \
  -c "DELETE FROM clinician_passkeys WHERE purpose = 'CLINICIAN';"
```
Expect: two `DELETE n` lines; the status call from step 0.4 now shows `"passkeys_registered":0`. The audit log is not
touched, so its chain stays valid. The old passkey stays in iCloud Keychain; delete it later in System Settings >
Passwords if you want (it is harmless: the server no longer knows its credential id).

## 2. Open the dashboard

1. In Chrome, open `http://127.0.0.1:8445`.
   Expect: the address bar changes to `http://localhost:8445/` (307 redirect, DECISIONS #55).
2. Expect the first-run card: "No clinician passkey yet. Register the first one with the setup code." with fields
   Clinician id, Display name, Admin setup code.

## 3. Register the first passkey (Touch ID)

1. **C**: `cat var/admin/setup-code` and copy the value.
2. Type Clinician id `dr_touchid`, Display name `Dr Touch ID`, paste the setup code. Click **Register passkey**.
3. Expect Chrome's passkey sheet: "Create a passkey for localhost" with your Mac account. Choose this Mac / iCloud
   Keychain and touch the sensor.
4. Expect: Chrome immediately asks to sign in with the new passkey (the page signs in right after registering).
   Touch the sensor again.
5. Expect: the dashboard, with `signed in as dr_touchid` in the header next to **Sign out**.
6. **C** (optional): the stored row.
   ```
   docker compose exec -T postgres psql -U vitalsshield -d vitalsshield -c "SELECT clinician_id, left(credential_id_b64,16), left(passkey_registry_kms_sig,16), sign_count FROM clinician_passkeys;"
   ```
   Expect: a `dr_touchid` row with a base64 DER signature starting `ME` (the KMS Key #4 anchor) and `sign_count` 0
   (iCloud Keychain passkeys always report 0, DECISIONS #61).

## 4. Sign out and sign in again (Touch ID)

1. Click **Sign out**.
   Expect: a card with "Sign in with the passkey on this Mac (Touch ID)." and a **Sign in with passkey** button (not
   the first-run form).
2. Click **Sign in with passkey**. Expect Chrome's sheet listing `dr_touchid` for localhost. Touch the sensor.
3. Expect: the dashboard again, `signed in as dr_touchid`.

## 5. Provision device dev_touchid_001 (Touch ID) and copy the token

1. Scroll to **Provision device**. Device id `dev_touchid_001`, Patient id `patient-001`, Birth year `1985`.
   Click **Approve with passkey**.
2. Expect Chrome's sheet ("Use your passkey for localhost"). Touch the sensor. This approval signs the
   ProvisioningDigest of this exact device, token, and expiry.
3. Expect a yellow-bordered box: "Bootstrap token for dev_touchid_001, approved by dr_touchid. Shown once; expires
   <time 15 minutes from now>." with a 43-character token and a **Copy** button. Click **Copy** (it turns to
   "Copied"). The token is never shown again; reloading the page loses it.

## 6. Enroll the simulator with that token, then stream

1. **B**:
   ```
   simulator/build/install/simulator/bin/simulator factory-wipe --device-id dev_touchid_001
   simulator/build/install/simulator/bin/simulator enroll --device-id dev_touchid_001 --token <paste>
   ```
   Expect: `ENROLLED serial=<hex> boot_epoch=1 not_after=<+12 h>`. The server re-verified your Touch ID assertion
   before signing anything (DECISIONS #57); in terminal A there is no "Provisioning approval ... does not verify"
   line.
2. **B**: `simulator/build/install/simulator/bin/simulator run --device-id dev_touchid_001`
   Expect: one `SENT seq=N ... status=200` line per second.
3. In the dashboard, expect a `dev_touchid_001` row: ACTIVE, epoch 1, last seq rising, cert ACTIVE with about 11 h 59
   min left, DEK anchor ✓, Sockets 1. Live mTLS sockets tile: 1.

## 7. Quarantine from the UI (Touch ID)

1. Click the `dev_touchid_001` row, then **Quarantine**. In the dialog keep Lookback 10 and the reason, click
   **Approve quarantine with passkey**.
2. Expect Chrome's sheet. Touch the sensor. This approval signs SHA-256 of (quarantine, dev_touchid_001, 10, reason,
   server nonce), so it cannot be reused for another device or other parameters (DECISIONS #58).
3. Expect the red result box: a latency like `10.8 ms`, "revocation latency · 1 cert(s) revoked · 1 socket(s)
   closed · N batches quarantined ...", and a line "approved by dr_touchid (passkey step-up)".
4. Expect within a second: Live mTLS sockets 0; the row shows QUARANTINED, cert REVOKED, DEK anchor –, Sockets 0;
   telemetry rows struck through with QUARANTINED badges; a new top line in the revocation log (KEY_COMPROMISE).
5. **B**: expect the simulator to stop with
   `REJECTED handshake_refused last_ok_seq=<n> ms_since_last_ok=<about 1000>`, then check the exit code:
   `echo $?` prints `3`.

## 8. Audit panel

1. Scroll to **Audit log**. Expect a green pill `chain valid · N entries` and, newest first: `DEVICE_QUARANTINED`,
   `DEVICE_PROVISIONED`, `ASSIGNMENT_CREATED`, `PASSKEY_REGISTERED`, each with actor `dr_touchid` (older entries from
   earlier runs may follow).
2. **C** (optional): the full entry for the quarantine, including the SHA-256 of your approving assertion.
   ```
   docker compose exec -T postgres psql -U vitalsshield -d vitalsshield -c "SELECT sequence_id, event_type, actor_id, payload_json FROM security_audit_log ORDER BY sequence_id DESC LIMIT 1;"
   ```

## What to report back

For each step: passed, or what you saw instead (the exact text and any red error line in the dashboard, plus the last
lines of terminal A). Useful extras: the Chrome version, and whether the passkey sheet offered iCloud Keychain.
