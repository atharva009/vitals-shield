# VitalsShield demo: static walkthrough

Use this if the live stack is down (`scripts/stage/99-panic.sh`). Every screenshot and output below is real. They come
from the timed rehearsal of `docs/DEMO_RUNBOOK.md` on 2026-11-20 (20:06 to 20:08 EST, Phase 10a.1). That run used
the demo profile (DECISIONS 99): LocalStack KMS, 3-minute device certificates, every clone trap on. A headless Chrome at 1440x900 with a
virtual authenticator stood in for Touch ID. Each screenshot links to its high-contrast version. Bootstrap tokens are
blanked in every image.

## 1. The problem

![Dashboard landing](learning/img/stage-01-problem.png)
([high contrast](learning/img/stage-01-problem-hc.png))

**What it proves.** The system is up and the dashboard reflects the server's own checks: boot complete, the KMS keys
present and enabled, and the database and server clocks in agreement. A wearable's readings drive clinical alerts.
Whoever holds its keys can forge those readings, so everything that follows is about who holds which key and how fast
a copied key is stopped.

**Evidence** (`scripts/stage/00-prestage.sh`, just before the run):

```
PASS  Server on 8445 with demo profile       profiles=demo
PASS  Boot status has all steps              all 8 steps
PASS  KMS health HEALTHY                     kms_state=HEALTHY
PASS  Clock skew under 2 s                   skew_ms=-3 state=GREEN
PRESTAGE: all checks PASS
```

## 2. The trust chain lives in KMS

![Trust chain](learning/img/stage-02-trust-chain.png)
([high contrast](learning/img/stage-02-trust-chain-hc.png))

**What it proves.** Three CAs (Root, Device Intermediate, Server TLS CA) whose private keys exist only in KMS. Every
certificate and CRL signature is a KMS Sign call, and no CA key is ever in the server's memory or on its disk.

**Evidence.** The four KMS keys the database points at (key IDs truncated):

```
       purpose       | status | key_id_suffix
---------------------+--------+---------------
 ROOT_CA             | ACTIVE | 1bca05edd742
 DEVICE_INTERMEDIATE | ACTIVE | 220dfed707cb
 SERVER_TLS_CA       | ACTIVE | 63fdbfff1bc2
 REGISTRY_ANCHOR     | ACTIVE | 151e18c2e906
```

The Device Intermediate's CRL at this point (`openssl crl -noout -text`):

```
Certificate Revocation List (CRL):
    Version 2 (0x1)
    Signature Algorithm: ecdsa-with-SHA256
    Issuer: O=VitalsShield, CN=VitalsShield Issuing CA G1
    Last Update: Nov 21 01:06:50 2026 GMT
    Next Update: Nov 22 01:06:50 2026 GMT
    CRL extensions:
        X509v3 CRL Number:
            1
No Revoked Certificates.
```

## 3. Touch ID provisioning, then enrollment

![Provisioned](learning/img/stage-03-provisioned.png)
([high contrast](learning/img/stage-03-provisioned-hc.png))

**What it proves.** A clinician's passkey approves the device. The bootstrap token is bound to that approval and shown
once. The device then enrolls: it proves it holds its long-lived device key (DEK) and a new transport key, and the
server records the DEK under a KMS Key #4 signature.

**Evidence** (`scripts/stage/02-enroll.sh dev_stage_001 <token>`):

```
== VitalsShield stage: 02 enroll dev_stage_001 ==
FACTORY_WIPED simulator-state/dev_stage_001
ENROLLED serial=3c2d56a36999a35526156a8a033a009ec84814d9 boot_epoch=1 not_after=2026-11-21T01:09:13Z
```

## 4. Streaming

![Streaming](learning/img/stage-04-streaming.png)
([high contrast](learning/img/stage-04-streaming-hc.png))

**What it proves.** One signed batch per second over mutual TLS. Each batch's JWS signature must come from the
certificate of that very connection. Each one is checked against the replay window and classified, and the patient's
resting baseline locks after 10 resting batches.

**Evidence** (`scripts/stage/03-stream.sh dev_stage_001`):

```
== VitalsShield stage: 03 stream dev_stage_001 (Ctrl-C to stop) ==
SCENARIO resting
SENT seq=1 batch=dbcd3118 status=200 rtt_ms=90 measured_at=2026-11-20T13:07:14.172429Z scenario=resting trust_state=ACCEPTED
SENT seq=20 batch=c4afff1e status=200 rtt_ms=18 measured_at=2026-11-20T13:26:14.172429Z scenario=resting trust_state=ACCEPTED
```

## 5. Automatic certificate rollover

![Rollover](learning/img/stage-05-rollover.png)
([high contrast](learning/img/stage-05-rollover-hc.png))

**What it proves.** The 3-minute certificate renews itself 60 s after issuance, at two thirds of its validity with no human (Protocol B). The new
certificate becomes active on its first accepted batch. The old one is accepted for a 60-second grace and then refused.

**Evidence** (same stream):

```
RENEWED old=3C2D56A36999A35526156A8A033A009EC84814D9 new=6D392D24038B5A0E9DBBE380D013DC387973DA51 due_at=2026-11-21T01:08:13Z at=2026-11-21T01:08:13.544885Z
ACTIVATED new=6D392D24038B5A0E9DBBE380D013DC387973DA51 at=2026-11-21T01:08:13.566112Z
```

21 ms from renewal to first use, 60 s after the enroll. In the 10-minute soak on the same PT3M profile (Phase 10a.1),
10 renewals, one a minute, took 23.3 ms to 41.7 ms to activate (median 32.3 ms), and all 600 batches were accepted.

## 6. Drift alert

![Drift](learning/img/stage-06-drift.png)
([high contrast](learning/img/stage-06-drift-hc.png))

**What it proves.** Alerts are relative to the patient's own locked baseline and need several consecutive resting
breaches. Every alert records the batches and the baseline version it was computed from.

**Evidence** (`scripts/stage/04-drift.sh dev_stage_001`, then on the dashboard):

```
DRIFT   Drift vs baseline v1: HR z=+4.8, HRV z=-3.8, SpO2 z=-2.6 over 4 resting batches   4 batches   v1   ACTIVE
```

## 7. Touch ID quarantine

![Quarantine](learning/img/stage-07-quarantine.png)
([high contrast](learning/img/stage-07-quarantine-hc.png))

**What it proves.** One passkey step-up, bound to this device and this action, does all of the following in one
operation:
- revokes every certificate of the device;
- closes its live connection;
- marks the lookback telemetry QUARANTINED;
- resets the baseline built on it;
- retracts exactly the alerts that came from that data;
- writes the audit entry in the same transaction.

**Evidence.** The quarantine result (from the overview API):

```json
{
  "device_id": "dev_stage_001",
  "at": "2026-11-21T01:08:20.454323Z",
  "certs_revoked": 2,
  "channels_closed": 1,
  "revocation_latency_micros": 8674,
  "batches_quarantined": 65,
  "baselines_reset": 1,
  "alerts_retracted": 1
}
```

The stream, a second later:

```
SCENARIO drift
REJECTED handshake_refused last_ok_seq=65 ms_since_last_ok=1017
simulator exit 3 (0 done, 3 refused/revoked, 4 expired and unrecoverable, 5 REAUTH_REQUIRED)
```

The renewal log right after: the quarantined device's predecessor shows its final status, REVOKED, not a grace
countdown (Phase 10a.1), and the alerts panel shows the drift alert retracted. Both stay inside their panels at 1440 px.

![Renewal log after quarantine](learning/img/stage-07b-renewal-log-after-quarantine.png)
([high contrast](learning/img/stage-07b-renewal-log-after-quarantine-hc.png))

![Alerts after quarantine](learning/img/stage-07c-alerts-after-quarantine.png)
([high contrast](learning/img/stage-07c-alerts-after-quarantine-hc.png))

## 8. Clone drill and Touch ID restore

![REAUTH_REQUIRED panel](learning/img/stage-08a-reauth.png)
([high contrast](learning/img/stage-08a-reauth-hc.png))

![Pinned security alert](learning/img/stage-08b-pinned-alert.png)
([high contrast](learning/img/stage-08b-pinned-alert-hc.png))

![After restore and re-enrollment](learning/img/stage-08c-recovered.png)
([high contrast](learning/img/stage-08c-recovered-hc.png))

**What it proves.** Two copies of one device's flash run at once. Each works on its own; the server sees their
sequence numbers collide. Within about a second:
- every certificate is revoked as a suspected clone;
- both copies are cut off;
- the device needs a clinician;
- no data is changed.

The clinician restores with Touch ID. The real device re-enrolls with its device key under a new epoch. A copy that
tries the same later presents the old epoch and is refused (shown in Phase 9's CloneTrapIT).

**Evidence** (`scripts/stage/05-clone.sh dev_stage_002`):

```
leaf renewal due in -29 s (or already expired): re-enrolling once before cloning
RE-ENROLLED serial=197444201A1E71A51FB3F27E2855D4C7D7B946BD boot_epoch=1 reason=manual at=2026-11-21T01:08:27.239422Z
CLONED simulator-state/dev_stage_002 -> simulator-state-clone/dev_stage_002
SENT seq=1 batch=68036c78 status=409 rtt_ms=110 ... error=DUPLICATE_SEQUENCE_REPLAY
SENT seq=2 batch=0e81b176 status=409 rtt_ms=11 ... error=DUPLICATE_SEQUENCE_REPLAY
SENT seq=3 batch=2f40d519 status=409 rtt_ms=9 ... error=DUPLICATE_SEQUENCE_REPLAY
REJECTED handshake_refused last_ok_seq=0 ms_since_last_ok=1718
clone exit 3; original exit 3; original's last lines:
SENT seq=2 batch=459c1e35 status=200 rtt_ms=8 ... trust_state=ACCEPTED
SENT seq=3 batch=e91e41ce status=200 rtt_ms=15 ... trust_state=ACCEPTED
REJECTED handshake_refused last_ok_seq=3 ms_since_last_ok=524
```

After "Restore (benign reset)" (`scripts/stage/06-recover.sh dev_stage_002`):

```
RE-ENROLLED serial=679A794D387EE9B9A8A23B00EE76C27195C50E0B boot_epoch=2 reason=manual previous_boot_epoch=1 at=2026-11-21T01:08:32.298159Z
SENT seq=5 batch=829c9f15 status=200 rtt_ms=89 ... trust_state=ACCEPTED
SENT seq=14 batch=0bc5d9b3 status=200 rtt_ms=7 ... trust_state=ACCEPTED
```

The CRL after both incidents:

```
    X509v3 CRL Number:
        5
Revoked Certificates:
    Serial Number: 3C2D56A36999A35526156A8A033A009EC84814D9   Key Compromise   (dev_stage_001, quarantine)
    Serial Number: 6D392D24038B5A0E9DBBE380D013DC387973DA51   Key Compromise   (dev_stage_001, quarantine)
    Serial Number: 42319CB80355DCF50113EF3A3510B9D4C2AF41D4   Superseded       (dev_stage_002, replaced by re-enrollment)
    Serial Number: 197444201A1E71A51FB3F27E2855D4C7D7B946BD   Key Compromise   (dev_stage_002, suspected clone)
```

## 9. Honest close: live vs designed

![Audit log](learning/img/stage-09-close.png)
([high contrast](learning/img/stage-09-close-hc.png))

**What it proves.** Every security decision is in a hash-chained, append-only audit log. Clinician actions and the
system's own anomaly response are both there.

**Evidence** (database after the run):

```
 device_id        | trust_state | boot_epoch | last_sequence_num
 dev_precheck_001 | ACTIVE      |          1 |                 5
 dev_stage_001    | QUARANTINED |          1 |                65
 dev_stage_002    | ACTIVE      |          2 |                14

 sequence_id |     event_type     | actor_id |      device
           1 | PASSKEY_REGISTERED | dr_stage |
           2 | ASSIGNMENT_CREATED | dr_stage | dev_precheck_001
           3 | DEVICE_PROVISIONED | dr_stage | dev_precheck_001
           4 | ASSIGNMENT_CREATED | dr_stage | dev_stage_002
           5 | DEVICE_PROVISIONED | dr_stage | dev_stage_002
           6 | ASSIGNMENT_CREATED | dr_stage | dev_stage_001
           7 | DEVICE_PROVISIONED | dr_stage | dev_stage_001
           8 | DEVICE_QUARANTINED | dr_stage | dev_stage_001
           9 | SECURITY_ANOMALY   | system   | dev_stage_002
          10 | DEVICE_RESTORED    | dr_stage | dev_stage_002

 device_id        | trust_state | count
 dev_precheck_001 | ACCEPTED    |     5
 dev_stage_001    | QUARANTINED |    65
 dev_stage_002    | ACCEPTED    |    13
```

The clone's 13 batches are still ACCEPTED: the anomaly response stops both copies but leaves the data for a clinician
to judge.

**Live today.** KMS-held CA keys, mTLS with per-request status, live socket eviction, JWS-signed telemetry with a
replay window, passkey-approved provisioning and actions, automatic renewal and offline recovery, three clone traps, a
backstop poller, and a hash-chained audit log.

**Designed, not built.** A standby Intermediate CA for failover (KMS Key #3), Redis for multi-gateway eviction and
shared rate limits, a hardware secure element for the device key, and S3 Object Lock anchoring of the audit chain.

**Residual risks.**
- A clone that re-enrolls while the real device is off goes unnoticed until the real device returns.
- A software device key can be copied by anyone who can read the device's storage.
- A clone copied right before a scheduled renewal can win the renewal race and run alone (DECISIONS 102). Found in
  the Phase 10a rehearsal.
