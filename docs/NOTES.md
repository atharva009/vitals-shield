# VitalsShield Implementation Notes

## Phase 0 KMS probe

Run on 2026-11-13 against `localstack/localstack:2026.10.7` (SERVICES=kms) via `scripts/kms-probe.sh`:

```
CREATE=ok SIGN=ok SURVIVES_RESTART=no
```

- `ECC_NIST_P256` / `SIGN_VERIFY` key creation and `ECDSA_SHA_256` RAW signing both work.
- KMS state does not survive `docker compose restart localstack` (persistence disabled). This is expected and is
  the reason the local profile needs the startup reconciliation check described in spec Section 3.
- `awslocal` inside the image prints a deprecation banner (recommends `lstk aws`); the probe suppresses it unless a
  step fails.
