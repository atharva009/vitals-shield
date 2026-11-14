# VitalsShield

Wearable vitals telemetry with a two-tier KMS-backed PKI. See
[`docs/vitalsshield_technical_architecture_specification.md`](docs/vitalsshield_technical_architecture_specification.md).

## Prerequisites

- OrbStack (or another Docker runtime with Compose v2)
- Host port 5433 free. Compose Postgres uses 5433 instead of 5432 so it does not clash with a host-native Postgres.
- JDK 21. Gradle uses a Java 21 toolchain and downloads one automatically if none is installed.
- A `.env` in the repo root, created from `.env.example` with a real LocalStack auth token:

  ```sh
  cp .env.example .env   # then set LOCALSTACK_AUTH_TOKEN
  ```

## Local stack

```sh
docker compose up -d          # postgres:16 on host port 5433 (container 5432), LocalStack (KMS only) on 4566
scripts/kms-probe.sh          # KMS gate: CREATE=ok|fail SIGN=ok|fail SURVIVES_RESTART=skipped
scripts/kms-probe.sh --restart  # also restarts LocalStack: SURVIVES_RESTART=yes|no (see warning below)
```

Changed in Phase 2: the probe restarts LocalStack only with `--restart`. LocalStack runs without persistence, so a
restart wipes every KMS key, and the next server boot finds the CA keys missing, rebuilds the whole hierarchy, and
revokes every issued certificate.

`nsmithuk/local-kms` is available as a fallback under `docker compose --profile kms-fallback up -d`. It does not start by default.

## Tests

| Task | Runs |
|---|---|
| `./gradlew test` | Unit tests only (excludes the `integration`, `e2e`, `drill` tags). Needs no Docker. |
| `./gradlew integrationTest` | `@Tag("integration")`: KMS, PKI, and listener tests against the Compose LocalStack, each with a Testcontainers postgres:16 and listeners on free ports. |
| `./gradlew e2eTest` | `@Tag("e2e")`: end-to-end flows (none yet). |
| `./gradlew drillTest` | `@Tag("drill")`: failure and recovery drills (none yet). |

To prove the unit tier needs no Docker, point it at a socket that does not exist and leave the Compose stack running:

```sh
DOCKER_HOST=unix:///nonexistent.sock ./gradlew test --rerun-tasks
```

Warning: LocalStack keeps no state across restarts. `docker compose stop`, `docker compose down`,
`docker compose restart localstack`, and `scripts/kms-probe.sh --restart` all wipe every KMS key, and the next server
boot rebuilds the CA hierarchy and revokes every device certificate.

In IntelliJ, set Settings > Build, Execution, Deployment > Build Tools > Gradle > "Build and run using: Gradle", so the
IDE and Gradle do not write to the same output directory (the likely cause of a one-off
`ClassNotFoundException: ReconcileResult`).

## PKI (Phase 1)

- `./gradlew :server:bootRun --args='--spring.profiles.active=local'` reconciles the KMS-backed CA hierarchy, issues the
  in-memory gateway TLS leaf, loads trust anchors, then exits (no listeners yet). The current Root is published to
  `var/trust/root-ca.pem`. Only the `local` profile may rebuild the hierarchy (`vitalsshield.pki.allow-hierarchy-rebuild`);
  every other profile fails startup if a CA key is missing.
- `python3 scripts/golden_vectors.py` prints the reference hex for the Section 3 canonical encodings used by
  `CanonicalEncodingsTest`.
- `PkiOpensslIT` cross-checks certificates and CRLs with OpenSSL 3 (`OPENSSL_BIN`, default
  `$(brew --prefix openssl@3)/bin/openssl`; skipped if not found) and leaves the PEMs in `build/pki-out/`.

## Listeners (Phase 2)

`bootRun` now stays running. The last boot step binds three listeners, all on `127.0.0.1` by default
(`vitalsshield.listeners.*`):

| Port | Protocol | Serves |
| :--- | :--- | :--- |
| 8443 | TLS 1.3, client certificate required | `/api/v1/telemetry/**`, `/api/v1/devices/renew`, `/api/v1/devices/renew-challenge` |
| 8444 | TLS 1.3, no client certificate | enrollment routes (later), `/api/v1/pki/intermediate-crl.pem`, `/api/v1/pki/root-crl.pem` |
| 8445 | plain HTTP, always 127.0.0.1 | `/api/v1/admin/**` (today: `/api/v1/admin/boot-status`) |

Any other path on a port returns 404 with an empty body. Stop the server with Ctrl-C. `ResumptionIT` needs
OpenSSL 3 (`OPENSSL_BIN`, default `$(brew --prefix openssl@3)/bin/openssl`).
