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
scripts/kms-probe.sh          # KMS gate: CREATE=ok|fail SIGN=ok|fail SURVIVES_RESTART=yes|no
```

`nsmithuk/local-kms` is available as a fallback under `docker compose --profile kms-fallback up -d`. It does not start by default.

## Tests

| Task | Runs |
|---|---|
| `./gradlew test` | Unit tests only (excludes the `integration`, `e2e`, `drill` tags). Needs no Docker. |
| `./gradlew integrationTest` | `@Tag("integration")`: KMS smoke tests against the Compose LocalStack, and schema and Flyway-on-startup tests on a Testcontainers postgres:16. |
| `./gradlew e2eTest` | `@Tag("e2e")`: end-to-end flows (none yet). |
| `./gradlew drillTest` | `@Tag("drill")`: failure and recovery drills (none yet). |
