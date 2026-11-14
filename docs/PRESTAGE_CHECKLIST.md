# Pre-stage checklist

Run through this before the demo slot. Later phases append to it.

- [ ] Start the Compose stack while online (LocalStack validates its token at startup).
- [ ] Never run `scripts/kms-probe.sh --restart`, `docker compose stop`, `docker compose down`, or
      `docker compose restart` after the final boot before the slot: each wipes KMS keys and forces a rebuild that
      revokes every device.
- [ ] Run `./gradlew clean build` before the final boot.
- [ ] Restart the server within 24 h of the slot (gateway TLS cert lifetime).
- [ ] Confirm `GET /api/v1/admin/boot-status` lists all six steps.
