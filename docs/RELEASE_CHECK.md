# Release check (DECISIONS 101)

Run on 2026-11-20 before the `demo-ready-v1` tag, over the full history: every commit reachable from any ref.
At the time that meant 29 commits on `main`, plus the tags `dashboard-green-v1` and `spine-green-v1`.
`gitleaks` is not installed on this machine, so the scan uses `git log -p` and `git grep`.

## Result

**One finding, not fixed by rewriting history (see below): two real bootstrap tokens from Phase 3 are in the history
of `docs/learning/phase-03-enrollment.md`.** Nothing else sensitive was found. No private key, no LocalStack token, no
setup code, no `.env`, and no key, state or keystore file was ever committed.

| # | Check | Result |
|---|---|---|
| 1 | `PRIVATE KEY` in any added line | 10 lines, all code or docs: PEM header constants in `EcKeys`, a test assertion, a test that writes a generated key with `Base64.getMimeEncoder()` at runtime, and notes describing `BootSequenceIT.noPrivateKeyOnDisk`. No key material. |
| 2 | The LocalStack auth token (read from `.env` at runtime, never printed) | not found: 0 lines in all history patches, 0 in any committed tree, 0 in working-tree files other than `.env` |
| 3 | Setup-code-shaped values (43 base64url characters next to "setup code", "bearer", "admin code") | not found (0) |
| 3 | Bootstrap-token-shaped values (43 base64url characters) | 25 distinct strings were found. 23 are harmless: 9 npm `integrity` hash fragments in `package-lock.json`, 12 long test method names, and 2 `x5t#S256` certificate thumbprints. **2 are real bootstrap tokens**, in `BOOTSTRAP_TOKEN=` lines of the Phase 3 notes. |
| 4 | `.env` committed | never (only `.env.example`, whose only value is `LOCALSTACK_AUTH_TOKEN=replace-me`) |
| 5 | `var/`, `simulator-state*/`, `*.key`, `*.p12`, `*.jks`, `*.pem` committed | never |
| 6 | `.gitignore` covers `.env`, `var/`, `simulator-state*/`, `dashboard/node_modules`, `dashboard/out`, `.next`, `build/`, `.gradle/`, `.vscode/` | yes. Phase 10a widened `simulator-state/` to `simulator-state*/` and added the dashboard paths at the root as well (they were already in `dashboard/.gitignore`). |

### The finding

- **Where:** `docs/learning/phase-03-enrollment.md` (the "Verify it yourself" outputs), added in `0886322`
  (docs(learning): phase 3 notes, 2026-11-13) and present in every later commit and both tags.
- **What:** two `./gradlew :server:seedDemoDevice` outputs, `BOOTSTRAP_TOKEN=<redacted-bootstrap-token>` and
  `BOOTSTRAP_TOKEN=<redacted-bootstrap-token>` (redacted here).
- **Risk assessment:** low. Both were dev-seed tokens for the local Compose database. Each is single-use and was
  consumed by the enrollment on the very next line of the same output. Bootstrap tokens expire after 15 minutes. Only
  a hash of each was ever stored, in a database that has been dropped and recreated by `scripts/reset-demo-state.sh`
  several times since. Neither can enroll anything today.
- **What was done:** the working-tree file now reads `BOOTSTRAP_TOKEN=<redacted in Phase 10a>`; that change is in
  the Phase 10a commit. History was **not** rewritten, as instructed. Removing the strings from history before
  publishing would need `git filter-repo` (or BFG) on `docs/learning/phase-03-enrollment.md`, followed by re-creating
  the tags, and is the owner's decision.

## Commands (outputs redacted)

```sh
git rev-list --all | wc -l                                  # 29
git for-each-ref --format='%(refname:short)'                # main dashboard-green-v1 spine-green-v1
git log --all -p --no-color > history.patch                 # 57308 lines

# 1. private keys
grep -c 'PRIVATE KEY' history.patch                          # 10 (all reviewed, none is key material)

# 2. LocalStack token: value read from .env into a variable, only counts printed
TOK="$(grep '^LOCALSTACK_AUTH_TOKEN=' .env | cut -d= -f2- | tr -d '"'"'"' \r')"
grep -c -F -- "$TOK" history.patch                           # 0
git grep -F -- "$TOK" $(git rev-list --all) | wc -l          # 0
grep -rIl -F -- "$TOK" --exclude=.env --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=build . | wc -l   # 0
unset TOK

# 3. 43-character base64url strings (setup codes and bootstrap tokens are 32 random bytes, base64url, no padding)
grep -E '^\+' history.patch | grep -oE '(^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{43}([^A-Za-z0-9_=-]|$)' \
  | grep -oE '[A-Za-z0-9_-]{43}' | sort -u | wc -l           # 25, each classified by context (table above)
git log --all --format='%h %ad %s' --date=short -S'BOOTSTRAP_TOKEN='
#   0886322 2026-11-13 docs(learning): phase 3 notes   (first commit containing the two tokens)
# setup-code / bearer next to a 43-character value (Python regex over the added lines)   # 0 hits

# 4, 5. sensitive paths ever committed
git log --all --name-only --format='' | sort -u \
  | grep -E '(^|/)\.env$|^var/|^simulator-state|\.key$|\.p12$|\.jks$|\.pem$'     # (none)

# 6. ignore rules
for p in .env var/x simulator-state/x simulator-state-clone/x dashboard/node_modules/x dashboard/out/x \
         dashboard/.next/x build/x .gradle/x .vscode/x; do git check-ignore -v "$p"; done   # all ignored
```

## CI and license

- `.github/workflows/ci.yml`: `./gradlew test` on Java 21 (Temurin), and the dashboard with `npm ci`, `npm run
  typecheck`, `npm run lint`, `npm run build` on Node 22. There are no integration or e2e jobs: they need Docker and a
  LocalStack Pro token, which must never be in CI. `actionlint` is not installed. The workflow was parsed with
  PyYAML and checked for its triggers, two jobs, and one `uses` or `run` per step.
- `LICENSE`: the repo had none; MIT, "Copyright (c) 2026 Atharva", added in Phase 10a.
