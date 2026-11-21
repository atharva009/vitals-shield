# Release check (DECISIONS 101)

Run on 2026-11-20 before the `demo-ready-v1` tag, over the full history: every commit reachable from any ref.
At the time that meant 29 commits on `main`, plus the tags `dashboard-green-v1` and `spine-green-v1`.
`gitleaks` is not installed on this machine, so the scan uses `git log -p` and `git grep`.

## Result

**One finding, removed by rewriting history before the first push (see below): two real bootstrap tokens from Phase 3 are in the history
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

- **Where:** `docs/learning/phase-03-enrollment.md` (the "Verify it yourself" outputs), added in `ce89a4f`
  (docs(learning): phase 3 notes, 2026-11-13) and present in every later commit and both tags.
- **What:** two `./gradlew :server:seedDemoDevice` outputs, `BOOTSTRAP_TOKEN=<redacted-bootstrap-token>` and
  `BOOTSTRAP_TOKEN=<redacted-bootstrap-token>` (redacted here).
- **Risk assessment:** low. Both were dev-seed tokens for the local Compose database. Each is single-use and was
  consumed by the enrollment on the very next line of the same output. Bootstrap tokens expire after 15 minutes. Only
  a hash of each was ever stored, in a database that has been dropped and recreated by `scripts/reset-demo-state.sh`
  several times since. Neither can enroll anything today.
- **What was done:** the working-tree file now reads `BOOTSTRAP_TOKEN=<redacted in Phase 10a>`; that change is in
  the Phase 10a commit.

  On 2026-11-21, before the first push, the history was rewritten with `git filter-repo` to remove the two consumed
  bootstrap tokens and their 4-plus-4-character fragments (each replaced with `<redacted-bootstrap-token>` in every
  version of every file) and to set a single author identity. The tags were re-created on the rewritten commits.

## Bootstrap tokens in history

- **File:** `docs/learning/phase-03-enrollment.md`, in the "Verify it yourself" outputs of `./gradlew
  :server:seedDemoDevice` (two `BOOTSTRAP_TOKEN=` lines, shown here as `<redacted-bootstrap-token>` and `<redacted-bootstrap-token>`).
- **First commit:** `ce89a4f` (docs(learning): phase 3 notes, 2026-11-13). They are in every later commit, in the tags
  `spine-green-v1` and `dashboard-green-v1`, and in `demo-ready-v1` as first tagged.
- **Why they are harmless:**
  - each is single-use, and each was consumed by the enrollment printed on the very next line of the same output;
  - a bootstrap token expires 15 minutes after it is issued;
  - the server stores only a hash, and every database that held those hashes has since been dropped by
    `scripts/reset-demo-state.sh` (DECISIONS 75);
  - they were dev-seed tokens for the local Compose stack, never for any shared environment.
- **Current tree:** both are redacted (`BOOTSTRAP_TOKEN=<redacted in Phase 10a>`) since commit `72cadfe`; `git grep -E
  'BOOTSTRAP_TOKEN=[A-Za-z0-9_-]{43}'` on the current tree finds nothing.
- **If rewriting:** `git filter-repo --replace-text` (or BFG) on that file, then re-create the three tags and
  force-push. Every clone of the old history keeps the strings.

Decision: rewrite, by Atharva Hankare, 2026-11-21. History was rewritten before the first push to remove the two consumed bootstrap tokens and set a single author identity.

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
#   ce89a4f 2026-11-13 docs(learning): phase 3 notes   (first commit containing the two tokens)
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
