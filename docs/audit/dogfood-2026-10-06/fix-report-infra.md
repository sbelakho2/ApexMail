# FIX report — infra findings (brief: `docs/audit/dogfood-2026-10-06/brief-fix-infra.md`)

Scope: `ci/**`, `deploy/**`, `scripts/**`, `.woodpecker.yml` (+ the two named
docs). No deploy, no production action, no host mutation — every proof is a
fixture/dry-run under `mktemp`, a stub `docker`/`systemctl`/`clickhouse-client`
on `PATH`, or the pipeline's own selftest.

Snapshot: working tree at HEAD `61c7110f` **plus other dogfood agents'
in-flight edits** (the tree was dirty when this work started). I touched only
the paths below; `ci/pipeline.conf`, `deploy/scripts/entrypoint-wrapper.sh`,
`deploy/tests/performance-budget.sh` and `scripts/consistency-test.sh` show as
modified but are **not mine**. One drive-by was unavoidable: another agent's
in-flight `ci/stages/ui.sh` line 134 used an em-dash inside a shellcheck
directive (`SC1125`), which failed `pipeline.sh selftest` step 1 — fixed to
the repo's `# shellcheck disable=SC2086  # …` form.

Verification status: `sh -n`/`bash -n` clean, `shellcheck -S warning` clean on
every file touched, and `sh ci/pipeline.sh selftest` **ALL OK** (11/11, see
item 1/6 evidence).

---

## P1

### 1. FIXED — verify-stage auto-rollback unreachable

`ci/stages/deploy.sh` no longer overwrites `.last-deployed-sha` before verify
runs. It now calls `record_deploy_state()`, which snapshots the previously
**verified** sha into `$RUN_DIR/pre-deploy-sha` and this rollout's sha into
`$RUN_DIR/deployed-sha`. `ci/stages/verify.sh`
(`rollback_to_previous_sha`) reads `pre-deploy-sha` first (falling back to
`.last-deployed-sha` for partial `--stages verify` runs), and only a fully
green verify advances `.last-deployed-sha` (from `deployed-sha`, never from
the running `CI_SHA`), so the file always names a verified rollout.

Evidence — `sh ci/tests/rollback-selftest.sh` (new fixture, 16 assertions):

```
ok   deploy: pre-deploy-sha captured the previously verified sha
ok   deploy: deployed-sha recorded this run's rollout sha
ok   deploy: .last-deployed-sha NOT advanced before verification
ok   rollback: refuses when the only recorded sha is the running one
ok   rollback: .last-deployed-sha untouched by the failure path
rollback-selftest: ALL OK
```

The fixture runs the real `record_deploy_state`/`rollback_to_previous_sha`
through env-gated hooks (`CI_DEPLOY_STATE_SELFTEST`,
`CI_VERIFY_ROLLBACK_SELFTEST`) with a stub docker and a synthetic image set.
It is wired into `ci/pipeline.sh selftest` step 11/11:

```
[info] selftest (11/11): verify-stage rollback contract (synthetic image fixture)
[info] selftest: ALL OK
```

Docs updated in the same change: `deploy/rollback-plan.md`,
`docs/deployment/migration-rollback.md` (the file now names a verified sha;
the auto-rollback target is the run's `pre-deploy-sha`).

### 2. FIXED — rollback retags by compose key but inspects image names; inverted missing-image policy

`ci/stages/verify.sh`: new `image_repo_for_key()` mirrors
`image_compose_key()` (`tracking` → `tracking-service`) and the loop now
inspects/retags the mapped repository. The missing-image branch is
un-inverted: a missing **canonical** image sets `_rb_missing=1` and the
rollback aborts (no `compose up`, clear `ROLLBACK ABORTED` error); only names
listed in `EXTRA_ROLLBACK_IMAGES` warn-and-continue.

Evidence — same fixture (synthetic compose/image set):

```
ok   rollback: compose key 'tracking' inspected/retagged as image 'tracking-service'
ok   rollback: no retag of the nonexistent 'tracking:<sha>' image
ok   rollback: missing canonical image (mta) aborts
ok   rollback: no compose up after the abort
ok   rollback: no false COMPLETE claim
ok   rollback: missing EXTRA_ROLLBACK_IMAGES name (redis) warns only
```

Teeth (the fixture runs HEAD's `verify.sh` against the same image set):

```
ok   teeth: HEAD verify.sh does NOT retag tracking-service (bug reproduced)
ok   teeth: HEAD verify.sh claims ROLLBACK COMPLETE with tracking left on the new image
ok   teeth: HEAD verify.sh retags a SUBSET and claims COMPLETE (missing canonical not fatal)
```

### 3. FIXED — manual rollback is a no-op while the digest override is in `COMPOSE_FILES`

`deploy/scripts/deploy.sh` `rollback_images()` no longer reuses
`$COMPOSE_FILES`. It retags `:pre-deploy → :latest` and composes
`base + prod + docker-compose.rollback-override.yml` (a generated override
pinning the `:pre-deploy` baseline for exactly the images that have one). The
Step 3.5 digest override — which pins the failed new images — is deliberately
excluded.

Evidence — `bash deploy/tests/deploy-rollback-selftest.sh` (real
`rollback_images()` extracted verbatim, stub docker records every call):

```
ok   deploy: rollback does NOT compose with the Step-3.5 digest override
ok   deploy: rollback uses its own baseline-pinning override
ok   deploy: base + prod + rollback override with the monitoring profile
ok   deploy: rollback override pins :pre-deploy baselines (incl. tracking-service key mapping)
ok   deploy: :pre-deploy retagged back onto :latest
ok   teeth: HEAD rollback DOES compose with the digest override (bug reproduced)
ok   teeth: HEAD rollback claims ROLLBACK COMPLETE while pinned to the failed images
deploy-rollback-selftest: ALL OK
```

(No full-script run: macOS' bash 3.2 cannot parse the script's `declare -A`;
the harness therefore runs the real function text, which is the production
code path.)

### 4. FIXED — manual deploy deletes the pipeline's own systemd units

`deploy/scripts/deploy.sh`: the `rm -f /etc/systemd/system/apexmail-*.service`
glob is replaced by `remove_retired_bare_metal_units()`, which removes
exactly `apexmail-{imap,mta,status}.service` and runs `systemctl
daemon-reload` afterwards; `apexmail-pipeline*.service` and the TLS-renew
units are untouched. (`SYSTEMD_UNIT_DIR` is the harness seam.)

Evidence — `bash deploy/tests/deploy-unit-cleanup-selftest.sh`:

```
ok   cleanup: retired unit apexmail-imap.service removed
ok   cleanup: apexmail-pipeline.service survives
ok   cleanup: apexmail-pipeline-webhook.service survives
ok   cleanup: apexmail-tls-renew-restart.service survives
ok   cleanup: systemd daemon-reload issued after the removals
ok   teeth: HEAD glob deleted apexmail-pipeline.service (bug reproduced)
deploy-unit-cleanup-selftest: ALL OK
```

### 5. FIXED — secret backup runs before `BACKUP_KEYS` is populated; empty backups + false success; `--rollback` broken

`scripts/rotate-secrets.sh`: `keys_for_action()` computes the action's
`PROD_*_FILE` list and the main flow populates `BACKUP_KEYS` **before**
`backup_current_secrets`; the rotate functions no longer append keys after
the fact. `backup_current_secrets` writes `index.txt` up front, warns per
missing key, and hard-fails (`exit 1`, "secrets backup is EMPTY") when it
snapshotted zero files. `rollback()` now also rejects an empty index and no
longer dies silently on an empty `BACKUP_DIR` (pipefail).

Evidence — `bash scripts/tests/rotate-secrets-selftest.sh` (temp dep dir,
stub docker, real rotated file):

```
ok   rotate: --api-key-hash exited 0
ok   rotate: backup index.txt records the rotated key (1 entry)
ok   rollback: restored the original secret contents
ok   teeth: HEAD rotate reports a 0-file backup
ok   teeth: HEAD backup has no index.txt (rollback target unrecoverable)
ok   teeth: HEAD --rollback cannot find a backup (bug reproduced)
ok   missing file: hard-fails before rotating (no silent unrecoverable rotation)
rotate-secrets-selftest: ALL OK
```

(The HEAD teeth run uses a `${arr[@]+"${arr[@]}"}` shim so macOS' bash 3.2
reproduces the deploy-host bash ≥ 4.4 semantics of an empty array; noted in
the harness.)

### 6. FIXED — a gates-only run can bless a never-deployed sha (timer then skips it forever)

`ci/pipeline.sh`: new `blessing_membership_missing()` requires the **full
`CI_STAGES` line** (deploy path included) before a `.last-good-sha` blessing
is written; a gates-only/`--skip-deploy` run logs
`NOT blessing <sha> — this run did not exercise the FULL stage line`. The
selftest proves both directions against the real `CI_STAGES`; direct probe:

```
$ sh -c '. /tmp/bmm.sh; blessing_membership_missing "validate ui test security"'
fetch
docs
images
migrate
deploy
verify
notify
$ ... "fetch validate docs ui test security verify notify"      # the --skip-deploy shape
images
migrate
deploy
$ ... "$CI_STAGES"                                              # full line
(nothing missing — full line covers every stage)
```

Pipeline selftest (steps 10 + 11 both green):

```
[info] selftest (10/11): blessing contract (audit SM14 F3 outcomes + P1 membership)
[info] selftest (11/11): verify-stage rollback contract (synthetic image fixture)
[info] selftest: ALL OK
```

The systemd timer's default run covers all of `CI_STAGES`, so the blessing
path it depends on is unchanged for real deploys.

---

## P2

### 7. FIXED — `redis-backup`/`analytics-backup` built but never deployed

Added to `STACK_SERVICES` (`ci/stages/deploy.sh`) and `VERIFY_SERVICES`
(`ci/stages/verify.sh`). New `backup_service_coverage()` in
`ci/stages/validate.sh` (docker-free, runs every validate) parses every
`*-backup` service out of `docker-compose.prod.yml` and fails the run if one
is absent from either list. `deploy/DEPLOYMENT.md`'s canonical
service→image map now lists all four schedulers and states the invariant;
`deploy/rollback-plan.md`'s retag list includes them.

Evidence — `sh ci/tests/validate-coverage-selftest.sh`:

```
ok   coverage: current lists cover every *-backup compose service
ok   coverage: a backup service missing from STACK_SERVICES fails the check
ok   coverage: a backup service missing from VERIFY_SERVICES fails the check
ok   teeth: HEAD had no backup-service coverage check
ok   teeth: HEAD's STACK_SERVICES omitted redis-backup/analytics-backup (bug reproduced)
validate-coverage-selftest: ALL OK
```

(The fixture immediately caught a word-boundary bug in my first version of
the checker — newline-delimited words at end-of-line never matched — now
folded to spaces.)

### 8. FIXED — REQUIRED lanes warn-skip when their runtime (python3/zola) is missing

`lane_tool_status()` moved from `test.sh` to `ci/lib.sh` and is now used by:
`ui.sh` (all UI gates; required if any `CI_UI_*_CHECK=required`, advisory
override honored otherwise), `validate.sh` (panic-path/capability/pricing/
knowledge/eval/repo-map/migration-lint block; plus `zola_gates` now fails
closed when `CI_MARKETING_VALIDATION=required` and no pinned zola is
obtainable), and `test.sh` (repo python gates + the i18n gate, which also
switched from the host `zola` to the pinned `ci_zola`). Deploy host /
`CI_MISSING_TOOLS=fail` → hard death (ci_have_tool); dev machine → REQUIRED
fails, `advisory` skips loudly.

Evidence — `sh ci/tests/missing-runtime-selftest.sh` (python3 hidden via an
empty PATH):

```
ok   lane_tool_status: REQUIRED lane reports fail when python3 is missing
ok   lane_tool_status: advisory override reports skip (bounded triage window)
ok   lane_tool_status: CI_MISSING_TOOLS=fail dies on the spot (deploy-host fail closed)
ok   ui.sh routes its python3 gates through lane_tool_status
ok   validate.sh routes its python3 gates through lane_tool_status
ok   test.sh routes its python3 gates through lane_tool_status
ok   test.sh i18n gate uses lane_tool_status + the pinned ci_zola
ok   validate.sh zola gates fail closed when the marketing validation is REQUIRED
ok   teeth: pre-fix ui.sh guard returns 0 with python3 absent (silent skip reproduced)
missing-runtime-selftest: ALL OK
```

### 9. FIXED — clickhouse-backup: query status ignored, empty backup "success", then prunes good archives

`scripts/clickhouse-backup.sh`: the table listing is captured to a temp file
(no pipeline/subshell), a non-zero listing exits 1 with the server error; each
per-table dump is checked and abandons the partial backup on failure; an empty
manifest is a hard error; a verification pass requires a non-empty schema and
a present data file for every manifest row before "Backup complete … (N
tables verified)". Pruning stays in the caller, so it only runs after a
verified success.

Evidence — `sh scripts/tests/clickhouse-backup-selftest.sh` (stub
`clickhouse-client`; old good archive seeded and aged):

```
ok   fail mode: exits non-zero (1)
ok   fail mode: no false success claim
ok   fail mode: older good archive NOT pruned
ok   fail mode: partial backup directory removed
ok   empty mode: refuses to report an empty backup
ok   ok mode: verified backup written (2 tables)
ok   teeth: HEAD reports success on a FAILED query (exit 0 + 'Backup complete')
ok   teeth: HEAD pruned the older good archive after the failed backup
clickhouse-backup-selftest: ALL OK
```

### 10. FIXED — gitleaks "full history" under the documented `--depth 1` bootstrap

Three changes: `deploy/DEPLOYMENT.md` step 2 no longer prescribes
`git fetch --depth 1`; `ci/stages/fetch.sh` gained `ensure_full_history()`
(it unshallows and warns if the repair fails); `ci/stages/security.sh` gained
`gitleaks_history_guard()` — the REQUIRED scan fails closed on a shallow
checkout (`CI_GITLEAKS_CHECK=advisory` is the only override).

Evidence — `sh ci/tests/fetch-selftest.sh` (synthetic origin, real shallow
clones) and `sh ci/tests/gitleaks-shallow-selftest.sh`:

```
ok   ensure_full_history: shallow clone repaired to full history (3 commits)
ok   teeth: plain 'git fetch --no-tags origin main' stays at depth 1 (bug reproduced)
ok   prove_head_pushed: accepts the pushed branch tip
fetch-selftest: ALL OK

ok   required: shallow checkout fails the full-history gate
ok   advisory: shallow checkout continues under the explicit triage override
ok   full checkout passes the guard
gitleaks-shallow-selftest: ALL OK
```

### 11. FIXED — documented fresh-host bootstrap installs no gh/token while `fetch` hard-fails without them

`ci/install.sh`: new `install_gh()` (official GitHub CLI apt repo on
Debian/Ubuntu; manual instruction elsewhere) added to the full install, plus a
token-prerequisite check that prints an explicit ACTION REQUIRED line; the
generated `/etc/apexmail/pipeline.conf` now carries a commented
`export GITHUB_TOKEN=…` (export matters: stages are child processes);
`do_check` requires gh AND a readable token and fails without them.
`deploy/DEPLOYMENT.md` step 5 documents installing gh + setting the token.

Evidence — `sh ci/install.sh check`:

```
[install] ok: gh (gh version 2.98.0 (2026-08-20))
[install] MISSING: GITHUB_TOKEN — set it in /etc/apexmail/pipeline.conf; the fetch stage fails closed without a readable token (ci/README.md §13)
```

Teeth: `git show HEAD:ci/install.sh | grep -c 'install_gh\|GITHUB_TOKEN'` → `0`;
current → `12`.

---

## P3

### 12. FIXED — dead `image_name_guard` version-tag check

`ci/stages/validate.sh`: `case $_ref in :v[0-9]*)` → `*:v[0-9]*` (POSIX case
patterns match from the start; the old form could never fire on
`ghcr.io/…/api-server:v1.2.3`).

### 13. FIXED — images.sh's promised advisory sidecar scan did not exist

`ci/stages/images.sh` renders the merged compose config once to a temp file
and derives BOTH sets: the blocking gate (unchanged) and a new advisory
`trivy image` pass over the excluded FIRST-PARTY sidecars
(`ci_check_advisory` + SBOM), so the comment now matches reality. The
release-manifest `sbom_digest` note in `images.sh` and `DEPLOYMENT.md` was
updated (sidecar SBOMs now exist).

### 14. FIXED — `compare-baseline.sh` fail-open without bc

Replaced both `bc` computations with `awk`, added a numeric validation that
exits 2 on non-numeric metric values, and documented it.

Evidence — `bash scripts/tests/compare-baseline-selftest.sh` (stub `bc` that
always fails):

```
ok   regression: 50% latency degradation FAILS without a usable bc
ok   improvement: faster than baseline still passes
ok   non-numeric metric: fails loudly (exit 2) instead of computing 0%
ok   teeth: HEAD reports 'All metrics pass' on a 50% regression without bc (bug reproduced)
compare-baseline-selftest: ALL OK
```

### 15. FIXED — the REQUIRED CTA gate cannot fail

Un-wired from the required path: `deploy/tests/cta-tracking-test.sh` is run
through `_mv_gate … advisory` with an in-code justification (the validator
only ever records `warning` severities — no critical class exists — and the
data-* attribute convention does not match this zero-JS server-side-analytics
site). Its JSON report is still produced and preserved.

### 16. FIXED — performance-budget (a required merge gate measuring live production)

Same mechanism: run advisory with an explicit in-code reason (it gates the
state of production from the merge lane; byte/TTFB budgets need network
verification against live prod, which is not the artifact under test). The
required/advisory split is now explicit instead of implicit-by-flag.

### 17. FIXED — stale workflow-archive / stale-frame references

- `deploy/DEPLOYMENT.md:18` (workflows-archive), the `deploy.yml` column
  header, the drift-guard paragraph (now names `ci/stages/validate.sh`
  `image_name_guard`), and the `APEXMAIL_PROD_ENV` GitHub-secret mention.
- `ci/stages/test.sh` header: DB/Redis policy now states the real defaults
  (`CI_TEST_DB=ephemeral`, `CI_TEST_REDIS=1`).
- `.woodpecker.yml`: the "all-zero PLACEHOLDER below" paragraph (the anchor
  carries a real digest) and "all six gates" → seven.
- `ci/stages/security.sh`: the cargo-audit log line no longer claims
  `--deny warnings` (the executed command has no `--deny`; the surrounding
  comment already explains warnings intentionally do not gate).
- `scripts/rotate-secrets.sh` header (deploy-hetzner.yml), the
  `APEXMAIL_PROD_ENV` instructions (header flow, `rotate_jwt` comment, the
  final "update APEXMAIL_PROD_ENV" note → operator secret source of truth).
- `deploy/tests/enterprise-gate-tracking.md` and
  `deploy/review/engineering-sign-off-checklist.md`: archive rows replaced
  with the current `ci/`/`deploy/tests/` equivalents.
- `ci/stages/test.sh` i18n gate: see item 8 (pinned zola, fail-closed).

### 18. FIXED — `ci/woodpecker/toolchain.sh` divergent-unreferenced duplicate

Deleted (`git status`: ` D ci/woodpecker/toolchain.sh`). `grep -rn
'woodpecker/toolchain'` in the live tree: no references (only `.kilo/`
worktrees and the audit docs). The image-baked
`ci/ci-image/toolchain.sh` (`apexmail-ci-toolchain --assert`), the first
Woodpecker step and the Dockerfile build assertion remain the single source.

### 19. FIXED — "HEAD is pushed" proof weaker than documented for a sha ref

`ci/stages/fetch.sh` gained `prove_head_pushed()`: for a raw-sha `CI_REF` it
fetches the tracked branch (`CI_BRANCH_PROTECTION_BRANCH`, default `main`)
and proves containment against that tip instead of the locally-short-circuited
`FETCH_HEAD`.

Evidence — `sh ci/tests/fetch-selftest.sh` (synthetic repo with an unpushed
local commit):

```
ok   prove_head_pushed: rejects a locally-present unpushed sha
ok   teeth: the raw FETCH_HEAD ancestor test accepts the unpushed sha (bug reproduced)
ok   prove_head_pushed: accepts the pushed branch tip
fetch-selftest: ALL OK
```

### 20. FIXED — non-git deploy dir hard-fails the manual full deploy

`deploy/scripts/deploy.sh`: new `fallback_pin_tag()` gives a locally-built
image without RepoDigests and without a git sha a unique per-run tag
(`manual-<UTC>-<pid>`) and Step 3.5 pins that, instead of refusing at
"release manifest would be empty". It never falls back to `:latest` or
`:pre-deploy` (the latter is the OLD image generation, i.e. what a rollback
returns to). Returns non-zero when even tagging fails (caller warns/skips).

Evidence — `bash deploy/tests/deploy-rollback-selftest.sh`:

```
ok   fallback_pin_tag: tagged an unpinnable image with a unique local tag (manual-20261007T133152-79605)
ok   fallback_pin_tag: returns non-zero when tagging fails (caller warns/skips)
```

---

## Also fixed while in the file (same finding family, mechanical)

- `ci/pipeline.sh` selftest step 9: the FOURTH RUSTSEC ledger
  (`scripts/security-audit.sh`'s `--ignore` list) is now asserted in lockstep
  with `CI_CARGO_AUDIT_IGNORES` (was asserted by inspection only). Output:
  `PASS: scripts/security-audit.sh ledger matches CI_CARGO_AUDIT_IGNORES`.
  `scripts/security-audit.sh`'s header no longer claims a CI path through the
  deleted `security-audit.yml`.
- `ci/stages/images.sh`/`DEPLOYMENT.md` SBOM-null wording (consequence of
  item 13).

## Stayed unfixed / outside owned paths (with justification)

- `docs/evaluation/load-testing.md:36` and `ARCHITECTURE.md:314` still
  reference `.github/workflows-archive/` (which never exists). Not in the
  brief's owned-doc list (`deploy/rollback-plan.md`,
  `docs/deployment/migration-rollback.md` only); a docs-owner task.
- Live GitHub branch-protection state and the `.woodpecker.yml` digest
  value: NOT-VERIFIED, unchanged from the review (no API/registry access).
- `$RUN_DIR/pre-deploy-sha` on the host: the file is created by the deploy
  stage at runtime; nothing to pre-create.

## Proof inventory (all re-runnable, no infra)

| Harness | Covers |
|---|---|
| `sh ci/tests/rollback-selftest.sh` | items 1, 2 |
| `sh ci/tests/fetch-selftest.sh` | items 10, 19 |
| `sh ci/tests/gitleaks-shallow-selftest.sh` | item 10 |
| `sh ci/tests/missing-runtime-selftest.sh` | item 8 |
| `sh ci/tests/validate-coverage-selftest.sh` | item 7 |
| `bash deploy/tests/deploy-rollback-selftest.sh` | items 3, 20 |
| `bash deploy/tests/deploy-unit-cleanup-selftest.sh` | item 4 |
| `bash scripts/tests/rotate-secrets-selftest.sh` | item 5 |
| `sh scripts/tests/clickhouse-backup-selftest.sh` | item 9 |
| `bash scripts/tests/compare-baseline-selftest.sh` | item 14 |
| `sh ci/pipeline.sh selftest` | items 1, 2, 6, 17 (plus the repo-wide contract) |
| `sh ci/install.sh check` | item 11 |

`ci/tests/rollback-selftest.sh` runs from `ci/pipeline.sh selftest` step 11;
the rest are standalone harnesses (not yet wired into a scheduled lane —
flagging that as follow-up rather than silently expanding the selftest's
runtime).
