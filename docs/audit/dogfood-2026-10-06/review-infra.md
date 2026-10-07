# Adversarial review — infrastructure (deploy, CI, workflows, compose, scripts, secrets policy)

Scope: `deploy/**` (115 tracked files), `ci/**` (31 tracked files, `ci/runs/**` excluded), `.github/**`,
`.woodpecker.yml`, root infra (`docker-compose.yml`, `docker-compose.prod.yml`, `docker-compose.override.yml`,
`Makefile`, `trivy-secret.yaml`, `.trivyignore`, `.gitleaks.toml`, `.pre-commit-config.yaml`, all
`Dockerfile*` outside `apps/`), `scripts/**` (8 files) and the `secrets/**` policy. Per
`docs/audit/dogfood-2026-10-06/brief-review-infra.md`. No code was edited; this file is the only write.

Snapshot: HEAD `61c7110f` ("fix(sales): immediately-due actions are claimable across sub-second clock
skew"), branch `main`. **The working tree was dirty while this review ran** (other dogfood agents were
editing; `git status` shows many modified files). All findings below are against committed HEAD
content of the files I cite; where I used a local run artifact or an empirical probe I say so.
Method: read every gate-bearing script/config in full; for suspected logic bugs I ran a proof probe
in `/tmp` (never in the repo). Local evidence used: `ci/runs/20261006T201533_37440/` (a local
pipeline run at HEAD whose `ui` stage failed on strings-catalog drift — a working-tree artifact, not
an infra defect) and `ci/.last-failure` (same run).

Severity scale used: P1 = broken safety net / deploy-path defect with silent failure; P2 = gate that
can silently not run or a documented behavior that is false; P3 = wrong/absent local check with
limited blast radius.

---

## Findings

### <P1> `ci/stages/verify.sh:293-297` — the verify-stage auto-rollback can never trigger on the canonical full run

Evidence (read in full; the writer runs before the reader in `CI_STAGES` order
`…,deploy,verify,…` per `ci/pipeline.conf:14`):

* `ci/stages/deploy.sh:255-257` — at the end of a *successful* deploy:
  `printf '%s\n' "$CI_SHA" >"$CI_ROOT/.last-deployed-sha"` (comment: "Record what is now live so a
  failed verify stage can roll back to the PREVIOUS sha" — but it records the *current* sha).
* `ci/stages/verify.sh:293-297` — the rollback reads that same file and bails when it equals the
  running run's sha:
  `_rb_sha=$(cat "$CI_ROOT/.last-deployed-sha") … if [ -z "$_rb_sha" ] || [ "$_rb_sha" = "${CI_SHA:-}" ]; then ci_warn "no previous deployed sha to roll back to — leaving the current rollout in place"; return 0; fi`.

Because the deploy stage always overwrites the file with `$CI_SHA` *before* verify executes, verify
always sees `_rb_sha == CI_SHA` and refuses. The auto-rollback branch is unreachable in any full
pipeline run; the only way to reach it is a partial `--stages verify` run (which is not the deploy
path). `deploy/rollback-plan.md:30-34,40` ("`ci/stages/verify.sh` ALREADY rolls back automatically";
"previous green deploy's sha") and `docs/deployment/migration-rollback.md:261,272` advertise the
feature as the seconds-fast recovery path.

This is exactly the failure the file's own comment claims to have fixed (`verify.sh:37-42` fixed the
empty-`STACK_SERVICES` bug) — the trigger is still dead, one layer up.

Fix: write `.last-deployed-sha` only when the rollout is *verified* (move the write into
`verify.sh` after all probes pass), or have the deploy stage read the previous value into a
`RUN_DIR/pre-deploy-sha` file before overwriting it and have verify consume that.

### <P1> `ci/stages/verify.sh:301-311` — the rollback loop silently skips a service and inverts its own missing-image policy

Evidence (same function, after the (dead) trigger above; assuming it is ever reached):

```
for _svc in $STACK_SERVICES; do                     # compose SERVICE keys
    if docker image inspect "$_rb_ns/$_svc:$_rb_sha" >/dev/null 2>&1; then
        docker tag … || { warn; _rb_missing=1; }
    else
        case " $EXTRA_ROLLBACK_IMAGES " in
            *" $_svc "*) ci_warn "image $_svc:$_rb_sha missing — not rolled back"; _rb_missing=1 ;;
        esac
    fi
done
```

* `STACK_SERVICES` is a list of compose keys and contains `tracking` (`verify.sh:29-35`), but the
  image the pipeline tags is `ghcr.io/sbelakho2/apexmail/tracking-service:<sha>`
  (`ci/stages/images.sh:41,48-53`). `.../tracking:<sha>` never exists, so the loop silently does
  nothing for it and leaves the tracking service on the new image while claiming success below.
* The `EXTRA_ROLLBACK_IMAGES` branch is inverted relative to its own comment (`verify.sh:282-284`:
  "only these warn when missing … canonical stack services must ALL exist or the rollback aborts").
  As written, a **missing canonical** image (e.g. `tracking`, or any pruned `:<sha>` tag) is
  silently skipped, while a **missing EXTRA** image sets `_rb_missing=1` and aborts. With the
  default empty `EXTRA_ROLLBACK_IMAGES`, the function can retag any subset and still print
  "ROLLBACK COMPLETE" (`verify.sh:321`) — a mixed-version stack, the exact outcome the abort was
  meant to prevent.

Fix: map compose key → image repository (`image_compose_key` already exists in
`ci/stages/images.sh:48-53`; mirror it), and abort when any canonical image of the rollback target
is absent (treat missing as failure, not as a silent `continue`).

### <P1> `deploy/scripts/deploy.sh:379,505-533` — the manual (emergency) rollback is a no-op when the digest override was rendered

Evidence: Step 3.5 appends the just-rendered override to every subsequent compose invocation:
`COMPOSE_FILES="$COMPOSE_FILES -f $_override"` (`deploy.sh:379`). The override pins every
first-party service to the content just built, as `repo@sha256:<digest>` or `repo:$GIT_SHA`
(`deploy.sh:357-372`). `rollback_images()` retags the snapshot back onto `:latest`
(`docker tag "$pre" "$img"`, `deploy.sh:512-519`) and then calls
`docker compose $COMPOSE_FILES … up -d --remove-orphans` (`deploy.sh:524-525`) — i.e. with the
override still pinned to the **new** images. The retag has no effect on what compose resolves, so
the "rolled back" stack comes back on the failed images while the script logs
`ROLLBACK COMPLETE: stack restored to the pre-deploy images` (`deploy.sh:528`).

This is the fallback path's only automatic safety net (`make deploy` is the documented emergency
hotfix route, `Makefile:82-106`).

Fix: `rollback_images()` must drop the override (`docker compose -f docker-compose.yml -f
docker-compose.prod.yml …`, optionally with a `:pre-deploy`-pinned override) or pin the
`:pre-deploy` tags explicitly in an override of its own.

### <P1> `deploy/scripts/deploy.sh:179-180` — a manual deploy deletes the self-hosted pipeline's own systemd units

Evidence:

```
systemctl disable --now apexmail-imap apexmail-mta apexmail-status 2>/dev/null || true
rm -f /etc/systemd/system/apexmail-*.service 2>/dev/null || true
```

The glob matches everything `ci/install.sh:330-343` installs: `apexmail-pipeline.service`,
`apexmail-pipeline-webhook.service` (and the `apexmail-tls-renew-restart.service` re-created 40
lines later). The removal happens without `systemctl daemon-reload` (the next one is in Step 1.7),
so the running systemd keeps the stale units in memory; after the next daemon-reload or reboot the
5-minute deploy timer and the webhook receiver are gone, silently turning "push to main" deployment
off. Reinstalling requires an operator to remember `ci/install.sh units`.

Fix: delete only the retired units by exact name (`rm -f /etc/systemd/system/apexmail-{imap,mta,status}.service`), or gate the cleanup on the unit being one of those names, and run `systemctl daemon-reload` afterwards.

### <P1> `scripts/rotate-secrets.sh:499-500` vs `:237,271,286,305,330` — the pre-rotation secret backup is always empty, yet prints success; `--rollback` can never work

Evidence: the main flow is

```
backup_current_secrets        # line 500 — iterates BACKUP_KEYS
case "$ACTION" in             # line 502 — rotate_jwt etc. append to BACKUP_KEYS
    jwt) rotate_jwt ;;        # rotate_jwt: BACKUP_KEYS+=(...) at line 237
```

`backup_current_secrets` (`:130-152`) loops over `BACKUP_KEYS`, which is populated only *inside* the
rotate functions, i.e. after the backup has already run. Every rotation therefore snapshots zero
files, logs `Secrets backed up to: … (0 files, mode 0600)`, and writes no `index.txt`; a later
`--rollback` hits `[ ! -f "$latest_backup/index.txt" ]` and exits 1 with "No backup found to roll
back to" (`:352-355`). The header (:41-44) and `--rollback` usage (:34) both promise a working
rollback. Rotating `JWT_PRIVATE_KEY_PEM` / `API_KEY_HASH_SECRET` / the DB password with no recoverable
copy is the one operation where this matters most.

Fix: compute the action's key list before calling `backup_current_secrets` (e.g. `case "$ACTION"` to
set `BACKUP_KEYS`, then backup, then rotate), and hard-fail when the snapshot is empty.

### <P1> `ci/pipeline.sh:88,361-407` + `ci/stages/fetch.sh:116-141` — a gates-only run can bless a sha that was never deployed, and the timer then refuses to deploy it forever

Evidence: the blessing membership set is `REQUIRED_BLESS_STAGES="validate ui test security"`
(`ci/pipeline.sh:88`) and a successful run writes `ci/runs/.last-good-sha` when those four stages were
requested and finished `ok` (`:374-406`). `fetch.sh:116-140` makes every *later* run with
`CI_SKIP_UNCHANGED=1` (the systemd unit: `ci/units/apexmail-pipeline.service:24` —
`run --lock-wait 0 --skip-unchanged`) exit 76 "nothing to do" as soon as the blessed sha matches.

So on the deploy host:

* `ci/pipeline.sh run --stages validate,ui,test,security` (any subset containing the four required
  names; three of them are also what `ci/check-pr.sh:33` runs — check-pr omits `ui`, so check-pr
  itself cannot bless) blesses the local HEAD, and the 5-minute timer then permanently no-ops for
  that commit: it is
  never built, migrated, deployed or verified, while `ci/pipeline.sh status` shows a green run.
* The documented `--skip-deploy` shorthand (`ci/pipeline.sh:17,68`; `ci/README.md:81`) skips exactly
  `images,migrate,deploy` while **keeping** `verify` (which on the deploy host probes the *live,
  unchanged* stack, `ci/stages/verify.sh:328-347`), so a healthy old stack makes a never-deployed
  sha eligible for blessing too — and a probe failure from that read-only run would invoke the
  rollback machinery against production.

Fix: include the deploy-path stages (`images,migrate,deploy,verify`) in the membership requirement
for a blessing (or refuse to bless unless `CI_STAGES` was run in full), and/or have the timer compare
`sha == origin/main` as the cheap-poll condition instead of trusting a blessing written by a
possibly-partial run.

### <P2> `ci/stages/deploy.sh:38-44` + `ci/stages/verify.sh:29-35` — `redis-backup` and `analytics-backup` are built, scanned and pinned, then never deployed

Evidence: `ci/stages/images.sh:36-41` builds `redis-backup` and `analytics-backup` (EXTRA_IMAGES),
sha-tags them (`:180-188`), gives them a digest pin in the deploy override and a release-manifest
entry (`:102-149`). Both are default-profile services in `docker-compose.prod.yml` (`:1836`,
`:1899`; no `profiles:` key). But the canonical deploy list omits them —
`STACK_SERVICES` (`ci/stages/deploy.sh:38-44`) contains `postgres-backup clickhouse-backup` and no
`redis-backup`/`analytics-backup` — and `compose up -d … $STACK_SERVICES` only acts on the named
services, so on a pipeline-led host the Redis snapshot scheduler and the cold-analytics archiver
are never started or recreated. `VERIFY_SERVICES` (`ci/stages/verify.sh:29-35`) omits them too,
so the verify stage cannot notice. `deploy/DEPLOYMENT.md:466-472` documents a deliberate known gap
for `ha`, `isolation`, `outbound-mta` only — these two are not covered by that note, and the manual
path's own verify list *does* include them (`deploy/scripts/deploy.sh:475-476`), which shows the
intended set.

Impact: on a fresh pipeline-bootstrapped host (the documented bootstrap,
`deploy/DEPLOYMENT.md:37-62`) Redis has no encrypted backups and the analytics cold store is never
archived; on an upgraded host the containers keep running old images indefinitely.

Fix: add `redis-backup analytics-backup` to `STACK_SERVICES` (deploy) and `VERIFY_SERVICES`
(verify), and extend the DEPLOYMENT.md service map accordingly.

### <P2> Required gate lanes silently warn-skip when their interpreter/tool is missing, and the run can still be blessed

Evidence: the framework's stated policy is fail-closed on the deploy host (`ci/lib.sh:504-525`,
`ci_have_tool`), and `ci/stages/validate.sh:65-78` implements it for docker. Three required lanes
instead skip with a warning and return success:

* `ci/stages/ui.sh:97-100` — `command -v python3 … || { ci_warn "python3 missing — all six ui gates
  skipped"; return 0; }`: with python3 absent the whole UI stage is `ok`, so a blessing records
  `ui` in `passedStages` although no UI gate ran.
* `ci/stages/validate.sh:362-364` (python3 missing → panic-path/capability/pricing/knowledge/eval/
  repo-map gates skipped) and `:574-580` (no pinned zola obtainable → "marketing gates … skipped",
  covering the `CI_MARKETING_VALIDATION=required` validators, `:628-659`).
* `ci/stages/test.sh:1019-1049` — python3 missing skips workspace cycles, feature-flag,
  entitlement and audit-coverage gates while the stage reports green.

These are exactly the "defaults that gated nothing" failures `pipeline.conf` says were fixed; the
tool-gated lanes (PHP/SDK/satellite/static lint/contrast) do it right via `lane_tool_status`.

Fix: route these through `ci_have_tool` / `lane_tool_status` (hard failure on the deploy host,
explicit advisory override otherwise), matching `validate_compose`'s own pattern.

### <P2> `scripts/clickhouse-backup.sh:76-89` — a failed/empty backup reports success, and the scheduler then prunes older good backups

Evidence:

```
ch_query "SELECT database, name FROM system.tables …" | while … do … done
if [ ! -s "${backup_root}/manifest" ]; then
    echo "WARNING: no non-system tables found — backup is empty." >&2
fi
echo "Backup complete: ${backup_root}"
```

The producer side of the pipeline can fail (auth error, ClickHouse down) without affecting the
pipeline's exit status (`set -eu` applies to the pipeline as a whole and the `while` exits 0 on
empty input), so the script prints "Backup complete" and exits 0 with an empty backup directory.
The production scheduler runs it as `if ! sh /usr/local/bin/clickhouse-backup.sh backup; then err
…; return 1; fi` (`deploy/hardening/scripts/clickhouse-backup-encrypt.sh:150-153`) — rc 0 is taken
as success — and then prunes old archives by age and count (`:135-145`), i.e. a persistently
misconfigured credential rotates out every good backup while the container reports healthy until
the 25h freshness healthcheck trips.

Fix: capture the `SELECT` command's status (temp file instead of a pipeline) and fail when it is
non-zero or the manifest is empty. A backup tool must never return 0 without a manifest.

### <P2> `ci/stages/security.sh:29-44` + `deploy/DEPLOYMENT.md:44` — the gitleaks "full history" gate scans one commit on the documented deploy-host checkout

Evidence: the gitleaks lane's contract is "Scans the FULL git history (same as the GitHub job, which
checked out with fetch-depth: 0)" (`ci/stages/security.sh:31-34`). The documented fresh-host
bootstrap clones shallow: `git fetch --depth 1 origin main && git checkout -f main`
(`deploy/DEPLOYMENT.md:44`), and nothing in `ci/stages/fetch.sh` (which runs
`git fetch --no-tags origin main`, `:52`) or anywhere else unshallows. I verified the Git semantics
locally: a `--depth 1` clone stays at depth 1 after `git fetch --no-tags origin main`
(`git rev-list --count HEAD` = 1 before and after). On such a host the required secret-scan gate
silently degrades to the current tree, and the `.gitleaks.toml` history triage (which allowlists
individual historical files and states that removed findings were reviewed in full history) proves
nothing.

Fix: make the host checkout a full clone (drop `--depth 1` in DEPLOYMENT.md, or add
`git fetch --unshallow` to the fetch stage), and have the security lane fail/warn loudly when
`git rev-parse --is-shallow-repository` is true.

### <P2> `ci/stages/fetch.sh:86-111` + `ci/README.md:773-799` + `deploy/DEPLOYMENT.md:60` — the documented fresh-host bootstrap cannot pass the branch-protection gate

Evidence: on the deploy host `fetch` hard-fails when `gh` is absent
(`ci/stages/fetch.sh:91-95`: `elif ! command -v gh … if [ "${CI_MISSING_TOOLS:-auto}" = fail ] ||
ci_on_deploy_host; then ci_err …; return fail`) and hard-fails when the protection table is missing a
row (`:103-109`). `ci/install.sh` (step 5 of the bootstrap, `deploy/DEPLOYMENT.md:60`) installs no
`gh` and no token, and `ci/README.md:272` records the live state as: "main has NO required approving
reviews, NO CODEOWNERS enforcement and NO direct-push restriction". Per the code, the sequence
bootstrap → `ci/pipeline.sh run` fails at stage 01 unless the operator also performs the README §13
prerequisites (gh + admin-read PAT), which the bootstrap itself does not mention.

Live GitHub protection state is NOT-VERIFIED here (no API access in this environment); the finding
is that the *documented* path is incomplete/contradictory, not that production is currently red.

Fix: add `install_gh()` + a `GITHUB_TOKEN` prerequisite check to `ci/install.sh` and step 5 of
DEPLOYMENT.md, or scope the fetch gate to "token configured" with a loud banner and adjust §13/§272
to match the chosen policy.

### <P3> `ci/stages/validate.sh:440-445` — the version-tag drift check is dead code

`case $_ref in :v[0-9]*)` is matched against values like
`ghcr.io/sbelakho2/apexmail/api-server:latest`; a POSIX `case` pattern must match from the start of
the string, so `:v…` can only ever match a ref *starting* with `:v`. Proved with
`sh -c 'ref=…api-server:v1.2.3; case $ref in :v[0-9]*) echo MATCHED;; *) echo NOT_MATCHED;; esac'`
→ `NOT_MATCHED`. Fix: use `case $_ref in *:v[0-9]*)` (or `${_ref##*:}`).

### <P3> `ci/stages/images.sh:200-249` — the comment promises an advisory scan of the excluded sidecars; no scan exists

The blocking gate derives `_scan_refs` from the compose config and excludes everything matching
`_sidecars='postgres-backup|clickhouse-backup|redis-backup|…'` (`:208-215`), with the comment
"they are scanned ADVISORILY below instead of blocking the deploy" (`:204-207`). There is no second
loop: excluded first-party images (the backup sidecars, which this pipeline builds) are never
scanned by trivy anywhere (`ci/stages/security.sh:181-213` re-scans only api-server+mta;
`scripts/scan-vulnerabilities.sh:52-69` scans a fixed third-party list and is not wired into CI).
Fix: add the promised advisory trivy pass over the excluded first-party builds (and keep it
advisory), or correct the comment and record the decision.

### <P3> `scripts/compare-baseline.sh:153-161` — without `bc`, every metric silently "passes"

`pct_change=$(… | bc -l 2>/dev/null || echo "0")` and `degraded=$(echo … | bc -l 2>/dev/null ||
echo "0")`: on a host with no `bc` (only `jq` is checked, `:82-86`) the change is computed as 0 and
`degraded` as false, so a regression run exits 0 with "✅ All metrics pass". This is the load-test
regression gate the perf wave was supposed to adopt (referenced from
`docs/evaluation/baselines/README.md`, `docs/evaluation/load-testing.md`). Fix: compute in
awk/python (or require `bc` with a hard error).

### <P3> `deploy/tests/cta-tracking-test.sh` wired as REQUIRED (`ci/stages/validate.sh:658`) but cannot fail

The script only ever records `warning` severities (`:81,100`) and its `main` ends without an exit
check (tail of file), so under `CI_MARKETING_VALIDATION=required` the "required" flag is decorative
for this validator: it can never produce a non-zero exit. Either give it a critical class or run it
advisory so the manifest doesn't claim a gate that cannot gate.

### <P3> `deploy/tests/performance-budget.sh` (via `ci/stages/validate.sh:653-657`) — a required merge gate that measures live production from the CI host

The gate budgets TTFB (median of 3 network samples) and per-page byte totals against
`https://apexmail.ee` (`:42-60,114-130`) and files failures against the merge when production or the
executor's path to it is slow. It is genuinely chromium-free (the raw-HTML path is the real one),
but it gates the *state of production*, not the artifact under test, from inside the merge lane.
Worth making the required/advisory split explicit (e.g. byte budgets required, TTFB advisory) so a
prod wobble cannot fail an unrelated merge.

### <P3> Stale references to retired GitHub-workflow artifacts

* `deploy/DEPLOYMENT.md:18` — "GitHub Actions is decommissioned (archived under
  `.github/workflows-archive/`)" but that directory does not exist, and
  `ci/stages/validate.sh:165-168` *fails the run* if it ever reappears. The same doc's step 2
  (`:44`) and `scripts/rotate-secrets.sh:6` ("rendered … by `.github/workflows/deploy-hetzner.yml`")
  and `:522` ("update APEXMAIL_PROD_ENV (GitHub secret)") reference deleted workflows/secrets.
* `deploy/tests/enterprise-gate-tracking.md:101-106` lists `.github/workflows-archive/*.yml` as
  live CI files.
* `ci/stages/test.sh:38-42` header still says "DB/Redis policy: GitHub-parity by default
  (`CI_TEST_DB=none`, `CI_TEST_REDIS=0`)" while `ci/pipeline.conf:57-58` defaults to
  `ephemeral`/`1` — the pipeline's own DB policy is mis-documented in the stage it governs.
* `.woodpecker.yml:33-36` says "The all-zero digest below is the committed PLACEHOLDER", but line 57
  pins a real digest; and the comment says "all six gates" (`:145`) where `ci/pipeline.conf` now
  defines seven `CI_UI_*` flags.
* `ci/stages/security.sh:74` logs `cargo audit --deny warnings (…)` while the executed command
  (`:82`) has no `--deny` flag — the log claims a stricter gate than runs (the surrounding comment
  explains warnings intentionally do not gate; the log line should say so).
* `ci/stages/test.sh:947-956` — the i18n gate warns and returns 0 when `i18n.json` or zola is
  missing, and shells out to the **host** `zola` rather than the pinned `ci_zola` — same
  silent-skip class as the P2 above, plus a pinned-tool-policy bypass.

### <P3> `ci/woodpecker/toolchain.sh` is an unreferenced, divergent duplicate

`grep -rn 'woodpecker/toolchain'` finds no caller; the Woodpecker first step runs the image-baked
`apexmail-ci-toolchain` (`ci/ci-image/toolchain.sh`, `.woodpecker.yml:123`), which is the stricter
exact-pin checker. The duplicate is weaker (major-version regexes only) and still feeds the blessing
hash (`ci/lib.sh:359-367` hashes `ci/woodpecker/*.sh`). Delete it or make one file the source.

### <P3> `ci/stages/fetch.sh:62-72` — the "HEAD is pushed" proof is weaker than documented when `--ref` is a sha

`git fetch origin <sha>` short-circuits when the object already exists locally (verified in a local
simulation: succeed rc=0 for a locally-present unpushed commit, rc=128 "not our ref" only when
neither side has it). `ci/check-pr.sh`/`ci/hooks/pre-push.example` pass a local sha, so the
`merge-base --is-ancestor HEAD FETCH_HEAD` assertion (`fetch.sh:66`) passes without the commit
being on the remote — the pre-push hook still works by accident, but the "pushed" evidence the
header advertises is not what it claims on that path. The branch-name path (`CI_REF=main`, the
timer) is sound.

### <P3> `deploy/scripts/deploy.sh:324-383` — on an rsync'd (non-git) deploy dir the manual full deploy hard-fails at Step 3.5

`GIT_SHA="$(git -C "$DEPLOY_DIR" rev-parse HEAD …)"` is empty when `/opt/apexmail` is not a checkout,
and local `docker build` images carry no `RepoDigests`, so neither pin branch is available; with
`_pinned -eq 0` the script exits with "release manifest would be empty — refusing to continue"
(`:374-377`). The Makefile syncs code over a host checkout, so this is unlikely in the documented
setup — but the emergency path is exactly where a hard failure is worst. Fix: fall back to
`pre-deploy`/`latest` pins with a loud warning instead of refusing, or document the git-checkout
requirement in the script header (it is in `Makefile:29-32` only implicitly).

### <P3> `scripts/security-audit.sh:1-13,51-72` — stale CI framing and a fourth RUSTSEC ledger

The header says "used both in CI (security-audit.yml)" — that workflow is deleted; the CI path is
`ci/stages/security.sh`. Its 20-item `--ignore` list currently matches `CI_CARGO_AUDIT_IGNORES`
(`ci/pipeline.conf:80`) by inspection, but nothing asserts it (the selftest asserts deny.toml ==
pipeline.conf only, `ci/pipeline.sh:563-599`), so this fourth copy can drift. It is wired only as a
pre-commit hook (`.pre-commit-config.yaml:76`).

### <P3> `ci/stages/fetch.sh:103-110` / live state — branch protection is release evidence but not verifiable from the repo

Kept here for the record: the pass/fail of the release lane depends on live GitHub branch-protection
state (approvals, CODEOWNERS, restrictions) which cannot be checked offline. `ci/README.md:786-795`
itself records the protections as unconfigured as of 2026-10-02. NOT-VERIFIED below.

---

## Verified-OK (probed or read end-to-end, no defect found)

* **Mutual exclusion of the two deploy paths** — `ci/pipeline.sh:242-257` and
  `deploy/scripts/deploy.sh:114-143` resolve the same `${APEXMAIL_DEPLOY_LOCK:-/opt/apexmail/.deploy.lock}`;
  the pipeline passes `APEXMAIL_DEPLOY_LOCK_INHERITED=1` to its child build
  (`ci/stages/images.sh:174`) so the images stage cannot self-deadlock.
* **Blessing JSON logic** — `pipeline.sh:92-136,374-407` derives `passedStages` from actual per-stage
  statuses, refuses blessings for advisory/skip/timeout/dry-run runs, and the selftest
  (`pipeline.sh:601-620`) proves the refusal table both directions. The reader/writer share one hash
  helper (`ci/lib.sh:359-367`).
* **Timeout contract** — `ci/lib.sh:217-249` (GNU timeout → gtimeout → watchdog), stage wrapper maps
  124 → failure and 75 → skip (`ci/woodpecker/stage.sh:88-107`), and selftest 7 exercises it.
* **Run-lock semantics** — `ci_lock_file_acquire` (`lib.sh:176-211`) has flock + stale-PID mkdir
  fallback; selftest 8 proves the child process cannot re-acquire.
* **`.woodpecker.yml` wiring** — digest-pinned executor anchor (line 57), services for
  postgres/postgres-fresh/redis/clickhouse, `CI_MISSING_TOOLS=fail`, release-mode soft-skip gate,
  and the notify-github steps posting the required `woodpecker` context. The pinned digest value
  itself is NOT-VERIFIED (no network).
* **Deploy-stage gates** — image-digest tamper guard + SHA256SUMS check
  (`ci/stages/deploy.sh:130-154`), live compose pinning gate + security-posture gate
  (`:174-197`), nginx inode-change restart vs graceful reload (`:207-248`), `.last-deployed-sha`
  recording (subject to the P1 above).
* **Polling/annotation** — `notify.sh` writes the failure marker/journal and enqueues the email via
  `psql -v` variables (injection-safe, `:124-143`); retention prunes in `lib.sh:530-552` +
  `ci/woodpecker/run-dir.sh:36-53`.
* **nginx.conf** — token redaction map, modern TLS at http scope, per-vhost security headers, 421
  default vhost, upstream keepalive, error pages, SSE timeouts; server blocks reference only
  services that exist. `proxy-headers.conf` is included everywhere it should be.
* **Secret bridging** — `deploy/scripts/entrypoint-wrapper.sh` exports `_FILE`/`_B64` variants,
  URL-encodes DSN userinfo, never logs values or lengths; `deploy/load-secret-env.sh` refuses
  setuid/setgid, unsets the `FILE` var, `exec`s directly.
* **Redis/ClickHouse auth** — runtime-generated SHA256-hash ACL with dangerous commands removed
  (`deploy/redis/entrypoint.sh:67-73`), admin user off unless credential present; ClickHouse
  three-user model with `from_env` passwords and loopback-only default
  (`deploy/clickhouse/users.xml:25-72`), bridged by the compose entrypoint chain.
* **Backup encryption wrappers** — AES-256-CBC + PBKDF2 (600k iters), decrypt-verify before shred,
  bounded retention (`deploy/hardening/scripts/postgres-backup-encrypt.sh:1-40` and siblings);
  the Dockerfiles bake openssl/rsync in (no runtime `apk add` on a no-egress network).
* **Alerting wiring** — every `job="…"` referenced by the alert rules exists in
  `deploy/prometheus.yml` (mechanically cross-checked: 16/16 refs match; the five scrape jobs with
  no alert rule are `apexmail-observability`, `blackbox-dns`, `blackbox-dns-txt`,
  `blackbox-http-login`, `synthetic-transactions`); the Alertmanager renderer fails fast on unset
  required vars and strips empty optional receivers (`deploy/scripts/render-alertmanager-config.sh`).
* **CI unit files** — timer every 5 min with `Persistent=true`, oneshot service with
  `CI_RUN_FROM_SYSTEMD=1`, webhook socket bound to 127.0.0.1 with token check
  (`ci/units/webhook-handler.sh`); webhook-handler.sh is committed 755 (the `install` self-copy at
  `ci/install.sh:337` is a no-op, not a defect).
* **Pre-push hook** — fails closed when `ci/check-pr.sh` is missing
  (`ci/hooks/pre-push.example:33-40`) and skips by ref glob only when asked.
* **Root compose invariants** — prod refuses to boot without each `PROD_*_FILE` (`${VAR:?}` guards);
  all 34 `PROD_*` guards appear in `.env.production.example` (mechanically checked); dev binds are
  hardcoded to 127.0.0.1 outside the port variable; the override file is not part of the canonical
  or manual compose invocations.

## `secrets/**` policy — verification, with one correction to the brief

The brief's premise is wrong on one point: these files are **not committed**. `git ls-files secrets`
returns 0 files, `git log --all -- secrets` is empty (matching `docs/security/secrets.md:30`), and
`.gitignore:74-75` ignores `secrets/` and `**/secrets/`. They are untracked local dev fixtures, so
no repository leak exists.

Verified anyway, because the files exist on disk and are what the dev compose mounts:

* **(a) No real external credential.** Stripe files are 64-hex strings, not `sk_live_`/`sk_test_`
  or `whsec_` patterns; `aws_access_key_id.txt`, `aws_secret_access_key.txt`, `smtp_username.txt`,
  `smtp_password.txt` are 0 bytes; `jwt_public_key_pem.txt` is the literal
  `placeholder-public-key`; the rest are random values generated for the dev stack
  (`dev-…-minimum-32` sentinels, UUID, hex). `secrets/dev-mta-tls/{cert,key}.pem` are a self-signed
  CN=mail.apexmail.ee pair (notBefore 2026-10-04) — dev TLS material, untracked.
* **(b) Intent documented and consistent.** `docs/security/secrets.md:1-24` states the model
  (local files under `secrets/`, ignored; prod from the platform secret store) and the dev compose
  mounts them; `.gitignore:74-75` agrees. `.env.example` correctly contains **no** `PROD_*_FILE`
  entries (all 34 live in `.env.production.example`).
* **(c) Production cannot boot from these dev files.** Every production secret is a `file:` entry
  guarded with `${PROD_*_FILE:?…}` in `docker-compose.prod.yml` (verified all 34), with no
  `./secrets/…` fallback; the dev `docker-compose.yml` defaults are a separate file tree that is
  never synced (`Makefile:97-99,120-125`).
* **(d) `trivy-secret.yaml` matches reality.** Its single allow-rule covers Stripe's *public
  documentation example keys* used as DLP detection-corpus constants — the constants really exist in
  `services/mail-server/crates/dlp-engine/src/entropy.rs:366,373,387,412` with matching `nosemgrep`
  justifications; it is not papering over a live secret. One policy note: `trivy fs` also skips the
  whole `secrets` directory (`ci/stages/security.sh:158`), consistent with the ignore rule, but it
  means a force-added real secret would only be caught by gitleaks.

---

## NOT-VERIFIED (and why)

* The `.woodpecker.yml` executor digest `sha256:3e3fedac…` and whether it exists/is current — no
  registry or network access from this environment.
* Live GitHub branch-protection state, and whether `gh` + a token are installed on the real deploy
  host — no API access; the repo docs themselves describe the state as incomplete (see P2).
* Host reality: whether `/opt/apexmail` is a shallow or full checkout; whether `redis-backup` /
  `analytics-backup` / `outbound-mta` / `ha` / `isolation` containers actually run there; whether
  `/var/lib/apexmail` exists (the TLS-renewal state-file directory is never created by any script —
  `deploy/hardening/tls-renew-restart.sh:37` would fail to persist its mtime guard if absent, a
  minor unverified follow-up); whether the systemd units survive (P1 finding 4 is static).
* Whether `ci/woodpecker/stage.sh`'s Woodpecker pipeline is currently green on the Woodpecker
  server, and whether the pushed `apexmail-ci` image contains the exact tool versions its
  `toolchain-versions.env` claims (the build-time `--assert` makes drift unlikely; the pushed image
  is not inspectable here).
* `ci/runs/**` (3907 artifacts — pipeline run outputs, not reviewed as source),
  `deploy/grafana/dashboards/*.json` (14 JSON files) and `deploy/monitoring/dashboards/*.json`
  (4) were screened for references/structure only, not read line-by-line; dashboard query
  correctness is not covered.
* `deploy/load-test-infra/**` (compose + seed SQL), `deploy/cdn/**` (CloudFront/Fastly configs —
  not exercised by this pipeline), `deploy/review/**` (sign-off checklists),
  `deploy/monitoring/incident_policy.md`, `deploy/tests/*.md` (process docs) were read at summary
  level; no testable infra claim failed from that pass.

## Coverage ledger

| Surface | Files | Read in full | Screened | Notes |
|---|---|---|---|---|
| `ci/**` (excl. `ci/runs/**`) | 31 | 31 (pipeline, lib, conf, check-pr, install, README, 11 stages, 3 woodpecker, 5 units, ci-image ×3, hooks, baseline) | – | every gate-bearing file read end-to-end |
| `deploy/scripts/**` | 11 | 11 | – | deploy.sh (594 lines), entrypoint-wrapper, verify-deployment, certbot loop, cache-warm, check-template-leaks, renders, issue-letsencrypt, hetzner-bootstrap, HETZNER_DEPLOY.md |
| `deploy/hardening/**` | 11 | 4 | 7 | tls-renew trio + Dockerfile.postgres-backup read in full; postgres/redis/clickhouse/analytics encrypt wrappers read partially (head + scheduler/retention bodies); other 3 Dockerfiles screened |
| `deploy/{nginx,redis,clickhouse,prometheus,blackbox,tempo,loki,otel-collector}/**` | ~20 | 12 | 8 | nginx.conf, proxy-headers, redis entrypoint+ACL, clickhouse entrypoint+users.xml, prometheus.yml/blackbox/prometheus-web, alerting rules cross-checked |
| `deploy/tests/**` | 32 | 4 | 28 | 13 gate scripts' exit/report logic read + tails; the rest (browser matrices, .md, report JSON fixtures) screened |
| `deploy/{grafana,monitoring}/**` | 29 | 3 | 26 | provisioning YAML read; dashboards JSON screened only |
| `deploy/grafana` dashboards | 14 | 0 | 14 | NOT-VERIFIED as above |
| `deploy/{review,load-test-infra,cdn,synthetic-monitor,clickhouse-exporter}/**` | ~18 | 6 | 12 | setup.sh/probe/exporter screened |
| `deploy/{DEPLOYMENT.md,rollback-plan.md,staging-equivalence.md}` | 3 | 3 | – | known-gap section and rollback procedure cross-checked against code |
| root compose ×3 + Makefile + trivy-secret + .trivyignore + .gitleaks.toml + .pre-commit + Dockerfiles (non-apps) | 9 + 6 | 9 + 5 | 1 | both compose files read in relevant sections (98 KB / 88 KB files were read by section, not line-by-line) |
| `scripts/**` | 8 | 8 | – | all read end-to-end |
| `secrets/**` | 27 | 27 (headers/content) | – | untracked; content-format inspection only |
| `.github/**`, `.woodpecker.yml` | 3 | 3 | – | no `.github/workflows/` exists (checked) |
| `ci/runs/**` | 3907 | 0 | 2 manifests + 2 logs | run outputs, not source |

What I did not reach: line-by-line review of the 14 Grafana/monitoring dashboard JSONs, the
`deploy/tests` browser-matrix docs and report fixtures, `deploy/cdn/**`, `deploy/review/**`, the
full body of `deploy/DEPLOYMENT.md` (read: architecture map, bootstrap, secrets table, immutable
artifacts, rollback, verification checklist sections), and all command execution that needs
production access (branch-protection API, registry digests, host state).
