# ApexMail self-hosted CI/CD pipeline (`ci/`)

Fully independent, GitHub-free CI/CD for ApexMail, per the owner's directive:
*“GitHub CI should not be relied on… extremely solid and reliable pipeline,
replaces all or almost all of GitHub Actions’s functionalities, fully
independent.”* Everything here is POSIX sh + the tools already on the host
(docker, cargo, jq). No YAML, no runners, no registry, no GitHub API.

---

## 1. Architecture

```
 (timer every 5 min)      (webhook 127.0.0.1:8088)      (human)
        │                        │                        │
        └───────────┬────────────┴───────────┬────────────┘
                    ▼                        ▼
             ci/pipeline.sh run [ --stages … --skip-deploy --ref … ]
                    │  (flock/mkdir lock: one run at a time)
                    ▼
   ci/runs/<UTC-ts>/  manifest.json + stages/<stage>.log + provenance
                    │
   ┌──────────────────────────────────────────────────────────────────┐
   │ 01 fetch      git fetch origin main (deploy key); refuse unpushed │
   │ 02 validate   env-file, compose -q, pipeline sanity, repo gates   │
   │ 03 test       fmt, clippy -D, cargo test --workspace (+ephemeral  │
   │               DB/Redis opt-in), PHP suites                        │
   │ 04 security   gitleaks, cargo audit (+RUSTSEC ignores), cargo vet,│
   │               fresh-DB migration validation, Trivy(+SBOM)         │
   │ 05 images     deploy.sh --build-only + :sha pins + Trivy gate     │
   │ 06 migrate    _sqlx_migrations backup + migrator one-shot         │
   │ 07 deploy     TLS publish, compose up -d, nginx reload            │
   │ 08 verify     per-service health, HTTP probes, SMTP, TLS, cache   │
   │ 09 notify     failure marker + journal + email via email_queue;   │
   │               run-dir pruning                                     │
   └──────────────────────────────────────────────────────────────────┘
        first hard failure stops the line; notify always runs
```

**Uniform stage contract** — every `ci/stages/<name>.sh` is executable POSIX
sh defining `stage_main()`; exit `0` ok / `1` fail / `75` skipped
(infrastructure intentionally absent, e.g. deploy stages on a dev machine) /
`124` timeout. The runner captures each stage's combined output (capped at
`CI_LOG_MAX_LINES`, default 200 000 lines: head + tail kept, middle
truncated) into `ci/runs/<ts>/stages/<stage>.log`, enforces a per-stage
timeout, and appends `{name,status,exit_code,duration_s}` to
`ci/runs/<ts>/manifest.json` (jq; falls back to `manifest.jsonl`).

**Defensive by construction**: `set -eu` everywhere; single-run lock
(`flock`, or a mkdir+PID lock with staleness detection on hosts without
flock — macOS); traps tear down ephemeral containers; run dirs pruned to the
newest `CI_KEEP_RUNS` (30) and `history.log` capped at 500 lines; notify
emails rate-limited (`CI_NOTIFY_COOLDOWN`, 30 min); stage logs and container
names are bounded; no unbounded growth anywhere.

**Commands**

```
ci/pipeline.sh run [--stages a,b] [--skip a,b] [--skip-deploy] [--ref REF]
                   [--advisory a,b] [--dry-run] [--force] [--lock-wait S]
ci/pipeline.sh status      # last run manifest, failure marker, containers
ci/pipeline.sh list        # stages, timeouts, advisory flags
ci/pipeline.sh selftest    # contract tests + full dry-run (no infrastructure)
ci/check-pr.sh [ref] [--fast|--skip-security] [--allow-dirty]
```

Configuration: `ci/pipeline.conf` (repo defaults) → `/etc/apexmail/
pipeline.conf` (host) → environment variables (always win).

---

## 2. Workflow replacement map — every file in `.github/workflows/`

The recommendation is to archive the GitHub workflows (move
`.github/workflows/` → `.github/workflows-archive/`), which only the repo
owner should do (this `ci/` directory deliberately does not touch `.github/`).
The validate stage enforces that this table stays complete: if a workflow
file exists without a row here, validation fails.

| Workflow | Verdict | Replaced by / why |
|---|---|---|
| `rust-check.yml` | **REPLACED** | `test` stage: cargo fmt --check (`CI_FMT_CHECK`, see §9 F7), clippy `--workspace --all-targets -D warnings`, `cargo test --workspace`, dependency-cycle / security-feature-flag / audit-coverage python gates, cargo-machete + cargo-deny (when installed — GitHub installed them on the runner; `ci/install.sh` installs them on the host, elsewhere they degrade to a warning). Secret-scan job → `security` stage (gitleaks). Semgrep SAST job → **not replicated** (see §5). |
| `security-audit.yml` | **REPLACED** | `security` stage: `cargo audit --deny warnings` with the identical 15-entry RUSTSEC ignore list (keep both lists in lockstep — the justifications live in the old workflow and in `ci/pipeline.conf`). `outdated` job → advisory report only, as upstream (`continue-on-error`). Weekly cadence → the timer runs it on every poll; set `--stages security` for a standalone audit. |
| `cargo-vet.yml` | **REPLACED** | `security` stage: runs `cargo vet --locked` **iff `services/mail-server/supply-chain/config.toml` exists** — it does not today, so vet skips with a note, exactly like the upstream job's `configured=false` path. |
| `sqlx-migration-validation.yml` | **REPLACED** | `security` stage: `migrator --dry-run` (embedded set) + `sqlx migrate run` **twice** against a throwaway `postgres:16-alpine` (clean apply + idempotency — the same two assertions). Currently **red**: §9 F1, so the gate runs as `CI_MIGRATION_CHECK=advisory` until migration 109 is fixed. |
| `deploy.yml` | **REPLACED** | `images` stage builds every canonical target (via `deploy/scripts/deploy.sh --build-only` — the same Dockerfile targets the workflow used), tags `:latest` + `:<sha>` locally (no registry at all). Trivy CRITICAL/HIGH gate on api-server + mta runs post-build in `images` (and pre-deploy in `security` on whatever images exist). Syft SBOM → Trivy SPDX JSON in the run dir (advisory, as upstream). Image-name drift guard job → `validate` stage (ported verbatim). `pr-gate` job (checks API polling) → **cannot replicate without GitHub** — substitute: `ci/check-pr.sh` + the pre-push hook (§4). |
| `deploy-hetzner.yml` | **REPLACED** | The pipeline runs **on the host itself**, which eliminates the entire SSH/runner layer: env validation (`validate`), the migration gate (`migrate`), `compose up` + nginx reload (`deploy`), the rollout verification incl. SMTP banner + TLS check (`verify`). Secrets stay in `/opt/apexmail/.env` + `secrets/` (0600) — nothing transits a third-party runner. |
| `rust-panic-paths.yml` | **REPLACED** | `validate` stage: `check_rust_panic_paths.py` + `check_outbound_delivery_contract.py`. |
| `release-gates.yml` | **REPLACED** | Build/lint/type/unit jobs → `validate` (zola build, legal constants, rollback doc) + `test` (clippy, cargo test). |
| `regression_checks.yml` | **REPLACED** | Obsolete-registry-code scan + `fixes.md` evidence → `validate` (required); prohibited-claims + placeholder scans → `validate` (advisory, as upstream which warned); `cargo test -p compliance` → subsumed by `cargo test --workspace` in `test`. |
| `legal-identity.yml` | **REPLACED** | `validate`: all 18 legal constants in `compliance/src/legal_entity.rs`, forbidden patterns, and (zola present) `validate_legal_identity.py` over the built HTML. |
| `pricing-drift.yml` | **REPLACED** | `validate`: zola build + `validate_pricing_drift.py` — **required** when zola is installed (it was a `deploy.yml` pr-gate required check); `CI_ZOLA_REQUIRED=1` makes a missing zola fatal. |
| `kiwi-leak-check.yml` | **REPLACED** | `validate`: `tools/check-kiwi-marketing-isolation.sh` (required). |
| `html-validation.yml` | **REPLACED** | `validate` (advisory): `deploy/tests/html-validate.sh` over the zola build. |
| `accessibility-check.yml` | **REPLACED** | `validate` (advisory): `deploy/tests/contrast-check.sh` over the zola build. |
| `seo-audit.yml` | **REPLACED** | `validate` (advisory): `deploy/tests/seo-validate.sh` over the zola build. |
| `claim-expiry-check.yml` | **REPLACED** | `validate` (advisory): `check_claim_expiry.py --warn-days 30`; the monthly stale-report job is unnecessary — the run dir keeps every check's output. |
| `broken-link-check.yml` | **MOVED-TO-ARCHIVE** | External-URL crawler whose flakiness (third-party sites) would block deploys if wired into the gate. Manual/periodic substitute (identical check): `cd apps/marketing-zola && zola build && BUILD_DIR=public bash ../../deploy/tests/broken-links.sh` |
| `load-gate.yml` | **MOVED-TO-ARCHIVE** | k6 load/stress/spike suites + `deploy/load-test-infra/docker-compose.ci.yml` need a dedicated ~2h window and idle hardware; polling them into the deploy gate would starve production. Manual substitute: `docker compose --env-file <secrets> -f deploy/load-test-infra/docker-compose.ci.yml up -d --build postgres redis api-server`, then `k6 run load-tests/http/*.js`. k6 remains installed on the dev machine. |
| `mobile-qa.yml` | **MOVED-TO-ARCHIVE** | Needs a real (headless) Chromium — a GUI-browser dependency CI hosts must not grow. Manual: `bash deploy/tests/mobile-test.sh`. |
| `performance-budget.yml` | **MOVED-TO-ARCHIVE** | Same Chromium dependency (`deploy/tests/performance-budget.sh`). |
| `mutation-testing.yml` | **MOVED-TO-ARCHIVE** | 3-hour cargo-mutants sweep, weekly by design. Manual: `cd services/mail-server && cargo mutants -p api-server … --output mutants-out`. |
| `auto-merge.yml` | **MOVED-TO-ARCHIVE** | Dependabot + GitHub PR API + `gh pr merge` — meaningless without GitHub PRs. Dependency updates are now: `cargo update` → `ci/check-pr.sh` full → push (the timer deploys it only if green). |

### Advisory vs required

Advisory checks log `ADVISORY failure — continuing` and never fail the stage.
Everything else fails the run. Which checks are advisory mirrors upstream
severity (e.g. claims scans warned; pricing drift was required). Move a check
between buckets by editing `ci/stages/validate.sh` (`ci_check` ↔ 
`ci_check_advisory`).

---

## 3. Stage reference (timeouts, durations)

| # | Stage | Timeout (conf) | Measured on the dev machine (2026-08-21, warm caches) |
|---|---|---|---|
| 1 | fetch | 180 s | 2 s (HTTPS fetch + pushed-HEAD check) |
| 2 | validate | 1800 s | 45–150 s (zola build + pricing/legal/a11y/seo gates dominate) |
| 3 | test | 5400 s | **247 s total**: fmt+clippy gates ~25 s, nextest 5410 tests 200 s, 3 PHP suites ~35 s, WCAG AA contrast gate ~2.5 min (after the PHP suites; loud-skip when node/playwright are absent) |
| 4 | security | 2700 s | **172 s**: gitleaks ~10 s (full-history first scan ~3.5 min), cargo audit ~10 s, fresh-DB migration validation ~60 s |
| 5 | images | 10800 s | host-only (Rust docker build; `deploy.sh --build-only` timing) |
| 6 | migrate | 600 s | host-only (migrator one-shot, seconds) |
| 7 | deploy | 1200 s | host-only (up -d + nginx reload, ~30 s) |
| 8 | verify | 900 s | host-only; remote mode (CI_VERIFY_REMOTE=1) ~5 s |
| 9 | notify | 300 s | <1 s (prune + marker; email only on failure) |

Off the deploy host, stages 5–8 exit `75` (skipped) — the pipeline on a dev
machine is a genuine CI (validate/test/security) without deploy rights.
`ci/pipeline.sh selftest` dry-runs the whole graph in ~7 s.

### Deploy decision (stages 5–7)

`deploy/scripts/deploy.sh` is **not** editable from `ci/`, and it has no
flags for "migrate only" or "up without rebuilding and without re-running the
migrator" (`--build-only` and `--no-build` are all it offers). So:

* **images** = `deploy.sh --build-only` — the single build implementation,
  reused verbatim (same Dockerfile targets as the GitHub workflow), then
  this stage adds `:<sha>` tags, the Trivy gate and sha-tag pruning.
* **migrate** = the exact compose invocation `--profile migrate run --rm
  migrator` (what deploy.sh Step 5 and deploy-hetzner.yml both run), plus a
  pre-run `pg_dump -t _sqlx_migrations` backup into the run dir and a
  ledger-count assertion. Not `deploy.sh --no-build`, because that would
  re-run the migrator and its cleanup passes.
* **deploy** = deploy.sh Steps 4/6/8 replicated (TLS publish, `up -d
  --remove-orphans` over the canonical service list, retried `nginx -s
  reload`, dangling-image prune). Calling `deploy.sh --no-build` here would
  duplicate the migration gate; the stage order of this pipeline already
  guarantees build → migrate → up.

---

## 4. The PR / branch-protection substitute

GitHub's check-runs API, PR status checks and the branch-protection UI have
no offline equivalent — nothing can put a red X on a website we do not own.
The substitutes, in enforcement order:

1. **Before push** — install the hook once:
   ```
   cp ci/hooks/pre-push.example .git/hooks/pre-push && chmod +x .git/hooks/pre-push
   ```
   Every push then runs the `validate` lane (~1–3 min) on the exact commits
   being pushed. `APEXMAIL_PREPUSH_MODE=full git push` runs everything
   (~15 min).
2. **Before merge (manual)** — `ci/check-pr.sh <branch-or-sha>` runs
   validate+test+security against a throwaway detached worktree of that ref
   (current tree for HEAD). This is the direct substitute for "the PR checks
   were green".
3. **After push (automatic, the real gate)** — the host timer pulls main and
   runs the same stages; **a red stage stops the line before images or
   deploy**, exactly like a required check blocking a deploy. `fetch`
   additionally refuses anything not pushed to origin/main.
4. **Visibility** — `ci/pipeline.sh status`, `ci/.last-failure` (machine
   readable), the journal (`journalctl -t apexmail-ci`), and the notify
   email (§6).

---

## 5. What is honestly NOT replicated

| GitHub feature | Status | Substitute |
|---|---|---|
| PR status checks / check runs UI | gone with GitHub | §4: pre-push hook + `check-pr.sh` + host-enforced gating |
| Branch protection rules | gone | same — plus the fetch stage's pushed-HEAD guarantee |
| Dependabot + auto-merge | gone | manual `cargo update` → `check-pr.sh` full → push |
| GHCR push + image provenance/SBOM attestation signatures | dropped (no registry by design) | local `:<sha>` tags; Trivy SPDX SBOMs per run (unsigned — add cosign later if needed) |
| Semgrep SAST (`p/default`, `p/rust`, …) | not replicated | gitleaks + cargo-audit + cargo-deny + Trivy cover the repo's declared lanes; to add: `pip install semgrep && semgrep scan --config p/default --config p/rust --error` as an advisory check |
| SARIF uploads to GitHub Security | gone | same reports as JSON/text in `ci/runs/<ts>/` |
| GitHub runner isolation | inverted model | the pipeline runs on the deploy host as root bounded to repo code fetched over the deploy key; hardening in the unit (`PrivateTmp`, journald logging, socket-activation rate caps) |

---

## 6. Notify mechanism & operational details

* **Email through the platform** (`ci/stages/notify.sh`): on failure, a row
  is INSERTed into `email_queue` via `docker compose exec -T postgres psql`,
  and the platform's own worker delivers it through the production path
  (MTA/SES). The notification is therefore also a live canary for outbound
  delivery. Rate-limited to one per `CI_NOTIFY_COOLDOWN` (1800 s); recipient
  `CI_NOTIFY_TO` (default `admin@apexmail.ee`).
* **Marker + journal**: `ci/.last-failure` (grep-able key=value) and
  `journalctl -t apexmail-ci -p err` on the host.
* **Webhook (optional push-trigger)**: `ci/install.sh webhook-token`, then
  `systemctl enable --now apexmail-pipeline-webhook.socket`; trigger with
  ```
  curl -H "X-ApexMail-Token: $(sudo cat /etc/apexmail/webhook-token)" \
       -d '{"ref":"main"}' http://127.0.0.1:8088/hooks/pipeline
  ```
  (tunnel the port or run curl on the host; the socket binds 127.0.0.1 only).
* **Boundedness**: run dirs pruned to newest 30; `history.log` 500 lines;
  stage logs head+tail capped; `:<sha>` image tags pruned to newest 5 per
  service; ephemeral containers removed in traps; notify email cooldown.

---

## 7. Host installation (Hetzner deploy host)

Run once as root from the repo checkout at `/opt/apexmail` (the repo tree
must live there — the units and `deploy.sh` paths assume it):

```
# 0. get ci/ onto the host (one-time; afterwards rsync from the Makefile
#    covers it — add ' ci' to SYNC_DIRS in the Makefile, see §9)
sudo -i
cd /opt/apexmail

# 1. deps + cargo tools (gitleaks, trivy, cargo-audit, sqlx-cli) + units + timer
./ci/install.sh

# 2. read-only deploy key for fetch (prints the PUBLIC key to add at
#    https://github.com/sbelakho2/ApexMail/settings/keys/new — tick READ-ONLY)
./ci/install.sh deploy-key

# 3. optional webhook secret
./ci/install.sh webhook-token
systemctl enable --now apexmail-pipeline-webhook.socket

# 4. verify
./ci/install.sh check
./ci/pipeline.sh selftest          # dry-run, touches nothing
./ci/pipeline.sh run --skip-deploy # first real CI run (no deploy)
./ci/pipeline.sh run               # full run: build → migrate → deploy → verify
```

The timer (`apexmail-pipeline.timer`) then polls every 5 minutes; runs are
no-ops while the tree already matches origin/main (the fetch stage records
the sha; add your own change-detection in `ci/pipeline.conf` if you want the
poll to skip stages when HEAD is unchanged).

On a dev machine (macOS): nothing to install — `ci/pipeline.sh selftest` and
`ci/pipeline.sh run --skip-deploy,verify` work as-is (flock-less lock fallback,
GNU-timeout-less watchdog). `zola`, `gitleaks`, `trivy`, `jq`, docker and
cargo are expected on PATH; missing optional tools degrade with warnings.

---

## 8. Test-stage DB/Redis policy

GitHub-parity by default (`CI_TEST_DB=none`, `CI_TEST_REDIS=0`): the
DB/Redis-gated Rust tests self-skip, exactly as they did on GitHub runners
(rust-check.yml ran no service containers). Stronger local modes:

```
CI_TEST_DB=ephemeral ci/pipeline.sh run --stages test   # postgres + canonical SCHEMA + TEST_DATABASE_URL
CI_TEST_REDIS=1      ci/pipeline.sh run --stages test   # redis + TEST_REDIS_URL
```

Both currently surface real defects that GitHub CI never executed (§9 F3,
F4) — they are opt-in until fixed.

---

## 9. Known pipeline findings (discovered while building this, 2026-08-21)

These are **product defects found by this pipeline**, not pipeline bugs:

* **F1 — the migration chain cannot bootstrap a fresh database.**
  `sqlx migrate run --source services/mail-server/migrations` (and the
  `migrator` binary) fail at migration `109_init.sql`:
  `unique constraint on partitioned table must include all partitioning
  columns` — migration 050 partitioned `mail_messages` (partition key
  `created_at`), and 109 later creates `UNIQUE INDEX (mailbox_id, uid)` and
  the `(account_id, mailbox_id, message_id)` dedup index without the
  partition key. Production survives because the objects pre-exist there;
  a fresh host cannot be provisioned, and the GitHub
  sqlx-migration-validation workflow would fail identically today. Until
  fixed, `CI_MIGRATION_CHECK=advisory` downgrades the security-stage check
  (it then reports instead of blocking).
* **F2 — the migrator one-shot crashes on a *completely* fresh database**:
  `applied_count` decodes `SELECT to_regclass(...)::text` as a non-optional
  String; on a fresh DB the row is present with a NULL column and decode
  fails (`unexpected null`). sqlx-cli is unaffected (the security stage
  prefers it for this reason).
* **F3 — `test_kiwi_token_is_single_use_when_redis_available` fails whenever
  Redis is actually present** (first verification rejected). GitHub never ran
  it (no Redis on the runner) so it self-skipped there.
* **F4 — two DB-backed api-server tests bind text ULIDs into UUID `id`
  columns** (`reset_password_token_roundtrip_against_db`,
  `ssr_data_layer_renders_seeded_rows_with_filters_and_paging`) against both
  the migration chain and the canonical `apexmail-db` SCHEMA — again, never
  executed on GitHub (no postgres on the runner).
* **F5 — `ui-foundation` cannot compile on a fresh checkout**: it
  `include_str!`s `apps/marketing-zola/public/**`, which is generated output
  and currently untracked. The pipeline's test and validate stages build the
  marketing site first; consider committing `public/` (the Makefile already
  documents it as a committed build input) or adding a zola build step to
  the Dockerfile entry conditions.
* **F6 — integration tests probe ambient local services**: the
  sales-autopilot (`SALES_TEST_DATABASE_URL`), enterprise
  (`ENTERPRISE_TEST_DATABASE_URL`) and api-server kiwi (`TEST_REDIS_URL`)
  suites default to `127.0.0.1:5432/6379` when their env var is unset. On
  this dev machine a brew postgres on 5432 made 7 dispatcher tests run
  against a stale dev DB and fail (`value too long for character
  varying(26)`); on GitHub they always soft-skipped (nothing listens there).
  The pipeline's default mode pins those probes at `127.0.0.1:1` so they
  soft-skip deterministically on every host (the deploy host's compose
  postgres has no host port binding, so it is safe there too — but explicit
  is better). `CI_TEST_DB=ephemeral`/`CI_TEST_REDIS=1` point them at the
  ephemeral containers instead.
* **F7 — committed formatting drift**: `cargo fmt --check` fails on
  origin/main itself (rust-check.yml never ran fmt; this pipeline adds it —
  991 files currently need formatting). The fmt gate therefore defaults to
  `CI_FMT_CHECK=advisory`: the full diff is recorded in the run dir and a
  warning logged. Run `cargo fmt` in `services/mail-server`, commit, then
  set `CI_FMT_CHECK=required` in `ci/pipeline.conf`.
* **F8 — clippy drift against a current toolchain**: `cargo clippy
  --workspace --all-targets -- -D warnings` (exactly rust-check.yml's lane)
  reports 64 errors on current main with rust-clippy 1.96 — a mix of real
  lint (e.g. `named argument 'content' is not used by name` in
  ui-foundation, `empty line after doc comment` in leptos_views) and newer
  lints the GitHub runner's older stable never saw
  (`unnecessary_first_then_check`). Same treatment: the gate runs on every
  test stage, records `clippy-check.log` in the run dir, and defaults to
  `CI_CLIPPY_CHECK=advisory` until the tree is clean — then required.
* **F9 — the WS-ALL audit-coverage ledger is stale**: `tools/
  check_audit_coverage.py` fails with "audit coverage crate listed but
  missing Cargo.toml: bounce-analytics" — the ledger still lists a crate the
  workspace removed (see deploy/DEPLOYMENT.md "Legacy / removed crates").
  rust-check.yml ran the same check and would fail identically. Advisory
  (`CI_AUDIT_COVERAGE_CHECK`) until the ledger row is removed.
* **F10 — env-mutating tests race under `cargo test` (not under nextest)**:
  `worker-processors::email::tracking::tests::
  encode_without_secret_is_refused_and_html_untouched` removes
  `TRACKING_SECRET_KEY` and asserts refusal — under `cargo test`'s threaded
  model a sibling test can re-set the variable mid-assertion, making the
  suite flaky. rust-check.yml ran `cargo nextest run` (one process per
  test), which is immune; this pipeline therefore prefers nextest and only
  falls back to `cargo test` when nextest is not installed (install it via
  `ci/install.sh`).
* **F11 — gitleaks flags findings in the git history**: `gitleaks detect`
  over the full history (exactly what rust-check.yml did with fetch-depth 0)
  reports `generic-api-key` hits in test fixtures — e.g.
  `signing_key`/`consent_signing_key` in
  `crates/compliance/tests/gdpr_compliance_db_tests.rs`,
  `unsubscribe_secret` in `crates/sales-autopilot/tests/common/mod.rs`,
  `api_key` in `packages/sdk-python/tests/test_sdk_fixes.py`. They look like
  named test constants, but the scanner is kept REQUIRED (fail closed):
  triage them in `.gitleaks.toml` (e.g. allowlist those test files — the
  config already allowlists `tests/fixtures/` directories, not `tests/*.rs`
  fixture constants) or rotate if any is real. `CI_GITLEAKS_CHECK=advisory`
  exists for a triage window only.
* **F12 — cargo audit reports unignored vulnerabilities**: with the current
  15-entry ignore list, `cargo audit --deny warnings` fails on
  RUSTSEC-2026-0193 / -0213 (ammonia mXSS/XSS, fixes in 4.1.3/4.1.4),
  RUSTSEC-2026-0204 (crossbeam-epoch, fix 0.9.20), an h2 advisory and more
  (full list: the stage's `cargo-audit.txt`). security-audit.yml would fail
  identically today. The gate stays REQUIRED: `cargo update` the affected
  crates (all have fixes) or extend the reviewed ignore list in
  `ci/pipeline.conf` AND the old workflow in lockstep.
  `CI_CARGO_AUDIT_CHECK=advisory` exists for a triage window only.
* **F13 — `ddos-protection::metrics::tests::random_paths_produce_bounded_
  distinct_labels` fails deterministically**: "distinct labels must stay
  bounded, got 501" (expected ≤ 500) — 6/6 runs under nextest process
  isolation. A real bounding bug (or off-by-one expectation) committed on
  main; rust-check.yml's nextest lane fails identically. Until fixed, the
  test is EXCLUDED from the run via `CI_NEXTEST_EXCLUDE` in
  `ci/pipeline.conf` — loudly (a warning per exclusion, every run). Remove
  the entry when the bound is fixed.

## 10. Owner actions to finish the cutover

1. Archive the workflows: `git mv .github/workflows .github/workflows-archive`
   (optional: delete `auto-merge.yml`, `mobile-qa.yml`,
   `performance-budget.yml`, `mutation-testing.yml`, `load-gate.yml`,
   `broken-link-check.yml` outright — they have no pipeline counterpart by
   design).
2. Add `ci` to `SYNC_DIRS` in the `Makefile` (one word) so `make deploy*`
   keeps the host's `ci/` current.
3. Install the pre-push hook (§4) on every dev machine.
4. Turn off branch protection / required checks in GitHub once confident.
