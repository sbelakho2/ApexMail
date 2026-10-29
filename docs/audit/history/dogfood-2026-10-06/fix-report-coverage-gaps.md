# Fix report — coverage-audit gaps (U-1 … U-14)

Agent: `fix-coverage-gaps`. Date: 2026-10-07. Base revision: `0557e55d` +
working tree (sibling agents' changes present). Deliverable of
`brief-fix-coverage-gaps.md`; inputs: `review-coverage-ledger.md` §3–5.

**Ownership.** Only the paths named in the brief were edited:
`services/mail-server/scripts/**`, `tools/lib/**`, `tools/definitive_audit.py`,
`tools/validate_pricing_drift.py`, `tools/ui_routes.py`, `tools/fix_all_errors.py`
+ the U-2b corpus rewriters, `tools/remediation-tracker.json`,
`services/mail-server/supply-chain/**`, `deploy/monitoring/dashboards/**`,
`ci/README.md`, plus `tools/migrations/README.md` and a new
`tools/migrations/check_archived.py` named by item U-11.
Not touched: `crates/api-server/src/routes/ai_chat.rs`,
`crates/worker-processors/src/reply_handler/**`, `docs/eval/**`,
`crates/ui-foundation/**`.

## Status table

| Item | Status | One-line evidence |
|---|---|---|
| U-1 | **FIXED** | fail-closed typed exits + 6-case faked-auditor self-test |
| U-2 | **FIXED** | mirror rebuilt from `platform-catalog/src/lib.rs`; docstring claim now enforced |
| U-2b | **FIXED** | canonical EUR values derived from the mirror; backup-or-dry-run guard + probes |
| U-3 | **FIXED** | per-plan/per-field structural comparison + mutation self-test |
| U-4 | **FIXED (retired)** | stub exits 2 with the retirement record; no success path |
| U-5 | **FIXED** | production region 473 of 26,265 lines → whole file with comments/test items blanked (67 routes unchanged); fixture probe |
| U-6 | **FIXED** | `staging` now runs the tests; zero-executed runs exit 2; unknown args exit 2 |
| U-7 | **FIXED** | line+branch+function enforced; `eval` removed; portable lcov parsing |
| U-8 | **FIXED** | failure counter; exit 1 when any executed check fails |
| U-9 | **FIXED (extra)** | stale cargo-vet row corrected in the owned `ci/README.md` + assurance note |
| U-10 | **FIXED** | 9 peer audit imports; 766 → 586 exemptions; vet was RED, now green (164 fully / 16 partially audited); policy README |
| U-11 | **FIXED** | archival banner + `check_archived.py` pin (can fail; 1,595 files scanned) |
| U-12 | **FIXED** | historical banner fields in `metadata` |
| U-13 | **NOT-FIXED (out of brief)** | not in the items list; documented in `tools/migrations/README.md` |
| U-14 | **FIXED** | 4 dead-job panels retargeted to real jobs; +1 latent `endpoint` label bug fixed |

0 unexplained residuals. Out-of-scope findings are filed at the end.

---

## U-1 · P2 · forged security pass — FIXED

Files: `services/mail-server/scripts/security-audit.sh` (rewritten),
`services/mail-server/scripts/security-audit-selftest.sh` (new).

**Before (reproduced).** Fake offline `cargo-audit` in PATH:
`PATH=/tmp/u1/bin:$PATH bash services/mail-server/scripts/security-audit.sh`
→ exit **0**, last line `✅ Security audit passed — no vulnerabilities found.`
The failing command's output was parsed by `jq … || echo "0"` (`:56`), so an
unreachable advisory DB rendered as count 0. The `--deny warnings` run's exit
status was discarded, and `.warnings.count` does not exist in the cargo-audit
JSON schema, so `Warnings: 0` was printed even with warnings present.

**Fix.** Typed, fail-closed exits: 0 clean · 1 vulnerabilities (or
`FAIL_ON_WARNINGS=1` and warnings) · 2 tool/DB failure (non-zero exit with no
vuln count) · 3 unparseable JSON / missing numeric `.vulnerabilities.count`.
The warning count now sums the `unmaintained`/`unsound` arrays. `REPORT_DIR`
is overridable and `--self-test` delegates to the probe.

**Fail-before / after probe (can fail).**

```
bash services/mail-server/scripts/security-audit-selftest.sh
  ✓ offline auditor fails closed (exit 3)      ← was: exit 0 "passed"
  ✓ tool error with clean-looking JSON fails (exit 2)
  ✓ clean audit passes (exit 0)
  ✓ vulnerabilities fail (exit 1)
  ✓ warnings advisory by default (exit 0)
  ✓ warnings gate when configured (exit 1)
security-audit-selftest: 6 passed, 0 failed
```

**Real run (fail-closed, not forged):** `Vulnerabilities found: 12`
(all 12 advisory ids are in CI's reviewed `CI_CARGO_AUDIT_IGNORES` ledger),
`Warnings: 5`, exit 1. This local script deliberately carries no ignore list,
so a red raw result on the current lockfile is the honest one; the clean pass
path is proven by the faked-clean auditor case above.

## U-2 · P2 · stale pricing mirror — FIXED

File: `tools/lib/pricing.py` (rewritten; static data module).
Authority cited in the docstring: `services/mail-server/crates/platform-catalog/src/lib.rs`
(`pub const PLANS`) for prices/limits/overage; the billing seeds'
`PlanFeatures.max_sending_domains` for the one field the catalog does not
carry. `tools/validate_pricing_drift.py` now parses this file and compares it
field-by-field (see U-3).

| field | before (stale) | after (canonical) |
|---|---|---|
| Free emails / API | 30,000 / 300,000 | **3,000 / 30,000** |
| Developer (starter) | €25.00 | **€29.00** |
| Pro | €65.00 | **€89.00** |
| Growth | €150.00 | **€229.00** |
| Business (scale) | €350.00 | **€699.00** |
| Enterprise Cloud | €3,000.00 | **€1,750.00** |
| overage | flat 40 mc | **80/60/35/35/35 mc** |
| dedicated IP | €30 (flat, stale) | **€49 first / €69 additional** (explorer.rs ladder) |

Keys are now billing ids (`free`, `starter`, …) with a `display_name` field;
`plan_for()` resolves id or display name. Unbacked exports were dropped or
replaced (`FREE_API_CALLS_PER_MONTH`, `PRICE_PER_1K_API_CALLS_CENTS`;
`DEDICATED_IP_PRICE_CENTS = 3_000` → `DEDICATED_IP_FIRST_CENTS = 4_900` /
`DEDICATED_IP_ADDITIONAL_CENTS = 6_900`) — the 3_000 token was exactly what
satisfied U-3's false-green. PAYG tiers are unchanged (they already matched
the catalog: 100/80/50/30 millicents).

**Proof.** New validator vs old mirror → exit 1; new validator vs new mirror
→ exit 0 (`pricing drift validation passed`); `--self-test` → exit 0.

## U-2b · P3 · corpus rewriters — FIXED

Files: `tools/lib/fix_utils.py`, `tools/fix_all_errors.py`,
`tools/fix_all_training_limits.py`, `tools/fix_payg_calculations.py`,
`tools/fix_payg_errors.py`.

**Values.** Every price and limit written by the rewriters is derived from
`lib/pricing.py`; `fix_all_errors.py`'s old hardcoded USD generation
(`$25/$65/$150`, flat `$1.50/1K`, stale limits/domains) is gone. Prose blocks
now quote €29/€89/€229/€699, canonical limits, and per-plan overage
(€0.80/1K for Developer). PAYG totals are computed by
`calculate_payg_cents`. Features that are not seeded (e.g. A/B testing) are no
longer claimed.

**Guard (can fail).** `write_jsonl`/`write_lines` now implement
backup-or-dry-run: overwriting an existing file requires `backup=True`
(creates `<file>.bak`) or `dry_run=True`; otherwise `UnsafeWriteError`.

```
python3 tools/lib/fix_utils.py --self-test
  → fix_utils self-test passed: dry-run, refusal, and backup paths behave
```
Fail-before: HEAD's `write_jsonl(path, records, backup=False)` overwrote the
tracked corpus in place (reproduced with the HEAD source: the file became
`{"text": "overwritten"}` with no backup).

**Rewriter probes** (temp corpus, modules re-pointed via `FILEPATH`/`CORPUS`):
dry-run for all three writers left the corpus byte-identical; a real run
created `.bak` holding the original and wrote canonical values only
(`€89`, `150,000`, `25 domains`, `10 team`, `€29`, `€229`, `€699`,
`€0.80/1K` present; `$65/$25/$150/$350/$1.50/1K` absent).
`fix_payg_errors.py` forwards `--dry-run` to its child.

**Corpus status (named residual).** The historical `apps/ai/training/data/train_agent.jsonl`
does not exist (only `augmented_*.jsonl` remain), so these scripts exit **2**
with a "corpus no longer exists" message rather than a traceback; they are
safe-to-repair tools, not a live pipeline. The old in-place/no-backup hazard
is removed for whoever repairs them.

## U-3 · P2 · false-green mirror pin — FIXED

File: `tools/validate_pricing_drift.py`.

The old block scanned the whole mirror source for `"3000"|"3,000"|"3_000"`
and required `"Free":` — `DEDICATED_IP_PRICE_CENTS = 3_000` satisfied it while
the Free row said 30_000, and no other plan field was pinned.

**Fix.** `validate_pricing_mirror()` executes the mirror source, then
`validate_mirror_rows()` compares every plan's `price_cents`,
`price_yearly_cents`, `emails`, `api_calls`, `domains`, `team`,
`retention_days`, and `overage_millicents_per_email` against the parsed
runtime catalog; it also pins `PAYG_TIERS_MILLICENTS` and the two
dedicated-IP ladder constants against `platform-catalog/src/lib.rs` and
`routes/explorer.rs`. `mirror_self_test()` runs on **every** invocation (so
the existing CI line `python3 tools/validate_pricing_drift.py` is
self-proving) and as `--self-test`.

**Fail-before (end to end).**

```
# BEFORE: HEAD validator + HEAD mirror
python3 tools/validate_pricing_drift.py → exit 0  "pricing drift validation passed"   (false green)

# AFTER: new validator + mirror with the free row mutated 3_000 → 30_000
python3 tools/validate_pricing_drift.py → exit 1
  tools/lib/pricing.py free.emails drift: expected 3000, got 30000

python3 tools/validate_pricing_drift.py                → exit 0 (restored)
python3 tools/validate_pricing_drift.py --self-test    → exit 0
  mirror self-test: Free emails=30_000 mutation detected by 1 error(s);
  historical stale table detected by 18 per-field error(s)
```

Adjacent fix (same function): the old block **asserted** the stale values in
`apps/ai/training/new_customer_profiles.py` as canonical
(`"email_limit": "30,000"`), blessing a file with pre-2026-09-08 data. That
assertion is replaced by an honest structural checker in the opt-in
`--check-training-profiles` mode (see filed finding F-1; the default gate no
longer blesses the stale values, and it no longer blocks a correct fix).

## U-4 · P3 · audit script that cannot run — FIXED (retired)

File: `tools/definitive_audit.py` (+ `tools/README.md`).

`tools/README.md` classifies it among one-off audit/remediation utilities
("archive or remove it once its purpose has ended"). It could not import
(`ImportError: cannot import name 'PAYG_TIERS'`), its schema assumptions
raised `KeyError: 'price'` if the import were fixed, its corpus is gone, and
its report path printed `✅ ALL 1,089 LINES CLEAN — zero issues found`.

**Fix.** The file is now a retirement stub: module docstring carries the full
reason and the required replacement path; running it always exits 2 with the
record and there is no success-printing path.

```
python3 tools/definitive_audit.py; echo $?   → retirement message, exit 2
```
`tools/README.md` no longer lists it as an importer, documents the
retirement, fixes the previously-wrong import names, and documents the new
`fix_utils` guard.

## U-5 · P3 · route extractor scanned 1.8% of web.rs — FIXED

File: `tools/ui_routes.py` (+ new `--self-test`).

**Before.** `production_source()` split at the first `#[cfg(test)]` (web.rs
line 474) → 473 of 26,265 lines scanned; a route registered after the alias
was invisible to `check_ui_form_hygiene.py`/`check_ui_links.py`.

**After.** Comments and string/raw-string literals are masked with
`ui_flash_extract`'s helpers (`comment_spans`, `rust_string_literals`), then
each real top-level `#[cfg(test)]` item is blanked by brace matching;
comments are also blanked in the returned source so a commented-out
`.route(...)` cannot pollute the table. Route extraction on web.rs is
unchanged today (67 routes / 60 POST — all 67 live in the pre-alias region)
but a post-alias route is now found.

**Fail-before proof and probe.**

```
# OLD split on the self-test fixture: routes = []  (post-alias route invisible)
# NEW split: ['/web/first', '/web/second'] and /web/test-only excluded
python3 tools/ui_routes.py --self-test → exit 0
  ui_routes self-test passed: fixture routes found (2), production region
  585 chars, real web.rs routes 67
```

**Gates.** `check_ui_form_hygiene.py` green (174/242 controls; with
`tools/contrast-audit/fixtures`: 250/327). `check_ui_links.py` green against
the **committed** fixtures (6,355 targets). Against the working tree's
sibling-modified fixtures it reports 42 dead links — identical before and
after this change (proved by swapping HEAD's `ui_routes.py` back in), so it
is pre-existing and unowned; filed precisely (F-6).

**Adjacent finding (filed, not owned).** `ui_flash_extract.production_split()`
— the function the brief pointed at — over-cuts: a `#[cfg(test)]` token
inside a doc comment or string literal is treated as a top-level item because
`_depth_prefix` records comment/string interiors at the same depth as code.
Repro: a 206-char fixture becomes 113 chars and loses the `use` statement.
`ui_routes.py` therefore implements the masking itself using that module's
masking helpers rather than calling `production_split()`; the file itself was
not edited (not owned). See F-4.

## U-6 · P3 · load tests ran nothing and printed success — FIXED

File: `services/mail-server/scripts/run-load-tests.sh`.

**Before (reproduced).** `K6_API_KEY=dummy scripts/run-load-tests.sh staging`
with fake k6 → exit 0, `✅ ALL TESTS PASSED`, **0** k6 invocations (the first
positional was treated as a test selector; `staging` matched no branch and
`TARGET_ENV` came only from `$ENV`).

**After.** The positional is an environment (`local|staging|prod`) or a test
selector (`all|api|smtp`); anything else exits 2. A `RUN_COUNT==0` run exits
2 before any success text; the summary only reads this run's timestamped
files.

```
staging → 2 k6 calls, exit 0, ALL TESTS PASSED
bogus   → exit 2 "unknown argument 'bogus'."
api     → 1 k6 call
fake k6 exit 1 → script exit 1, "SOME TESTS FAILED"
```

## U-7 · P3 · thresholds never enforced + eval injection — FIXED

File: `services/mail-server/scripts/coverage.sh` (rewritten).

**Before.** HEAD contains no `BRF/BRH/FNF/FNH` parsing at all
(`grep -c 'BRF\|BRH\|FNF\|FNH'` → 0); branch/function thresholds were only
written into the summary JSON as if enforced. `eval $COVERAGE_CMD` executed
`-p 'foo; touch /tmp/u7-pwned #'` — reproduced: the file `/tmp/u7-pwned` was
created. (On this macOS host the old line-coverage math also crashed on BSD
`paste`; the script could not measure anything portably.)

**After.** Argv array (no `eval`); package names validated
`^[A-Za-z0-9_-]+$`; lcov totals parsed with `awk` (no `bc`/`paste`
dependency); line, branch and function coverage all enforced with the
declared thresholds; a missing/empty lcov exits 2.

```
low branch/function lcov (90% lines, 10% branches, 20% functions) → exit 1
all-green lcov (90/80/80)                                          → exit 0
-p 'foo; touch /tmp/u7-pwned2 #'                                   → exit 2
  "invalid package name"; no file created
```

## U-8 · P3 · smoke script that cannot fail — FIXED

File: `services/mail-server/scripts/test-mail-server.sh`.

**Before (reproduced with nothing running):** three `✗` lines, `Tests
completed`, exit **0** (every check ended in `|| true`).

**After:** failures are counted; closed SMTP ports / unavailable worker
health are failures; missing `nc`/`curl` are explicit skips. Nothing running
→ exit 1, `Tests FAILED: 3 check(s) failed`. With a local healthy worker on
:9090 → `✓ Worker healthy` (the SMTP ports remain closed here, so exit 1 is
correct for this host).

## U-9 · P3 · stale CI README (extra, owned path) — FIXED

File: `ci/README.md`. The `cargo-vet.yml` row claimed vet "runs iff
config.toml exists — it does not today, so vet skips". The config is
committed and `ci/stages/security.sh:119-127` hard-fails when it is missing,
running `cargo vet --locked` otherwise. The row now states this and carries
the U-10 assurance split (quote it; green ≠ full provenance).

## U-10 · P3 · supply-chain gate that cannot say anything — FIXED

Files: `services/mail-server/supply-chain/{config.toml,imports.lock}`
(`audits.toml` stays empty by design — no first-party audits exist) plus new
`services/mail-server/supply-chain/README.md`.

**Before (measured, and worse than the ledger said).** 766 exemptions, 0
imported audits (imports.lock 26 bytes), and `cargo vet --locked` did not
merely pass vacuously — it **failed** (exit 255):

```
4 unvetted dependencies:
  aws-lc-rs:1.18.1, aws-lc-sys:0.45.0, rustls:0.23.45, rustls-webpki:0.103.15 missing ["safe-to-deploy"]
```

**After.** Imported 9 peer audit sets (actix, ariel-os, bytecode-alliance,
embark-studios, fermyon, google, isrg, mozilla, zcash) and ran
`cargo vet regenerate exemptions` (which also added exemptions for the four
crates no peer covers and pruned the rest):

```
cargo vet --locked → exit 0
Vetting Succeeded (164 fully audited, 16 partially audited, 586 exempted)
```

766 → 586 self-exemptions; 180 crates now carry real imported audit paths.
The policy is explicit in `supply-chain/README.md` (what green means, the
before/after, how to shrink exemptions, and the rule never to cite vet green
as full provenance). `ci/README.md` carries the CI-visible note.

**Note on format:** cargo-vet fails closed on a store it did not format
(`cargo vet fmt` strips free-form comments), so the policy banner lives in
the README, not as a TOML comment; `cargo vet fmt` was run and the store is
canonical.

## U-11 · P3 · archived migration tree — FIXED

Files: `tools/migrations/README.md` (banner + defects), new
`tools/migrations/check_archived.py` (pin).

The README now carries an archival banner ("HISTORICAL, DO NOT RUN"), the F01
history (tests once bootstrapped this tree), the sample defects (003's
no-WHERE `UPDATE`, 009's bare `DROP TABLE`, `pre_migration_validate.sh`'s
no-op lock/string-exact version check), and the pin. The pin scans the live
runner surfaces (`ci/`, `scripts/`, `services/` except the archive,
`tests/`, `deploy/`, `docker-compose*.yml`, `Makefile`, `.github/`) for
usage of the tree, ignoring comments so historical citations pass:

```
python3 tools/migrations/check_archived.py → exit 0
  archived-tree pin passed: no live runner surface reads tools/migrations (1595 files scanned)
# injection probe (scratch file with `sqlx migrate run --source tools/migrations`) → exit 1
```

Residual: the pin is runnable but not wired into a CI stage (the migration
lane is outside this brief's owned paths) — documented in the README.

## U-12 · P3 · stale remediation tracker — FIXED

File: `tools/remediation-tracker.json`. `metadata` now carries
`"historical": true`, a `status` ("HISTORICAL — NOT ACTIVE …"),
a `banner` ("HISTORICAL — DO NOT USE … 2026-07-29 snapshot …"), and
`superseded_by` (`docs/audit/dogfood-2026-10-06/**` + git history). The file
still parses and all 9 task records are intact.

## U-13 · P3 · legacy pre-migration checker — NOT-FIXED (out of the brief)

Not in the brief's items list (Section 3 groups only; U-13 is Section 4) and
`tools/migrations/**` is named only by U-11. It is documented as a known
archived defect in the U-11 README banner so it cannot be mistaken for
tooling. If a sibling owns it, the fix is "delete, or re-implement as a real
lock-holding preflight".

## U-14 · P3 · dashboard panels that could never have data — FIXED

File: `deploy/monitoring/dashboards/api-server-overview.json`.

The 4 panels queried `job="api-server"`, which no scrape config defines
(`deploy/prometheus.yml` has `apexmail-api`, …). Deeper check: three of the
four metric names **do not exist in that job at all** —
`metrics-exporter-prometheus 0.16.2` has no process collector, there is no
`metrics-process` dependency and no custom `process_*` registration, so
`process_resident_memory_bytes`/`process_virtual_memory_bytes`/
`process_open_fds` (and `node_cpu_seconds_total`, which is node-exporter)
could never be scraped from `apexmail-api`. The panels were retargeted to
the metrics that actually exist on the deployed stack (node-exporter
`job="node"`), with titles/descriptions stating exactly what they show and
why per-process panels would be empty:

* CPU → `node_cpu_seconds_total{mode="idle",job="node"}`
* Memory → `node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes{job="node"}`
* FDs → `node_filefd_allocated{job="node"}`

Adjacent fix in the same dashboard: panel 9 selected
`{endpoint!=""} … by (endpoint)` but the api-server middleware emits the
label `path_pattern` (and `status`), so it was permanently empty; the query
now uses `path_pattern`. (The same label bug exists in the unowned
`deploy/grafana/dashboards/api-performance.json` — filed, F-2.)

**Verification.**

```
# JSON valid; all 18 dashboards × prometheus.yml job labels:
dashboards with undefined jobs: 0 / 18
```

## Section 3 "not reached" groups — verdicts

**`tools/contrast-audit/lib/png.mjs`** — read in full (107 lines). Clean.
8-bit non-interlaced PNG decoder (color types 0/2/3/4/6, filters 0–4,
palette+tRNS); `pngPixel` clamps. No correctness defect on the gate's paths
(Playwright screenshots are 8-bit RGBA non-interlaced). No change (not
owned anyway).

**`tools/contrast-audit/crop.mjs`** — read in full (76 lines). Clean-with-minor:
`new URL(import.meta.url).pathname` is not percent-decoded, so a checkout path
containing spaces would break the fixture server root; the repo path is
space-free. Support/manual helper only, not a gate. Filed as a note (F-5).

**`tools/contrast-audit/gen-summary.py`** — read in full (153 lines). Clean:
reads `reports/violations.json` from CWD (documented invocation), groups by
fg/bg/surface/theme, emits `reports/summary.md`. Cosmetic: the "summary.md
written" line is printed twice (`:152-153`). No fix needed.

**`tools/contrast-audit/fixtures/**`** — gate-consumed, not read
individually (128 files, many modified mid-flight by a sibling agent; see
F-6). Consumption is covered by the green `audit.mjs` gate (12/12
self-tests per the ledger).

**14 Grafana + 4 monitoring dashboards** — all 18 parse as JSON; every
`job="…"` selector now matches a `job_name` in `deploy/prometheus.yml`
(U-14 was the only mismatch); a label-name check found the `endpoint` vs
`path_pattern` bug (fixed in the owned dashboard, filed for
`deploy/grafana/dashboards/api-performance.json`); a metric-name screen
against the metrics the Rust services emit plus standard `node_*`/`probe_*`
exporter metrics surfaced no further dead panels. Verdict: clean apart from
F-2/F-3.

---

## Filed findings outside the owned paths (precise, with evidence)

**F-1 — `apps/ai/training/new_customer_profiles.py` carries pre-2026-09-08
values, and the validator used to assert them as canonical.**
`python3 tools/validate_pricing_drift.py --check-training-profiles` reports
19 drifts, e.g. `free_hitting_limits_v2 (Free) email_limit drift: expected
'3,000', got '30,000'`; `starter_healthy_v2 (Developer) plan_price drift:
expected '29', got '25'`; Pro €65, team limits, etc. Owner: AI training
surface (not in this brief's owned paths). Required fix: rewrite the
EXTENDED_PROFILES values from the canonical catalog, then optionally wire
`--check-training-profiles` into the pricing gate.

**F-2 — `deploy/grafana/dashboards/api-performance.json:1147`** queries
`… by (endpoint)` against `apexmail_http_requests_total`, whose label is
`path_pattern` (api-server `middleware/metrics.rs`) — permanently empty
panel. Owner: deploy/grafana (not this brief's owned path).

**F-3 — `docs/operations/monitoring.md:49-51`** documents
`process_cpu_seconds_total`, `process_resident_memory_bytes`,
`process_open_fds` as exported by ApexMail; no service registers them
(metrics-exporter-prometheus 0.16.2 has no process collector; no
`metrics-process` dep). Either add a collector to the api-server or correct
the doc. This is why U-14's panels were retargeted rather than job-aligned.

**F-4 — `tools/ui_flash_extract.py: production_split()` over-cuts on
attribute-shaped text inside comments/strings** (repro in U-5). It is the
module the brief pointed U-5 at, but it is not owned by this brief; the
consumers (flash-copy/terminology/catalog gates) are unaffected on the
current tree. If its owner wants the fix: filter `#[cfg(test)]` matches to
positions not inside comment/string spans (the masking helpers already exist
in the same file).

**F-5 — `tools/contrast-audit/crop.mjs`** URL pathname not decoded (minor,
manual helper).

**F-6 — UI dead-link gate vs the working tree's modified contrast
fixtures.** `python3 tools/check_ui_links.py tools/contrast-audit/fixtures`
fails with 42 dead links to
`/web/admin/ai/drafts/draft_dogfood_ui_visual_000N/{approve,reject}`
(control-plane fixtures). Evidence it is not this brief's doing: the count is
identical (42) with HEAD's `ui_routes.py` swapped in, and the gate is green
against HEAD's committed fixtures (6,355 targets, 0 failures). Root cause
candidates: `check_ui_links.LinkResolver` exact-matches web.rs route paths
and only shape-matches MANIFEST routes, so the `:id` pattern from web.rs
cannot absorb the concrete fixture ids. Owners: `tools/check_ui_links.py` /
`tools/contrast-audit/fixtures/**` (sibling agents).

**F-7 — `tools/migrations/check_archived.py` is not CI-wired** (see U-11
residual). Wiring it into the validate/migration lane needs an edit to
`ci/stages/validate.sh`, outside the owned paths.

---

## Gate evidence (all green)

| Gate | Command | Result |
|---|---|---|
| knowledge-consistency | `python3 tools/check_knowledge_consistency.py` | exit 0, PASS |
| knowledge-consistency self-test | `… --self-test` | exit 0, PASS |
| pricing drift | `python3 tools/validate_pricing_drift.py` | exit 0 (incl. inline mirror mutation proof) |
| pricing-drift self-test | `… --self-test` | exit 0 (1 + 18 mutations detected) |
| migration lint | `python3 tools/migration_lint.py` | exit 0, 217 clean |
| UI form hygiene | `python3 tools/check_ui_form_hygiene.py [fixtures]` | exit 0 |
| UI dead links | `python3 tools/check_ui_links.py` (committed fixtures) | exit 0 |
| eval corpora | `python3 tools/check_eval_corpora.py` + `--self-test` | exit 0 |
| docs-lint ratchet | `sh tools/docs-lint.sh --baseline …` | exit 0 (2787 ≤ 2828) |
| cargo cycles | `python3 tools/check_cargo_cycles.py` | exit 0 |
| cargo vet | `cargo vet --locked` | exit 0, 164/16/586 |
| U-1 selftest | `bash …/security-audit-selftest.sh` | 6/6 |
| U-5 selftest | `python3 tools/ui_routes.py --self-test` | exit 0 |
| U-2b guard selftest | `python3 tools/lib/fix_utils.py --self-test` | exit 0 |
| U-11 pin | `python3 tools/migrations/check_archived.py` | exit 0 (+ injection fails) |
| validate stage | `sh ci/pipeline.sh run --stages validate --skip-deploy --force` | **exit 0** (676 s), run `20261007T211839_4662`, log ends `validate: all gates green`; 45 PASS checks incl. `PASS: pricing drift`, `PASS: knowledge consistency (canonical catalog)` (runs the self-test in the same check), `PASS: eval corpora vs canonical facts` (same), `PASS: docs-lint ratchet/integrity`, `PASS: migration SQL lint` |

The one logged failure inside that stage is explicitly advisory:
`[ERROR] FAIL: Performance budget (live, read-only) (exit 1)` →
`[warn] ADVISORY failure — continuing (stage result unaffected)`; it measures
live TTFB against the configured `BASE_URL` (network/host-dependent) and is
unrelated to any file touched here. Sibling-modified working-tree files
(`crates/ui-foundation/**`, `docs/eval/**`, contrast fixtures) took part in
the stage and are outside this brief's ownership.

## Residual risks / unexplained residuals

None for U-1 … U-12, U-14. Named residuals:
1. U-13 is out of the brief (documented, not fixed).
2. U-2b scripts cannot run today because their historical corpus was
   deleted; they now fail with a clear exit 2 instead of a traceback.
3. The U-11 pin is not CI-wired (F-7).
4. U-14's per-process resource panels are impossible without a process
   collector in the api-server (F-3); panels are host-level and labeled as
   such.
5. F-1 … F-6 are outside the owned paths.
