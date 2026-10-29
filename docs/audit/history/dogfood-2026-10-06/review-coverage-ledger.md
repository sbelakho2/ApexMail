# Coverage ledger — auditing the claim "100% whole-repo, file by file"

Auditor: coverage-audit agent (read-only). Date: 2026-10-07. Repo revision:
`0557e55d` (the dogfood wave commit) + working tree.
Deliverable of `brief-coverage-audit.md`. No code was edited.

Legend for depth: **F** = read in full / line-by-line iteration;
**S** = sampled / targeted reads; **Sc** = screened mechanically
(grep/single analyzer pass); **L** = exercised live; **N** = named but
explicitly not read by the artifact that names it.

---

## 0. Bottom line (up front)

**"100% whole-repo, file by file" is overstated.** Precisely:

* The 3,352-file worklist denominator is the file list the campaign itself
  chose; all audit artifacts together explicitly name only **468** of those
  files (14%). This campaign's artifacts alone explicitly name **346** (10%).
  Everything else is claimed at directory/crate granularity, by prior waves,
  or not at all.
* The campaign's own progress files contract the final report:
  `progress-delivery-plane.md:53-78` lists mta and outbound-mta files
  "NOT read in this run" and six crates "scan-only, NOT file-by-file";
  `progress-sales-money-compliance.md:58-60` lists ~60 compliance modules,
  most sales-autopilot files, ai-service adversarial/training files and
  email-grader files as "NOT reviewed file-by-file"; `review-infra.md:508`
  and `review-docs-protocol-data.md:243` and
  `review-packages-harness.md:637` carry explicit "what I did not reach".
* A small but real set of files has **no review artifact at any depth from
  any wave** (Section 3), including the whole `tools/` helper layer and
  `tools/migrations/**`, `services/mail-server/scripts/**`, the cargo-vet
  supply-chain configuration, and the 18 Grafana/monitoring dashboard JSONs.
  Fourteen defects (U-1…U-14) were found there in one afternoon of reading;
  the higher-value ones are U-1…U-5, U-9, U-10 and U-14.
* Four tracked/working trees sit **outside the worklist denominator**:
  `reports/**` (714 files), `secrets/**` (27), `data/**` (6), and an
  untracked 210 MB `.kilo/worktrees/estimated-palladium` copy (3,399 files);
  plus 125 files added during the campaign itself (new tests, migration 245,
  selftests, tools) that no independent pass reviewed.

The defensible characterization is **true-with-exceptions for the crates the
prior sub-module audit claimed, and overstated as stated**: the campaign is a
strong directory-level sweep plus a genuinely file-level pass over roughly a
tenth of the tree, not a file-by-file whole-repo review.

---

## 1. Denominator accounting (worklist.txt)

| Item | Count | Notes |
|---|---|---|
| Worklist lines (= denominator) | 3,352 | generated 2026-10-06 20:17 |
| Worklist entries not present in git | 5 | 4 × `tools/contrast-audit/fixtures/*` (since renamed/added), `ci/woodpecker/toolchain.sh` (never tracked) |
| Worklist ∩ git now | 3,347 | |
| Tracked files **not** in worklist | 125 | created/modified during the campaign: 44 × `docs/audit/dogfood-2026-10-06/**`, 21 × `services/mail-server/crates/**` (incl. `migrations/245_dsr_outbox_idempotency.sql`, new contract tests, selftests), 15 × marketing static assets, 9 × contrast fixtures, 6 × SDK contract tests, 10 × locks/selftests/tools |
| Out-of-denominator working trees | — | `reports/**` 714, `secrets/**` 27, `data/**` 6 (was 25; 18 JSONL removed by the docs fix wave), `.kilo/worktrees/estimated-palladium/**` 3,399 files / 210 MB (git-excluded via `.git/info/exclude`) |

Naming statistics (objective, reproducible):

| Set | Distinct repo paths named | Of which in worklist |
|---|---|---|
| All `docs/audit/**` artifacts (current + prior waves) | 558 | **468** (14.0%) |
| This campaign's artifacts only | 417 | **346** (10.3%) |

Even "named" is an upper bound on review: many citations are context
("the consumer is X"), not evidence of reading.

---

## 2. Coverage ledger

### 2.1 Top-level surfaces

| Surface (worklist files) | Artifact(s) — this campaign | Depth | Prior waves | Gaps left by the report's own words |
|---|---|---|---|---|
| `services/**` (1,501) | per-crate below | — | sub-module audit 2026-09-30 (SM1–SM12), full-repo 2026-09-05 | per-crate below |
| `packages/**` (721) | `fix-sdks.md` (sdk-php/python/java/ruby, live stack); `fix-kiwicaptcha.md` (kiwicaptcha ×5 + risk-v1, suites re-run); `review-packages-harness.md` (sdk-go F, smtp-auth-proxy F, contract F, check_versions F, VERSIONING F, README F) | F/L for named files; **N** for the rest | SM15, full-repo 09-05 | `review-packages-harness.md:637` §6: "Other packages (kiwicaptcha*, sdk-php/python/java/ruby) were read only as cross-references for the Go comparisons"; the kiwicaptcha/sdk agent reports are fix reports with findings, not per-file ledgers |
| `apps/**` (378) | marketing-zola: no per-file review; gates executed over the built site (contrast 88 pages, html-validate, links/terminology, pricing drift). ai: `progress-frontend-and-gateways.md` apps/ai section (all 101 files: ~25 F, rest targeted/sampled; model binaries opaque) | Sc + S; ai = S/F | SM11, full-repo 09-05 | `review-docs-protocol-data.md:217`: dataset content quality beyond price/freshness not reviewed; 212 ui-foundation/marketing baseline HTML fixtures are gate-consumed, never read |
| `docs/**` (253) | `review-docs-protocol-data.md` | F for ~40 load-bearing files; **claim-scan (Sc)** for the rest | full-repo 09-05 | `:243`: "Per-line review of every one of the 261 markdown files … not [done]"; `docs/audit/**` skipped by direction |
| `tools/**` (241) | `review-gates-migrations.md` (42 tool rows in the gate ledger; gates executed with can-fail probes) | F for named gates, **Sc** for the rest | SM14 | helper layer and non-gate scripts unclaimed (Section 3); `tools/migrations/**` only referenced via F01; contrast-audit fixtures/lib unread |
| `deploy/**` (115) | `review-infra.md` coverage table (`:491-507`) | F ≈ 60, Sc ≈ 55 | SM13 | `:508-512`: 14 Grafana + 4 monitoring dashboard JSONs line-by-line **NOT read** (`:499` marks them "NOT-VERIFIED"); `deploy/tests` 28/32 screened; `deploy/cdn`, `deploy/review`, `deploy/load-test-infra`, `deploy/DEPLOYMENT.md` body partial |
| `tests/**` (36) | `review-packages-harness.md` + `progress-frontend-and-gateways.md`: configs/router/migration fixtures F; 18 specs scanned (S) and later executed (L: 220+240+21) | F/S/L | SM12 | `:637` §4: 12 of 18 specs spot-read only; live execution was NOT in that review (done by the fix agents) |
| `ci/**` (31) | `review-infra.md` | claimed F 31/31 | SM14 | claim falsified by U-9 (stale `ci/README.md:110`); `ci/runs/**` (3,125 files on disk) excluded as outputs |
| `scripts/**` (8) | `review-infra.md` F 8/8 | F | SM13 | — |
| `protocol/**` (14) | `review-docs-protocol-data.md`: execution-v1 + risk-v1 full verification; `fix-kiwicaptcha.md` parity gates | F | SM15 | — |
| `load-tests/**` (13) | `review-packages-harness.md` F all + k6 executed on `http/*.js` | F/L | SM12 | journey scripts modelled only by threshold/payload checks |
| `templates/**` (15) | placeholders+consumers scan (`review-docs-protocol-data.md`) | Sc/S | SM11 | — |
| `.github/**` (2) | `review-infra.md` F | F | SM14 | no workflows dir (verified) |
| Root files (~24) | compose×3 / Makefile / scanners = `review-infra.md` (F/S); README / fixes.md / marketing_audit_v2.md = `review-docs-protocol-data.md` F | F/S | SM13/SM15 | `CHANGELOG.md`, `CODEOWNERS`, `CONTRIBUTING.md`, `LICENSE`, `.editorconfig` only name-dropped, never reviewed by any artifact |

### 2.2 `services/mail-server/crates/*` (1,264 worklist files)

Count = worklist files in crate. "This campaign" column names the artifact;
"Depth" uses the legend.

| Crate (files) | This campaign | Depth | Prior | Not-reached (artifact's own words) |
|---|---|---|---|---|
| ui-foundation (250) | `progress-frontend-and-gateways.md` | F ~40 src; S ~15 large files; 212 baselines only gate-executed | SM11 | `baselines/{rust-ui,web,control-plane}` fixtures never read |
| api-server (116) | `progress-frontend-and-gateways.md` | F ~10; S "targeted pattern census" for ~45 route files | SM3 | `web.rs` (26k lines) and `web/data.rs` (8k) targeted, not full; ~35 admin modules pattern-censused only |
| compliance (100) | `progress-sales-money-compliance.md`; `ledger-money-compliance.md` (L) | F ~10; S ~15; **N ~60 modules + bulk tests** | SM8 | `:58`: "the bulk of compliance tests + ~60 compliance modules" not file-by-file |
| sales-autopilot (65) | same | F ~5; S ~15; **N most** | SM7 | `:58`: "most sales-autopilot src/test files" not file-by-file |
| worker-processors (37) | `progress-delivery-plane.md` | F production; test modules inventoried | SM10 | `:35` tests via outlines + targeted reads only |
| mta (32) | `progress-delivery-plane.md` + live mail plane (L) | F ~18; **N 11** | SM1 | `:53-54` inbound_delivery.rs, util.rs, tls.rs, supervision.rs, gmail_annotations.rs, bin/mta.rs, postmaster/* (5 files) NOT read in this run |
| ai-service (29) | money slice S; live sales-ai/chatbot/mailbot (L) | S | SM9 | adversarial/training files untouched; chatbot/mailbot live passes are parallel (excluded here by brief) |
| billing-service (27) | money slice + live money plane | F ~15, S ~10, L | SM7 | coverage_adversarial tests not reviewed |
| analytics (26) | live sales-ai-analytics | L/S | SM10 | — |
| enterprise (25) | live money plane E1–E4 | L/S | SM8 | — |
| tracking-service (26) | live mail plane Flow 3 | L/S | SM2 | — |
| apexmail-db (25), apexmail-lib (22) | — (packages review touched `crypto.rs` only) | N | SM4 | not opened this campaign |
| fuzz-tests (20), integration-tests (16), functional-tests (12), perf-tests (9), smoke-tests (4), edge-cases (12), load-tests (15) | — | N | SM12 (+K6 execution for root `load-tests/`) | not opened this campaign |
| ddos-protection (33), waf-engine (19) | `progress-delivery-plane.md` | **Sc only** | SM5 | `:63-67` "scan-only, NOT file-by-file" |
| mailstore-core (19) | delivery scan + live mail plane | Sc + L | SM1 | spot-read encryption.rs only |
| imap-server (5) | delivery scan + live IMAPS | Sc + L | SM2 | spot-read LOGIN/AUTH only |
| template-renderer (13), spam-filter (9) | delivery scan | **Sc only** | SM2/SM6 | sandbox.rs spot-read |
| ha (18), isolation (16), observability-service (15), devex-service (13), ato-protection (13), ai-embeddings (12), threat-intel (11), ids-engine (10), dlp-engine (10), rate-limiter (9), sandbox (9), fingerprint (7), pattern-matcher (7), queue-provider (7), dns-resolver (8), mail-common (11), mail-proto (5), migrator (4), billing-common (8), billing-entitlements (4), pdf-renderer (17), inbox-placement (17) | — | N | SM1–SM10 each crate | not opened this campaign |
| accounting-core (17) | money slice | F/S | SM7 | — |
| email-grader (11) | money slice S | S | SM6 | crypto/network_checks/dns_provider not reviewed |
| sales-knowledge (2), platform-catalog (2) | money slice | F | SM7 | — |
| auth-server (2) | — | N | SM4 | auth-server login bypass was a Sept-30 finding (SM4-1); not re-opened |
| migrations (216 in worklist; 217 on disk) | `review-gates-migrations.md` + live | 41 F, 14 partial, 161 Sc; 245 added+fixed mid-wave | SM7/SM8 | 161 files screened by analyzer only |
| mail-server/scripts (5) | **none** | — | none | Section 3 |
| supply-chain (3), deny/coverage/mutants/Cargo(3), README/src README (3) | **none** | — | audit-remediation notes inside some files; never reviewed as artifacts | Section 3 |

---

## 3. UNCOVERED list (no review artifact from any wave) — with my verdicts

I read every file below in full (unless noted) against the brief's focus
classes: claims-vs-code honesty, forged-success tests, authz, error
swallowing, resource leaks, TOCTOU, secret handling.

| Uncovered file / tight group | Verdict |
|---|---|
| `tools/definitive_audit.py` | **finding U-4** — cannot even import; claims line-by-line validation |
| `tools/lib/pricing.py` | **finding U-2** — stale pricing mirror, false "single source of truth" claim |
| `tools/fix_all_errors.py`, `fix_all_training_limits.py`, `fix_payg_calculations.py`, `fix_payg_errors.py`, `tools/lib/fix_utils.py` | **finding U-2b** — corpus rewriters driven by the stale mirror; two write tracked data in place with no backup |
| `tools/validate_pricing_drift.py` (mirror block) | **finding U-3** — the mirror check is a false-green (wrong-token match) |
| `tools/ui_routes.py` | **finding U-5** — naive `#[cfg(test)]` split scans 1.8% of web.rs |
| `tools/ui_flash_extract.py` | **clean** — explicitly fixes the U-5 class (`:42-49`); decoder/tokenizer correct on the paths I traced |
| `tools/ui_html_rules.py` | **clean** (minor: no implicit wrapping-`<label>` association, a false-positive-only limitation) |
| `tools/coverage_hotspots.py`, `tools/common_paths.py` | **clean** (read; small, correct) |
| `tools/remediation-tracker.json` | **finding U-12** — stale 2026-07-29 P0 tracker, no historical banner |
| `tools/checksums.sha256`, `tools/fixtures/compose_pinning/*.json`, `tools/ui_*_allowlist.*` | **clean-by-inspection** (small; consistent with consumers) |
| `tools/contrast-audit/lib/png.mjs`, `gen-summary.py`, `crop.mjs`, `fixtures/*.html` | **not reached** (support code; the gate `audit.mjs` itself is self-tested 12/12). Residual gap. |
| `tools/migrations/**` (37 archived files) | **finding U-11** — sample defects; README says archived, but F01 showed tests once bootstrapped it |
| `services/mail-server/scripts/security-audit.sh` | **finding U-1** — forged security pass |
| `services/mail-server/scripts/run-load-tests.sh` | **finding U-6** — documented invocation runs zero tests and prints ALL TESTS PASSED |
| `services/mail-server/scripts/coverage.sh` | **finding U-7** — branch/function thresholds never enforced; `eval` injection |
| `services/mail-server/scripts/test-mail-server.sh` | **finding U-8** — cannot fail |
| `services/mail-server/scripts/generate-dkim.sh` | **clean** (key in gitignored dir, chmod 600; `*.pem` ignored `.gitignore:72`) |
| `services/mail-server/supply-chain/config.toml`, `audits.toml`, `imports.lock` | **finding U-10** — 766 self-exemptions, zero imported audits; `cargo vet` can only pass |
| `services/mail-server/{deny,coverage,mutants}.toml`, `Cargo.toml`, `README.md`, `src/README.md` | **clean/mostly honest** — coverage.toml and mutants.toml carry explicit "NOT enforced by CI" banners (good); deny.toml ignore list justified per entry; no defects found |
| `deploy/monitoring/dashboards/api-server-overview.json` | **finding U-14** — 4 panels query `job="api-server"`, which no scrape config defines |
| `deploy/grafana/dashboards/*.json` (14) + remaining `deploy/monitoring/dashboards/*.json` (3) | **not reached** (still explicitly NOT-VERIFIED by `review-infra.md:499,508`). JSON-valid; job labels sampled match `deploy/prometheus.yml` except U-14. Residual gap. |
| Campaign-created artifacts not in worklist: `ci/tests/*-selftest.sh` (5), `scripts/tests/*.sh` (3), `deploy/tests/*-selftest.sh` (2), `tools/dogfood-live-adversarial.py`, `tools/refresh-migration-ledger.py`, `tools/check_eval_corpora.py`, migration 245, SDK/kiwi contract tests | **spot-checked clean**: the selftests I read (`ci/tests/validate-coverage-selftest.sh`) do assert negative paths; they are can-fail probes, not forged-success. Not independently reviewed as a set. |
| `reports/**` (714), `secrets/**` (27), `data/**` (6), `.kilo/worktrees/estimated-palladium/**` (3,399) | outside the worklist denominator; `reports/**` inventoried only ("self-reported, not re-verified"); `secrets/**` content-format inspection only; the `.kilo` worktree is a 210 MB stale copy excluded from git — unreviewed and a standing risk of drift/secret copies |

---

## 4. Findings from the uncovered-file deep dive

### U-1 · P2 · forged security pass — `services/mail-server/scripts/security-audit.sh`
`cargo audit --json` output is captured with `|| true` (`:45-47`) and the
count is parsed with `jq '.vulnerabilities.count | values // 0' ... || echo "0"`
(`:56`). If the audit fails for any non-vulnerability reason (advisory DB
unreachable, network, parse error), the file holds error text, jq fails, the
count becomes `0`, and the script prints "✅ Security audit passed — no
vulnerabilities found" and exits 0 (`:106-113`). Reproduced with a fake
error-file: `VULN_COUNT=[0]`, exit path "PASSED-exit-0". This is the
error-swallowing class: an outage renders as a clean audit. Also
`cargo audit --deny warnings` (`:50-53`) is executed but its exit status and
the `WARN_COUNT` never gate anything. Fix: fail closed on the audit command's
exit code and on `jq -e` parse failure; make warnings a configurable gate;
add a can-fail probe with a corrupted JSON fixture.

### U-2 · P2 · stale pricing mirror presented as canonical — `tools/lib/pricing.py`
The module's docstring (`:1-11`) claims it "Mirrors the Rust runtime catalog
… if the two disagree the drift validator … fails". It does not mirror it:

| field | mirror (`tools/lib/pricing.py`) | runtime (`platform-catalog/src/lib.rs`) |
|---|---|---|
| Free emails / API | 30,000 / 300,000 | **3,000 / 30,000** (`platform-catalog/src/lib.rs:46-47`) |
| Developer (Starter) | €25.00 | **€29.00** (`:55`) |
| Pro | €65.00 | **€89.00** (`:66`) |
| Growth | €150.00 | **€229.00** (`:77`) |
| Business (Scale) | €350.00 | **€699.00** (`:88`) |
| Enterprise | €3,000.00 | **€1,750.00** (`:99`) |
| overage | flat 40 mc | **80/60/35/35/35 mc** (`:61,72,83,94,106`) |

### U-2b · P3 · corpus rewriters driven by the stale mirror (latent)
`tools/fix_all_errors.py:25-30`, `fix_all_training_limits.py:14,109-110`,
`fix_payg_calculations.py:16,72-73`, `definitive_audit.py:16` all consume
`tools/lib/pricing.py` and target the tracked corpus file
`apps/ai/training/data/train_agent.jsonl`. That file **no longer exists** —
`apps/ai/training/data/` now holds only the 12 `augmented_*.jsonl` files — so
the four scripts are dead code that would raise `FileNotFoundError` if run.
The hazard is latent but real for whoever repairs them: they would rewrite the
corpus to the stale values above, and `fix_all_training_limits.py` /
`fix_payg_calculations.py` write in place with **no backup** (only
`fix_all_errors.py` writes a `.bak2`). Fix: regenerate the mirror from
`platform-catalog` (or delete it and import a generated JSON), point the
scripts at the real data files, make them refuse to run when the drift
validator fails, and always back up before writing.

### U-3 · P2 · the drift validator's mirror pin is a false-green — `tools/validate_pricing_drift.py:887-915`
The check for the Free email limit is
`plain in source or grouped in source or underscore in source` over the whole
file, with values `"3000"/"3,000"/"3_000"`. The mirror contains
`DEDICATED_IP_PRICE_CENTS = 3_000` (`tools/lib/pricing.py:38`), so the
predicate passes while the Free row says `30_000` (proved: removing the
dedicated-IP line flips the predicate to False). No other plan field is
pinned at all. Fix: parse the mirror's `PLANS` dict structurally and compare
every field against the parsed catalog; add a mutation self-test (change
`"emails": 30_000` → expect exit 1).

### U-4 · P3 · audit script that cannot run, but reports clean — `tools/definitive_audit.py`
`from lib.pricing import PLANS, PAYG_TIERS, DEDICATED_IP_PRICE, OVERAGE_RATE_PER_1K`
(`:16`) — none of those three names exist in `tools/lib/pricing.py`
(`PAYG_TIERS_MILLICENTS`, `DEDICATED_IP_PRICE_CENTS`, `OVERAGE_RATE_PER_1K_CENTS`),
so importing raises `ImportError` (verified). If the import were fixed, the
first plan would raise `KeyError: 'price'` (`:36`), and its data source
`train_agent.jsonl` is gone, so it would fail on open. The script's report path
still prints "✅ ALL 1,089 LINES CLEAN — zero issues found" (`:506`). Fix:
repair or delete; if kept, gate it with a can-fail selftest.

### U-5 · P3 · route extractor scans 1.8% of web.rs — `tools/ui_routes.py:34-40`
`production_source()` splits at the **first** `#[cfg(test)]` attribute. In
`api-server/src/routes/web.rs` that attribute is at line 474 — a lone
test-visible alias (`web_form_rejection_middleware_for_tests`) followed by
8,500 lines of production code; the real test module starts at line 8,982.
The extractor therefore scans lines 1-473 of 26,265 (1.8%). Today that is
accidentally correct (all 67 production `.route(` registrations happen to be
in the first 473 lines), so `check_ui_form_hygiene.py` and
`check_ui_links.py` work — but any route registered below a `#[cfg(test)]`
alias becomes invisible to both gates. `tools/ui_flash_extract.py:42-49`
documents this exact hazard and implements `production_split()` to remove
top-level cfg(test) items individually; `ui_routes.py` did not adopt it.
Fix: call `ui_flash_extract.production_split()` (or split at a top-level
`mod tests {`), and add a fixture probe asserting a route added after the
alias is found.

### U-6 · P3 · documented load-test invocation runs nothing and reports success — `services/mail-server/scripts/run-load-tests.sh`
Usage says `./scripts/run-load-tests.sh staging` runs all tests against
staging (`:9-13`), but `TARGET="${1:-all}"` (`:113`) and `TARGET_ENV` comes
only from `$ENV` (`:33`). With arg `staging`, neither `all`/`api` nor
`smtp` branches run (`:128-134`), `EXIT_CODE=0`, and the script prints
"✅ ALL TESTS PASSED" (`:175-182`). Fix: treat the first positional as the
environment or reject unknown targets with exit 2.

### U-7 · P3 · declared thresholds never enforced + eval injection — `services/mail-server/scripts/coverage.sh`
`MIN_BRANCH_COVERAGE`/`MIN_FUNCTION_COVERAGE` (`:31-32`) are only written
into the summary JSON as if enforced (`:126-143`); only line coverage is
diffed (`:116-123`). `eval $COVERAGE_CMD` (`:95`) executes shell
metacharacters supplied via `-p` (`:75`). Fix: compute BRF/BRH and FNF/FNH
from the lcov file and enforce; build an argv array instead of `eval`.

### U-8 · P3 · smoke script that cannot fail — `services/mail-server/scripts/test-mail-server.sh`
Every check ends in `|| true` / `|| echo "✗ ..."` (`:23-39`) and the script
always reaches "Tests completed" with exit 0 under `set -e` (`:42-44`).
Fix: count failures and exit non-zero.

### U-9 · P3 · stale CI README vs gate code — `ci/README.md:110` (missed by the "ci/** read in full" claim)
The retired-workflow table still says the vet lane "runs `cargo vet --locked`
**iff `…/supply-chain/config.toml` exists** — it does not today, so vet skips
with a note". The config is committed (1,900+ lines; initialized 2026-09-28)
and `ci/stages/security.sh:115-127` now hard-fails if it disappears and runs
`cargo vet --locked` otherwise. Fix: correct the row (and add a doc pin or
gate so the README's "REPLACED" table cannot drift from the stage code).

### U-10 · P3 · supply-chain gate that cannot say anything — `services/mail-server/supply-chain/*`
`config.toml` carries **766** `[[exemptions.*]]` blocks (every third-party
crate, criteria `safe-to-deploy`), `audits.toml` is empty, `imports.lock`
contains zero imported audits (26 bytes). `cargo vet --locked` therefore
cannot fail on provenance — a green run certifies only that the file was
edited to match `Cargo.lock`. Fix (policy, not code): import upstream audit
sets (bytecodealliance/Google/etc.) so exemptions are the exception, or
remove cargo-vet from the required security lane and stop counting it as
assurance.

### U-11 · P3 · archived migration tree unreviewed — `tools/migrations/**`
No artifact reviews these 37 files (only F01 cites them as a past test
bootstrap). Sample defects: `003_reconcile_schemas.sql:34` performs a
whole-table `UPDATE domains …` with no WHERE; `009_events_partitioning.sql:187`
does `DROP TABLE events_old;` (no `IF EXISTS`) in the up path. Archived by
`tools/migrations/README.md`, but F01's lesson was that test code once
bootstrapped from it. Fix: either delete the tree or mark it read-only in CI
(e.g., a gate that fails if any live source references it).

### U-12 · P3 · stale remediation tracker — `tools/remediation-tracker.json`
Created 2026-07-29, `source_document: fixes.md` (which itself carries a
"HISTORICAL — DO NOT USE" banner), still lists P0 tasks "In development"
with production URLs and no historical banner. Fix: banner + move under
`docs/audit/`, or delete.

### U-13 · P3 · legacy pre-migration checker — `tools/migrations/pre_migration_validate.sh`
Declares `LOCK_TIMEOUT_MS` (never read), and its "check 4" acquires the
advisory lock then immediately releases it while claiming the check
"prevent[s] concurrent migrations" (`:1-15` header) — a TOCTOU-shaped
assertion that protects nothing. Version comparison is string-exact
(`MAX(version)` from `_sqlx_migrations` vs an argument like `"014"`), which
cannot match the live sqlx chain. Fix: delete or re-implement as a real
lock-holding preflight.

### U-14 · P3 · dashboard panels can never have data — `deploy/monitoring/dashboards/api-server-overview.json`
Four panels query `job="api-server"` (`:540, :602, :609, :671`) but
`deploy/prometheus.yml` defines `job_name: 'apexmail-api'` (`:22`) and no
scrape config anywhere names an `api-server` job (grep-verified). These panels
are permanently empty. This is precisely the group `review-infra.md:499,508`
declared NOT-VERIFIED. Fix: align the job label (or document that these
dashboards target an external managed Prometheus). The 14 `deploy/grafana`
dashboards' job labels sampled clean against the same file.

---

## 5. Falsification checks on campaign claims

**F-1 — "100% whole-repo dogfooding, file by file" (final-report.md:3;
commit 0557e55d "every surface reviewed file-by-file").** Refuted by the
campaign's own progress ledgers: `progress-delivery-plane.md:53,54,63,67`
(11 mta + 9 outbound-mta files "NOT read in this run"; six crates "NOT a
complete file-by-file pass"), `progress-sales-money-compliance.md:58-60`,
`review-infra.md:508`, `review-docs-protocol-data.md:243`,
`review-packages-harness.md:637` (mta ~6,200 lines untouched; `reports/**`
unverified). Only 346/3,352 worklist files (10.3%) are even named by this
campaign's artifacts.

**F-2 — "ci/** read in full (31/31)" (review-infra.md:493) vs
`ci/README.md:110`.** The stale cargo-vet row (U-9) contradicts the shipped
`ci/stages/security.sh` and could not have been read in full against the
current tree. One named directory a report claims but does not evidence.

**F-3 — "read in full" vs the file that was already known broken.**
`review-gates-migrations.md:557` marks `tools/docs-lint.sh` VERIFIED, while
`fix-report-docs.md:319` records three rows still over baseline
(`user-guide/glossary.md`, `migration-rollback.md`,
`inbox-placement-testing.md`) — the final report's "docs-lint's vacuous pass
fixed" (commit message) is true for exit-2, but the committed baseline is
still red for two byte-identical files. A green `--baseline` run can still
hide over-baseline files; that nuance is not in the final report.

**F-4 — "migrations 217/217 consistent; 41 read in full" is honest, but the
161 `[s]` files are analyzer-screened only** (`review-gates-migrations.md:576-579,803`).
The final report's table ("gates (tools/) + migrations … P1×5, P2×5, P3×5")
does not carry the 161-file screen-only caveat.

**F-5 — "481 browser tests" verified as enumerated (220+240+21) by
`review-packages-harness.md:458-463`, and executed by the kiwi fix agent
(`fix-kiwicaptcha.md` table). Consistent — clean.**

**F-6 — "Every fix carries a regression test proven to fail before it"
(commit message).** True for the fix reports I sampled (e.g.,
`ci/tests/validate-coverage-selftest.sh` asserts negative paths), but the
"proven to fail before" evidence lives in agent-authored narratives for most
items; the claim is not machine-checkable and two fixer scripts in the
uncovered set (U-2b) can still rewrite the corpus with stale values. Partial.

**F-7 — denominator integrity.** The worklist excludes `reports/**` (714),
`secrets/**` (27), `data/**` and the 210 MB `.kilo` worktree, and predates
125 tracked files added during the wave. A "whole-repo" claim anchored on
this denominator is therefore narrower than literally "whole repo"; the
campaign never states the exclusions.

---

## 6. Totals

| Status | Files (approx.) | Basis |
|---|---|---|
| Individually named by a campaign artifact | **346** of 3,352 (10.3%) | grep of all `docs/audit/dogfood-2026-10-06/*.md` paths ∩ worklist |
| Of those, genuinely read in full this campaign | ~150–200 | ledger `[x]` entries: frontend 73, delivery 46, sales 28, gates 42 tools + 41 migrations, packages/infra/docs named reads |
| Claimed at directory/crate level only (this campaign) | ~2,900 | "targeted/scan-only/screened" notes |
| Owned only by prior waves (2026-09-05, 09-09/10, 09-30) | the bulk of the crate table | prior artifacts are also directory/hot-path level, not file-by-file |
| **No artifact at any depth** | **~100 worklist files + 4 out-of-denominator trees** | Section 3 |
| Explicitly NOT read this campaign per its own ledger | 20 mta/outbound-mta + ~60 compliance modules + most sales-autopilot + 161 migrations screen-only + 18 dashboards + `ci/runs` + `reports/**` | progress files and review ledgers |

**Honest bottom line.** The wave is a strong directory-level sweep with a
real file-level core and an unusually honest set of self-declared limits —
but the claim "100% whole-repo, file by file" is **overstated**. The accurate
statement is **true-with-exceptions**, where the exceptions are: (1) all
files/groups in Section 3, (2) the crates this campaign only scan-read
(ddos-protection, waf-engine, spam-filter, mailstore-core, imap-server,
template-renderer, and the test crates), (3) the ~60 compliance modules and
most sales-autopilot files, (4) 161 screen-only migrations, (5) the 18
dashboard JSONs, `ci/runs/**`, `reports/**`, `secrets/**`, `data/**`,
`.kilo/worktrees/**`, and (6) the 125 campaign-created files that no
independent pass reviewed. Fixing the higher-value defects found here
(U-1…U-5, U-9, U-10, U-14) would also remove the two false-green gates the
campaign believed it had hardened.
