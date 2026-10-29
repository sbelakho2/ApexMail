# Brief — FIX the coverage-audit's uncovered-file findings (U-1..U-14)

You are a fix agent. Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail.
READ `docs/audit/dogfood-2026-10-06/review-coverage-ledger.md` (Sections 4
and 5) in full — it carries file:line evidence and reproductions for every
U-number below. Fix each properly (the capability must WORK; a cleaner
message or a deleted claim is not a fix unless the capability itself is
impossible — say so with evidence if so). Every fix needs a can-fail proof:
a self-test, a probe script, or a regression test that fails before.

Owned paths: `services/mail-server/scripts/**` (except migrate-time files),
`tools/lib/**`, `tools/definitive_audit.py`, `tools/validate_pricing_drift.py`,
`tools/ui_routes.py`, `tools/fix_all_errors.py` + the other corpus rewriters
named in U-2b, `tools/remediation-tracker.json`, `services/mail-server/
supply-chain/**`, `deploy/monitoring/dashboards/**`, `ci/README.md`.
Do NOT touch `crates/api-server/src/routes/ai_chat.rs`,
`crates/worker-processors/src/reply_handler/**`, `docs/eval/**`, or
`crates/ui-foundation/**` (sibling agents own those).

## Items (severity order)
- **U-1 P2** `services/mail-server/scripts/security-audit.sh`: a failed/offline
  cargo-audit becomes count 0 → "Security audit passed", exit 0. Make failures
  fail (typed exit; advisory-DB unreachable ≠ clean), keep the pass path real;
  add a self-test with a faked failing auditor.
- **U-2 P2** `tools/lib/pricing.py`: stale mirror (Free 30k/300k vs runtime
  3k/30k, wrong prices, flat 40 mc overage). Rebuild the mirror FROM the
  canonical catalog (`services/mail-server/crates/platform-catalog/src/lib.rs`
  or the billing seeds — pick one authority and cite it) or make the module
  derive it at import; the docstring's "the drift validator fails on
  disagreement" claim must become TRUE (see U-3).
- **U-2b P2** the corpus rewriters driven by that mirror (fix_all_errors.py,
  fix_all_training_limits.py, fix_payg_calculations.py, fix_payg_errors.py,
  tools/lib/fix_utils.py): they must use the canonical values and NOT write
  tracked data in place without a backup; add the backup-or-dry-run guard.
- **U-3 P2** `tools/validate_pricing_drift.py` mirror block: false-green
  ("3_000" satisfied by DEDICATED_IP_PRICE_CENTS while the Free row says
  30_000). Make the check compare the REAL parsed numbers per field, and add
  a self-test mutation proving it now fails on the stale mirror.
- **U-4 P3** `tools/definitive_audit.py`: cannot import yet claims 1,089
  lines clean. Fix the import (or retire the script honestly with the reason
  — it is a one-off historical tool; check tools/README classification first)
  and ensure no path prints success without running.
- **U-5 P3** `tools/ui_routes.py`: naive first-`#[cfg(test)]` split scans 1.8%
  of web.rs. Reuse the `ui_flash_extract.py` masking approach (mask comments/
  strings, blank the REAL test module by brace matching). After fixing, run
  the link + form-hygiene gates — if the deeper scan surfaces real violations,
  fix them or file them precisely.
- **U-6 P3** `services/mail-server/scripts/run-load-tests.sh`: documented
  invocation runs zero tests and prints ALL TESTS PASSED. Make it fail when
  nothing ran.
- **U-7 P3** `services/mail-server/scripts/coverage.sh`: branch/function
  thresholds never enforced + `eval` injection. Enforce the thresholds for
  real; remove the eval-tainted path.
- **U-8 P3** `services/mail-server/scripts/test-mail-server.sh`: cannot fail.
  Make the exit code carry the test result.
- **U-10 P3** `services/mail-server/supply-chain/**`: 766 blanket
  self-exemptions with zero imported audits. Reduce the blanket
  self-exemptions to the honest minimum (the deps this repo actually vets) and
  document the policy; if a real audit import is infeasible offline, leave the
  policy banner + a CI-visible note — but no more "green by exempting
  everything" without it being explicit.
- **U-11 P3** `tools/migrations/**` archived up/down pairs: sample defects
  found. Add the README banner asserting archival status (the finding is that
  tests once bootstrapped it — pin that no current test/migration runner reads
  this directory).
- **U-12 P3** `tools/remediation-tracker.json`: stale 2026-07-29 P0 tracker —
  add the historical banner field (or move under the historical category per
  tools/README).
- **U-14 P3** `deploy/monitoring/dashboards/api-server-overview.json`: 4
  panels query `job="api-server"` which no scrape config defines. Align the
  job label with `deploy/prometheus.yml` (or add the scrape job if the
  target genuinely exists).
- Also from Section 3: read the two "not reached" groups
  (`tools/contrast-audit/lib|gen-summary|crop`, and the 14+3 Grafana/monitoring
  dashboards) and record verdicts; fix anything broken found there.

## Rules
- Leave every touched gate green: knowledge-consistency (+self-test),
  pricing-drift (+its new self-test), migration-lint, ui link/form gates,
  validate stage by inspection (`sh ci/pipeline.sh run --stages validate
  --skip-deploy --force` if the environment allows).
- Report file: `docs/audit/dogfood-2026-10-06/fix-report-coverage-gaps.md`
  with per-U status: FIXED (evidence + fail-before proof) or NOT-FIXED
  (named blocker). 0 unexplained residuals.
- No deploy; no edits outside the owned paths.
