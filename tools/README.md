# Tools Directory

This directory contains both supported workflow scripts and historical one-off remediation utilities.

## Supported Workflow Scripts

These scripts are part of the current repeatable developer workflow and are referenced by tasks or active docs:

- `browser_smoke.py`: visual/browser smoke validation used by the VS Code visual parity tasks. Artifact updates default to Playwright screenshots with linked-stylesheet validation and marketing cookie-consent preload; use `--screenshot-engine chromium-cli` only for local fallback debugging.
- `run-browser-smoke.sh`: local runner for `browser_smoke.py`; creates `.venv/browser-smoke` and installs the Playwright Python package there so system Python stays untouched.
- `run-mail-server-tests.sh`: mail-server test wrapper used by focused cargo task definitions.
- `run-compose-smoke.sh`: Docker Compose smoke validation helper.
- `bots_perf_budget.py`: mass-concurrency performance budgets for the chat assistant and the mailbot reply pipeline against the running compose stack (16 concurrent conversations across 3 tenants, session/turn storms, rate-limit isolation, Postgres/container sampling, 20 simultaneous inbound messages, first-response lane). Exits non-zero on any budget breach; raw report to `/tmp/apexmail-bots-perf-report.json`. Documented in `docs/evaluation/load-testing.md` §AI Bots — Mass-Concurrency Budgets.
- `bots_disclosure_suite.py`: adversarial disclosure/RBAC suite against both bots (prompt extraction, internal identifiers, secrets, cross-tenant probes, hostile inbound drafts) with per-probe prompt+answer evidence in `/tmp/apexmail-bots-disclosure-report.json`; exits non-zero on any leak or RBAC failure. Reuses the tenants/users provisioned by `bots_perf_budget.py`.
- `validate-prod-env.sh`: preflight that validates an environment file against the `${VAR:?}` contract in docker-compose*.yml (missing/placeholder values fail fast). Used by `make verify-env` and by the pipeline's validate stage; supersedes the old validate-compose-secrets.sh local-file check.
- `dev-start.sh`: local development startup helper.
- `bootstrap.sh`: repository/bootstrap helper.
- `check-forbidden-patterns.sh`: quality gate that blocks known regression patterns in production Rust, Docker Compose, and GitHub workflow changes. It scans the BUILT marketing site: CI calls it with `--require-build` after the zola build; without the flag (pre-commit) an absent `public/` is an announced skip, never a silent pass.
- `check-risk-lua-parity.sh`: WAF risk-Lua parity + trust-neutrality gate (byte-identical packaged Lua copies; `event == 3` stays trust-neutral). Wired into the validate stage 2026-10-07 after the gates review found it orphaned.
- `check_hsts_preload.py`: manual HSTS-preload readiness probe (`python3 tools/check_hsts_preload.py <domain>`), run by hand when preparing a preload submission — see `docs/security/hsts-preload.md`; it needs a public HTTPS endpoint, so it is not a CI stage gate.
- `update-checksums.sh`: refreshes `tools/checksums.sha256` from real local release artifacts instead of hand-editing hashes.

## Quality Gates

### Forbidden Pattern Gate

Run `bash tools/check-forbidden-patterns.sh` before pushing changes that touch Rust runtime code, Docker Compose, or workflow files.

The gate currently checks for:

- `todo!()` and `unimplemented!()` in production Rust code
- localhost fallback connection strings in service binaries
- floating container image tags in compose files
- unpinned GitHub Actions versions
- CI jobs missing `timeout-minutes`
- accidental resurrection of the removed legacy `apps/billing` package

### Toolchain Checksums

`tools/checksums.sha256` stores the release hashes that the current bootstrap flow can verify. The checked-in entries now cover the Go archives used by `tools/bootstrap.sh`; add other ecosystems only when the bootstrap path actually downloads and verifies them.

Refresh the file from actual downloaded artifacts with:

```bash
bash tools/update-checksums.sh \
	go-darwin-arm64 /path/to/go1.22.6.darwin-arm64.tar.gz \
	go-linux-amd64 /path/to/go1.22.6.linux-amd64.tar.gz
```

The script rewrites the checksum file atomically so stale placeholder hashes do not linger across releases.

## Shared Library (`tools/lib/`)

The `tools/lib/` package provides a single source of truth for pricing constants and fix utilities,
shared across all audit/fix scripts to eliminate duplication:

- `lib/pricing.py` — Python mirror of the canonical Rust catalog
  (`services/mail-server/crates/platform-catalog/src/lib.rs`): plan prices,
  limits, PAYG tiers, per-plan overage rates, and the dedicated-IP ladder.
  Import with: `from lib.pricing import PLANS, plan_for, PAYG_TIERS_MILLICENTS,
  OVERAGE_RATE_PER_1K_CENTS, DEDICATED_IP_FIRST_CENTS`.
  `tools/validate_pricing_drift.py` compares it field-by-field against the
  catalog and fails on any disagreement — do not hardcode prices elsewhere.
- `lib/fix_utils.py` — Shared JSONL helpers (`read_jsonl`, `write_jsonl`, `iter_jsonl`),
  ChatML parsing (`split_messages`, `edit_assistant_text`), and the `apply_line_fixes` batch framework.
  Writes are guarded: overwriting an existing file requires a `.bak` backup
  unless `dry_run=True` (coverage audit U-2b). Probe:
  `python3 tools/lib/fix_utils.py --self-test`.

Scripts that used to have their own hardcoded pricing constants now import from
`lib/pricing.py`: `fix_all_errors.py`, `fix_all_training_limits.py`,
`fix_payg_calculations.py`, `fix_payg_errors.py`.

`definitive_audit.py` is RETIRED (coverage audit U-4): it imported
nonexistent `lib.pricing` names, targeted a deleted corpus, and printed
"ALL 1,089 LINES CLEAN" without running. The file is now a stub that always
exits 2 with the retirement record. Use `validate_pricing_drift.py`
(catalog mirror gate) and `check_eval_corpora.py` (AI goldens) instead.

## Historical Audit And Remediation Scripts

Files matching patterns such as `fix_*`, `debug_*`, `audit_*`, `extract_*`, `show_*`, and `generate_bigfix.py` are ad hoc investigation or remediation scripts created during previous repo audits.

These scripts are intentionally kept as historical/manual utilities, but they are not part of the supported day-to-day workflow:

- they are not referenced by the current VS Code tasks or service startup paths;
- they should not be treated as stable automation contracts;
- new repeatable tooling should use a descriptive stable name instead of another numbered `fix_v*.py` variant.

## Maintenance Rule

- If a script is part of an active workflow, give it a stable descriptive name and document it here.
- If a script is a one-off investigation aid, treat it as temporary and archive or remove it once its purpose has ended.
- If a new script is kept under `tools/`, add it to either the supported workflow list above or the historical/manual category in this section during the same change.