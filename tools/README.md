# Tools Directory

This directory contains both supported workflow scripts and historical one-off remediation utilities.

## Supported Workflow Scripts

These scripts are part of the current repeatable developer workflow and are referenced by tasks or active docs:

- `browser_smoke.py`: visual/browser smoke validation used by the VS Code visual parity tasks. Artifact updates default to Playwright screenshots with linked-stylesheet validation and marketing cookie-consent preload; use `--screenshot-engine chromium-cli` only for local fallback debugging.
- `run-browser-smoke.sh`: local runner for `browser_smoke.py`; creates `.venv/browser-smoke` and installs the Playwright Python package there so system Python stays untouched.
- `run-mail-server-tests.sh`: mail-server test wrapper used by focused cargo task definitions.
- `run-compose-smoke.sh`: Docker Compose smoke validation helper.
- `validate-compose-secrets.sh`: preflight check that required local Docker secret files exist and are non-empty before compose startup.
- `dev-start.sh`: local development startup helper.
- `bootstrap.sh`: repository/bootstrap helper.
- `check-forbidden-patterns.sh`: quality gate that blocks known regression patterns in production Rust, Docker Compose, and GitHub workflow changes.
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

- `lib/pricing.py` — Canonical plan prices, PAYG tiers, overage rates, and IP pricing.
  Import with: `from lib.pricing import PLANS, PAYG_TIERS, DEDICATED_IP_PRICE, OVERAGE_RATE_PER_1K`
- `lib/fix_utils.py` — Shared JSONL helpers (`read_jsonl`, `write_jsonl`, `iter_jsonl`),
  ChatML parsing (`split_messages`, `edit_assistant_text`), and the `apply_line_fixes` batch framework.

Scripts that used to have their own hardcoded pricing constants now import from `lib/pricing.py`:
`definitive_audit.py`, `fix_all_errors.py`, `fix_all_training_limits.py`,
`fix_payg_calculations.py`, `fix_payg_errors.py`.

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