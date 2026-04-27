# Tools Directory

This directory contains both supported workflow scripts and historical one-off remediation utilities.

## Supported Workflow Scripts

These scripts are part of the current repeatable developer workflow and are referenced by tasks or active docs:

- `browser_smoke.py`: visual/browser smoke validation used by the VS Code visual parity tasks.
- `run-mail-server-tests.sh`: mail-server test wrapper used by focused cargo task definitions.
- `run-compose-smoke.sh`: Docker Compose smoke validation helper.
- `dev-start.sh`: local development startup helper.
- `bootstrap.sh`: repository/bootstrap helper.
- `migrations/`: migration-related helpers.

## Historical Audit And Remediation Scripts

Files matching patterns such as `fix_*`, `debug_*`, `audit_*`, `extract_*`, `show_*`, and `generate_bigfix.py` are ad hoc investigation or remediation scripts created during previous repo audits.

These scripts are intentionally kept as historical/manual utilities, but they are not part of the supported day-to-day workflow:

- they are not referenced by the current VS Code tasks or service startup paths;
- they should not be treated as stable automation contracts;
- new repeatable tooling should use a descriptive stable name instead of another numbered `fix_v*.py` variant.

## Maintenance Rule

- If a script is part of an active workflow, give it a stable descriptive name and document it here.
- If a script is a one-off investigation aid, treat it as temporary and archive or remove it once its purpose has ended.