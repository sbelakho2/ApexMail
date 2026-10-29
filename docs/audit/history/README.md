# Audit history (point-in-time records)

Everything under this directory is a dated record: an external audit, a
dogfood run, a review wave or a migration write-up as it stood on its
date. These records are never edited after the fact. A later record
supersedes an earlier one in full, and the dates in the filenames are the
order to read them in.

The current state of the repository does not live here. It lives in
`docs/audit/CURRENT_READINESS.md`, a generated dashboard rebuilt from
mechanical sources by `tools/generate_current_readiness.py`. The
generator pins concrete files, content needles and required-lane rows for
every verdict it prints, and `ci/stages/validate.sh` runs it with
`--check` so a dashboard that lags the tree fails the validate stage.

## Path note (added 2026-10-29, eighth audit item 26)

These records were moved here from their original directories (e.g.
`docs/audit/dogfood-2026-10-06/` → `history/dogfood-2026-10-06/`) in the
seventh-audit ledger normalization. The documents themselves keep the
paths as written when they were frozen, so a reference inside a record
to `docs/audit/<original-dir>/...` resolves to the same-named
subdirectory under THIS one. Concretely:

- `docs/audit/dogfood-2026-10-06/evidence-mailbot-live/`
  → `history/dogfood-2026-10-06/evidence-mailbot-live/` (complete: the
  eleven large suite/mutation logs the move initially dropped were
  restored from git history on 2026-10-29).
- `docs/audit/dogfood-v2-2026-10-09/`, `docs/audit/findings-*`,
  `docs/audit/backlog-*`, `docs/audit/kiwicaptcha-integration-2026-10-09/`,
  `docs/audit/ui-external-review-2026-10-08/` → the same-named
  subdirectory here.

Some records also cite scratch evidence that was always ephemeral and is
declared as such in the text (`/tmp/k1-evidence/`, `/tmp/r1-evidence/`).
Those were never repo paths; the text is honest about it and they were
deliberately not reproduced in the repository. Anyone needing them can
regenerate the probes from the documented scripts; the claims they backed
carry the result inline in the record.
