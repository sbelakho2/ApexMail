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
