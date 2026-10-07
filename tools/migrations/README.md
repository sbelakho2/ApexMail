# Legacy Migration Archive — HISTORICAL, DO NOT RUN

> **ARCHIVAL BANNER (coverage audit U-11, 2026-10-07).**
> This directory is a **read-only historical archive**. Its `*_up.sql` /
> `*_down.sql` pairs were already superseded when they were archived, they
> contain known defects (samples below), and **no test or migration runner in
> this repository reads them**. The active chain is
> `services/mail-server/migrations/` (SQLx); validate/apply only from there.
> `tools/migrations/pre_migration_validate.sh` is part of this archive.

These paired `_up.sql` / `_down.sql` files are retained for historical schema
archaeology only. They are no longer mounted into Docker Compose Postgres
containers.

The active database migration source of truth is:

```text
services/mail-server/migrations/
```

Validate or apply the active SQLx chain with:

```bash
sqlx migrate run  --source services/mail-server/migrations
sqlx migrate info --source services/mail-server/migrations
```

Do not add new runtime migrations here. New schema changes must be added as
SQLx migrations under `services/mail-server/migrations/`.

## Why the pin exists (F01 history)

The 2026-09-09 F01 finding was that **test code once bootstrapped this tree** —
tests built their schema from `tools/migrations` while deployment used
`services/mail-server/migrations`, and the two lineages' identifier/column
shapes differed. That is the failure mode this banner and the pin below
prevent from returning.

## Known defects in the archive (samples; the tree is not exhaustive)

* `003_reconcile_schemas.sql:34` — whole-table `UPDATE domains …` with **no
  WHERE clause**.
* `009_events_partitioning.sql:187` — `DROP TABLE events_old;` with no
  `IF EXISTS` in the up path.
* `pre_migration_validate.sh` — declares `LOCK_TIMEOUT_MS` (never read) and
  its "check 4" takes the advisory lock then immediately releases it while
  claiming to prevent concurrent migrations; its version comparison is
  string-exact and cannot match the live SQLx chain (coverage audit U-13).

These are not fixed here because the tree is archival; "fixing" them would
suggest they are executable.

## The pin

`tools/migrations/check_archived.py` fails if any live runner surface (ci/,
scripts/, services/** except this directory, tests/, deploy/,
docker-compose*.yml, Makefile, .github/) references this tree — ignoring SQL
and prose comments, which may legitimately cite it as history.

```bash
python3 tools/migrations/check_archived.py   # exit 0 = no live runner reads the archive
```
