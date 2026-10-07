#!/usr/bin/env python3
"""Refresh _sqlx_migrations checksums after an approved edit to applied files.

sqlx records a SHA-384 (hex) of each applied migration file's BYTES in
`_sqlx_migrations`; a byte edit — including a comment-only edit — makes
`Migrator::run` fail VersionMismatch on the next start. tools/migration_lint.py
documents the prescribed sweep for touching a ledger-frozen file: back up the
ledger (ci/stages/migrate.sh does this on every run), then update the edited
files' checksum rows "in the same maintenance window". This tool is that step.

Usage:
    python3 tools/refresh-migration-ledger.py                 # dry-run: list mismatches
    python3 tools/refresh-migration-ledger.py --apply         # update checksum rows

Target database (either):
    DATABASE_URL=postgres://apexmail:…@127.0.0.1:5432/apexmail python3 …
    LEDGER_PSQL="docker exec -i apexmail-postgres psql -U apexmail -d apexmail" python3 …

Exit codes: 0 consistent (or applied), 1 mismatches found in dry-run, 2 usage.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS = ROOT / "services" / "mail-server" / "migrations"


def file_checksum(path: Path) -> str:
    return hashlib.sha384(path.read_bytes()).hexdigest()


def main(argv: list[str]) -> int:
    apply = "--apply" in argv[1:]
    base = os.environ.get("LEDGER_PSQL")
    if base:
        psql_base = base.split()
    else:
        dsn = os.environ.get("DATABASE_URL")
        if not dsn:
            print("set DATABASE_URL, or LEDGER_PSQL for a container/psql prefix", file=sys.stderr)
            return 2
        psql_base = ["psql", dsn]

    def psql(sql: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [*psql_base, "-tAc", sql], capture_output=True, text=True
        )

    ledger: dict[int, str] = {}
    read = psql("SELECT version, encode(checksum,'hex') FROM _sqlx_migrations ORDER BY version")
    if read.returncode != 0:
        print(f"cannot read the migration ledger: {read.stderr.strip()}", file=sys.stderr)
        return 2
    for line in read.stdout.splitlines():
        if "|" not in line:
            continue
        version, digest = line.split("|", 1)
        ledger[int(version)] = digest.strip()

    mismatches: list[tuple[int, str, str, str]] = []
    for path in sorted(MIGRATIONS.glob("[0-9]*_*.sql")):
        version = int(re.match(r"(\d+)_", path.name).group(1))
        if version not in ledger:
            continue  # not applied on this database
        digest = file_checksum(path)
        if digest != ledger[version]:
            mismatches.append((version, path.name, digest, ledger[version]))

    if not mismatches:
        print(f"migration ledger consistent: {len(ledger)} applied file(s) all match their bytes")
        return 0

    for version, name, new, old in mismatches:
        print(f"{version:>4}  {name}\n      ledger {old[:16]}…  file {new[:16]}…")
    if not apply:
        print(
            f"{len(mismatches)} mismatch(es) — dry-run only. Back up the ledger "
            f"(ci/stages/migrate.sh does this per run) and re-run with --apply "
            f"in the same maintenance window."
        )
        return 1

    for version, name, new, _old in mismatches:
        upd = psql(
            f"UPDATE _sqlx_migrations SET checksum = decode('{new}','hex') "
            f"WHERE version = {version}"
        )
        if upd.returncode != 0:
            print(f"FAILED to update {version} ({name}): {upd.stderr.strip()}", file=sys.stderr)
            return 2
    print(f"updated {len(mismatches)} checksum row(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
