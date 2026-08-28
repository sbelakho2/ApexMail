#!/usr/bin/env bash
# =============================================================================
# deploy/sync-migration-checksums.sh — one-time live-DB migration checksum sync
# =============================================================================
# The canonical migration chain (services/mail-server/migrations) was
# shape-reconciled so ONE chain applies cleanly to fresh databases AND live
# databases that were migrated under the earlier file shapes. Semantics for
# already-applied migrations are unchanged, but sqlx records the SHA-384 of
# the exact file bytes it applied — the reconciled files therefore mismatch
# the rows already in the live `_sqlx_migrations`, and the migrator refuses
# to run ("migration X was previously applied but has been modified").
#
# This script, run ON THE DEPLOY HOST with the live DATABASE_URL exported:
#   1. takes a safety backup of _sqlx_migrations to _sqlx_migrations_backup_<ts>
#   2. for every migration file whose version row exists with a different
#      checksum, emits and applies the UPDATE (and prints each one)
#   3. reports the total; exits non-zero if any psql statement failed
#
# It never INSERTs or DELETEs rows — a missing version row stays missing (the
# migrator will apply that migration), an extra row stays (flagged for review).
# =============================================================================
set -euo pipefail

MIGRATIONS_DIR="$(cd "$(dirname "$0")/../services/mail-server/migrations" && pwd)"

if [ -z "${DATABASE_URL:-}" ]; then
    echo "sync-migration-checksums: DATABASE_URL must be set to the live database" >&2
    exit 2
fi

command -v psql >/dev/null 2>&1 || { echo "psql required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 required" >&2; exit 2; }

TS=$(date +%Y%m%d%H%M%S)
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "CREATE TABLE _sqlx_migrations_backup_${TS} AS SELECT * FROM _sqlx_migrations;" >/dev/null
echo "backup: _sqlx_migrations_backup_${TS}"

# version -> sha384 hex of file bytes (sqlx's checksum format)
python3 - "$MIGRATIONS_DIR" <<'PY' > /tmp/migration-checksums.tsv
import hashlib, os, re, sys
d = sys.argv[1]
for name in sorted(os.listdir(d)):
    m = re.match(r"^(\d+)_", name)
    if not m or not name.endswith(".sql"):
        continue
    data = open(os.path.join(d, name), "rb").read()
    print(f"{m.group(1)}\t{hashlib.sha384(data).hexdigest()}\t{name}")
PY

UPDATED=0
while IFS=$'\t' read -r version checksum name; do
    CURRENT=$(psql "$DATABASE_URL" -t -A -c \
        "SELECT checksum FROM _sqlx_migrations WHERE version = ${version};")
    [ -z "$CURRENT" ] && { echo "note: version ${version} (${name}) not applied yet — migrator will apply it"; continue; }
    # psql renders bytea as "\x<hex>"; strip the prefix so the comparison is
    # hex-to-hex. Without this every row compares unequal (leading "\x") and
    # the script rewrites all of them on every run, hiding which files really
    # changed.
    CURRENT_HEX="${CURRENT#\\x}"
    if [ "$CURRENT_HEX" != "$checksum" ]; then
        echo "update: v${version} (${name})"
        psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
            "UPDATE _sqlx_migrations SET checksum = '\\x${checksum}' WHERE version = ${version};" >/dev/null
        UPDATED=$((UPDATED + 1))
    fi
done < /tmp/migration-checksums.tsv

echo "sync-migration-checksums: ${UPDATED} row(s) updated (backup: _sqlx_migrations_backup_${TS})"
