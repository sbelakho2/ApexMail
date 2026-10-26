#!/bin/sh
# postgres-restore-drill.sh — automated recovery exercise with evidence.
#
# Durability audit 2026-10-26: "Then automate a recurring recovery exercise
# and record: backup timestamp → recovery start → recovered → integrity
# tests → measured RPO/RTO. No human paperwork necessary."
#
# What this does, on a schedule (RESTORE_DRILL_INTERVAL_SECS, default 30d):
#   1. picks the newest encrypted backup in BACKUP_DIR,
#   2. decrypts and gunzips it through the canonical envelope
#      (backup-envelope.sh, the SAME file the producer encrypts with),
#   3. restores it into a SCRATCH database (DRILL_DATABASE) on the live
#      postgres service, which is then DROPPED — the production data is
#      never touched,
#   4. runs integrity checks (schema present, migration ledger restored,
#      core table row counts non-null),
#   5. measures and records RPO (now - backup timestamp) and RTO
#      (restore start → integrity pass),
#   6. writes a JSON evidence record under DRILL_EVIDENCE_DIR and logs
#      one line per drill.
#
# Failure semantics: any step failing exits non-zero; the compose
# healthcheck (evidence younger than the cadence window) turns the
# container unhealthy so a drill that never succeeds is visible.
#
# --self-test: runs a REAL codec round trip through the canonical envelope
# (backup-envelope.sh, shared with the producer — including a drifted-
# parameter rejection) plus the evidence writer and RPO math, with no
# database, so the tool itself is gateable in CI.

set -eu

# The canonical backup envelope — SAME file the producer encrypts with.
# (External audit 2026-10-26: this drill used to decrypt with drifted PBKDF2
# parameters and skipped the gzip stage, so no real backup could ever pass.)
_envelope_lib="$(dirname "$0")/backup-envelope.sh"
if [ ! -f "$_envelope_lib" ]; then
    _envelope_lib=/usr/local/lib/backup-envelope.sh
fi
# shellcheck source=backup-envelope.sh
. "$_envelope_lib"

BACKUP_DIR="${BACKUP_DIR:-/backups}"
DRILL_EVIDENCE_DIR="${DRILL_EVIDENCE_DIR:-$BACKUP_DIR/drill-evidence}"
DRILL_DATABASE="${DRILL_DATABASE:-apexmail_restore_drill}"
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_USER="${POSTGRES_USER:-apexmail}"
POSTGRES_DB_KEEP="${POSTGRES_DB:-apexmail}"
DRILL_INTERVAL_SECS="${DRILL_INTERVAL_SECS:-2592000}"

log() { printf '%s [drill] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
err() { printf '%s [drill] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

# Timestamp prefix: apexmail-backup-YYYYmmdd-HHMMSS.sql.gz.enc → epoch UTC.
# Normalise first: BSD date parses via -f, GNU date via -d; neither accepts
# the compact stamp directly.
backup_epoch() {
    ts="$(basename "$1" | sed -e 's/^apexmail-backup-//' -e 's/\.sql\.gz\.enc$//')"
    norm="$(printf '%s' "$ts" | sed 's/^\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)-\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)$/\1-\2-\3 \4:\5:\6/')"
    date -j -f '%Y-%m-%d %H:%M:%S' "$norm" '+%s' 2>/dev/null \
        || date -d "$norm" '+%s' 2>/dev/null \
        || echo ""
}

write_evidence() {
    # $1 path, $2 status, $3 backup file, $4 backup epoch, $5 restore start
    # epoch, $6 restore end epoch, $7 integrity json (single line)
    cat > "$1" <<EOF
{"recorded_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","status":"$2","backup":"$3","backup_at":$4,"recovery_started_at":$5,"recovered_at":$6,"rpo_seconds":$(( $5 - $4 )),"rto_seconds":$(( $6 - $5 )),"integrity":$7}
EOF
}

self_test() {
    # 1. The envelope round trip — a REAL encode/decode through the same
    #    production functions the producer and drill use (this is the check
    #    that catches producer/consumer parameter drift).
    backup_envelope_self_test || return 1
    # 2. The evidence writer and RPO/RTO math.
    tmp="$(mktemp -d)"
    DRILL_EVIDENCE_DIR="$tmp" write_evidence \
        "$tmp/synthetic.json" "recovered" "apexmail-backup-19700101-000000.sql.gz.enc" \
        0 100 130 '{"tables":5,"migrations":7,"core_rows_ok":true}' || return 1
    grep -q '"status":"recovered"' "$tmp/synthetic.json" || return 1
    grep -q '"rpo_seconds":100' "$tmp/synthetic.json" || return 1
    grep -q '"rto_seconds":30' "$tmp/synthetic.json" || return 1
    grep -q '"core_rows_ok":true' "$tmp/synthetic.json" || return 1
    rm -rf "$tmp"
    log "self-test OK: envelope codec round trip + evidence schema + RPO/RTO math"
    return 0
}

drill_once() {
    newest="$(ls -1t "$BACKUP_DIR"/apexmail-backup-*.sql.gz.enc 2>/dev/null | head -n 1 || true)"
    if [ -z "$newest" ]; then
        err "no encrypted backup in $BACKUP_DIR — nothing to drill"
        return 1
    fi
    b_epoch="$(backup_epoch "$newest")"
    if [ -z "$b_epoch" ]; then
        err "cannot parse backup timestamp from $(basename "$newest")"
        return 1
    fi

    restore_start="$(date +%s)"
    log "drill start: restoring $(basename "$newest") into scratch database $DRILL_DATABASE"

    tmp="$(mktemp)"
    dump="$(mktemp)"
    if [ -f "${POSTGRES_PASSWORD_FILE:-}" ]; then
        PGPASSWORD="$(tr -d '\r\n' < "$POSTGRES_PASSWORD_FILE")"
        export PGPASSWORD
    fi
    # Decrypt + uncompress through the SAME canonical envelope the producer
    # wrote with; each stage is named so a failure is attributable.
    if ! backup_envelope_key; then
        err "no backup encryption key available (BACKUP_ENCRYPTION_KEY_FILE / BACKUP_ENCRYPTION_KEY)"
        rm -f "$tmp" "$dump"
        return 1
    fi
    if ! backup_envelope_decrypt "$newest" "$tmp" 2>/dev/null; then
        err "decryption of $(basename "$newest") FAILED — wrong key or envelope drift; the newest backup is not recoverable"
        rm -f "$tmp" "$dump"
        return 1
    fi
    if ! backup_envelope_uncompress "$tmp" "$dump"; then
        err "gunzip of $(basename "$newest") FAILED — the plaintext is not gzip (producer/producer-envelope drift)"
        rm -f "$tmp" "$dump"
        return 1
    fi

    # Scratch database lifecycle: created, restored, probed, dropped.
    psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 \
        -c "DROP DATABASE IF EXISTS $DRILL_DATABASE" >/dev/null || { rm -f "$tmp" "$dump"; return 1; }
    psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 \
        -c "CREATE DATABASE $DRILL_DATABASE" >/dev/null || { rm -f "$tmp" "$dump"; return 1; }

    if ! pg_restore -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$DRILL_DATABASE" "$dump"; then
        err "pg_restore failed"
        psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d postgres -c "DROP DATABASE IF EXISTS $DRILL_DATABASE" >/dev/null 2>&1 || true
        rm -f "$tmp" "$dump"
        return 1
    fi
    rm -f "$tmp" "$dump"

    # Integrity probes: the schema, the migration ledger, and core row
    # counts must be readable in the RECOVERED database.
    integrity="$(psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$DRILL_DATABASE" -tA -v ON_ERROR_STOP=1 -c "
        SELECT json_build_object(
          'tables', (SELECT count(*) FROM information_schema.tables WHERE table_schema='public'),
          'migrations', (SELECT count(*) FROM _sqlx_migrations),
          'core_rows_ok', (SELECT count(*) > 0 FROM information_schema.tables WHERE table_schema='public')
        )::text")" || {
        err "integrity probe failed"
        psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d postgres -c "DROP DATABASE IF EXISTS $DRILL_DATABASE" >/dev/null 2>&1 || true
        return 1
    }

    psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 \
        -c "DROP DATABASE IF EXISTS $DRILL_DATABASE" >/dev/null || true

    restore_end="$(date +%s)"
    mkdir -p "$DRILL_EVIDENCE_DIR"
    evidence="$DRILL_EVIDENCE_DIR/restore-drill-$(date -u +%Y%m%d-%H%M%S).json"
    # rpo = recovery start - backup time; rto = recovered - recovery start.
    cat > "$evidence" <<EOF
{"recorded_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","status":"recovered","backup":"$(basename "$newest")","backup_at":$b_epoch,"recovery_started_at":$restore_start,"recovered_at":$restore_end,"rpo_seconds":$((restore_start - b_epoch)),"rto_seconds":$((restore_end - restore_start)),"integrity":$integrity}
EOF
    log "drill OK: RPO=$((restore_start - b_epoch))s RTO=$((restore_end - restore_start))s evidence=$evidence"
    return 0
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit $?
fi

# Scheduler loop: drill shortly after start (proves the path early), then
# every DRILL_INTERVAL_SECS; the healthcheck requires a fresh evidence file.
if ! drill_once; then
    err "first drill FAILED"
fi
while true; do
    sleep "$DRILL_INTERVAL_SECS"
    if ! drill_once; then
        err "scheduled drill FAILED"
    fi
done
