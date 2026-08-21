#!/bin/sh
# =============================================================================
# ApexMail ClickHouse Backup Script — revised August 2026 (audit P)
# =============================================================================
# Creates consistent backups of ClickHouse databases using native
# clickhouse-client dumps.
#
# Backup layout (BACKUP_DIR/<timestamp>/):
#   manifest          one "db.table" per line, in backup order
#   <n>.schema.sql    CREATE TABLE statement for the n-th table
#   <n>.data.native   table data in ClickHouse Native format
#
# The per-table layout is what makes RESTORE possible: schema is applied
# with clickhouse-client and data is streamed back in Native format. (The
# old single concatenated .sql.gz mixed SQL text with Native binary and
# could not be restored mechanically.)
#
# SECURITY (audit P): the password is passed to clickhouse-client via the
# CLICKHOUSE_PASSWORD environment variable (which it reads natively) — it
# is never interpolated into command lines where `ps` could reveal it.
#
# Usage:
#   ./scripts/clickhouse-backup.sh                    # Full backup
#   ./scripts/clickhouse-backup.sh --list             # List available backups
#   ./scripts/clickhouse-backup.sh --restore <dir>    # Restore from backup dir
#
# Environment (set before running):
#   CLICKHOUSE_HOST     (default: localhost)
#   CLICKHOUSE_PORT     (default: 8123)
#   CLICKHOUSE_USER     (default: apexmail)
#   CLICKHOUSE_PASSWORD (required; may also live in CLICKHOUSE_PASSWORD_FILE)
#   BACKUP_DIR          (default: ./backups/clickhouse)
#   BACKUP_RETENTION_DAYS (default: 30)
# =============================================================================
set -eu

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-apexmail}"
BACKUP_DIR="${BACKUP_DIR:-./backups/clickhouse}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# Load the password from a file (e.g. /run/secrets/clickhouse_password)
# without echoing it.
if [ -z "${CLICKHOUSE_PASSWORD:-}" ] && [ -n "${CLICKHOUSE_PASSWORD_FILE:-}" ] && [ -f "${CLICKHOUSE_PASSWORD_FILE}" ]; then
    CLICKHOUSE_PASSWORD="$(tr -d '\r\n' < "${CLICKHOUSE_PASSWORD_FILE}")"
    export CLICKHOUSE_PASSWORD
fi
if [ -z "${CLICKHOUSE_PASSWORD:-}" ]; then
    echo "ERROR: CLICKHOUSE_PASSWORD (or CLICKHOUSE_PASSWORD_FILE) is required." >&2
    exit 1
fi
export CLICKHOUSE_PASSWORD

# Connection options WITHOUT the password — clickhouse-client reads the
# CLICKHOUSE_PASSWORD env var natively, keeping it off the command line.
CONN_OPTS="--host ${CLICKHOUSE_HOST} --port ${CLICKHOUSE_PORT} --user ${CLICKHOUSE_USER}"

ch_query() {
    clickhouse-client ${CONN_OPTS} --query "$1"
}

ensure_backup_dir() {
    mkdir -p "${BACKUP_DIR}"
}

full_backup() {
    timestamp="$(date -u +%Y%m%d_%H%M%S)"
    backup_root="${BACKUP_DIR}/${timestamp}"

    echo "Starting ClickHouse full backup to ${backup_root}..."
    ensure_backup_dir
    mkdir -p "${backup_root}"

    n=0
    ch_query "SELECT database, name FROM system.tables WHERE database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema') ORDER BY database, name" \
        | while IFS="$(printf '\t')" read -r db table; do
            [ -n "${db}" ] || continue
            [ -n "${table}" ] || continue
            n=$((n + 1))
            echo "  Backing up: ${db}.${table}"
            ch_query "SHOW CREATE TABLE ${db}.${table}" > "${backup_root}/${n}.schema.sql"
            ch_query "SELECT * FROM ${db}.${table} FORMAT Native" > "${backup_root}/${n}.data.native"
            printf '%s\t%s\n' "${db}" "${table}" >> "${backup_root}/manifest"
        done

    if [ ! -s "${backup_root}/manifest" ]; then
        echo "WARNING: no non-system tables found — backup is empty." >&2
    fi
    echo "Backup complete: ${backup_root}"
    echo "Size: $(du -sh "${backup_root}" | cut -f1)"
    echo "Restore with: $0 --restore ${backup_root}"
}

list_backups() {
    echo "Available backups:"
    found=0
    for dir in "${BACKUP_DIR}"/*/; do
        [ -f "${dir}manifest" ] || continue
        found=1
        tables=$(wc -l < "${dir}manifest" | tr -d ' ')
        size=$(du -sh "${dir}" | cut -f1)
        echo "  ${dir}  (${tables} tables, ${size})"
    done
    if [ "${found}" -eq 0 ]; then
        echo "  No restorable backups found in ${BACKUP_DIR}"
    fi
    # Legacy pre-2026-08 single-file backups (NOT mechanically restorable —
    # see the header) are listed for reference.
    ls -lh "${BACKUP_DIR}"/*.sql.gz 2>/dev/null && \
        echo "  (legacy .sql.gz files above are single-stream dumps; restore manually)" || true
}

restore_backup() {
    backup_root="$1"
    if [ ! -f "${backup_root}/manifest" ]; then
        echo "ERROR: ${backup_root} is not a backup directory (no manifest)." >&2
        echo "Legacy single-file .sql.gz backups cannot be restored by this script:" >&2
        echo "  gunzip -c <file> | clickhouse-client ${CONN_OPTS}   # manual review required" >&2
        exit 1
    fi

    echo "Restoring from ${backup_root}..."
    echo "(schema is applied with CREATE TABLE; data streams in Native format)"
    n=0
    while IFS="$(printf '\t')" read -r db table; do
        [ -n "${db}" ] || continue
        n=$((n + 1))
        echo "  Restoring: ${db}.${table}"
        ch_query "CREATE DATABASE IF NOT EXISTS ${db}"
        ch_query "$(cat "${backup_root}/${n}.schema.sql")"
        cat "${backup_root}/${n}.data.native" | clickhouse-client ${CONN_OPTS} \
            --query "INSERT INTO ${db}.${table} FORMAT Native"
    done < "${backup_root}/manifest"
    echo "Restore complete (${n} tables)."
}

cleanup_old_backups() {
    echo "Cleaning up backups older than ${RETENTION_DAYS} days..."
    find "${BACKUP_DIR}" -mindepth 1 -maxdepth 1 -type d -mtime "+${RETENTION_DAYS}" -exec rm -rf {} +
    find "${BACKUP_DIR}" -name "*.sql.gz" -type f -mtime "+${RETENTION_DAYS}" -delete
    echo "Cleanup complete."
}

# Parse command
case "${1:-backup}" in
    backup|full)
        full_backup
        cleanup_old_backups
        ;;
    --list|-l)
        list_backups
        ;;
    --restore|-r)
        shift
        [ -n "${1:-}" ] || { echo "Usage: $0 --restore <backup-dir>" >&2; exit 1; }
        restore_backup "$1"
        ;;
    *)
        echo "Usage: $0 [backup|--list|--restore <dir>]"
        echo ""
        echo "Commands:"
        echo "  backup                    Perform full backup (default)"
        echo "  --list, -l                List available backups"
        echo "  --restore, -r <dir>       Restore from a backup directory"
        exit 1
        ;;
esac
