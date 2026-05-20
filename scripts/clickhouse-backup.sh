#!/bin/sh
# =============================================================================
# ApexMail ClickHouse Backup Script
# =============================================================================
# Creates consistent backups of ClickHouse databases using clickhouse-backup
# or native SQL dump.
#
# Prerequisites:
#   - clickhouse-backup installed: https://github.com/Altinity/clickhouse-backup
#     Or use the built-in clickhouse-client for SQL dumps
#
# Usage:
#   ./scripts/clickhouse-backup.sh                    # Full backup
#   ./scripts/clickhouse-backup.sh --incremental      # Incremental backup
#   ./scripts/clickhouse-backup.sh --list             # List available backups
#   ./scripts/clickhouse-backup.sh --restore <name>   # Restore from backup
#
# Environment (set before running):
#   CLICKHOUSE_HOST     (default: localhost)
#   CLICKHOUSE_PORT     (default: 8123)
#   CLICKHOUSE_USER     (default: apexmail)
#   CLICKHOUSE_PASSWORD (required for production)
#   BACKUP_DIR          (default: ./backups/clickhouse)
#   BACKUP_RETENTION_DAYS (default: 30)
# =============================================================================
set -e

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-apexmail}"
CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"
BACKUP_DIR="${BACKUP_DIR:-./backups/clickhouse}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# Build connection string
CONN_OPTS="--host ${CLICKHOUSE_HOST} --port ${CLICKHOUSE_PORT} --user ${CLICKHOUSE_USER}"
if [ -n "$CLICKHOUSE_PASSWORD" ]; then
    CONN_OPTS="${CONN_OPTS} --password '${CLICKHOUSE_PASSWORD}'"
fi

ensure_backup_dir() {
    mkdir -p "${BACKUP_DIR}"
}

full_backup() {
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"
    local backup_file="${BACKUP_DIR}/apexmail_clickhouse_${timestamp}.sql.gz"
    
    echo "Starting ClickHouse full backup to ${backup_file}..."
    ensure_backup_dir
    
    # Dump all databases except system.* and INFORMATIONAL_SCHEMA
    clickhouse-client ${CONN_OPTS} --query "SELECT database, name FROM system.tables WHERE database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema')" \
        | while IFS=$'\t' read -r db table; do
            echo "  Backing up: ${db}.${table}"
            clickhouse-client ${CONN_OPTS} --query "SHOW CREATE TABLE ${db}.${table}" \
                | gzip >> "${backup_file}"
            clickhouse-client ${CONN_OPTS} --query "SELECT * FROM ${db}.${table} FORMAT Native" \
                | gzip >> "${backup_file}"
        done
    
    echo "Backup complete: ${backup_file}"
    echo "Size: $(du -h "${backup_file}" | cut -f1)"
}

list_backups() {
    echo "Available backups:"
    ls -lh "${BACKUP_DIR}"/*.sql.gz 2>/dev/null || echo "  No backups found in ${BACKUP_DIR}"
}

restore_backup() {
    local backup_file="$1"
    if [ ! -f "${backup_file}" ]; then
        echo "ERROR: Backup file not found: ${backup_file}"
        exit 1
    fi
    
    echo "Restoring from ${backup_file}..."
    # NOTE: Restoration requires manual review of the SQL dump
    # This is a placeholder for the actual restore logic
    echo "WARNING: Automated restore is not implemented."
    echo "Please restore manually using:"
    echo "  gunzip -c ${backup_file} | clickhouse-client ${CONN_OPTS}"
}

cleanup_old_backups() {
    echo "Cleaning up backups older than ${RETENTION_DAYS} days..."
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
        restore_backup "$1"
        ;;
    *)
        echo "Usage: $0 [backup|--list|--restore <file>]"
        echo ""
        echo "Commands:"
        echo "  backup              Perform full backup (default)"
        echo "  --list, -l          List available backups"
        echo "  --restore <file>    Restore from backup file"
        exit 1
        ;;
esac
