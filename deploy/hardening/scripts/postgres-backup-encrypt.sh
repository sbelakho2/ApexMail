#!/bin/sh
# ApexMail Backup Encryption Wrapper — July 2026
# Wraps pg_dump backups with AES-256-GCM encryption before storage.
# Requires BACKUP_ENCRYPTION_KEY (32-byte hex) to be set.
# Without it, backups are stored unencrypted (not recommended for production).

set -e

ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
BACKUP_KEEP_WEEKS="${BACKUP_KEEP_WEEKS:-8}"
BACKUP_KEEP_MONTHS="${BACKUP_KEEP_MONTHS:-6}"
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-apexmail}"
POSTGRES_USER="${POSTGRES_USER:-apexmail}"
POSTGRES_PASSWORD_FILE="${POSTGRES_PASSWORD_FILE:-/run/secrets/postgres_password}"

# Daily backup schedule via cron wrapper
SCHEDULE="${SCHEDULE:-@daily}"
CRON_SCHEDULE="0 3 * * *"

encrypt_backup() {
    local input_file="$1"
    local output_file="$2"
    if [ -n "$ENCRYPTION_KEY" ] && command -v openssl >/dev/null 2>&1; then
        openssl enc -aes-256-gcm -md sha512 -pbkdf2 -iter 100000 \
            -pass "pass:${ENCRYPTION_KEY}" \
            -in "$input_file" -out "$output_file" 2>/dev/null
        shred -u "$input_file" 2>/dev/null || rm -f "$input_file"
        echo "[backup-encrypt] Encrypted: $(basename "$output_file")"
    else
        if [ -z "$ENCRYPTION_KEY" ]; then
            echo "[backup-encrypt] WARNING: BACKUP_ENCRYPTION_KEY not set — backup is UNENCRYPTED"
        fi
        mv "$input_file" "$output_file"
    fi
}

perform_backup() {
    local timestamp
    timestamp="$(date -u +%Y%m%d-%H%M%S)"
    local tmpdump="/tmp/apexmail-backup-${timestamp}.sql.gz"
    local backup_file="${BACKUP_DIR}/apexmail-backup-${timestamp}.sql.gz.enc"

    if [ -f "$POSTGRES_PASSWORD_FILE" ]; then
        export PGPASSWORD="$(tr -d '\r\n' < "$POSTGRES_PASSWORD_FILE")"
    fi

    echo "[backup-encrypt] Starting backup of ${POSTGRES_DB}@${POSTGRES_HOST}..."
    pg_dump -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
        -Fc --no-owner --no-acl 2>/dev/null | gzip > "$tmpdump"

    if [ -s "$tmpdump" ]; then
        encrypt_backup "$tmpdump" "$backup_file"
        echo "[backup-encrypt] Backup complete: $(du -h "$backup_file" 2>/dev/null | cut -f1)"
    else
        echo "[backup-encrypt] ERROR: Backup file is empty or pg_dump failed"
        rm -f "$tmpdump"
    fi

    unset PGPASSWORD
}

cleanup_old_backups() {
    echo "[backup-encrypt] Cleaning up backups older than ${BACKUP_KEEP_DAYS} days..."
    find "$BACKUP_DIR" -name "*.sql.gz.enc" -mtime "+${BACKUP_KEEP_DAYS}" -delete 2>/dev/null || true
}

# Main loop
echo "[backup-encrypt] Starting backup scheduler (schedule: ${SCHEDULE})"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

perform_backup

while true; do
    sleep 86400
    perform_backup
    cleanup_old_backups
done
