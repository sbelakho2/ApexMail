#!/bin/sh
# =============================================================================
# ApexMail Backup Encryption Wrapper — revised August 2026 (audit E)
# =============================================================================
# Wraps pg_dump backups with AES-256-CBC + PBKDF2 encryption before storage.
#
# Why not AES-256-GCM: `openssl enc` does NOT support AEAD cipher modes — the
# previous `-aes-256-gcm` invocation always failed (stderr was silenced with
# 2>/dev/null) and the old script then shredded the plaintext, destroying the
# only good copy. This version:
#   * uses `openssl enc -aes-256-cbc -pbkdf2 -iter 600000` (supported),
#   * checks the encrypt exit code BEFORE deleting anything,
#   * verifies restorability (decrypt + pg_restore --list) before cleanup,
#   * keeps a bounded number of backups (BACKUP_KEEP_COUNT, newest first),
#   * optionally copies backups offsite (BACKUP_TARGET, rsync over ssh).
#
# The encryption key is read from BACKUP_ENCRYPTION_KEY_FILE (Docker secret,
# preferred) or the BACKUP_ENCRYPTION_KEY env var. Without a key the backup
# is stored UNENCRYPTED with a loud warning (not recommended).
#
# Wired into the postgres-backup service in docker-compose.prod.yml.
# =============================================================================

set -eu

ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"
ENCRYPTION_KEY_FILE="${BACKUP_ENCRYPTION_KEY_FILE:-}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
BACKUP_KEEP_COUNT="${BACKUP_KEEP_COUNT:-30}"
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-apexmail}"
POSTGRES_USER="${POSTGRES_USER:-apexmail}"
POSTGRES_PASSWORD_FILE="${POSTGRES_PASSWORD_FILE:-/run/secrets/postgres_password}"
BACKUP_TARGET="${BACKUP_TARGET:-}"

# Daily backup schedule (informational; the loop below sleeps 24h).
SCHEDULE="${SCHEDULE:-@daily}"

OPENSSL_ITER=600000

# Sanitize numeric inputs so arithmetic below can never explode.
case "$BACKUP_KEEP_DAYS" in
    ''|*[!0-9]*) BACKUP_KEEP_DAYS=14 ;;
esac
case "$BACKUP_KEEP_COUNT" in
    ''|*[!0-9]*) BACKUP_KEEP_COUNT=30 ;;
esac

log()  { echo "[backup-encrypt] $*"; }
warn() { echo "[backup-encrypt] WARNING: $*" >&2; }
err()  { echo "[backup-encrypt] ERROR: $*" >&2; }

# Best-effort tooling bootstrap on Alpine-based images (non-fatal).
if ! command -v openssl >/dev/null 2>&1 || ! command -v rsync >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache openssl rsync >/dev/null 2>&1 || \
            warn "could not install missing tools (openssl/rsync) via apk"
    fi
fi

if [ -n "$ENCRYPTION_KEY_FILE" ] && [ -f "$ENCRYPTION_KEY_FILE" ]; then
    ENCRYPTION_KEY="$(tr -d '\r\n' < "$ENCRYPTION_KEY_FILE")"
fi

# Remove a plaintext file as securely as the available tooling allows.
secure_remove() {
    rm_file="$1"
    if command -v shred >/dev/null 2>&1; then
        shred -u "$rm_file" 2>/dev/null || rm -f "$rm_file"
    else
        rm -f "$rm_file"
    fi
}

# encrypt_backup <plaintext> <ciphertext>
# Encrypts and VERIFIES; only deletes the plaintext when the ciphertext is
# proven decryptable AND restorable. On any failure the plaintext is kept
# and the error is loud (the opposite of the old self-destructing path).
encrypt_backup() {
    input_file="$1"
    output_file="$2"

    if [ -z "$ENCRYPTION_KEY" ]; then
        warn "BACKUP_ENCRYPTION_KEY(_FILE) not set — storing backup UNENCRYPTED"
        mv "$input_file" "$output_file"
        return 0
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        warn "openssl not available — storing backup UNENCRYPTED"
        mv "$input_file" "$output_file"
        return 0
    fi

    if openssl enc -aes-256-cbc -pbkdf2 -iter "$OPENSSL_ITER" -md sha256 \
            -pass "pass:${ENCRYPTION_KEY}" \
            -in "$input_file" -out "$output_file"; then
        log "encrypted: $(basename "$output_file")"
    else
        rc=$?
        rm -f "$output_file"
        err "encryption FAILED (openssl exit ${rc}) — plaintext kept at ${input_file} for manual recovery"
        return 1
    fi

    # ── Restore verification BEFORE destroying the plaintext ──────────────
    if openssl enc -d -aes-256-cbc -pbkdf2 -iter "$OPENSSL_ITER" -md sha256 \
            -pass "pass:${ENCRYPTION_KEY}" \
            -in "$output_file" \
            | gzip -d \
            | pg_restore --list > /dev/null 2>&1; then
        log "restore verification OK (decrypt + pg_restore --list)"
    else
        rc=$?
        err "restore verification FAILED (decrypt/pg_restore exit ${rc}) — plaintext kept at ${input_file}; removing bad ciphertext"
        rm -f "$output_file"
        return 1
    fi

    # Only now is the ciphertext proven good — the plaintext can go.
    secure_remove "$input_file"
}

# Copy the newest backup offsite when BACKUP_TARGET is configured.
offsite_copy() {
    newest="$(ls -1t "$BACKUP_DIR"/apexmail-backup-*.sql.gz.enc 2>/dev/null | head -n 1 || true)"
    [ -n "$newest" ] || return 0
    if [ -z "$BACKUP_TARGET" ]; then
        return 0
    fi
    if command -v rsync >/dev/null 2>&1; then
        if rsync -a "$newest" "$BACKUP_TARGET/"; then
            log "offsite copy OK: $(basename "$newest") -> ${BACKUP_TARGET}"
        else
            warn "offsite rsync to ${BACKUP_TARGET} failed (exit $?)"
        fi
    else
        warn "BACKUP_TARGET set but rsync is not available in this image"
    fi
}

# Count-based retention: keep the newest BACKUP_KEEP_COUNT encrypted backups.
enforce_keep_count() {
    if [ "$BACKUP_KEEP_COUNT" -le 0 ] 2>/dev/null; then
        return 0
    fi
    ls -1t "$BACKUP_DIR"/apexmail-backup-*.sql.gz.enc 2>/dev/null \
        | tail -n +"$((BACKUP_KEEP_COUNT + 1))" \
        | while IFS= read -r old; do
            rm -f "$old"
            log "retention (count): removed $(basename "$old")"
        done
}

cleanup_old_backups() {
    log "cleaning up backups older than ${BACKUP_KEEP_DAYS} days"
    find "$BACKUP_DIR" -name "*.sql.gz.enc" -mtime "+${BACKUP_KEEP_DAYS}" -delete 2>/dev/null || true
    enforce_keep_count
}

perform_backup() {
    timestamp="$(date -u +%Y%m%d-%H%M%S)"
    tmpdump="/tmp/apexmail-backup-${timestamp}.dump.gz"
    backup_file="${BACKUP_DIR}/apexmail-backup-${timestamp}.sql.gz.enc"

    if [ -f "$POSTGRES_PASSWORD_FILE" ]; then
        PGPASSWORD="$(tr -d '\r\n' < "$POSTGRES_PASSWORD_FILE")"
        export PGPASSWORD
    fi

    log "starting backup of ${POSTGRES_DB}@${POSTGRES_HOST}"
    if pg_dump -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
            -Fc --no-owner --no-acl > "$tmpdump" 2>/tmp/apexmail-backup-pgdump.err && \
       gzip -f "$tmpdump"; then
        :
    else
        rc=$?
        err "pg_dump failed (exit ${rc}); stderr follows:"
        sed 's/^/  /' /tmp/apexmail-backup-pgdump.err >&2 || true
        rm -f "$tmpdump" /tmp/apexmail-backup-pgdump.err
        unset PGPASSWORD || true
        return 1
    fi
    rm -f /tmp/apexmail-backup-pgdump.err
    unset PGPASSWORD || true

    if [ -s "${tmpdump}.gz" ]; then
        if encrypt_backup "${tmpdump}.gz" "$backup_file"; then
            log "backup complete: $(du -h "$backup_file" 2>/dev/null | cut -f1) $(basename "$backup_file")"
        else
            err "backup ${timestamp} NOT completed — see errors above (plaintext may remain in /tmp)"
            return 1
        fi
    else
        err "backup file is empty or pg_dump produced no output"
        rm -f "${tmpdump}.gz"
        return 1
    fi

    offsite_copy
}

# ── Main loop ─────────────────────────────────────────────────────────────────
log "starting backup scheduler (schedule: ${SCHEDULE}, keep: ${BACKUP_KEEP_DAYS}d / ${BACKUP_KEEP_COUNT} backups)"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

perform_backup
cleanup_old_backups

while true; do
    sleep 86400
    perform_backup
    cleanup_old_backups
done
