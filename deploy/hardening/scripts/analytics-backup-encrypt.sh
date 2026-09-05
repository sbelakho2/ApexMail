#!/bin/sh
# =============================================================================
# ApexMail Analytics Cold-Storage Backup — nightly encrypted tar (audit §2)
# =============================================================================
# The analytics-cold volume (compacted event storage written by the
# analytics-worker under /var/lib/apexmail/analytics) had no backup. This
# scheduler tars the READ-ONLY mounted cold-storage tree, gzips it, and
# applies the same AES-256-CBC + PBKDF2 envelope + verification-before-
# delete + retention/offsite contract as the other backup schedulers:
#   * day- and count-based retention (BACKUP_KEEP_DAYS / BACKUP_KEEP_COUNT);
#   * optional offsite mirror (BACKUP_TARGET, rsync over ssh);
#   * the source is mounted :ro — this job can never write the cold store.
#
# CONSISTENCY: the cold store is append-only output of the nightly
# compaction pass (immutable files + retention deletes); a nightly tar is
# therefore a coherent archive for practical purposes, though not a
# point-in-time snapshot of a compaction that happens to run concurrently.
#
# Restore: decrypt (openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
#   -pass pass:<key> -in <file>.tar.gz.enc | tar -xzf - -C <cold dir>).
#
# Wired into the analytics-backup service in docker-compose.prod.yml.
# =============================================================================

set -eu

ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"
ENCRYPTION_KEY_FILE="${BACKUP_ENCRYPTION_KEY_FILE:-}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
BACKUP_KEEP_COUNT="${BACKUP_KEEP_COUNT:-14}"
ANALYTICS_STORAGE_PATH="${ANALYTICS_STORAGE_PATH:-/var/lib/apexmail/analytics}"
BACKUP_TARGET="${BACKUP_TARGET:-}"

# Daily backup schedule (informational; the loop below sleeps 24h).
SCHEDULE="${SCHEDULE:-@daily}"

OPENSSL_ITER=600000

# Sanitize numeric inputs so arithmetic below can never explode.
case "$BACKUP_KEEP_DAYS" in
    ''|*[!0-9]*) BACKUP_KEEP_DAYS=14 ;;
esac
case "$BACKUP_KEEP_COUNT" in
    ''|*[!0-9]*) BACKUP_KEEP_COUNT=14 ;;
esac

log()  { echo "[analytics-backup] $*"; }
warn() { echo "[analytics-backup] WARNING: $*" >&2; }
err()  { echo "[analytics-backup] ERROR: $*" >&2; }

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
# Encrypts and VERIFIES (decrypt + gunzip + tar listing); only deletes the
# plaintext when the ciphertext is proven restorable.
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
            | tar -t -f - >/dev/null 2>&1; then
        log "restore verification OK (decrypt + gunzip + tar listing)"
    else
        rc=$?
        rm -f "$output_file"
        err "restore verification FAILED (decrypt/gunzip/tar exit ${rc}) — plaintext kept at ${input_file}; removing bad ciphertext"
        return 1
    fi

    # Only now is the ciphertext proven good — the plaintext can go.
    secure_remove "$input_file"
}

# Copy the newest backup offsite when BACKUP_TARGET is configured.
offsite_copy() {
    newest="$(ls -1t "$BACKUP_DIR"/analytics-cold-*.tar.gz.enc 2>/dev/null | head -n 1 || true)"
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
    ls -1t "$BACKUP_DIR"/analytics-cold-*.tar.gz.enc 2>/dev/null \
        | tail -n +"$((BACKUP_KEEP_COUNT + 1))" \
        | while IFS= read -r old; do
            rm -f "$old"
            log "retention (count): removed $(basename "$old")"
        done
}

cleanup_old_backups() {
    log "cleaning up backups older than ${BACKUP_KEEP_DAYS} days"
    find "$BACKUP_DIR" -name "*.tar.gz.enc" -mtime "+${BACKUP_KEEP_DAYS}" -delete 2>/dev/null || true
    enforce_keep_count
}

perform_backup() {
    timestamp="$(date -u +%Y%m%d-%H%M%S)"
    tmptar="/tmp/analytics-cold-${timestamp}.tar.gz"
    backup_file="${BACKUP_DIR}/analytics-cold-${timestamp}.tar.gz.enc"

    if [ ! -d "$ANALYTICS_STORAGE_PATH" ]; then
        err "cold-storage directory ${ANALYTICS_STORAGE_PATH} does not exist — nothing to back up"
        return 1
    fi

    # NOTE: an EMPTY cold store still produces a valid (empty) archive —
    # deliberately, so the healthcheck's "an encrypted backup exists within
    # the last 25h" stays an honest signal that the scheduler runs.
    log "archiving ${ANALYTICS_STORAGE_PATH}"
    if ! tar -c -f - -C "$ANALYTICS_STORAGE_PATH" . | gzip > "$tmptar"; then
        rc=$?
        err "tar/gzip of ${ANALYTICS_STORAGE_PATH} failed (exit ${rc})"
        rm -f "$tmptar"
        return 1
    fi

    if encrypt_backup "$tmptar" "$backup_file"; then
        log "backup complete: $(du -h "$backup_file" 2>/dev/null | cut -f1) $(basename "$backup_file")"
    else
        err "backup ${timestamp} NOT completed — see errors above (plaintext may remain in /tmp)"
        return 1
    fi

    offsite_copy
}

# ── Main loop ─────────────────────────────────────────────────────────────────
log "starting analytics cold-storage backup scheduler (schedule: ${SCHEDULE}, keep: ${BACKUP_KEEP_DAYS}d / ${BACKUP_KEEP_COUNT} backups)"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

perform_backup
cleanup_old_backups

while true; do
    sleep 86400
    perform_backup
    cleanup_old_backups
done
