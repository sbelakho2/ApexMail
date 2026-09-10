#!/bin/sh
# =============================================================================
# ApexMail ClickHouse Backup Scheduler + Encryption Wrapper (audit fix)
# =============================================================================
# Nightly scheduler that runs scripts/clickhouse-backup.sh (mounted at
# /usr/local/bin/clickhouse-backup.sh in the clickhouse-backup service) and
# then encrypts each produced backup directory:
#   * AES-256-CBC + PBKDF2 (same envelope as postgres-backup-encrypt.sh —
#     `openssl enc -aes-256-gcm` does NOT exist),
#   * decrypt + tar -t verification BEFORE the plaintext directory is
#     deleted,
#   * day- and count-based retention,
#   * optional offsite mirror (BACKUP_TARGET, rsync over ssh).
#
# CONSISTENCY (deliberate trade-off, stated): the underlying script dumps
# each table with its own `SELECT * ... FORMAT Native`. Every single SELECT
# is atomic in ClickHouse, but the backup is NOT a cross-table snapshot
# (no FREEZE / BACKUP statement) — tables written concurrently can be a few
# seconds apart from each other. For this deployment's OLAP data (append-
# only tracking/billing events, rebuildable from Postgres), per-table ASOF
# consistency is acceptable; the upgrade path for true snapshots is the
# native `BACKUP ... TO File(...)` statement once the server-side storage
# config for it is added.
#
# Environment (mirrors postgres-backup):
#   CLICKHOUSE_HOST/PORT/USER, CLICKHOUSE_PASSWORD(_FILE)  connection
#   BACKUP_DIR               (default /backups)
#   BACKUP_KEEP_DAYS         (default 14)   day-based retention
#   BACKUP_KEEP_COUNT        (default 14)   count-based retention
#   BACKUP_ENCRYPTION_KEY(_FILE)            AES key (Docker secret preferred)
#   BACKUP_TARGET            optional rsync/ssh offsite destination
#   SCHEDULE                 informational; the loop sleeps 24h
# =============================================================================
set -eu

BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
BACKUP_KEEP_COUNT="${BACKUP_KEEP_COUNT:-14}"
ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"
ENCRYPTION_KEY_FILE="${BACKUP_ENCRYPTION_KEY_FILE:-}"
BACKUP_TARGET="${BACKUP_TARGET:-}"
SCHEDULE="${SCHEDULE:-@daily}"
OPENSSL_ITER=600000

case "$BACKUP_KEEP_DAYS" in
    ''|*[!0-9]*) BACKUP_KEEP_DAYS=14 ;;
esac
case "$BACKUP_KEEP_COUNT" in
    ''|*[!0-9]*) BACKUP_KEEP_COUNT=14 ;;
esac

log()  { echo "[clickhouse-backup] $*"; }
warn() { echo "[clickhouse-backup] WARNING: $*" >&2; }
err()  { echo "[clickhouse-backup] ERROR: $*" >&2; }

if [ -n "$ENCRYPTION_KEY_FILE" ] && [ -f "$ENCRYPTION_KEY_FILE" ]; then
    ENCRYPTION_KEY="$(tr -d '\r\n' < "$ENCRYPTION_KEY_FILE")"
fi

secure_remove() {
    _rm_dir="$1"
    if command -v shred >/dev/null 2>&1; then
        find "$_rm_dir" -type f -exec sh -c 'shred -u "$1" 2>/dev/null' _ {} \; || true
    fi
    rm -rf "$_rm_dir"
}

# encrypt_dir <plaintext-dir> <ciphertext.tar.enc>
# tar the backup directory, encrypt, verify decryptability + tar listing,
# and only then remove the plaintext.
encrypt_dir() {
    _in_dir="$1"
    _out_file="$2"

    if [ -z "$ENCRYPTION_KEY" ]; then
        warn "BACKUP_ENCRYPTION_KEY(_FILE) not set — keeping backup UNENCRYPTED at $_in_dir"
        return 0
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        warn "openssl not available — keeping backup UNENCRYPTED at $_in_dir"
        return 0
    fi

    _tmp_tar="${_out_file%.enc}.tar"
    if ! (cd "$BACKUP_DIR" && tar -cf "$_tmp_tar" "$(basename "$_in_dir")"); then
        rm -f "$_tmp_tar"
        err "tar of $_in_dir FAILED — plaintext kept"
        return 1
    fi
    if ! openssl enc -aes-256-cbc -pbkdf2 -iter "$OPENSSL_ITER" -md sha256 \
            -pass "pass:${ENCRYPTION_KEY}" \
            -in "$_tmp_tar" -out "$_out_file"; then
        rm -f "$_out_file" "$_tmp_tar"
        err "encryption FAILED — plaintext kept at $_in_dir for manual recovery"
        return 1
    fi

    # Restore verification BEFORE destroying the plaintext.
    if openssl enc -d -aes-256-cbc -pbkdf2 -iter "$OPENSSL_ITER" -md sha256 \
            -pass "pass:${ENCRYPTION_KEY}" \
            -in "$_out_file" | tar -tf - >/dev/null 2>&1; then
        log "restore verification OK (decrypt + tar -t): $(basename "$_out_file")"
    else
        rm -f "$_out_file" "$_tmp_tar"
        err "restore verification FAILED — plaintext kept at $_in_dir; bad ciphertext removed"
        return 1
    fi
    rm -f "$_tmp_tar"
    secure_remove "$_in_dir"
}

offsite_copy() {
    _newest="$(ls -1t "$BACKUP_DIR"/clickhouse-backup-*.tar.enc 2>/dev/null | head -n 1 || true)"
    [ -n "$_newest" ] || return 0
    [ -n "$BACKUP_TARGET" ] || return 0
    if command -v rsync >/dev/null 2>&1; then
        if rsync -a "$_newest" "$BACKUP_TARGET/"; then
            log "offsite copy OK: $(basename "$_newest") -> ${BACKUP_TARGET}"
        else
            warn "offsite rsync to ${BACKUP_TARGET} failed (exit $?)"
        fi
    else
        warn "BACKUP_TARGET set but rsync is not available in this image"
    fi
}

enforce_keep_count() {
    if [ "$BACKUP_KEEP_COUNT" -le 0 ] 2>/dev/null; then
        return 0
    fi
    ls -1t "$BACKUP_DIR"/clickhouse-backup-*.tar.enc 2>/dev/null \
        | tail -n +"$((BACKUP_KEEP_COUNT + 1))" \
        | while IFS= read -r _old; do
            rm -f "$_old"
            log "retention (count): removed $(basename "$_old")"
        done
}

cleanup_old_backups() {
    log "cleaning up backups older than ${BACKUP_KEEP_DAYS} days"
    find "$BACKUP_DIR" -name "clickhouse-backup-*.tar.enc" -mtime "+${BACKUP_KEEP_DAYS}" -delete 2>/dev/null || true
    # Unencrypted leftovers from failed/skipped-encryption runs age out too.
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -mtime "+${BACKUP_KEEP_DAYS}" -exec rm -rf {} + 2>/dev/null || true
    enforce_keep_count
}

perform_backup() {
    # scripts/clickhouse-backup.sh writes ${BACKUP_DIR}/<timestamp>/ (manifest
    # + per-table schema/data files) and runs its own retention pass. Locate
    # the newest manifest directory it produced rather than re-deriving the
    # timestamp (avoids a second-boundary mismatch).
    if ! sh /usr/local/bin/clickhouse-backup.sh backup; then
        err "clickhouse-backup.sh run FAILED — see output above"
        return 1
    fi

    _dir="$(ls -1dt "$BACKUP_DIR"/*/ 2>/dev/null | while IFS= read -r _d; do
        [ -f "${_d}manifest" ] && { printf '%s' "$_d"; break; }
    done || true)"
    _dir="${_dir%/}"
    if [ -n "$_dir" ] && [ -d "$_dir" ]; then
        _ts="$(basename "$_dir")"
        if encrypt_dir "$_dir" "${BACKUP_DIR}/clickhouse-backup-${_ts}.tar.enc"; then
            log "backup complete: $(du -h "${BACKUP_DIR}/clickhouse-backup-${_ts}.tar.enc" 2>/dev/null | cut -f1)"
        else
            err "backup ${_ts} NOT encrypted — plaintext kept at $_dir"
            return 1
        fi
    else
        warn "no manifest directory found under ${BACKUP_DIR} (empty ClickHouse?); nothing to encrypt"
    fi
    offsite_copy
}

# ── Main loop ─────────────────────────────────────────────────────────────────
log "starting clickhouse backup scheduler (schedule: ${SCHEDULE}, keep: ${BACKUP_KEEP_DAYS}d / ${BACKUP_KEEP_COUNT} backups)"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR" 2>/dev/null || true

perform_backup
cleanup_old_backups

while true; do
    sleep 86400
    perform_backup
    cleanup_old_backups
done
