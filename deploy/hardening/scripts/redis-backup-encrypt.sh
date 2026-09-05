#!/bin/sh
# =============================================================================
# ApexMail Redis Backup — nightly encrypted snapshot (audit §2 backup gap)
# =============================================================================
# Redis had NO backup at all. This scheduler closes the gap with the same
# contract as postgres-backup-encrypt.sh / clickhouse-backup-encrypt.sh:
#   * nightly snapshot via `redis-cli --rdb` — the server runs a BGSAVE and
#     streams the dump over the network, so the produced file is
#     byte-identical to the server's dump.rdb WITHOUT mounting the redis
#     data volume (no partial-write race, no write access to the datastore);
#   * the RDB magic header ("REDIS") is verified before the snapshot is
#     trusted (redis-cli leaves a partial/empty file on a failed transfer);
#   * AES-256-CBC + PBKDF2 encryption (the supported envelope — see the
#     GCM note in postgres-backup-encrypt.sh), decrypt-verified BEFORE the
#     plaintext is removed;
#   * day- and count-based retention;
#   * optional offsite mirror (BACKUP_TARGET, rsync over ssh).
#
# Restore: decrypt (openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
#   -pass pass:<key> -in <file>.rdb.enc -out dump.rdb), stop the redis
#   service, place dump.rdb on the redis_data volume (/data/dump.rdb,
#   owned by the redis uid), start redis — it loads the RDB at boot.
#
# Wired into the redis-backup service in docker-compose.prod.yml.
# =============================================================================

set -eu

ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"
ENCRYPTION_KEY_FILE="${BACKUP_ENCRYPTION_KEY_FILE:-}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
BACKUP_KEEP_COUNT="${BACKUP_KEEP_COUNT:-30}"
REDIS_HOST="${REDIS_HOST:-redis}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_PASSWORD_FILE="${REDIS_PASSWORD_FILE:-/run/secrets/redis_password}"
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

log()  { echo "[redis-backup] $*"; }
warn() { echo "[redis-backup] WARNING: $*" >&2; }
err()  { echo "[redis-backup] ERROR: $*" >&2; }

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

if [ -f "$REDIS_PASSWORD_FILE" ]; then
    REDIS_PASSWORD="$(tr -d '\r\n' < "$REDIS_PASSWORD_FILE")"
else
    REDIS_PASSWORD=""
    warn "REDIS_PASSWORD_FILE not found — attempting an unauthenticated snapshot"
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

# rdb_magic_ok <file> — a trustworthy Redis dump starts with the 5-byte
# "REDIS" magic followed by a 4-digit version.
rdb_magic_ok() {
    [ -s "$1" ] && [ "$(head -c 5 "$1")" = "REDIS" ]
}

# encrypt_backup <plaintext> <ciphertext>
# Encrypts and VERIFIES (decrypt + RDB magic re-check); only deletes the
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
    _tmp_verify="${input_file}.verify"
    if openssl enc -d -aes-256-cbc -pbkdf2 -iter "$OPENSSL_ITER" -md sha256 \
            -pass "pass:${ENCRYPTION_KEY}" \
            -in "$output_file" -out "$_tmp_verify" \
        && rdb_magic_ok "$_tmp_verify"; then
        rm -f "$_tmp_verify"
        log "restore verification OK (decrypt + RDB magic header)"
    else
        rc=$?
        rm -f "$_tmp_verify" "$output_file"
        err "restore verification FAILED (decrypt/magic exit ${rc}) — plaintext kept at ${input_file}; removing bad ciphertext"
        return 1
    fi

    # Only now is the ciphertext proven good — the plaintext can go.
    secure_remove "$input_file"
}

# Copy the newest backup offsite when BACKUP_TARGET is configured.
offsite_copy() {
    newest="$(ls -1t "$BACKUP_DIR"/redis-backup-*.rdb.enc 2>/dev/null | head -n 1 || true)"
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
    ls -1t "$BACKUP_DIR"/redis-backup-*.rdb.enc 2>/dev/null \
        | tail -n +"$((BACKUP_KEEP_COUNT + 1))" \
        | while IFS= read -r old; do
            rm -f "$old"
            log "retention (count): removed $(basename "$old")"
        done
}

cleanup_old_backups() {
    log "cleaning up backups older than ${BACKUP_KEEP_DAYS} days"
    find "$BACKUP_DIR" -name "*.rdb.enc" -mtime "+${BACKUP_KEEP_DAYS}" -delete 2>/dev/null || true
    enforce_keep_count
}

perform_backup() {
    timestamp="$(date -u +%Y%m%d-%H%M%S)"
    tmpdump="/tmp/redis-backup-${timestamp}.rdb"
    backup_file="${BACKUP_DIR}/redis-backup-${timestamp}.rdb.enc"

    log "starting snapshot of redis://${REDIS_HOST}:${REDIS_PORT}"
    if [ -n "$REDIS_PASSWORD" ]; then
        # --no-auth-warning: the password would otherwise be echoed as a
        # warning line into the scheduler log on every run.
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
            --no-auth-warning -a "$REDIS_PASSWORD" \
            --rdb "$tmpdump" >/dev/null 2>/tmp/redis-backup-cli.err || true
    else
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
            --rdb "$tmpdump" >/dev/null 2>/tmp/redis-backup-cli.err || true
    fi

    if ! rdb_magic_ok "$tmpdump"; then
        rc=$?
        err "snapshot FAILED or incomplete (bad/empty RDB); redis-cli stderr follows:"
        sed 's/^/  /' /tmp/redis-backup-cli.err >&2 || true
        rm -f "$tmpdump" /tmp/redis-backup-cli.err
        return 1
    fi
    rm -f /tmp/redis-backup-cli.err

    if encrypt_backup "$tmpdump" "$backup_file"; then
        log "backup complete: $(du -h "$backup_file" 2>/dev/null | cut -f1) $(basename "$backup_file")"
    else
        err "backup ${timestamp} NOT completed — see errors above (plaintext may remain in /tmp)"
        return 1
    fi

    offsite_copy
}

# ── Main loop ─────────────────────────────────────────────────────────────────
log "starting redis backup scheduler (schedule: ${SCHEDULE}, keep: ${BACKUP_KEEP_DAYS}d / ${BACKUP_KEEP_COUNT} backups)"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

perform_backup
cleanup_old_backups

while true; do
    sleep 86400
    perform_backup
    cleanup_old_backups
done
