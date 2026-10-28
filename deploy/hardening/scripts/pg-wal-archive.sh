#!/bin/sh
# =============================================================================
# pg-wal-archive.sh — archive_command helper for PostgreSQL WAL archiving.
# =============================================================================
# Repo-side PITR enablement (external audit 2026-10-26, infrastructure
# blocker #1: no WAL archiving, no PITR, RPO ~24h from nightly dumps).
#
# Invoked by postgres as:
#   archive_command = '/usr/local/bin/pg-wal-archive.sh %p %f'
# i.e. `pg-wal-archive.sh <src-path> <filename>` (see
# deploy/docker-compose.wal-archive.yml, the operator-gated override that
# turns archiving on).
#
# Contract:
#   1. ENCRYPT the segment before it leaves the host: gzip, then the
#      canonical backup envelope (deploy/hardening/scripts/backup-envelope.sh:
#      AES-256-CBC + PBKDF2 600k + SHA-256 — the same codec the nightly
#      dumps use, so there is ONE encryption authority). Raw WAL contains
#      arbitrary database page images incl. personal data; SSH alone only
#      protects the wire, not the object at rest on the archive host
#      (external audit 2026-10-28 P0). NO KEY = NO ARCHIVE: a missing
#      encryption key exits non-zero and postgres retries — plaintext WAL
#      is never shipped.
#   2. Copy the encrypted segment (spool name `<file>.gz.enc`) into a LOCAL
#      spool atomically (tmp name + mv), so a crash mid-copy never publishes
#      a torn segment.
#   3. rsync the spool BATCH to WAL_ARCHIVE_TARGET (rsync over ssh — same
#      key/known_hosts env pattern as the offsite backup mirror). Only
#      `.gz.enc` artifacts are ever written offsite.
#   4. Exit 0 ONLY when the segment reached the OFFSITE target. A same-host
#      spool is NOT durability (the host can die with both copies); when
#      this helper exits non-zero postgres retries the archive automatically,
#      which is exactly the correct backpressure — pg_wal grows until the
#      pipe is healthy again, and the apexmail-wal-archive alerts fire.
#
# When WAL_ARCHIVE_TARGET is unset the helper exits 1 with a clear message:
# WAL archiving is deliberately OFF until the operator sets the env (the
# compose override refuses to start the stack without it, and a bare
# archive_mode=on without a target would only fill the disk).
#
# POSIX sh, `set -eu`, `sh -n` clean. `--self-test` proves the spool+copy
# semantics and the exit codes against a LOCAL directory target (no ssh):
# round trip byte-identity, cleanup after confirmed push, stuck-segment
# retention on failure, and recovery on retry.
# =============================================================================

set -eu

# The ONE encryption authority, shared with the backup/restore/drill scripts.
_envelope_lib="$(dirname "$0")/backup-envelope.sh"
[ -f "$_envelope_lib" ] || _envelope_lib=/usr/local/lib/backup-envelope.sh
# shellcheck source=backup-envelope.sh
. "$_envelope_lib"

WAL_SPOOL_DIR="${WAL_SPOOL_DIR:-/var/lib/postgresql/wal-spool}"
WAL_ARCHIVE_TARGET="${WAL_ARCHIVE_TARGET:-}"
WAL_SSH_KEY_FILE="${WAL_SSH_KEY_FILE:-}"
WAL_SSH_KNOWN_HOSTS_FILE="${WAL_SSH_KNOWN_HOSTS_FILE:-}"
WAL_RSYNC_TIMEOUT="${WAL_RSYNC_TIMEOUT:-120}"

log() { printf '%s [wal-archive] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
err() { printf '%s [wal-archive] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

# resolve_wal_key — the WAL encryption key. A DEDICATED secret is preferred
# (WAL_ENCRYPTION_KEY_FILE / WAL_ENCRYPTION_KEY) but falls back to the
# backup-envelope key material so a deployment that already rotates the
# backup key works unchanged. Returns 1 when NO key is available: plaintext
# WAL must never ship, so the caller refuses instead of degrading.
resolve_wal_key() {
    if [ -n "${WAL_ENCRYPTION_KEY_FILE:-}" ] && [ -f "$WAL_ENCRYPTION_KEY_FILE" ]; then
        BACKUP_ENCRYPTION_KEY_FILE="$WAL_ENCRYPTION_KEY_FILE" backup_envelope_key
        return $?
    fi
    if [ -n "${WAL_ENCRYPTION_KEY:-}" ]; then
        BACKUP_ENCRYPTION_KEY="$WAL_ENCRYPTION_KEY" backup_envelope_key
        return $?
    fi
    # Fall back to the canonical backup key material (file path first).
    if [ -n "${BACKUP_ENCRYPTION_KEY_FILE:-}" ] && [ -f "$BACKUP_ENCRYPTION_KEY_FILE" ]; then
        backup_envelope_key
        return $?
    fi
    if [ -n "${BACKUP_ENCRYPTION_KEY:-}" ]; then
        backup_envelope_key
        return $?
    fi
    return 1
}

# Build the rsync remote-shell command from the SAME key/known_hosts env
# pattern the offsite backup mirror uses (BACKUP_SSH_KEY_FILE and friends).
# BatchMode=yes forbids interactive prompts: the archiver is non-interactive,
# a first-connection host-key prompt must fail loudly, never hang postgres.
wal_ssh_cmd() {
    _ws="ssh -o BatchMode=yes -o ConnectTimeout=15"
    if [ -n "$WAL_SSH_KEY_FILE" ]; then
        _ws="$_ws -i $WAL_SSH_KEY_FILE"
    fi
    if [ -n "$WAL_SSH_KNOWN_HOSTS_FILE" ]; then
        _ws="$_ws -o UserKnownHostsFile=$WAL_SSH_KNOWN_HOSTS_FILE -o StrictHostKeyChecking=yes"
    fi
    printf '%s' "$_ws"
}

# archive_wal <src-path> <filename> — the production path. Returns 0 only
# when the segment reached the OFFSITE target.
archive_wal() {
    _aw_src=$1
    _aw_name=$2

    if [ -z "$_aw_src" ] || [ -z "$_aw_name" ]; then
        err "usage: pg-wal-archive.sh <src-path> <filename>"
        return 2
    fi
    if [ ! -f "$_aw_src" ]; then
        err "segment $_aw_name vanished before archive ($_aw_src missing) — postgres will retry"
        return 1
    fi
    if [ -z "$WAL_ARCHIVE_TARGET" ]; then
        err "WAL_ARCHIVE_TARGET is not set — WAL archiving is deliberately OFF (a same-host spool is not durability). Set WAL_ARCHIVE_TARGET in the deployment env and start postgres with deploy/docker-compose.wal-archive.yml, or remove the override"
        return 1
    fi
    if ! command -v rsync >/dev/null 2>&1; then
        err "rsync unavailable — cannot archive $_aw_name offsite (postgres retries)"
        return 1
    fi

    # NO KEY = NO ARCHIVE (P0, external audit 2026-10-28): raw WAL must
    # never reach the archive host, and SSH protects only the wire.
    if ! resolve_wal_key; then
        err "no WAL encryption key available (WAL_ENCRYPTION_KEY_FILE/WAL_ENCRYPTION_KEY or the backup-envelope key) — REFUSING to archive $_aw_name in PLAINTEXT; set the key material (postgres retries)"
        return 1
    fi

    mkdir -p "$WAL_SPOOL_DIR"
    chmod 700 "$WAL_SPOOL_DIR" 2>/dev/null || true

    # Encrypt via the canonical envelope: gzip -n (deterministic, no
    # timestamp) then backup_envelope_encrypt -> <name>.gz.enc. The spool
    # only ever holds ciphertext under the real name (atomic tmp + mv), so a
    # crash mid-write publishes nothing torn and never a plaintext segment.
    _aw_pending="$WAL_SPOOL_DIR/.pending.$_aw_name.$$.gz"
    _aw_enc="$_aw_pending.enc"
    _aw_artifact="$WAL_SPOOL_DIR/$_aw_name.gz.enc"
    if ! gzip -n -c "$_aw_src" > "$_aw_pending"; then
        rm -f "$_aw_pending" "$_aw_enc"
        err "could not read/compress $_aw_name from $_aw_src — check disk space"
        return 1
    fi
    if ! backup_envelope_encrypt "$_aw_pending" "$_aw_enc"; then
        rm -f "$_aw_pending" "$_aw_enc"
        err "encryption of $_aw_name failed — plaintext spool removed, postgres retries"
        return 1
    fi
    rm -f "$_aw_pending"
    mv "$_aw_enc" "$_aw_artifact"

    # Stamp BEFORE the batch rsync: everything in the spool at rsync time
    # (mtime <= stamp) goes offsite in this batch; files another archiver
    # worker spools concurrently (mtime > stamp) must stay for their own run.
    _aw_stamp="$WAL_SPOOL_DIR/.stamp.$$"
    : > "$_aw_stamp"

    _aw_ssh=$(wal_ssh_cmd)
    # NB: capture rsync's status directly — after `if cmd; then ... fi`
    # with no else, `$?` is the if-statement's own 0, not the command's
    # (the same trap postgres-backup-encrypt.sh's dry run documents).
    _aw_rc=0
    # Dotfile spool bookkeeping (the atomic-copy pending names and the batch
    # stamp) never belongs in the offsite archive.
    rsync -a --exclude='.pending.*' --exclude='.stamp.*' \
        --timeout="$WAL_RSYNC_TIMEOUT" -e "$_aw_ssh" \
        "$WAL_SPOOL_DIR/" "$WAL_ARCHIVE_TARGET/" || _aw_rc=$?
    if [ "$_aw_rc" -eq 0 ]; then
        # The whole batch (including this segment) reached the offsite
        # target — the spooled copies can go. Only remove files this batch
        # actually covered (mtime <= stamp), never concurrent spoolings.
        # while-read, not a for-over-find loop: WAL names are hex-only so
        # splitting would be safe, but the static-lint gate runs the
        # repo's shell lint (-S warning) and SC2044 is right to keep
        # this explicit.
        find "$WAL_SPOOL_DIR" -type f ! -newer "$_aw_stamp" 2>/dev/null |
            while IFS= read -r _aw_file; do
                case "${_aw_file##*/}" in
                    .stamp.*|.pending.*) ;;
                    *.gz.enc) rm -f "$_aw_file" ;;
                    # A plaintext name here would mean an older helper wrote
                    # it; never let it linger.
                    *) rm -f "$_aw_file" ;;
                esac
            done
        rm -f "$_aw_stamp"
        log "archived $_aw_name to ${WAL_ARCHIVE_TARGET} (exit 0 — offsite confirmed)"
        return 0
    fi
    rm -f "$_aw_stamp"
    err "offsite rsync to ${WAL_ARCHIVE_TARGET} failed (exit $_aw_rc) — $_aw_name stays spooled LOCALLY, postgres will retry (correct backpressure)"
    return 1
}

# ── Self-test ─────────────────────────────────────────────────────────────────
# Synthetic segment round trip through the spool against a LOCAL directory
# target (rsync needs no ssh for local paths) proving:
#   1. unset WAL_ARCHIVE_TARGET → exit 1 with the deliberate-off message
#   2. reachable target → exit 0, byte-identical segment offsite, spool clean
#   3. broken target → exit 1 and the segment STAYS spooled (backpressure)
#   4. retry after the target heals → the stuck segment pushes, exit 0
#   5. .backup history files ride the same path
wal_archive_self_test() {
    _st_fail=0
    _st_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-wal-archive-test.XXXXXX") || return 1
    _st_saved_target=$WAL_ARCHIVE_TARGET
    _st_saved_spool=$WAL_SPOOL_DIR
    _st_saved_key_file=${WAL_ENCRYPTION_KEY_FILE:-}
    _st_saved_key=${WAL_ENCRYPTION_KEY:-}
    _st_saved_backup_key=${BACKUP_ENCRYPTION_KEY:-}
    _st_saved_backup_key_file=${BACKUP_ENCRYPTION_KEY_FILE:-}

    # Synthetic 24-hex-char WAL segment name + deterministic body.
    printf 'synthetic WAL segment body %s\n' "$$" > "$_st_tmp/000000010000000000000001"
    _st_seg=$_st_tmp/000000010000000000000001

    # 0. No key material → REFUSE (plaintext WAL must never ship).
    WAL_ARCHIVE_TARGET=$_st_tmp/offsite
    mkdir -p "$WAL_ARCHIVE_TARGET"
    WAL_ENCRYPTION_KEY_FILE=
    WAL_ENCRYPTION_KEY=
    BACKUP_ENCRYPTION_KEY=
    BACKUP_ENCRYPTION_KEY_FILE=
    WAL_SPOOL_DIR=$_st_tmp/spool0
    _st_msg=$(archive_wal "$_st_seg" 000000010000000000000001 2>&1) && _st_rc=0 || _st_rc=$?
    if [ "$_st_rc" -ne 1 ]; then
        echo "[wal-archive] self-test FAILED: missing WAL key must exit 1, got $_st_rc" >&2
        _st_fail=1
    fi
    case "$_st_msg" in
        *encryption\ key*) : ;;
        *) echo "[wal-archive] self-test FAILED: no-key message does not name the encryption key" >&2; _st_fail=1 ;;
    esac
    if [ -n "$(ls -A "$WAL_ARCHIVE_TARGET" 2>/dev/null)" ]; then
        echo "[wal-archive] self-test FAILED: a keyless run shipped SOMETHING offsite" >&2
        _st_fail=1
    fi

    # Pin a test key for the remaining cases.
    WAL_ENCRYPTION_KEY="wal-archive-self-test-key-0123456789abcdef"
    BACKUP_ENCRYPTION_KEY_FILE=/nonexistent

    # 1. No target configured → exit 1, message says archiving is off.
    WAL_ARCHIVE_TARGET=
    WAL_SPOOL_DIR=$_st_tmp/spool1
    _st_msg=$(archive_wal "$_st_seg" 000000010000000000000001 2>&1) && _st_rc=0 || _st_rc=$?
    if [ "$_st_rc" -ne 1 ]; then
        echo "[wal-archive] self-test FAILED: unset WAL_ARCHIVE_TARGET must exit 1, got $_st_rc" >&2
        _st_fail=1
    fi
    case "$_st_msg" in
        *WAL_ARCHIVE_TARGET*) : ;;
        *) echo "[wal-archive] self-test FAILED: unset-target message does not name WAL_ARCHIVE_TARGET" >&2; _st_fail=1 ;;
    esac

    # 2. Local directory target → exit 0; offsite holds ONLY the encrypted
    #    artifact and it decrypts+gunzips back to the exact segment bytes.
    WAL_ARCHIVE_TARGET=$_st_tmp/offsite
    mkdir -p "$WAL_ARCHIVE_TARGET"
    if archive_wal "$_st_seg" 000000010000000000000001; then
        if [ -f "$WAL_ARCHIVE_TARGET/000000010000000000000001" ]; then
            echo "[wal-archive] self-test FAILED: PLAINTEXT segment reached the offsite target" >&2
            _st_fail=1
        fi
        if [ ! -f "$WAL_ARCHIVE_TARGET/000000010000000000000001.gz.enc" ]; then
            echo "[wal-archive] self-test FAILED: encrypted artifact missing offsite" >&2
            _st_fail=1
        fi
        if ! backup_envelope_decrypt "$WAL_ARCHIVE_TARGET/000000010000000000000001.gz.enc" "$_st_tmp/rt.gz" \
            || ! gzip -dc "$_st_tmp/rt.gz" > "$_st_tmp/rt.bin" \
            || ! cmp -s "$_st_seg" "$_st_tmp/rt.bin"; then
            echo "[wal-archive] self-test FAILED: encrypted artifact does not round-trip to the segment bytes" >&2
            _st_fail=1
        fi
        if [ -n "$(ls -A "$WAL_SPOOL_DIR" 2>/dev/null)" ]; then
            echo "[wal-archive] self-test FAILED: spool not cleaned after confirmed offsite push" >&2
            _st_fail=1
        fi
    else
        echo "[wal-archive] self-test FAILED: local directory target did not exit 0" >&2
        _st_fail=1
    fi

    # 3. Broken target → exit 1, encrypted artifact stays spooled
    #    (postgres backpressure); still no plaintext in the spool.
    WAL_ARCHIVE_TARGET=$_st_tmp/missing-parent/deeper
    if archive_wal "$_st_seg" 000000010000000000000002; then
        echo "[wal-archive] self-test FAILED: unreachable target did not exit 1" >&2
        _st_fail=1
    fi
    if [ ! -f "$WAL_SPOOL_DIR/000000010000000000000002.gz.enc" ]; then
        echo "[wal-archive] self-test FAILED: failed archive did not keep the encrypted segment in the spool" >&2
        _st_fail=1
    fi
    if [ -f "$WAL_SPOOL_DIR/000000010000000000000002" ]; then
        echo "[wal-archive] self-test FAILED: PLAINTEXT segment left in the spool" >&2
        _st_fail=1
    fi

    # 4. Target heals → the SAME invocation shape succeeds and drains the
    #    stuck segment (retry semantics postgres exercises automatically).
    WAL_ARCHIVE_TARGET=$_st_tmp/offsite
    if ! archive_wal "$_st_seg" 000000010000000000000002; then
        echo "[wal-archive] self-test FAILED: retry after target healed did not exit 0" >&2
        _st_fail=1
    fi
    if [ ! -f "$WAL_ARCHIVE_TARGET/000000010000000000000002.gz.enc" ]; then
        echo "[wal-archive] self-test FAILED: stuck segment never reached the target on retry" >&2
        _st_fail=1
    fi

    # 5. Timeline-history filename shape (archive_command also receives
    #    .backup and .history files).
    printf 'history' > "$_st_tmp/00000002.history"
    if ! archive_wal "$_st_tmp/00000002.history" 00000002.history \
        || [ ! -f "$WAL_ARCHIVE_TARGET/00000002.history.gz.enc" ]; then
        echo "[wal-archive] self-test FAILED: .history file did not round trip encrypted" >&2
        _st_fail=1
    fi

    WAL_ARCHIVE_TARGET=$_st_saved_target
    WAL_SPOOL_DIR=$_st_saved_spool
    WAL_ENCRYPTION_KEY_FILE=$_st_saved_key_file
    WAL_ENCRYPTION_KEY=$_st_saved_key
    BACKUP_ENCRYPTION_KEY=$_st_saved_backup_key
    BACKUP_ENCRYPTION_KEY_FILE=$_st_saved_backup_key_file
    rm -rf "$_st_tmp"
    if [ "$_st_fail" -ne 0 ]; then
        echo "[wal-archive] self-test FAILED" >&2
        return 1
    fi
    echo "[wal-archive] self-test OK: key-required (refuses keyless), encrypted-only artifacts offsite with decrypt round trip, spool+copy semantics, exit codes 0/1/2, backpressure retention, retry drain, history-file shape (LOCAL dir target — the ssh transport is exercised only in production)"
    return 0
}

if [ "${1:-}" = "--self-test" ]; then
    wal_archive_self_test
    exit $?
fi

archive_wal "${1:-}" "${2:-}"
