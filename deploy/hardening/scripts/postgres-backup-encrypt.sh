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
#   * grandfather-father-son retention: every daily backup for
#     BACKUP_KEEP_DAYS, the newest backup of each week for
#     BACKUP_KEEP_WEEKS weeks, the newest of each month for
#     BACKUP_KEEP_MONTHS months, then a hard cap of BACKUP_KEEP_COUNT,
#   * optionally copies backups offsite (BACKUP_TARGET, rsync over ssh).
#
# The encryption key is read from BACKUP_ENCRYPTION_KEY_FILE (Docker secret,
# preferred) or the BACKUP_ENCRYPTION_KEY env var. Without a key the backup
# FAILS (fail-closed; the TOM promises encrypted backups). Development can
# opt into the old behaviour with ALLOW_UNENCRYPTED_BACKUPS=true.
#
# Weekly PHYSICAL base backup (PITR enablement, external audit 2026-10-26):
# when WAL_BASE_BACKUP_ENABLED is truthy the scheduler additionally takes a
# plain `pg_basebackup -F tar -z` once a week into ${BACKUP_DIR}/wal-base/
# (2-generation retention). This is deliberately NOT the logical envelope —
# PITR replay needs a physical base plus the archived WAL segments (see
# pg-wal-archive.sh + deploy/docker-compose.wal-archive.yml + pg-pitr-restore.sh).
# The nightly logical dumps are untouched and remain the recovery path this
# script is built around; a base-backup failure is LOUD but never blocks or
# degrades the nightly dump.
#
# Wired into the postgres-backup service in docker-compose.prod.yml.
# =============================================================================

set -eu

# The canonical backup envelope (cipher/KDF/iterations/gzip) lives in
# backup-envelope.sh, sourced by BOTH this producer and the restore drill —
# a parameter drift between them once made the drill unable to decode real
# backups (external audit 2026-10-26). Prefer the sibling file (bind mount
# or repo checkout), fall back to the copy baked into the image.
_envelope_lib="$(dirname "$0")/backup-envelope.sh"
if [ ! -f "$_envelope_lib" ]; then
    _envelope_lib=/usr/local/lib/backup-envelope.sh
fi
# shellcheck source=backup-envelope.sh
. "$_envelope_lib"

ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"
ENCRYPTION_KEY_FILE="${BACKUP_ENCRYPTION_KEY_FILE:-}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
BACKUP_KEEP_WEEKS="${BACKUP_KEEP_WEEKS:-8}"
BACKUP_KEEP_MONTHS="${BACKUP_KEEP_MONTHS:-6}"
BACKUP_KEEP_COUNT="${BACKUP_KEEP_COUNT:-30}"
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-apexmail}"
POSTGRES_USER="${POSTGRES_USER:-apexmail}"
POSTGRES_PASSWORD_FILE="${POSTGRES_PASSWORD_FILE:-/run/secrets/postgres_password}"
BACKUP_TARGET="${BACKUP_TARGET:-}"

# ── Weekly physical base backup (PITR) — OFF until the operator turns it on ──
# The gate stays closed by default: a physical base backup is only useful
# together with WAL archiving (deploy/docker-compose.wal-archive.yml sets
# archive_mode=on + WAL_ARCHIVE_TARGET), so enabling this before archiving
# would burn I/O for nothing. The operator sets both in the deployment env.
WAL_BASE_BACKUP_ENABLED="${WAL_BASE_BACKUP_ENABLED:-}"
WAL_BASE_KEEP_GENERATIONS="${WAL_BASE_KEEP_GENERATIONS:-2}"
WAL_BASE_INTERVAL_SECS="${WAL_BASE_INTERVAL_SECS:-604800}"
case "$WAL_BASE_KEEP_GENERATIONS" in
    ''|*[!0-9]*) WAL_BASE_KEEP_GENERATIONS=2 ;;
esac
case "$WAL_BASE_INTERVAL_SECS" in
    ''|*[!0-9]*) WAL_BASE_INTERVAL_SECS=604800 ;;
esac

# Daily backup schedule (informational; the loop below sleeps 24h).
SCHEDULE="${SCHEDULE:-@daily}"

# Sanitize numeric inputs so arithmetic below can never explode.
case "$BACKUP_KEEP_DAYS" in
    ''|*[!0-9]*) BACKUP_KEEP_DAYS=14 ;;
esac
case "$BACKUP_KEEP_WEEKS" in
    ''|*[!0-9]*) BACKUP_KEEP_WEEKS=8 ;;
esac
case "$BACKUP_KEEP_MONTHS" in
    ''|*[!0-9]*) BACKUP_KEEP_MONTHS=6 ;;
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

    # Fail closed (external audit 2026-10-26 §4): the TOM/DPA promises
    # encrypted backups, so a missing key or missing openssl is a FAILED
    # backup, not a silent plaintext. Throwaway development can opt out
    # explicitly with ALLOW_UNENCRYPTED_BACKUPS=true.
    if [ -z "$ENCRYPTION_KEY" ]; then
        if [ "${ALLOW_UNENCRYPTED_BACKUPS:-false}" = "true" ]; then
            warn "BACKUP_ENCRYPTION_KEY(_FILE) not set — ALLOW_UNENCRYPTED_BACKUPS=true, storing backup UNENCRYPTED"
            mv "$input_file" "$output_file"
            return 0
        fi
        err "BACKUP_ENCRYPTION_KEY(_FILE) not set — refusing to store an UNENCRYPTED backup (encrypted backups are contractual; set ALLOW_UNENCRYPTED_BACKUPS=true only for disposable development data)"
        return 1
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        if [ "${ALLOW_UNENCRYPTED_BACKUPS:-false}" = "true" ]; then
            warn "openssl not available — ALLOW_UNENCRYPTED_BACKUPS=true, storing backup UNENCRYPTED"
            mv "$input_file" "$output_file"
            return 0
        fi
        err "openssl not available — refusing to store an UNENCRYPTED backup (the image bakes openssl in; this container is misbuilt)"
        return 1
    fi
    BACKUP_ENVELOPE_KEY="$ENCRYPTION_KEY"

    if backup_envelope_encrypt "$input_file" "$output_file"; then
        log "encrypted: $(basename "$output_file")"
    else
        rc=$?
        rm -f "$output_file"
        err "encryption FAILED (openssl exit ${rc}) — plaintext kept at ${input_file} for manual recovery"
        return 1
    fi

    # ── Restore verification BEFORE destroying the plaintext ──────────────
    if backup_envelope_decrypt "$output_file" "${output_file}.verify.sql.gz" 2>/dev/null \
        && backup_envelope_uncompress "${output_file}.verify.sql.gz" "${output_file}.verify.dump" 2>/dev/null \
        && pg_restore --list "${output_file}.verify.dump" > /dev/null 2>&1; then
        log "restore verification OK (decrypt + gunzip + pg_restore --list)"
        rm -f "${output_file}.verify.sql.gz" "${output_file}.verify.dump"
    else
        err "restore verification FAILED (decrypt/gunzip/pg_restore) — plaintext kept at ${input_file}; removing bad ciphertext"
        rm -f "$output_file" "${output_file}.verify.sql.gz" "${output_file}.verify.dump"
        return 1
    fi

    # Only now is the ciphertext proven good — the plaintext can go.
    secure_remove "$input_file"
}

# Mandatory offsite mirror (durability audit 2026-10-26: optional →
# required). A backup that has not left the host is NOT a backup: the
# single host can die before the next nightly run, and a local-only copy
# gives RPO 24h with zero geographic redundancy. Failure is loud and
# non-zero, and success refreshes the `.last_offsite_ok` stamp the
# compose healthcheck requires, so a skipped or failed mirror turns the
# container unhealthy instead of scrolling past in a log line.
offsite_copy() {
    newest="$(ls -1t "$BACKUP_DIR"/apexmail-backup-*.sql.gz.enc 2>/dev/null | head -n 1 || true)"
    [ -n "$newest" ] || return 0
    if [ -z "$BACKUP_TARGET" ]; then
        err "BACKUP_TARGET is not set — the offsite mirror is MANDATORY; $(basename "$newest") exists only on this host"
        return 1
    fi
    if ! command -v rsync >/dev/null 2>&1; then
        err "rsync unavailable — cannot mirror $(basename "$newest") offsite"
        return 1
    fi
    if rsync -a "$newest" "$BACKUP_TARGET/"; then
        log "offsite copy OK: $(basename "$newest") -> ${BACKUP_TARGET}"
        touch "$BACKUP_DIR/.last_offsite_ok" 2>/dev/null || true
        return 0
    fi
    err "offsite rsync to ${BACKUP_TARGET} failed (exit $?) — $(basename "$newest") is LOCAL-ONLY"
    return 1
}

# ── Weekly physical base backup (PITR) ───────────────────────────────────────
# A physical base backup is the anchor PITR replays archived WAL against;
# it is plain `pg_basebackup -F tar -z` output (base.tar.gz + pg_wal.tar.gz),
# NOT the logical envelope — pg_recovery cannot replay into a pg_dump.
# Artifacts: ${BACKUP_DIR}/wal-base/apexmail-wal-base-<ts>.tar.gz and
# apexmail-wal-base-<ts>.pg_wal.tar.gz (paired by the shared timestamp).
#
# Cadence: WAL_BASE_INTERVAL_SECS (default 7d) measured against a stamp file
# written ONLY after a fully successful run (artifact + offsite mirror), so
# a failed mirror retries on the next scheduler pass instead of leaving a
# week-old local-only base behind. The mirror itself reuses BACKUP_TARGET
# (rsync over ssh, same key/known_hosts mounts as the nightly dump): a
# same-host-only base backup is not durability, exactly like the dumps.
# The nightly logical path is NEVER gated on this — failures are loud errors
# and nothing more (see maybe_wal_base_backup callers in the main loop).

# wal_file_epoch <file> — mtime as epoch; GNU stat first, then BSD, else 0.
wal_file_epoch() {
    stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || printf '0\n'
}

# wal_base_due <now-epoch> — gate + cadence decision (pure; self-testable).
wal_base_due() {
    _wbd_now=$1
    [ -n "$WAL_BASE_BACKUP_ENABLED" ] && [ "$WAL_BASE_BACKUP_ENABLED" != "0" ] && [ "$WAL_BASE_BACKUP_ENABLED" != "false" ] || return 1
    _wbd_stamp="${BACKUP_DIR}/wal-base/.last_base_backup"
    if [ ! -f "$_wbd_stamp" ]; then
        return 0
    fi
    _wbd_last=$(wal_file_epoch "$_wbd_stamp")
    [ "$((_wbd_now - _wbd_last))" -ge "$WAL_BASE_INTERVAL_SECS" ] || return 1
    return 0
}

# wal_base_artifacts — newest-first list of the base backup tars, one per
# line, with the .pg_wal.tar.gz siblings excluded (a case filter, not an
# ls|grep pipe: the static-lint gate runs shellcheck -S warning over this
# file, and the loop keeps the gate clean while the glob stays simple).
wal_base_artifacts() {
    ls -1t "${BACKUP_DIR}"/wal-base/apexmail-wal-base-*.tar.gz 2>/dev/null \
        | while IFS= read -r _wba; do
            case $_wba in
                *.pg_wal.tar.gz) ;;
                *) printf '%s\n' "$_wba" ;;
            esac
        done
}

# plan_wal_base_retention — prints the base artifacts beyond the newest
# WAL_BASE_KEEP_GENERATIONS generations (the .pg_wal.tar.gz sibling of each
# printed base is implied). Prints, removes nothing: cleanup_wal_base owns
# removal, mirroring plan_retention/cleanup_old_backups.
plan_wal_base_retention() {
    wal_base_artifacts | tail -n +"$((WAL_BASE_KEEP_GENERATIONS + 1))" 2>/dev/null || true
}

cleanup_wal_base() {
    plan_wal_base_retention | while IFS= read -r _cwb_old; do
        [ -n "$_cwb_old" ] || continue
        rm -f "$_cwb_old" "${_cwb_old%.tar.gz}.pg_wal.tar.gz"
        log "wal-base retention: removed $(basename "$_cwb_old") (+ pg_wal sibling), keeping ${WAL_BASE_KEEP_GENERATIONS} generations"
    done
}

# run_wal_base_backup <now-epoch> — one weekly attempt. Returns non-zero on
# any failure WITHOUT touching the nightly logical path.
run_wal_base_backup() {
    _wb_now=$1
    _wb_ts="$(date -u +%Y%m%d-%H%M%S)"
    _wb_dir="${BACKUP_DIR}/wal-base"
    _wb_spool="$(mktemp -d "${TMPDIR:-/tmp}/apexmail-wal-base-${_wb_ts}.XXXXXX")"

    if [ -f "$POSTGRES_PASSWORD_FILE" ]; then
        PGPASSWORD="$(tr -d '\r\n' < "$POSTGRES_PASSWORD_FILE")"
        export PGPASSWORD
    fi

    log "wal-base: starting PHYSICAL base backup of ${POSTGRES_DB}@${POSTGRES_HOST} (pg_basebackup -F tar -z)"
    if ! command -v pg_basebackup >/dev/null 2>&1; then
        err "pg_basebackup not available — physical base backup skipped (the postgres-backup image bakes it in; this container is misbuilt)"
        rm -rf "$_wb_spool"
        return 1
    fi
    # -F tar -z: base.tar.gz + pg_wal.tar.gz in the -D directory. -X stream
    # carries the WAL needed for a consistent restore inside the artifacts
    # (no second connection to pg_wal required at unpack time).
    if pg_basebackup -h "$POSTGRES_HOST" -U "$POSTGRES_USER" \
            -D "$_wb_spool" -F tar -z -X stream -c fast \
            --label="apexmail-wal-base-${_wb_ts}" \
            2>/tmp/apexmail-wal-base.err; then
        :
    else
        rc=$?
        err "pg_basebackup failed (exit ${rc}); stderr follows:"
        sed 's/^/  /' /tmp/apexmail-wal-base.err >&2 || true
        rm -rf "$_wb_spool" /tmp/apexmail-wal-base.err
        unset PGPASSWORD || true
        return 1
    fi
    rm -f /tmp/apexmail-wal-base.err
    unset PGPASSWORD || true

    if [ ! -s "$_wb_spool/base.tar.gz" ]; then
        err "pg_basebackup produced no base.tar.gz — physical base backup aborted"
        rm -rf "$_wb_spool"
        return 1
    fi

    mkdir -p "$_wb_dir"
    chmod 700 "$_wb_dir" 2>/dev/null || true
    mv "$_wb_spool/base.tar.gz" "${_wb_dir}/apexmail-wal-base-${_wb_ts}.tar.gz"
    if [ -f "$_wb_spool/pg_wal.tar.gz" ]; then
        mv "$_wb_spool/pg_wal.tar.gz" "${_wb_dir}/apexmail-wal-base-${_wb_ts}.pg_wal.tar.gz"
    fi
    rmdir "$_wb_spool" 2>/dev/null || rm -rf "$_wb_spool"
    log "wal-base: physical base backup complete: $(du -h "${_wb_dir}/apexmail-wal-base-${_wb_ts}.tar.gz" 2>/dev/null | cut -f1) apexmail-wal-base-${_wb_ts}.tar.gz"

    # Offsite mirror — mandatory like the nightly dumps. The cadence stamp
    # is only written after this succeeds, so a failed mirror retries.
    if [ -z "$BACKUP_TARGET" ]; then
        err "BACKUP_TARGET is not set — wal-base artifact apexmail-wal-base-${_wb_ts}.tar.gz exists only on this host; NOT stamped (will retry)"
        return 1
    fi
    if rsync -a "$_wb_dir/" "$BACKUP_TARGET/wal-base/"; then
        log "wal-base: offsite mirror OK -> ${BACKUP_TARGET}/wal-base/"
    else
        rc=$?
        err "wal-base offsite rsync to ${BACKUP_TARGET}/wal-base/ failed (exit ${rc}) — apexmail-wal-base-${_wb_ts}.tar.gz is LOCAL-ONLY; NOT stamped (will retry)"
        return 1
    fi

    # Full success: stamp the cadence (mtime is what wal_base_due reads)
    # and bound the local generations.
    : > "${_wb_dir}/.last_base_backup"
    cleanup_wal_base
    return 0
}

# maybe_wal_base_backup — the scheduler entry point: gate + cadence, then one
# weekly attempt. Never fatal for the caller (the nightly dumps continue).
maybe_wal_base_backup() {
    if ! wal_base_due "$(date -u +%s)"; then
        return 0
    fi
    if ! run_wal_base_backup "$(date -u +%s)"; then
        err "weekly physical base backup FAILED — nightly dumps continue unaffected; PITR anchor is stale until this succeeds"
        return 1
    fi
    return 0
}

# ── Physical-base-backup self-test (--self-test-wal-base) ────────────────────
# Proves the gate (OFF by default), the cadence decision against a pinned
# clock, the artifact naming/pairing + offsite mirror + retention using a
# STUB pg_basebackup on PATH (real pg_basebackup runs only against a live
# server — production or a drill; stated honestly in the output), and that
# the nightly logical retention planner is untouched by all of it.
wal_base_self_test() {
    _st_fail=0
    _st_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-wal-base-test.XXXXXX") || return 1
    _sv_dir=$BACKUP_DIR _sv_target=$BACKUP_TARGET _sv_gate=$WAL_BASE_BACKUP_ENABLED
    _sv_path=$PATH _sv_keep=$WAL_BASE_KEEP_GENERATIONS _sv_int=$WAL_BASE_INTERVAL_SECS

    # 1. Default OFF: gate closed, run is a no-op even without any stamp.
    BACKUP_DIR=$_st_tmp BACKUP_TARGET=$_st_tmp/offsite WAL_BASE_BACKUP_ENABLED=
    if wal_base_due 1000000000; then
        echo "[wal-base] self-test FAILED: gate must be CLOSED by default" >&2
        _st_fail=1
    fi

    # 2. Enabled + no stamp: due. A stub pg_basebackup "takes" the backup;
    #    artifacts must appear (named + pg_wal sibling), the offsite mirror
    #    must receive them, and the cadence stamp must be written.
    WAL_BASE_BACKUP_ENABLED=1
    mkdir -p "$_st_tmp/offsite" "$_st_tmp/bin"
    { printf '#!/bin/sh\n'
      printf 'dir=""\n'
      printf 'while [ $# -gt 0 ]; do case $1 in -D) dir=$2; shift 2;; *) shift;; esac; done\n'
      printf 'printf fake-base > "$dir/base.tar.gz"\n'
      printf 'printf fake-wal > "$dir/pg_wal.tar.gz"\n' ; } > "$_st_tmp/bin/pg_basebackup"
    chmod +x "$_st_tmp/bin/pg_basebackup"
    PATH="$_st_tmp/bin:$PATH"
    export PATH
    if ! wal_base_due 1000000000; then
        echo "[wal-base] self-test FAILED: enabled + no stamp must be DUE" >&2
        _st_fail=1
    fi
    if ! run_wal_base_backup 1000000000; then
        echo "[wal-base] self-test FAILED: run_wal_base_backup with a stub pg_basebackup errored" >&2
        _st_fail=1
    else
        _st_base=$(wal_base_artifacts | head -n 1)
        [ -n "$_st_base" ] || { echo "[wal-base] self-test FAILED: no base artifact produced" >&2; _st_fail=1; }
        [ -f "${_st_base%.tar.gz}.pg_wal.tar.gz" ] || { echo "[wal-base] self-test FAILED: pg_wal sibling missing" >&2; _st_fail=1; }
        _st_base_name=${_st_base##*/}
        [ -f "$_st_tmp/offsite/wal-base/$_st_base_name" ] || { echo "[wal-base] self-test FAILED: base artifact not mirrored offsite" >&2; _st_fail=1; }
        [ -f "$_st_tmp/wal-base/.last_base_backup" ] || { echo "[wal-base] self-test FAILED: cadence stamp not written on success" >&2; _st_fail=1; }
    fi

    # 3. Fresh stamp: NOT due (cadence honored) — the stamp written by the
    #    successful run in step 2 carries a current mtime, and the decision
    #    clock is the same real clock.
    if wal_base_due "$(date -u +%s)"; then
        echo "[wal-base] self-test FAILED: fresh stamp must not be due" >&2
        _st_fail=1
    fi
    #    ... but due again once the interval has elapsed: pin the stamp to a
    #    week-old mtime and keep the default 7d interval.
    WAL_BASE_INTERVAL_SECS=$_sv_int
    touch -t 202601010000 "$_st_tmp/wal-base/.last_base_backup" 2>/dev/null || true
    if ! wal_base_due "$(date -u +%s)"; then
        echo "[wal-base] self-test FAILED: week-old stamp (past interval) must be due" >&2
        _st_fail=1
    fi

    # 4. Retention keeps the newest WAL_BASE_KEEP_GENERATIONS and removes
    #    each dropped generation's pg_wal sibling with it. Three fabricated
    #    generations (+ the real one from step 2) with PINNED mtimes make
    #    the newest-first ordering deterministic.
    WAL_BASE_KEEP_GENERATIONS=2
    for _st_gen in 20261001-000000 20260915-000000 20260801-000000; do
        : > "$_st_tmp/wal-base/apexmail-wal-base-${_st_gen}.tar.gz"
        : > "$_st_tmp/wal-base/apexmail-wal-base-${_st_gen}.pg_wal.tar.gz"
        touch -t "${_st_gen%-*}0000" "$_st_tmp/wal-base/apexmail-wal-base-${_st_gen}.tar.gz" \
            "$_st_tmp/wal-base/apexmail-wal-base-${_st_gen}.pg_wal.tar.gz" 2>/dev/null || true
    done
    cleanup_wal_base
    _st_left=$(wal_base_artifacts | wc -l | tr -d ' ')
    [ "$_st_left" -eq 2 ] || { echo "[wal-base] self-test FAILED: retention left $_st_left base generations, expected 2" >&2; _st_fail=1; }
    [ -f "$_st_tmp/wal-base/apexmail-wal-base-20261001-000000.tar.gz" ] || { echo "[wal-base] self-test FAILED: retention dropped a generation it must keep" >&2; _st_fail=1; }
    [ ! -f "$_st_tmp/wal-base/apexmail-wal-base-20260915-000000.tar.gz" ] || { echo "[wal-base] self-test FAILED: retention kept an over-age generation" >&2; _st_fail=1; }
    [ ! -f "$_st_tmp/wal-base/apexmail-wal-base-20260801-000000.tar.gz" ] || { echo "[wal-base] self-test FAILED: retention kept an over-age generation" >&2; _st_fail=1; }
    [ ! -f "$_st_tmp/wal-base/apexmail-wal-base-20260915-000000.pg_wal.tar.gz" ] || { echo "[wal-base] self-test FAILED: retention left the pg_wal sibling behind" >&2; _st_fail=1; }
    [ ! -f "$_st_tmp/wal-base/apexmail-wal-base-20260801-000000.pg_wal.tar.gz" ] || { echo "[wal-base] self-test FAILED: retention left the pg_wal sibling behind" >&2; _st_fail=1; }

    # 5. Failed mirror does NOT stamp (retries next pass): stub backup
    #    against a broken target must keep the stamp untouched.
    WAL_BASE_BACKUP_ENABLED=1
    rm -f "$_st_tmp/wal-base/.last_base_backup"
    BACKUP_TARGET=$_st_tmp/missing-parent/deeper
    if run_wal_base_backup 1000000000; then
        echo "[wal-base] self-test FAILED: broken offsite target must fail the run" >&2
        _st_fail=1
    fi
    [ ! -f "$_st_tmp/wal-base/.last_base_backup" ] || { echo "[wal-base] self-test FAILED: failed mirror must not write the cadence stamp" >&2; _st_fail=1; }

    BACKUP_DIR=$_sv_dir BACKUP_TARGET=$_sv_target WAL_BASE_BACKUP_ENABLED=$_sv_gate
    WAL_BASE_KEEP_GENERATIONS=$_sv_keep WAL_BASE_INTERVAL_SECS=$_sv_int
    PATH=$_sv_path
    rm -rf "$_st_tmp"
    if [ "$_st_fail" -ne 0 ]; then
        echo "[wal-base] self-test FAILED" >&2
        return 1
    fi
    echo "[wal-base] self-test OK: default-off gate, pinned-clock cadence, artifact naming + pg_wal pairing, offsite mirror, no-stamp-on-failure, ${WAL_BASE_KEEP_GENERATIONS}-generation retention (STUB pg_basebackup — the real binary is exercised only against a live server in production/drills)"
    return 0
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

# ── Grandfather-father-son retention ─────────────────────────────────────────
# Backups are named apexmail-backup-YYYYMMDD-HHMMSS.sql.gz.enc (UTC). The
# planner keeps:
#   * every backup inside the BACKUP_KEEP_DAYS day window,
#   * the newest backup of each of the BACKUP_KEEP_WEEKS most recent weeks,
#   * the newest backup of each of the BACKUP_KEEP_MONTHS most recent months.
# It PRINTS the files to delete (one per line) and removes nothing itself;
# cleanup_old_backups owns removal. The clock is an argument so the self-test
# can pin it. Buckets are the newest-first distinct weeks/months, which is
# calendar-agnostic and exactly the grandfather-father-son shape.

backup_ymd() {
    _by_base=${1##*/}
    _by_stem=${_by_base#apexmail-backup-}
    _by_ymd=${_by_stem%%-*}
    case "$_by_ymd" in
        [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) printf '%s\n' "$_by_ymd" ;;
        *) printf '' ;;
    esac
}

# backup_date_field <YYYYMMDD> <strftime-format>
# GNU/busybox `date -d` first, then BSD `date -j` (developer Macs).
backup_date_field() {
    _bd_ymd=$1
    _bd_fmt=$2
    _bd_iso=$(printf '%s' "$_bd_ymd" \
        | sed 's/^\([0-9][0-9][0-9][0-9]\)\([0-9][0-9]\)\([0-9][0-9]\)$/\1-\2-\3/')
    _bd_out=''
    _bd_out=$(date -u -d "$_bd_iso" "+$_bd_fmt" 2>/dev/null) || _bd_out=''
    if [ -z "$_bd_out" ]; then
        _bd_out=$(date -j -f "%Y-%m-%d" "$_bd_iso" "+$_bd_fmt" 2>/dev/null) || _bd_out=''
    fi
    printf '%s\n' "$_bd_out"
}

backup_epoch() {
    _be_ymd=$(backup_ymd "$1")
    if [ -n "$_be_ymd" ]; then
        _be_epoch=$(backup_date_field "$_be_ymd" "%s")
        if [ -n "$_be_epoch" ]; then
            printf '%s\n' "$_be_epoch"
            return 0
        fi
    fi
    # Filesystem mtime fallback: GNU stat, then BSD stat.
    stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || printf '0\n'
}

backup_month() {
    _bm_ymd=$(backup_ymd "$1")
    _bm_month=''
    if [ -n "$_bm_ymd" ]; then
        _bm_month=$(backup_date_field "$_bm_ymd" "%Y-%m")
    fi
    case "$_bm_month" in
        ''|*%*)
            _bm_month=$(printf '%s' "$_bm_ymd" \
                | sed 's/^\([0-9][0-9][0-9][0-9][0-9][0-9]\).*/\1/')
            ;;
    esac
    printf '%s\n' "$_bm_month"
}

backup_week() {
    _bw_ymd=$(backup_ymd "$1")
    _bw_week=''
    if [ -n "$_bw_ymd" ]; then
        _bw_week=$(backup_date_field "$_bw_ymd" "%G-W%V")
    fi
    case "$_bw_week" in
        ''|*%*)
            # strftime lacks %G/%V here — degrade the weekly tier to months
            # rather than silently keeping nothing (or everything).
            _bw_week=$(backup_month "$1")
            ;;
    esac
    printf '%s\n' "$_bw_week"
}

plan_retention() {
    _pr_now=$1
    _pr_files=$(ls -1 "$BACKUP_DIR"/apexmail-backup-*.sql.gz.enc 2>/dev/null \
        | sort -r || true)
    [ -n "$_pr_files" ] || return 0
    _pr_day_cutoff=$((_pr_now - BACKUP_KEEP_DAYS * 86400))
    _pr_seen_weeks='
'
    _pr_seen_months='
'
    _pr_week_rank=0
    _pr_month_rank=0
    while IFS= read -r _pr_file; do
        [ -n "$_pr_file" ] || continue
        _pr_keep=0
        # Daily window: every backup inside it survives.
        _pr_epoch=$(backup_epoch "$_pr_file")
        if [ "$_pr_epoch" -ge "$_pr_day_cutoff" ] 2>/dev/null; then
            _pr_keep=1
        fi
        # Weekly bucket: the FIRST (newest) file of a week is its survivor.
        _pr_week=$(backup_week "$_pr_file")
        case "$_pr_seen_weeks" in
            *"
$_pr_week
"*) : ;;
            *)
                _pr_seen_weeks="${_pr_seen_weeks}${_pr_week}
"
                _pr_week_rank=$((_pr_week_rank + 1))
                if [ "$_pr_week_rank" -le "$BACKUP_KEEP_WEEKS" ]; then
                    _pr_keep=1
                fi
                ;;
        esac
        # Monthly bucket: same shape, independent of the weekly tier.
        _pr_month=$(backup_month "$_pr_file")
        case "$_pr_seen_months" in
            *"
$_pr_month
"*) : ;;
            *)
                _pr_seen_months="${_pr_seen_months}${_pr_month}
"
                _pr_month_rank=$((_pr_month_rank + 1))
                if [ "$_pr_month_rank" -le "$BACKUP_KEEP_MONTHS" ]; then
                    _pr_keep=1
                fi
                ;;
        esac
        if [ "$_pr_keep" -eq 0 ]; then
            printf '%s\n' "$_pr_file"
        fi
    done <<EOF
$_pr_files
EOF
}

cleanup_old_backups() {
    log "retention: daily ${BACKUP_KEEP_DAYS}d, weekly ${BACKUP_KEEP_WEEKS}w, monthly ${BACKUP_KEEP_MONTHS}m, count cap ${BACKUP_KEEP_COUNT}"
    plan_retention "$(date -u +%s)" | while IFS= read -r old; do
        [ -n "$old" ] || continue
        rm -f "$old"
        log "retention: removed $(basename "$old")"
    done
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

    if ! offsite_copy; then
        err "backup ${timestamp} is encrypted and verified LOCALLY but NOT mirrored offsite — healthcheck turns unhealthy within one interval"
        return 1
    fi
    return 0
}

# ── Dry run (--dry-run|-n) ────────────────────────────────────────────────────
# Proves the postgres target is reachable and summarizes the plan, writing
# NOTHING: no dump, no ciphertext, no retention cleanup. An unreachable
# target fails LOUDLY (exit 1, pg_dump/psql stderr printed) — the U-1/U-9
# class this script must never hide behind a silent empty backup.
dry_run_check() {
    timestamp="$(date -u +%Y%m%d-%H%M%S)"
    log "DRY RUN: postgres backup of ${POSTGRES_DB}@${POSTGRES_HOST} would write ${BACKUP_DIR}/apexmail-backup-${timestamp}.sql.gz.enc"
    if [ -f "$POSTGRES_PASSWORD_FILE" ]; then
        PGPASSWORD="$(tr -d '\r\n' < "$POSTGRES_PASSWORD_FILE")"
        export PGPASSWORD
    fi
    # Small temp target (removed below): `-f /dev/null` cannot be fsynced by
    # pg_dump on every platform ("could not fsync file /dev/null"), and the
    # point of the dry run is that nothing remains afterwards.
    tmpcheck="$(mktemp "${TMPDIR:-/tmp}/apexmail-backup-dryrun.XXXXXX")"
    # NB: capture the status inside the else branch — after an `if` with a
    # false condition and no else, `$?` is the if-statement's own 0.
    if pg_dump -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
            -Fc --no-owner --no-acl --schema-only -f "$tmpcheck" 2>/tmp/apexmail-backup-pgdump.err; then
        rm -f "$tmpcheck" /tmp/apexmail-backup-pgdump.err
        unset PGPASSWORD || true
        if [ -n "$ENCRYPTION_KEY" ]; then
            log "DRY RUN: encryption key present; ciphertext would be AES-256-CBC/PBKDF2 with verified restore listing"
        else
            warn "DRY RUN: no BACKUP_ENCRYPTION_KEY(_FILE) — a real run would store UNENCRYPTED backups"
        fi
        log "Dry run complete: ${POSTGRES_DB}@${POSTGRES_HOST} reachable; nothing was written."
        exit 0
    else
        rc=$?
    fi
    err "DRY RUN failed: pg_dump could not read ${POSTGRES_DB}@${POSTGRES_HOST} (exit ${rc}); stderr follows:"
    sed 's/^/  /' /tmp/apexmail-backup-pgdump.err >&2 || true
    rm -f "$tmpcheck" /tmp/apexmail-backup-pgdump.err
    unset PGPASSWORD || true
    exit 1
}

# ── Retention self-test (--self-test-retention) ──────────────────────────────
# Proves the grandfather-father-son planner against a pinned clock and a
# synthetic backup set; needs no database and touches only a temp dir. The
# validate stage runs it on every change to this script.
retention_self_test() {
    _st_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-retention-test.XXXXXX")
    _st_saved_dir=$BACKUP_DIR
    BACKUP_DIR=$_st_tmp
    BACKUP_KEEP_DAYS=2
    BACKUP_KEEP_WEEKS=2
    BACKUP_KEEP_MONTHS=2
    for _st_ts in 20261016-010000 20261015-010000 20261014-010000 \
                  20261008-010000 20261001-010000 20260915-010000 \
                  20260801-010000; do
        : > "$_st_tmp/apexmail-backup-${_st_ts}.sql.gz.enc"
    done
    _st_now=$(backup_date_field 20261017 "%s")
    if [ -z "$_st_now" ]; then
        warn "retention self-test SKIPPED: this date(1) cannot convert YYYYMMDD"
        BACKUP_DIR=$_st_saved_dir
        rm -rf "$_st_tmp"
        return 0
    fi
    _st_deleted=$(plan_retention "$_st_now" \
        | sed 's#.*/apexmail-backup-##; s#\.sql\.gz\.enc$##' | sort)
    _st_expected=$(printf '%s\n' \
        20261014-010000 20261001-010000 20260801-010000 | sort)
    BACKUP_DIR=$_st_saved_dir
    rm -rf "$_st_tmp"
    if [ "$_st_deleted" != "$_st_expected" ]; then
        err "retention self-test FAILED"
        err "  expected to delete: $(printf '%s' "$_st_expected" | tr '\n' ' ')"
        err "  actually deleted:   $(printf '%s' "$_st_deleted" | tr '\n' ' ')"
        return 1
    fi
    log "retention self-test: OK (daily/window survivors and weekly/monthly representatives)"
}

# ── Main loop ─────────────────────────────────────────────────────────────────
if [ "${1:-}" = "--self-test-retention" ]; then
    retention_self_test
    exit $?
fi
if [ "${1:-}" = "--self-test-wal-base" ]; then
    wal_base_self_test
    exit $?
fi
if [ "${1:-}" = "--dry-run" ] || [ "${1:-}" = "-n" ]; then
    dry_run_check
fi

log "starting backup scheduler (schedule: ${SCHEDULE}, keep: ${BACKUP_KEEP_DAYS}d / ${BACKUP_KEEP_WEEKS}w / ${BACKUP_KEEP_MONTHS}m / ${BACKUP_KEEP_COUNT} backups)"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

perform_backup
cleanup_old_backups
# Weekly physical base backup (PITR anchor): OFF until WAL_BASE_BACKUP_ENABLED
# is set; a failure is loud but NEVER blocks or degrades the nightly dumps.
maybe_wal_base_backup || err "continuing with the nightly logical schedule (wal-base retry on the next pass)"

while true; do
    sleep 86400
    perform_backup
    cleanup_old_backups
    maybe_wal_base_backup || err "continuing with the nightly logical schedule (wal-base retry on the next pass)"
done
