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
# is stored UNENCRYPTED with a loud warning (not recommended).
#
# Wired into the postgres-backup service in docker-compose.prod.yml.
# =============================================================================

set -eu

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

# Daily backup schedule (informational; the loop below sleeps 24h).
SCHEDULE="${SCHEDULE:-@daily}"

OPENSSL_ITER=600000

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
if [ "${1:-}" = "--dry-run" ] || [ "${1:-}" = "-n" ]; then
    dry_run_check
fi

log "starting backup scheduler (schedule: ${SCHEDULE}, keep: ${BACKUP_KEEP_DAYS}d / ${BACKUP_KEEP_WEEKS}w / ${BACKUP_KEEP_MONTHS}m / ${BACKUP_KEEP_COUNT} backups)"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

perform_backup
cleanup_old_backups

while true; do
    sleep 86400
    perform_backup
    cleanup_old_backups
done
