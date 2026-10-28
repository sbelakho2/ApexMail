#!/bin/sh
# =============================================================================
# pg-pitr-restore.sh — point-in-time recovery against a physical base backup.
# =============================================================================
# Repo-side PITR enablement (external audit 2026-10-26, infrastructure
# blocker #1). Companions:
#   * deploy/docker-compose.wal-archive.yml — turns WAL archiving on
#     (archive_command = pg-wal-archive.sh, offsite WAL_ARCHIVE_TARGET)
#   * pg-wal-archive.sh — the archive_command helper
#   * postgres-backup-encrypt.sh --WAL_BASE_BACKUP_ENABLED — weekly physical
#     base backups in ${BACKUP_DIR}/wal-base/ (apexmail-wal-base-<ts>.tar.gz.enc)
#
# ENCRYPTION (external audit 2026-10-28 P0): archived WAL segments and base
# backups are envelope ciphertext (backup-envelope.sh — the same codec as the
# nightly dumps). This script decrypts them:
#   * --base accepts the .tar.gz.enc artifact (decrypted to a private spool
#     before extraction); plain .tar/.tar.gz legacy artifacts still work,
#   * restore_command is THIS script in --restore-command mode, which
#     decrypts <archive>/<file>.gz.enc (or a legacy plain segment) into the
#     path postgres asks for.
# The key comes from WAL_ENCRYPTION_KEY_FILE / WAL_ENCRYPTION_KEY, falling
# back to the backup-envelope key material.
#
# What this does:
#   1. rsync-PULLs the archived WAL segments from WAL_ARCHIVE_TARGET into a
#      local archive dir (same key/known_hosts env pattern as the archive
#      push; a plain local directory works too and is what --self-test uses),
#   2. builds a SCRATCH postgres data dir from the physical base backup
#      (extract base.tar[.gz]; extract the paired pg_wal.tar[.gz] into
#      pg_wal/; prepend a local-trust line to the scratch pg_hba.conf; write
#      restore_command + recovery_target_* into postgresql.auto.conf; touch
#      recovery.signal). No initdb: a physical base backup IS a cloned data
#      directory — initdb would produce an incompatible empty cluster,
#   3. starts postgres on a private unix socket + high port and waits until
#      the target is reached (recovery exits recovery = promoted, or pauses
#      for --target-action pause),
#   4. writes a JSON evidence record with the SAME shape the monthly restore
#      drill writes (recorded_at/status/backup/backup_at/recovery_started_at/
#      recovered_at/rpo_seconds/rto_seconds/integrity) into WAL_EVIDENCE_DIR,
#   5. stops postgres and removes the scratch dir (PITR_KEEP_SCRATCH=1 keeps
#      it for inspection).
#
# This script is for the OPERATOR and the quarterly PITR drill — it is NOT
# the monthly logical restore drill (postgres-restore-drill.sh), which keeps
# running unchanged against the encrypted nightly dumps.
#
# Run as the postgres OS user (postgres refuses root): inside the postgres
# container (`docker compose exec postgres ...` with the wal-archive override,
# or any host with a postgres client/server installed).
#
# --self-test proves the PLUMBING without a database: argument validation,
# RFC3339 normalization, the WAL fetch against a local archive dir, recovery
# config generation (restore_command / target / hba / recovery.signal), and
# the evidence record + RPO/RTO math. The live replay path (a real postgres
# consuming real WAL) is exercised only by the operator's quarterly drill —
# the self-test says so honestly.
# =============================================================================

set -eu

# The ONE encryption authority (shared with the producer and the drill).
_envelope_lib="$(dirname "$0")/backup-envelope.sh"
[ -f "$_envelope_lib" ] || _envelope_lib=/usr/local/lib/backup-envelope.sh
# shellcheck source=backup-envelope.sh
. "$_envelope_lib"

WAL_ARCHIVE_TARGET="${WAL_ARCHIVE_TARGET:-}"
WAL_SSH_KEY_FILE="${WAL_SSH_KEY_FILE:-}"
WAL_SSH_KNOWN_HOSTS_FILE="${WAL_SSH_KNOWN_HOSTS_FILE:-}"
WAL_RSYNC_TIMEOUT="${WAL_RSYNC_TIMEOUT:-120}"
WAL_EVIDENCE_DIR="${WAL_EVIDENCE_DIR:-/backups/pitr-evidence}"
PITR_PORT="${PITR_PORT:-55432}"
PITR_SCRATCH_ROOT="${PITR_SCRATCH_ROOT:-${TMPDIR:-/tmp}}"
PITR_KEEP_SCRATCH="${PITR_KEEP_SCRATCH:-0}"
PITR_POLL_SECS="${PITR_POLL_SECS:-5}"
PITR_REPLAY_TIMEOUT_SECS="${PITR_REPLAY_TIMEOUT_SECS:-3600}"

log() { printf '%s [pitr] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
err() { printf '%s [pitr] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

usage() {
    cat >&2 <<'EOF'
usage: pg-pitr-restore.sh --base <base.tar[.gz]> --target <RFC3339|latest> [--target-action promote|pause]

  --base           path to the physical base backup produced by
                   postgres-backup-encrypt.sh (WAL_BASE_BACKUP_ENABLED),
                   e.g. /backups/wal-base/apexmail-wal-base-20261025-010000.tar.gz.enc
                   (envelope ciphertext; plain .tar/.tar.gz legacy artifacts
                   are accepted too)
  --target         RFC3339 timestamp to recover to (e.g. 2026-10-25T08:30:00Z)
                   or the literal "latest" (replay all archived WAL)
  --target-action  what to do when the target is reached: "promote" (default)
                   or "pause" (leave the instance in read-only paused recovery)

Environment: WAL_ARCHIVE_TARGET (rsync pull source; local dir ok),
WAL_SSH_KEY_FILE / WAL_SSH_KNOWN_HOSTS_FILE, WAL_EVIDENCE_DIR, PITR_PORT,
PITR_KEEP_SCRATCH, PITR_REPLAY_TIMEOUT_SECS.
EOF
}

PITR_BASE=""
PITR_TARGET=""
PITR_TARGET_ACTION="promote"

parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            --base)
                [ $# -ge 2 ] || { err "--base needs a value"; usage; return 2; }
                PITR_BASE=$2; shift 2 ;;
            --target)
                [ $# -ge 2 ] || { err "--target needs a value"; usage; return 2; }
                PITR_TARGET=$2; shift 2 ;;
            --target-action)
                [ $# -ge 2 ] || { err "--target-action needs a value"; usage; return 2; }
                PITR_TARGET_ACTION=$2; shift 2 ;;
            --help|-h)
                usage; return 0 ;;
            *)
                err "unknown argument: $1"; usage; return 2 ;;
        esac
    done
    [ -n "$PITR_BASE" ] || { err "--base is required"; usage; return 2; }
    [ -n "$PITR_TARGET" ] || { err "--target is required (RFC3339 timestamp or 'latest')"; usage; return 2; }
    case $PITR_TARGET_ACTION in
        promote|pause) : ;;
        *) err "--target-action must be 'promote' or 'pause' (got $PITR_TARGET_ACTION)"; usage; return 2 ;;
    esac
    [ -f "$PITR_BASE" ] || { err "base backup not found: $PITR_BASE"; return 1; }
    return 0
}

# normalize_target_time <RFC3339> — postgres accepts ISO strings but the
# canonical form avoids parser surprises: T separator -> space, Z -> +00.
normalize_target_time() {
    printf '%s' "$1" | sed -e 's/T/ /' -e 's/Z$/+00/'
}

# resolve_pitr_key — same precedence as the archive helper: a dedicated WAL
# key first, then the backup-envelope key material. Returns 1 when nothing
# is available (decryption is impossible without it).
resolve_pitr_key() {
    if [ -n "${WAL_ENCRYPTION_KEY_FILE:-}" ] && [ -f "$WAL_ENCRYPTION_KEY_FILE" ]; then
        BACKUP_ENCRYPTION_KEY_FILE="$WAL_ENCRYPTION_KEY_FILE" backup_envelope_key
        return $?
    fi
    if [ -n "${WAL_ENCRYPTION_KEY:-}" ]; then
        BACKUP_ENCRYPTION_KEY="$WAL_ENCRYPTION_KEY" backup_envelope_key
        return $?
    fi
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

# restore_command_fetch <archive-dir> <filename> <dest-path> — the
# restore_command target. Prefers the encrypted form (<file>.gz.enc:
# decrypt then gunzip), accepts <file>.enc (decrypt only, already-compressed
# payloads) and a legacy plaintext <file>. Exit 0 only when <dest-path> was
# written with the real bytes; a failed decrypt leaves NOTHING at the dest
# (postgres treats a missing segment as "keep replaying/wait").
restore_command_fetch() {
    _rf_archive=$1
    _rf_name=$2
    _rf_dest=$3
    _rf_tmp="${_rf_dest}.pitr-tmp.$$"
    if [ -f "$_rf_archive/$_rf_name.gz.enc" ]; then
        if ! resolve_pitr_key; then
            err "restore_command: no WAL decryption key available ($_rf_name) — replay cannot proceed"
            return 1
        fi
        if ! backup_envelope_decrypt "$_rf_archive/$_rf_name.gz.enc" "${_rf_tmp}.gz" 2>/dev/null \
            || ! gzip -dc "${_rf_tmp}.gz" > "$_rf_tmp"; then
            rm -f "${_rf_tmp}.gz" "$_rf_tmp"
            err "restore_command: decrypt/gunzip of $_rf_name.gz.enc failed"
            return 1
        fi
        rm -f "${_rf_tmp}.gz"
        mv "$_rf_tmp" "$_rf_dest"
        return 0
    fi
    if [ -f "$_rf_archive/$_rf_name.enc" ]; then
        if ! resolve_pitr_key; then
            err "restore_command: no WAL decryption key available ($_rf_name) — replay cannot proceed"
            return 1
        fi
        if ! backup_envelope_decrypt "$_rf_archive/$_rf_name.enc" "$_rf_tmp" 2>/dev/null; then
            rm -f "$_rf_tmp"
            err "restore_command: decrypt of $_rf_name.enc failed"
            return 1
        fi
        mv "$_rf_tmp" "$_rf_dest"
        return 0
    fi
    if [ -f "$_rf_archive/$_rf_name" ]; then
        # Legacy plaintext segment (archives written before encryption).
        cp "$_rf_archive/$_rf_name" "$_rf_tmp" && mv "$_rf_tmp" "$_rf_dest"
        return $?
    fi
    return 1
}

# wal_pull_ssh_cmd — the SAME key/known_hosts pattern as the archive push.
wal_pull_ssh_cmd() {
    _ws="ssh -o BatchMode=yes -o ConnectTimeout=15"
    if [ -n "$WAL_SSH_KEY_FILE" ]; then
        _ws="$_ws -i $WAL_SSH_KEY_FILE"
    fi
    if [ -n "$WAL_SSH_KNOWN_HOSTS_FILE" ]; then
        _ws="$_ws -o UserKnownHostsFile=$WAL_SSH_KNOWN_HOSTS_FILE -o StrictHostKeyChecking=yes"
    fi
    printf '%s' "$_ws"
}

# fetch_wal_archive <dest-dir> — pull the archived WAL batch offsite -> local.
fetch_wal_archive() {
    _fw_dest=$1
    if [ -z "$WAL_ARCHIVE_TARGET" ]; then
        err "WAL_ARCHIVE_TARGET is not set — nowhere to pull archived WAL from (archiving is disabled or the env is incomplete)"
        return 1
    fi
    if ! command -v rsync >/dev/null 2>&1; then
        err "rsync unavailable — cannot pull the WAL archive"
        return 1
    fi
    mkdir -p "$_fw_dest"
    _fw_ssh=$(wal_pull_ssh_cmd)
    log "pulling WAL archive from ${WAL_ARCHIVE_TARGET} -> ${_fw_dest}"
    _fw_rc=0
    rsync -a --timeout="$WAL_RSYNC_TIMEOUT" -e "$_fw_ssh" \
        "$WAL_ARCHIVE_TARGET/" "$_fw_dest/" || _fw_rc=$?
    if [ "$_fw_rc" -ne 0 ]; then
        err "WAL archive pull from ${WAL_ARCHIVE_TARGET} failed (exit $_fw_rc)"
        return 1
    fi
    _fw_count=$(find "$_fw_dest" -type f ! -name '.*' 2>/dev/null | wc -l | tr -d ' ')
    log "WAL archive pulled: ${_fw_count} segment files"
    [ "$_fw_count" -gt 0 ] || {
        err "the WAL archive at ${WAL_ARCHIVE_TARGET} is EMPTY — archiving has never succeeded; PITR beyond the base backup is impossible"
        return 1
    }
    return 0
}

# prepare_scratch_datadir <datadir> <archive-dir> — base tar + recovery config.
prepare_scratch_datadir() {
    _pd_dir=$1
    _pd_archive=$2

    mkdir -p "$_pd_dir"
    chmod 700 "$_pd_dir"

    # Resolve the base artifact to a local PLAIN tar.gz/tar for extraction:
    # an .enc artifact is envelope ciphertext (external audit 2026-10-28 P0)
    # and is decrypted into the private scratch dir; plain legacy artifacts
    # pass through unchanged.
    _pd_base_plain=$PITR_BASE
    case $PITR_BASE in
        *.enc)
            if ! resolve_pitr_key; then
                err "base backup is encrypted but no WAL/backup decryption key is available (WAL_ENCRYPTION_KEY_FILE / BACKUP_ENCRYPTION_KEY_FILE)"
                return 1
            fi
            # Keep the artifact's own extension on the decrypted copy: the
            # extraction case below dispatches on it (.tar.gz vs .tar).
            _pd_base_plain="${_pd_dir}/$(basename "${PITR_BASE%.enc}")"
            if ! backup_envelope_decrypt "$PITR_BASE" "$_pd_base_plain" 2>/dev/null; then
                err "decryption of the base backup $(basename "$PITR_BASE") failed (wrong key?)"
                rm -f "$_pd_base_plain"
                return 1
            fi
            log "base backup decrypted to a private scratch copy (envelope ciphertext offsite)"
            ;;
    esac
    _pd_stem=$PITR_BASE
    case $_pd_stem in *.enc) _pd_stem=${_pd_stem%.enc} ;; esac
    case $_pd_base_plain in
        *.tar.gz|*.tgz) tar -xzf "$_pd_base_plain" -C "$_pd_dir" || return 1 ;;
        *.tar)          tar -xf  "$_pd_base_plain" -C "$_pd_dir" || return 1 ;;
        *) err "unsupported base backup format: $PITR_BASE (expected .tar[.gz][.enc] from pg_basebackup -F tar)"; return 1 ;;
    esac
    [ "$_pd_base_plain" = "$PITR_BASE" ] || rm -f "$_pd_base_plain"

    # The paired WAL tar (same timestamp stem) carries the backup-end WAL.
    _pd_waltar=""
    for _pd_cand in \
        "${PITR_BASE%.tar.gz.enc}.pg_wal.tar.gz.enc" \
        "${PITR_BASE%.tar.gz}.pg_wal.tar.gz" \
        "${PITR_BASE%.tar}.pg_wal.tar.gz"; do
        [ -f "$_pd_cand" ] && { _pd_waltar=$_pd_cand; break; }
    done
    if [ -n "$_pd_waltar" ]; then
        mkdir -p "$_pd_dir/pg_wal"
        _pd_wal_plain=$_pd_waltar
        case $_pd_waltar in
            *.enc)
                if ! resolve_pitr_key; then
                    err "paired WAL tar is encrypted but no decryption key is available"
                    return 1
                fi
                _pd_wal_plain="${_pd_dir}.pg_wal.$$"
                if ! backup_envelope_decrypt "$_pd_waltar" "$_pd_wal_plain" 2>/dev/null; then
                    err "decryption of $(basename "$_pd_waltar") failed (wrong key?)"
                    rm -f "$_pd_wal_plain"
                    return 1
                fi
                ;;
        esac
        tar -xzf "$_pd_wal_plain" -C "$_pd_dir/pg_wal" 2>/dev/null \
            || tar -xf "${_pd_wal_plain%.gz}" -C "$_pd_dir/pg_wal" \
            || { err "cannot extract the pg_wal tar $(basename "$_pd_waltar")"; return 1; }
        [ "$_pd_wal_plain" = "$_pd_waltar" ] || rm -f "$_pd_wal_plain"
        log "extracted backup-end WAL from $(basename "$_pd_waltar")"
    else
        log "no paired pg_wal tar next to the base backup — replay relies fully on restore_command"
    fi

    # Local-trust FIRST in the scratch pg_hba.conf so the drill can reach the
    # instance over its private socket without the production scram secret
    # (the file belongs to the throwaway copy only).
    if [ -f "$_pd_dir/pg_hba.conf" ]; then
        { printf 'local all all trust\nlocal replication all trust\n'; cat "$_pd_dir/pg_hba.conf"; } \
            > "$_pd_dir/pg_hba.conf.pitr" && mv "$_pd_dir/pg_hba.conf.pitr" "$_pd_dir/pg_hba.conf"
    fi

    # Recovery settings: restore_command copies any requested segment or
    # timeline/history file from the local archive; the target governs where
    # replay stops. recovery_target_action decides promote vs pause.
    {
        # restore_command is THIS script in --restore-command mode: it
        # decrypts the archived segment (envelope ciphertext) into the path
        # postgres asks for. %f = segment name, %p = destination.
        printf "restore_command = 'sh %s --restore-command %s %%f %%p'\n" "$0" "$_pd_archive"
        printf "recovery_target_timeline = 'latest'\n"
        if [ "$PITR_TARGET" != "latest" ]; then
            printf "recovery_target_time = '%s'\n" "$(normalize_target_time "$PITR_TARGET")"
        fi
        printf "recovery_target_action = '%s'\n" "$PITR_TARGET_ACTION"
    } >> "$_pd_dir/postgresql.auto.conf"
    : > "$_pd_dir/recovery.signal"
    log "scratch data dir ready: recovery.signal + restore_command from ${_pd_archive}, target=${PITR_TARGET}, action=${PITR_TARGET_ACTION}"
}

# base_epoch <base-path> — apexmail-wal-base-YYYYmmdd-HHMMSS.tar[.gz] -> epoch
# (the same shape the monthly drill parses); falls back to the file's mtime.
base_epoch() {
    _be_name=$(basename "$1")
    _be_ts=$(printf '%s' "$_be_name" | sed -n 's/^apexmail-wal-base-\([0-9]\{8\}-[0-9]\{6\}\)\..*/\1/p')
    if [ -n "$_be_ts" ]; then
        _be_norm=$(printf '%s' "$_be_ts" \
            | sed 's/^\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)-\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)$/\1-\2-\3 \4:\5:\6/')
        _be_out=$(date -j -f '%Y-%m-%d %H:%M:%S' "$_be_norm" '+%s' 2>/dev/null \
            || date -d "$_be_norm" '+%s' 2>/dev/null || echo "")
        if [ -n "$_be_out" ]; then
            printf '%s\n' "$_be_out"
            return 0
        fi
    fi
    stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || printf '0\n'
}

# write_pitr_evidence <path> <status> <base-name> <base-epoch> <start-epoch>
#                     <end-epoch> <integrity-json-single-line>
# The SAME JSON shape postgres-restore-drill.sh writes, with the integrity
# object carrying the PITR specifics.
write_pitr_evidence() {
    cat > "$1" <<EOF
{"recorded_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","status":"$2","backup":"$3","backup_at":$4,"recovery_started_at":$5,"recovered_at":$6,"rpo_seconds":$(( $5 - $4 )),"rto_seconds":$(( $6 - $5 )),"integrity":$7}
EOF
}

# run_pitr — the full orchestration (needs a postgres server binary).
run_pitr() {
    if ! command -v postgres >/dev/null 2>&1 || ! command -v psql >/dev/null 2>&1; then
        err "postgres/psql not on PATH — run inside the postgres container or on a host with postgres installed"
        return 1
    fi
    if [ "$(id -u)" = "0" ]; then
        err "refusing to run as root (postgres refuses root) — run as the postgres OS user (docker compose exec postgres ...)"
        return 1
    fi

    _rp_start=$(date +%s)
    _rp_work=$(mktemp -d "$PITR_SCRATCH_ROOT/apexmail-pitr.XXXXXX")
    _rp_datadir="$_rp_work/data"
    _rp_archive="$_rp_work/wal-archive"
    _rp_sock="$_rp_work/sock"
    mkdir -p "$_rp_sock"

    if ! fetch_wal_archive "$_rp_archive"; then
        rm -rf "$_rp_work"
        return 1
    fi
    if ! prepare_scratch_datadir "$_rp_datadir" "$_rp_archive"; then
        rm -rf "$_rp_work"
        return 1
    fi

    _rp_bepoch=$(base_epoch "$PITR_BASE")
    log "starting scratch postgres (port ${PITR_PORT}, unix socket ${_rp_sock}); replaying toward ${PITR_TARGET}"
    postgres -D "$_rp_datadir" -k "$_rp_sock" -p "$PITR_PORT" \
        -c listen_addresses='' \
        > "$_rp_work/postgres.log" 2>&1 &
    _rp_pid=$!

    _rp_end=""
    _rp_waited=0
    while :; do
        if ! kill -0 "$_rp_pid" 2>/dev/null; then
            err "scratch postgres exited early — last log lines:"
            tail -n 20 "$_rp_work/postgres.log" >&2 || true
            rm -rf "$_rp_work"
            return 1
        fi
        if psql -h "$_rp_sock" -p "$PITR_PORT" -U postgres -d postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
            _rp_inrec=$(psql -h "$_rp_sock" -p "$PITR_PORT" -U postgres -d postgres \
                -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null || echo "t")
            _rp_paused=$(psql -h "$_rp_sock" -p "$PITR_PORT" -U postgres -d postgres \
                -tAc 'SELECT pg_get_wal_replay_pause_state()' 2>/dev/null || echo "notpaused")
            if [ "$_rp_inrec" = "f" ]; then
                _rp_end="promoted"
                break
            fi
            if [ "$_rp_paused" = "paused" ]; then
                _rp_end="paused"
                break
            fi
        fi
        if [ "$_rp_waited" -ge "$PITR_REPLAY_TIMEOUT_SECS" ]; then
            err "replay did not reach the target within ${PITR_REPLAY_TIMEOUT_SECS}s — last log lines:"
            tail -n 20 "$_rp_work/postgres.log" >&2 || true
            kill "$_rp_pid" 2>/dev/null || true
            rm -rf "$_rp_work"
            return 1
        fi
        sleep "$PITR_POLL_SECS"
        _rp_waited=$((_rp_waited + PITR_POLL_SECS))
    done

    # Evidence from the recovered instance: how far replay actually went.
    # (Dollar-quoting keeps the SQL string literal inside the shell's
    # single quotes — "null" would parse as a column identifier.)
    _rp_replay_ts=$(psql -h "$_rp_sock" -p "$PITR_PORT" -U postgres -d postgres \
        -tAc 'SELECT COALESCE(pg_last_xact_replay_timestamp()::text, $$null$$)' 2>/dev/null || echo "null")
    [ "$_rp_replay_ts" = "null" ] || _rp_replay_ts="\"$_rp_replay_ts\""
    _rp_segcount=$(find "$_rp_archive" -type f ! -name '.*' 2>/dev/null | wc -l | tr -d ' ')

    pg_ctl -D "$_rp_datadir" -m fast stop >/dev/null 2>&1 || kill "$_rp_pid" 2>/dev/null || true
    wait "$_rp_pid" 2>/dev/null || true
    _rp_done=$(date +%s)

    mkdir -p "$WAL_EVIDENCE_DIR"
    _rp_evidence="$WAL_EVIDENCE_DIR/pitr-restore-$(date -u +%Y%m%d-%H%M%S).json"
    # rpo = recovery start - base backup time; rto = reached-target - start.
    write_pitr_evidence "$_rp_evidence" "recovered" "$(basename "$PITR_BASE")" \
        "$_rp_bepoch" "$_rp_start" "$_rp_done" \
        "{\"mode\":\"pitr\",\"target\":\"$PITR_TARGET\",\"target_action\":\"$PITR_TARGET_ACTION\",\"end_state\":\"$_rp_end\",\"replay_timestamp\":$_rp_replay_ts,\"wal_segments_fetched\":$_rp_segcount}"
    log "PITR OK: reached ${PITR_TARGET} ($_rp_end) — RPO=$(( _rp_start - _rp_bepoch ))s RTO=$(( _rp_done - _rp_start ))s evidence=$_rp_evidence"

    if [ "$PITR_KEEP_SCRATCH" = "1" ]; then
        log "PITR_KEEP_SCRATCH=1 — scratch dir kept: $_rp_work"
    else
        rm -rf "$_rp_work"
    fi
    return 0
}

# ── Self-test: plumbing without a database ────────────────────────────────────
pitr_self_test() {
    _st_fail=0
    _st_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-pitr-test.XXXXXX") || return 1

    # 1. Usage errors exit non-zero (recursive invocation; CLI contract).
    if sh "$0" >/dev/null 2>&1; then
        echo "[pitr] self-test FAILED: no-argument invocation must fail" >&2
        _st_fail=1
    fi
    if sh "$0" --base /nonexistent/base.tar.gz --target latest >/dev/null 2>&1; then
        echo "[pitr] self-test FAILED: missing base file must fail" >&2
        _st_fail=1
    fi
    if sh "$0" --base /nonexistent/base.tar.gz --target latest --target-action explode >/dev/null 2>&1; then
        echo "[pitr] self-test FAILED: invalid --target-action must fail" >&2
        _st_fail=1
    fi

    # 2. RFC3339 normalization for recovery_target_time.
    _st_norm=$(normalize_target_time "2026-10-25T08:30:00Z")
    [ "$_st_norm" = "2026-10-25 08:30:00+00" ] || {
        echo "[pitr] self-test FAILED: RFC3339 normalization produced '$_st_norm'" >&2
        _st_fail=1
    }

    # 3. WAL fetch against a LOCAL directory target (no ssh).
    mkdir -p "$_st_tmp/offsite-wal"
    printf 'x' > "$_st_tmp/offsite-wal/000000010000000000000001"
    printf 'x' > "$_st_tmp/offsite-wal/000000010000000000000002"
    _sv_target=$WAL_ARCHIVE_TARGET
    WAL_ARCHIVE_TARGET=$_st_tmp/offsite-wal
    if ! fetch_wal_archive "$_st_tmp/pulled"; then
        echo "[pitr] self-test FAILED: local-dir WAL fetch errored" >&2
        _st_fail=1
    fi
    [ -f "$_st_tmp/pulled/000000010000000000000002" ] || {
        echo "[pitr] self-test FAILED: fetched archive is missing segments" >&2
        _st_fail=1
    }
    WAL_ARCHIVE_TARGET=
    if fetch_wal_archive "$_st_tmp/pulled2"; then
        echo "[pitr] self-test FAILED: fetch with no WAL_ARCHIVE_TARGET must fail" >&2
        _st_fail=1
    fi
    WAL_ARCHIVE_TARGET=$_sv_target

    # 4. Recovery config generation: a minimal datadir gets restore_command,
    #    the normalized target, the action, recovery.signal, and the
    #    local-trust pg_hba line FIRST. The fixture is a REAL gzipped tar
    #    (a bare file would exercise the failure path, not the extraction).
    PITR_BASE="$_st_tmp/apexmail-wal-base-20261025-010000.tar.gz"
    PITR_TARGET="2026-10-25T08:30:00Z"
    PITR_TARGET_ACTION="promote"
    mkdir -p "$_st_tmp/fakesrc"
    printf 'PGDMP' > "$_st_tmp/fakesrc/PG_VERSION"
    tar -czf "$PITR_BASE" -C "$_st_tmp/fakesrc" PG_VERSION
    printf 'x' > "$_st_tmp/offsite-wal/000000010000000000000003"
    _st_datadir=$_st_tmp/data
    mkdir -p "$_st_datadir"
    : > "$_st_datadir/postgresql.auto.conf"
    printf 'host all all all scram-sha-256\n' > "$_st_datadir/pg_hba.conf"
    prepare_scratch_datadir "$_st_datadir" "$_st_tmp/offsite-wal"
    grep -q "^restore_command = 'sh $0 --restore-command $_st_tmp/offsite-wal %f %p'$" "$_st_datadir/postgresql.auto.conf" || {
        echo "[pitr] self-test FAILED: restore_command (decrypting mode) not generated correctly: $(grep '^restore_command' "$_st_datadir/postgresql.auto.conf")" >&2
        _st_fail=1
    }
    grep -q "^recovery_target_time = '2026-10-25 08:30:00+00'$" "$_st_datadir/postgresql.auto.conf" || {
        echo "[pitr] self-test FAILED: recovery_target_time missing/unnormalized" >&2
        _st_fail=1
    }
    grep -q "^recovery_target_action = 'promote'$" "$_st_datadir/postgresql.auto.conf" || {
        echo "[pitr] self-test FAILED: recovery_target_action not generated" >&2
        _st_fail=1
    }
    [ "$(head -n 1 "$_st_datadir/pg_hba.conf")" = "local all all trust" ] || {
        echo "[pitr] self-test FAILED: local-trust hba line is not first" >&2
        _st_fail=1
    }
    [ -f "$_st_datadir/recovery.signal" ] || {
        echo "[pitr] self-test FAILED: recovery.signal missing" >&2
        _st_fail=1
    }
    #    'latest' must NOT pin a time target (trailing-space anchor:
    #    "recovery_target_time" is a strict PREFIX of "recovery_target_timeline",
    #    so a bare pattern matches the timeline line and lies).
    PITR_TARGET="latest"
    : > "$_st_datadir/postgresql.auto.conf"
    prepare_scratch_datadir "$_st_datadir" "$_st_tmp/offsite-wal"
    if grep -q '^recovery_target_time ' "$_st_datadir/postgresql.auto.conf"; then
        echo "[pitr] self-test FAILED: --target latest must not set recovery_target_time" >&2
        _st_fail=1
    fi
    PITR_TARGET="2026-10-25T08:30:00Z"

    # 4b. restore_command_fetch decrypts envelope WAL: encrypt a synthetic
    #     segment with the test key, fetch it, bytes must match the source.
    #     The lib reads BACKUP_ENCRYPTION_KEY / _FILE; resolve_pitr_key layers
    #     WAL_ENCRYPTION_KEY over it in production, so pin the lib-level var.
    BACKUP_ENCRYPTION_KEY="pitr-self-test-key-0123456789abcdef"
    BACKUP_ENCRYPTION_KEY_FILE=/nonexistent
    printf 'synthetic-segment-%s\n' "$$" > "$_st_tmp/seg.plain"
    gzip -n -c "$_st_tmp/seg.plain" > "$_st_tmp/seg.gz"
    backup_envelope_key >/dev/null 2>&1 || true
    backup_envelope_encrypt "$_st_tmp/seg.gz" "$_st_tmp/offsite-wal/000000010000000000000009.gz.enc" || _st_fail=1
    if restore_command_fetch "$_st_tmp/offsite-wal" 000000010000000000000009 "$_st_tmp/fetched.seg" \
        && cmp -s "$_st_tmp/seg.plain" "$_st_tmp/fetched.seg"; then
        :
    else
        echo "[pitr] self-test FAILED: decrypting restore_command did not reproduce the segment" >&2
        _st_fail=1
    fi
    #    Legacy plaintext segments still fetch (archives written pre-encryption).
    printf 'legacy-segment' > "$_st_tmp/offsite-wal/000000010000000000000008"
    if restore_command_fetch "$_st_tmp/offsite-wal" 000000010000000000000008 "$_st_tmp/fetched.legacy" \
        && [ "$(cat "$_st_tmp/fetched.legacy")" = "legacy-segment" ]; then
        :
    else
        echo "[pitr] self-test FAILED: legacy plaintext segment fetch regressed" >&2
        _st_fail=1
    fi
    #    No key + encrypted segment → the fetch refuses (no partial dest).
    WAL_ENCRYPTION_KEY=
    BACKUP_ENCRYPTION_KEY=
    BACKUP_ENCRYPTION_KEY_FILE=/nonexistent
    if restore_command_fetch "$_st_tmp/offsite-wal" 000000010000000000000009 "$_st_tmp/fetched.nokey"; then
        echo "[pitr] self-test FAILED: keyless decrypt must fail" >&2
        _st_fail=1
    fi
    [ ! -f "$_st_tmp/fetched.nokey" ] || { echo "[pitr] self-test FAILED: keyless fetch left a destination file" >&2; _st_fail=1; }
    BACKUP_ENCRYPTION_KEY="pitr-self-test-key-0123456789abcdef"

    # 4c. ENCRYPTED base artifact extracts: encrypt the fixture tar.gz and
    #     run prepare_scratch_datadir against the .enc path.
    BACKUP_ENCRYPTION_KEY="pitr-self-test-key-0123456789abcdef"
    BACKUP_ENCRYPTION_KEY_FILE=/nonexistent
    mkdir -p "$_st_tmp/fakesrc2"
    printf 'PGDATA' > "$_st_tmp/fakesrc2/PG_VERSION"
    tar -czf "$_st_tmp/base.src.tar.gz" -C "$_st_tmp/fakesrc2" PG_VERSION
    backup_envelope_key >/dev/null 2>&1 || true
    backup_envelope_encrypt "$_st_tmp/base.src.tar.gz" "$_st_tmp/apexmail-wal-base-20261025-010000.tar.gz.enc" || _st_fail=1
    _sv_base=$PITR_BASE
    PITR_BASE="$_st_tmp/apexmail-wal-base-20261025-010000.tar.gz.enc"
    _st_datadir2=$_st_tmp/data2
    mkdir -p "$_st_datadir2"
    : > "$_st_datadir2/postgresql.auto.conf"
    printf 'host all all all scram-sha-256\n' > "$_st_datadir2/pg_hba.conf"
    if prepare_scratch_datadir "$_st_datadir2" "$_st_tmp/offsite-wal" \
        && [ -f "$_st_datadir2/PG_VERSION" ]; then
        :
    else
        echo "[pitr] self-test FAILED: encrypted base artifact did not extract" >&2
        _st_fail=1
    fi
    PITR_BASE=$_sv_base
    WAL_ENCRYPTION_KEY=
    BACKUP_ENCRYPTION_KEY=
    BACKUP_ENCRYPTION_KEY_FILE=/nonexistent

    # 5. Evidence record: drill-identical schema + RPO/RTO math.
    _st_be=$(base_epoch "$PITR_BASE")
    [ -n "$_st_be" ] && [ "$_st_be" != "0" ] || {
        echo "[pitr] self-test FAILED: base epoch parse failed" >&2
        _st_fail=1
    }
    write_pitr_evidence "$_st_tmp/evidence.json" "recovered" \
        "apexmail-wal-base-20261025-010000.tar.gz" "$_st_be" "$((_st_be + 100))" "$((_st_be + 130))" \
        '{"mode":"pitr","target":"2026-10-25T08:30:00Z","target_action":"promote","end_state":"promoted","wal_segments_fetched":3}'
    grep -q '"status":"recovered"' "$_st_tmp/evidence.json" || { echo "[pitr] self-test FAILED: evidence status missing" >&2; _st_fail=1; }
    grep -q '"rpo_seconds":100' "$_st_tmp/evidence.json" || { echo "[pitr] self-test FAILED: rpo math wrong" >&2; _st_fail=1; }
    grep -q '"rto_seconds":30' "$_st_tmp/evidence.json" || { echo "[pitr] self-test FAILED: rto math wrong" >&2; _st_fail=1; }
    grep -q '"mode":"pitr"' "$_st_tmp/evidence.json" || { echo "[pitr] self-test FAILED: pitr mode missing from integrity" >&2; _st_fail=1; }

    rm -rf "$_st_tmp"
    if [ "$_st_fail" -ne 0 ]; then
        echo "[pitr] self-test FAILED" >&2
        return 1
    fi
    echo "[pitr] self-test OK: arg validation, RFC3339 normalization, local-dir WAL fetch, ENCRYPTED restore_command round trip (decrypt+gunzip, legacy plaintext fallback, keyless refusal), ENCRYPTED base artifact extraction, recovery config generation (decrypting restore_command/target/hba/recovery.signal), evidence schema + RPO/RTO math. NOTE: no live postgres replay is exercised here — the real base+Wal replay path is proven only by the operator's quarterly PITR drill (see docs/operations/disaster-recovery.md)"
    return 0
}

if [ "${1:-}" = "--self-test" ]; then
    pitr_self_test
    exit $?
fi

# restore_command dispatch (see prepare_scratch_datadir): postgres invokes
# `sh <this script> --restore-command <archive-dir> %f %p` for every segment.
if [ "${1:-}" = "--restore-command" ]; then
    if [ $# -ne 4 ]; then
        echo "usage: pg-pitr-restore.sh --restore-command <archive-dir> <filename> <dest>" >&2
        exit 2
    fi
    restore_command_fetch "$2" "$3" "$4"
    exit $?
fi

case "${1:-}" in
    --help|-h) usage; exit 0 ;;
esac
# Under set -e a failing parse_args exits with its own status (2 on usage
# errors, 1 on a missing base file) — never capture it through an
# `if ! ...; then exit $?` wrapper ($? there is the negation's 0).
parse_args "$@"
run_pitr
