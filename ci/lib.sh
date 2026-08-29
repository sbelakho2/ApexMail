#!/bin/sh
# =============================================================================
# ci/lib.sh — shared library for the ApexMail self-hosted CI/CD pipeline.
# =============================================================================
# Sourced (never executed directly) by ci/pipeline.sh, ci/stages/*.sh and
# ci/check-pr.sh. Everything here is POSIX sh (dash/bash on Linux, /bin/sh on
# macOS) and passes `shellcheck -S error`.
#
# Provides:
#   * logging            ci_log/ci_info/ci_warn/ci_err  (timestamped, stdout)
#   * exit contract      CI_EXIT_OK=0 CI_EXIT_FAIL=1 CI_EXIT_SKIP=75
#                        CI_EXIT_TIMEOUT=124
#   * run locking        ci_lock_acquire/ci_lock_release (flock when present,
#                        portable mkdir+PID lock otherwise)
#   * timeouts           ci_timeout <secs> <cmd...> (GNU timeout/gtimeout when
#                        present, watchdog subprocess otherwise)
#   * manifest           manifest_init/manifest_stage/manifest_finish
#                        (ci/runs/<ts>/manifest.json via jq, .jsonl fallback)
#   * log capping        ci_run_logged — run a command, keep its exit code,
#                        append at most CI_LOG_MAX_LINES lines to the stage log
#   * docker helpers     ci_docker_ok, ephemeral postgres/redis with trap-based
#                        teardown and free-port allocation
#   * dry-run support    ci_exec — echo instead of execute when CI_DRY_RUN=1
#
# Environment (all optional; see ci/pipeline.conf):
#   CI_LOG_MAX_LINES   cap for a single command's captured output (def. 200000)
#   CI_EPHEM_PG_IMAGE  ephemeral postgres image (def. postgres:16-alpine)
#   CI_EPHEM_REDIS_IMAGE ephemeral redis image (def. redis:7-alpine)
# =============================================================================

# --- exit contract -----------------------------------------------------------
CI_EXIT_OK=0
CI_EXIT_FAIL=1
CI_EXIT_SKIP=75
CI_EXIT_UNCHANGED=76
CI_EXIT_TIMEOUT=124

# --- paths --------------------------------------------------------------------
# CI_ROOT is derived from this file so the pipeline works from any cwd, and
# may be pre-set via the environment (children of pipeline.sh inherit it —
# deriving from $0 alone breaks when lib.sh is sourced through `sh -c`).
# REPO_ROOT is the parent of ci/ — overridable via CI_REPO_ROOT for
# ci/check-pr.sh, which validates a detached worktree of another ref.
CI_ROOT=${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)}
[ -n "${CI_ROOT:-}" ] && [ -f "$CI_ROOT/lib.sh" ] || \
    CI_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
REPO_ROOT=${CI_REPO_ROOT:-$(CDPATH='' cd -- "$CI_ROOT/.." && pwd -P)}
RUNS_DIR=${CI_RUNS_DIR:-$CI_ROOT/runs}
LOCK_DIR="$RUNS_DIR/.locks"

# --- logging ------------------------------------------------------------------
_ci_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
ci_log()  { printf '[%s] [ci] %s\n' "$(_ci_ts)" "$*"; }
ci_info() { printf '[%s] [info] %s\n' "$(_ci_ts)" "$*"; }
ci_warn() { printf '[%s] [warn] %s\n' "$(_ci_ts)" "$*" >&2; }

# PATH hardening: rustup-installed cargo lives in ~/.cargo/bin, which is
# absent from non-interactive shells (plain ssh commands) and systemd units.
case ":$PATH:" in
    *":$HOME/.cargo/bin:"*) ;;
    *) [ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH" && export PATH ;;
esac
command -v cargo >/dev/null 2>&1 || command -v "$HOME/.cargo/bin/cargo" >/dev/null 2>&1 || \
    ci_warn "cargo not on PATH — test/validate stages will fail (install rustup via ci/install.sh)"
ci_err()  { printf '[%s] [ERROR] %s\n' "$(_ci_ts)" "$*" >&2; }

# Die with an error message (exit CI_EXIT_FAIL).
ci_die() { ci_err "$*"; exit "$CI_EXIT_FAIL"; }

# --- required binaries --------------------------------------------------------
# Fail fast and loudly when a hard dependency is missing.
ci_require() {
    for _cmd in "$@"; do
        if ! command -v "$_cmd" >/dev/null 2>&1; then
            ci_die "required command '$_cmd' not found in PATH"
        fi
    done
}

# --- pipeline defaults ----------------------------------------------------------
# Loaded once so stage scripts are safe to run standalone (the runner sources
# lib.sh first, and re-sourcing is a no-op thanks to : "${VAR:=…}" guards).
if [ -z "${CI_CONF_LOADED:-}" ]; then
    CI_CONF_LOADED=1
    if [ -f "$CI_ROOT/pipeline.conf" ]; then
        # shellcheck source=pipeline.conf
        . "$CI_ROOT/pipeline.conf"
    fi
    if [ -f /etc/apexmail/pipeline.conf ]; then
        # shellcheck disable=SC1091
        . /etc/apexmail/pipeline.conf
    fi
fi

# --- dry-run aware execution ---------------------------------------------------
# --- dry-run support ------------------------------------------------------------
# ci_dry — true (0) when the pipeline runs in dry-run mode (selftest): heavy
# and side-effecting commands must be echoed, not executed.
ci_dry() { [ "${CI_DRY_RUN:-0}" = 1 ]; }

# ci_exec <cmd...> — run a command for real, or print it when CI_DRY_RUN=1.
# Use for every action with side effects so `pipeline.sh selftest` can dry-run
# the full stage graph without touching infrastructure.
ci_exec() {
    if ci_dry; then
        ci_log "dry-run: $*"
        return "$CI_EXIT_OK"
    fi
    "$@"
}

# --- locking -------------------------------------------------------------------
# ci_lock_acquire <name> <wait_seconds>
#   Prefers flock(1) (Linux hosts). Falls back to an atomic mkdir lock with a
#   PID file; a lock whose owning PID is gone is treated as stale and removed.
#   Returns 0 when acquired, 1 on timeout (caller decides: skip or fail).
ci_lock_acquire() {
    _lock_name=$1
    _lock_wait=${2:-0}
    mkdir -p "$LOCK_DIR"
    if command -v flock >/dev/null 2>&1; then
        _lock_file="$LOCK_DIR/$_lock_name.lock"
        # shellcheck disable=SC2094  # fd 9 is intentionally held open for the lock
        eval "exec 9>>\"\$_lock_file\"" || return 1
        if flock -w "$_lock_wait" 9; then
            CI_LOCK_NAME="$_lock_name"
            CI_LOCK_MODE=flock
            return "$CI_EXIT_OK"
        fi
        return 1
    fi
    _lock_dir="$LOCK_DIR/$_lock_name.dir"
    _lock_deadline=$(( $(date +%s) + _lock_wait ))
    while :; do
        if mkdir "$_lock_dir" 2>/dev/null; then
            printf '%s\n' $$ >"$_lock_dir/pid" 2>/dev/null || true
            CI_LOCK_NAME="$_lock_name"
            CI_LOCK_MODE=mkdir
            return "$CI_EXIT_OK"
        fi
        _lock_pid=$(cat "$_lock_dir/pid" 2>/dev/null || printf '')
        if [ -n "$_lock_pid" ] && ! kill -0 "$_lock_pid" 2>/dev/null; then
            ci_warn "removing stale lock '$_lock_name' (pid $_lock_pid gone)"
            rm -rf "$_lock_dir"
            continue
        fi
        [ "$(date +%s)" -ge "$_lock_deadline" ] && return 1
        sleep 1
    done
}

# ci_lock_release — release whatever ci_lock_acquire took (no-op when unlocked).
ci_lock_release() {
    [ -n "${CI_LOCK_NAME:-}" ] || return "$CI_EXIT_OK"
    if [ "${CI_LOCK_MODE:-}" = flock ] && command -v flock >/dev/null 2>&1; then
        flock -u 9 2>/dev/null || true
    else
        rm -rf "${CI_LOCK_DIR_PATH:-$LOCK_DIR/$CI_LOCK_NAME.dir}" 2>/dev/null || true
    fi
    CI_LOCK_NAME=''
    CI_LOCK_DIR_PATH=''
    return "$CI_EXIT_OK"
}

# ci_lock_file_acquire <absolute-lock-file> <wait_seconds>
#   F5 — acquire an ABSOLUTE lock file path instead of a name under LOCK_DIR.
#   Used by ci/pipeline.sh to hold the SAME lock deploy/scripts/deploy.sh
#   takes (${APEXMAIL_DEPLOY_LOCK:-/opt/apexmail/.deploy.lock}) so pipeline
#   runs and manual deploys are mutually exclusive. Release via the same
#   ci_lock_release (the mkdir fallback records its absolute dir in
#   CI_LOCK_DIR_PATH).
ci_lock_file_acquire() {
    _lfa_file=$1
    _lfa_wait=${2:-0}
    # Best effort: an unwritable location fails below at open time (which is
    # reported by the caller as lock-not-acquired rather than a hard crash).
    mkdir -p "$(dirname "$_lfa_file")" 2>/dev/null || true
    if command -v flock >/dev/null 2>&1; then
        # shellcheck disable=SC2094  # fd 9 is intentionally held open for the lock
        eval "exec 9>>\"\$_lfa_file\"" || return 1
        if flock -w "$_lfa_wait" 9; then
            CI_LOCK_NAME=$(basename "$_lfa_file" | sed 's/\.lock$//')
            CI_LOCK_MODE=flock
            return "$CI_EXIT_OK"
        fi
        return 1
    fi
    _lfa_dir="${_lfa_file}.dir"
    _lfa_deadline=$(( $(date +%s) + _lfa_wait ))
    while :; do
        if mkdir "$_lfa_dir" 2>/dev/null; then
            printf '%s\n' $$ >"$_lfa_dir/pid" 2>/dev/null || true
            CI_LOCK_NAME=$(basename "$_lfa_file" | sed 's/\.lock$//')
            CI_LOCK_MODE=mkdir
            CI_LOCK_DIR_PATH="$_lfa_dir"
            return "$CI_EXIT_OK"
        fi
        _lfa_pid=$(cat "$_lfa_dir/pid" 2>/dev/null || printf '')
        if [ -n "$_lfa_pid" ] && ! kill -0 "$_lfa_pid" 2>/dev/null; then
            ci_warn "removing stale lock '$_lfa_file' (pid $_lfa_pid gone)"
            rm -rf "$_lfa_dir"
            continue
        fi
        [ "$(date +%s)" -ge "$_lfa_deadline" ] && return 1
        sleep 1
    done
}

# --- timeouts -------------------------------------------------------------------
# ci_timeout <seconds> <cmd...> — run cmd bounded by a wall-clock timeout.
# Prefers GNU timeout/gtimeout. Fallback: background cmd + watchdog that TERMs
# (then KILLs) after the budget. Exit code 124 signals a timeout.
ci_timeout() {
    _t_secs=$1
    shift
    case $_t_secs in
        ''|*[!0-9]*) ci_die "ci_timeout: invalid timeout '$_t_secs'" ;;
    esac
    if command -v timeout >/dev/null 2>&1 && timeout --version >/dev/null 2>&1; then
        timeout --kill-after=10 "$_t_secs" "$@"
        return $?
    fi
    if command -v gtimeout >/dev/null 2>&1; then
        gtimeout --kill-after=10 "$_t_secs" "$@"
        return $?
    fi
    # Portable watchdog.
    "$@" &
    _t_pid=$!
    (
        sleep "$_t_secs"
        kill -TERM "$_t_pid" 2>/dev/null || true
        sleep 10
        kill -KILL "$_t_pid" 2>/dev/null || true
    ) &
    _t_watch=$!
    _t_rc=0
    wait "$_t_pid" || _t_rc=$?
    kill -TERM "$_t_watch" 2>/dev/null || true
    wait "$_t_watch" 2>/dev/null || true
    if [ "$_t_rc" -ge 128 ] && [ $(( _t_rc - 128 )) -eq 15 ]; then
        return "$CI_EXIT_TIMEOUT"
    fi
    return "$_t_rc"
}

# --- bounded output capture -------------------------------------------------------
# CI_LOG_MAX_LINES: first N-5000 lines are kept verbatim, the last 5000 are
# kept in a ring buffer, everything between is replaced by one marker line —
# compiler/docker output can never grow stage logs without bound.
ci_cap_stream() {
    _cap_max=${1:-${CI_LOG_MAX_LINES:-200000}}
    awk -v max="$_cap_max" '
        NR <= max { print; next }
        { buf[NR % 5000] = $0 }
        END {
            if (NR > max) {
                print "...[ci] truncated " (NR - max) " middle lines (cap " max ")..."
                for (i = NR - 4999; i <= NR; i++)
                    if (i > max) print buf[i % 5000]
            }
        }'
}

# ci_run_logged <cmd...> — run cmd, tee its combined output (capped) into
# $CI_STAGE_LOG, and RETURN THE COMMAND'S EXIT CODE (POSIX sh has no pipefail,
# so a temp file is used to preserve the status; the `|| _rl_rc=$?` form also
# keeps `set -e` from aborting before the log flush).
ci_run_logged() {
    _rl_tmp=$(mktemp "${TMPDIR:-/tmp}/apexmail-ci.XXXXXX")
    _rl_rc=0
    "$@" >"$_rl_tmp" 2>&1 || _rl_rc=$?
    ci_cap_stream <"$_rl_tmp" >>"$CI_STAGE_LOG"
    rm -f "$_rl_tmp"
    return "$_rl_rc"
}

# --- run manifest -------------------------------------------------------------------
# manifest.json accumulates one record per stage. jq assembles it; when jq is
# missing the records are appended as JSONL to manifest.jsonl instead (and a
# note is logged — install.sh installs jq on hosts).
json_escape() {
    printf '%s' "$1" | awk 'BEGIN { ORS = "" }
        { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); print $0 "\\n" }'
}

_j() { printf '"%s"' "$(json_escape "$1")"; }   # emit a JSON string literal

manifest_init() {
    MANIFEST="$RUN_DIR/manifest.json"
    MANIFEST_JSONL="$RUN_DIR/manifest.jsonl"
    [ -n "${CI_RUN_ID:-}" ] || CI_RUN_ID=$(date -u '+%Y%m%dT%H%M%S')
    MANIFEST_EPOCH=$(date +%s)
    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg run_id "$CI_RUN_ID" \
            --arg started "$(_ci_ts)" \
            --argjson epoch "$MANIFEST_EPOCH" \
            --arg repo "${CI_REPO_URL:-unknown}" \
            --arg ref "${CI_REF:-unknown}" \
            --arg sha "${CI_SHA:-unknown}" \
            '{run_id:$run_id, started_at:$started, started_epoch:$epoch,
              repo:$repo, ref:$ref, sha:$sha, stages:[]}' >"$MANIFEST"
    else
        ci_warn "jq missing — manifest records go to manifest.jsonl (run ci/install.sh)"
        : >"$MANIFEST_JSONL"
    fi
}

# manifest_stage <name> <status> <exit_code> <started_epoch> <ended_epoch>
manifest_stage() {
    _ms_name=$1 _ms_status=$2 _ms_exit=$3 _ms_start=$4 _ms_end=$5
    _ms_dur=$(( _ms_end - _ms_start ))
    if command -v jq >/dev/null 2>&1 && [ -f "$MANIFEST" ]; then
        _ms_tmp=$(mktemp "${TMPDIR:-/tmp}/apexmail-ci.XXXXXX")
        jq --arg n "$_ms_name" --arg s "$_ms_status" --argjson e "$_ms_exit" \
           --argjson d "$_ms_dur" \
           '.stages += [{name:$n,status:$s,exit_code:$e,duration_s:$d}]' \
           "$MANIFEST" >"$_ms_tmp" && mv "$_ms_tmp" "$MANIFEST"
        rm -f "$_ms_tmp"
    else
        printf '{"name":%s,"status":%s,"exit_code":%s,"duration_s":%s}\n' \
            "$(_j "$_ms_name")" "$(_j "$_ms_status")" "$_ms_exit" "$_ms_dur" >>"$MANIFEST_JSONL"
    fi
}

# manifest_finish <overall_status> — stamp totals and mirror a summary line.
manifest_finish() {
    _mf_status=$1
    _mf_end=$(date +%s)
    if command -v jq >/dev/null 2>&1 && [ -f "$MANIFEST" ]; then
        _mf_tmp=$(mktemp "${TMPDIR:-/tmp}/apexmail-ci.XXXXXX")
        if jq --arg s "$_mf_status" --argjson dur "$(( _mf_end - MANIFEST_EPOCH ))" \
              '. + {overall:$s, total_duration_s:$dur}' \
              "$MANIFEST" >"$_mf_tmp" 2>/dev/null; then
            mv "$_mf_tmp" "$MANIFEST"
        else
            rm -f "$_mf_tmp"
        fi
    fi
    printf '%s %s %s\n' "$CI_RUN_ID" "$_mf_status" "$RUN_DIR" >>"$RUNS_DIR/history.log"
}

# --- docker / ephemeral services ------------------------------------------------------
ci_docker_ok() {
    [ "${CI_DRY_RUN:-0}" = "1" ] && return "$CI_EXIT_OK"
    command -v docker >/dev/null 2>&1 || return 1
    ci_timeout 15 docker info --format '{{.ServerVersion}}' >/dev/null 2>&1
}

# Pick a free TCP port on 127.0.0.1 (python3 when available, fixed-port probe
# otherwise). Printed on stdout.
ci_free_port() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
        return
    fi
    _fp_p=55432
    while [ "$_fp_p" -lt 55532 ]; do
        if ! (exec 3<>"/dev/tcp/127.0.0.1/$_fp_p") 2>/dev/null; then
            printf '%s\n' "$_fp_p"
            return
        fi
        _fp_p=$((_fp_p + 1))
    done
    ci_die "ci_free_port: no free port in 55432-55531"
}

# Ephemeral container registry — cleanup runs from the pipeline EXIT trap.
EPHEM_CONTAINERS=''
ci_ephem_register() { EPHEM_CONTAINERS="$EPHEM_CONTAINERS $1"; }
ci_ephem_cleanup() {
    for _ec in $EPHEM_CONTAINERS; do
        if [ "${CI_DRY_RUN:-0}" = "1" ]; then
            ci_log "dry-run: docker rm -f $_ec"
        else
            docker rm -f "$_ec" >/dev/null 2>&1 || true
        fi
    done
    EPHEM_CONTAINERS=''
}

# ci_ephem_postgres <name> <user> <pass> <db> <port>
#   Starts a throwaway postgres and waits for readiness. Returns 0/1.
ci_ephem_postgres() {
    _ep_name=$1 _ep_user=$2 _ep_pass=$3 _ep_db=$4 _ep_port=$5
    ci_exec docker rm -f "$_ep_name" >/dev/null 2>&1 || true
    ci_exec docker run -d --rm --name "$_ep_name" \
        -e "POSTGRES_USER=$_ep_user" -e "POSTGRES_PASSWORD=$_ep_pass" -e "POSTGRES_DB=$_ep_db" \
        -p "127.0.0.1:$_ep_port:5432" "${CI_EPHEM_PG_IMAGE:-postgres:16-alpine}" >/dev/null || return 1
    ci_ephem_register "$_ep_name"
    [ "${CI_DRY_RUN:-0}" = "1" ] && return "$CI_EXIT_OK"
    _ep_i=0
    while [ "$_ep_i" -lt 45 ]; do
        if docker exec "$_ep_name" pg_isready -U "$_ep_user" -d "$_ep_db" >/dev/null 2>&1; then
            ci_info "ephemeral postgres '$_ep_name' ready on 127.0.0.1:$_ep_port"
            return "$CI_EXIT_OK"
        fi
        _ep_i=$((_ep_i + 1))
        sleep 2
    done
    ci_err "ephemeral postgres '$_ep_name' not ready after 90s"
    return 1
}

# ci_ephem_redis <name> <port>
ci_ephem_redis() {
    _er_name=$1 _er_port=$2
    ci_exec docker rm -f "$_er_name" >/dev/null 2>&1 || true
    ci_exec docker run -d --rm --name "$_er_name" \
        -p "127.0.0.1:$_er_port:6379" "${CI_EPHEM_REDIS_IMAGE:-redis:7-alpine}" >/dev/null || return 1
    ci_ephem_register "$_er_name"
    [ "${CI_DRY_RUN:-0}" = "1" ] && return "$CI_EXIT_OK"
    _er_i=0
    while [ "$_er_i" -lt 30 ]; do
        if docker exec "$_er_name" redis-cli ping 2>/dev/null | grep -q PONG; then
            ci_info "ephemeral redis '$_er_name' ready on 127.0.0.1:$_er_port"
            return "$CI_EXIT_OK"
        fi
        _er_i=$((_er_i + 1))
        sleep 2
    done
    ci_err "ephemeral redis '$_er_name' not ready after 60s"
    return 1
}

# --- host detection --------------------------------------------------------------------
# The deploy host runs the compose stack at CI_DEPLOY_DIR (default /opt/apexmail).
ci_on_deploy_host() {
    [ -f "${CI_DEPLOY_DIR:-/opt/apexmail}/.env" ] && [ -d "${CI_DEPLOY_DIR:-/opt/apexmail}/deploy" ]
}

# --- check helpers -----------------------------------------------------------------------
# ci_check <label> <cmd...> — run one named check, log PASS/FAIL with the
# command's real exit code preserved (output capped into $CI_STAGE_LOG).
# In dry-run mode the command is not executed (logged as a dry-run skip).
ci_check() {
    _ck_label=$1
    shift
    if ci_dry; then
        ci_info "check (dry-run): $_ck_label"
        return "$CI_EXIT_OK"
    fi
    ci_info "── check: $_ck_label"
    _ck_rc=0
    ci_run_logged "$@" || _ck_rc=$?
    if [ "$_ck_rc" -eq 0 ]; then
        ci_info "PASS: $_ck_label"
    else
        ci_err "FAIL: $_ck_label (exit $_ck_rc)"
    fi
    return "$_ck_rc"
}

# ci_check_advisory — same, but a failure is logged and swallowed.
ci_check_advisory() {
    if ci_check "$@"; then
        return "$CI_EXIT_OK"
    fi
    ci_warn "ADVISORY failure — continuing (stage result unaffected)"
    return "$CI_EXIT_OK"
}

# ci_skip_stage <reason> — exit the stage as intentionally skipped.
ci_skip_stage() {
    ci_info "SKIP: $*"
    exit "$CI_EXIT_SKIP"
}

# Missing-tool policy: on the deploy host a missing security/CI tool is a hard
# failure (fail closed); elsewhere it degrades to a warning so dev machines
# without, say, cargo-audit can still run the pipeline.
ci_tool_missing() {
    _tm_name=$1
    if [ "${CI_MISSING_TOOLS:-auto}" = fail ]; then return 0; fi
    if [ "${CI_MISSING_TOOLS:-auto}" = warn ]; then return 1; fi
    ci_on_deploy_host
}

# ci_have_tool <name> — true when present; when missing, die on the deploy host
# (fail closed) and warn elsewhere.
ci_have_tool() {
    _ht_name=$1
    if command -v "$_ht_name" >/dev/null 2>&1; then
        return "$CI_EXIT_OK"
    fi
    if ci_tool_missing "$_ht_name"; then
        ci_die "tool '$_ht_name' missing on the deploy host — run ci/install.sh (fail closed)"
    fi
    ci_warn "tool '$_ht_name' missing — related check skipped (install it for full coverage)"
    return 1
}

# --- retention ---------------------------------------------------------------------------
# ci_prune_runs <keep_n> — delete the oldest run dirs beyond the newest N, and
# cap history.log. Called by the notify stage so ci/runs never grows unbounded.
ci_prune_runs() {
    _pr_keep=${1:-30}
    [ -d "$RUNS_DIR" ] || return "$CI_EXIT_OK"
    _pr_tmp=$(mktemp "${TMPDIR:-/tmp}/apexmail-ci.XXXXXX")
    ls -1 "$RUNS_DIR" 2>/dev/null | grep -E '^[0-9]{8}T[0-9]{6}' | sort -r >"$_pr_tmp"
    _pr_n=0
    while IFS= read -r _pr_dir; do
        _pr_n=$((_pr_n + 1))
        [ "$_pr_n" -le "$_pr_keep" ] && continue
        rm -rf "${RUNS_DIR:?}/$_pr_dir"
    done <"$_pr_tmp"
    rm -f "$_pr_tmp"
    # history.log: keep the newest 500 lines.
    if [ -f "$RUNS_DIR/history.log" ]; then
        _pr_h=$(mktemp "${TMPDIR:-/tmp}/apexmail-ci.XXXXXX")
        tail -n 500 "$RUNS_DIR/history.log" >"$_pr_h" && mv "$_pr_h" "$RUNS_DIR/history.log"
        rm -f "$_pr_h"
    fi
}
