#!/bin/sh
# =============================================================================
# ci/pipeline.sh — ApexMail self-hosted CI/CD stage runner.
# =============================================================================
# Replaces GitHub Actions as the production CI/CD path (see ci/README.md for
# the full workflow replacement map).
#
# Usage:
#   ci/pipeline.sh run [options]        execute a pipeline run
#   ci/pipeline.sh status               show the latest run + live stack state
#   ci/pipeline.sh list                 list stages, timeouts, advisory flags
#   ci/pipeline.sh selftest             dry-run contract tests (no infra)
#
# run options:
#   --stages a,b,c     run only these stages (executed in CI_STAGES order)
#   --skip a,b         skip these stages
#   --skip-deploy      shorthand for --skip images,migrate,deploy
#   --ref REF          git ref the run validates (default CI_REF, i.e. main)
#   --advisory a,b     treat these stages as advisory for THIS run
#   --dry-run          echo infrastructure actions instead of executing them
#   --force            proceed even when another run holds the lock
#   --lock-wait SECS   seconds to wait for the run lock (default 0)
#
# Stage contract (ci/stages/<name>.sh):
#   * POSIX sh, executable, defines stage_main(); run as its own process.
#   * receives env: REPO_ROOT, CI_ROOT, RUN_DIR, CI_STAGE_LOG, CI_STAGE_NAME,
#     CI_REF, CI_SHA, CI_DEPLOY_DIR, CI_DRY_RUN + everything in pipeline.conf.
#   * exit 0 = ok, 1 = fail, 75 = skipped (infrastructure intentionally
#     absent, e.g. deploy stages on a dev machine), 124 = timeout.
#   * combined output is captured (capped) into ci/runs/<ts>/stages/<name>.log.
#
# Concurrency: one run at a time — the pipeline takes THE SAME lock as a
# manual deploy/scripts/deploy.sh run (${APEXMAIL_DEPLOY_LOCK:-/opt/apexmail/
# .deploy.lock}; flock when available, mkdir lock otherwise) so the two
# deploy paths can never interleave (F5).
# The systemd timer polls every 5 min; while a run is in progress the next
# tick exits 0 immediately instead of queueing.
# =============================================================================
set -eu

CI_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
CI_ROOT=$CI_DIR
export CI_ROOT
# shellcheck source=lib.sh
. "$CI_DIR/lib.sh"

# --- configuration: repo defaults, then host overrides; env always wins --------
# shellcheck source=pipeline.conf
. "$CI_DIR/pipeline.conf"
if [ -f /etc/apexmail/pipeline.conf ]; then
    # shellcheck disable=SC1091
    . /etc/apexmail/pipeline.conf
fi

usage() {
    cat <<'USAGE'
Usage: ci/pipeline.sh <command> [options]

Commands:
  run          execute a pipeline run
  status       latest run manifest, failure marker, live containers
  list         stage table (timeout + advisory flags)
  selftest     contract tests + full dry-run (safe: no infrastructure)

run options:
  --stages a,b,c      run only these stages (in CI_STAGES order)
  --skip a,b          skip these stages
  --skip-deploy       shorthand for --skip images,migrate,deploy
  --ref REF           git ref the run validates (default: main)
  --advisory a,b      these stages may fail without failing the run
  --dry-run           echo infrastructure actions instead of executing
  --force             run without the pipeline lock
  --lock-wait SECS    wait up to SECS for the lock (default 0)
USAGE
    exit "${1:-0}"
}

# --- list -------------------------------------------------------------------------
cmd_list() {
    printf '%-10s %-8s %-9s %s\n' STAGE TIMEOUT ADVISORY SCRIPT
    for st in $(printf '%s' "$CI_STAGES" | tr ',' ' '); do
        adv=no
        case ",$CI_ADVISORY_STAGES," in *",$st,"*) adv=yes ;; esac
        eval "tmo=\${CI_TIMEOUT_$st:-600}"
        printf '%-10s %-8s %-9s %s\n' "$st" "${tmo}s" "$adv" "$CI_DIR/stages/$st.sh"
    done
    exit 0
}

# --- status -----------------------------------------------------------------------
cmd_status() {
    printf '== latest runs (ci/runs/history.log) ==\n'
    if [ -f "$RUNS_DIR/history.log" ]; then
        tail -n 10 "$RUNS_DIR/history.log"
    else
        printf '(none)\n'
    fi
    printf '\n== latest manifest ==\n'
    _latest=$(ls -1 "$RUNS_DIR" 2>/dev/null | grep -E '^[0-9]{8}T[0-9]{6}' | sort -r | head -1 || true)
    if [ -n "$_latest" ] && [ -f "$RUNS_DIR/$_latest/manifest.json" ]; then
        cat "$RUNS_DIR/$_latest/manifest.json"
    elif [ -n "$_latest" ] && [ -f "$RUNS_DIR/$_latest/manifest.jsonl" ]; then
        cat "$RUNS_DIR/$_latest/manifest.jsonl"
    else
        printf '(no runs recorded)\n'
    fi
    printf '\n== failure marker ==\n'
    if [ -f "$CI_DIR/.last-failure" ]; then
        cat "$CI_DIR/.last-failure"
    else
        printf '(none — last run succeeded or nothing has run yet)\n'
    fi
    printf '\n== live containers (deploy host) ==\n'
    if ci_docker_ok; then
        docker ps --format '{{.Names}}\t{{.Status}}' | head -30 || true
    else
        printf '(docker unavailable)\n'
    fi
    exit 0
}

# --- run --------------------------------------------------------------------------
cmd_run() {
    _want=''
    _skip=''
    _ref=$CI_REF
    _advisory_run=''
    _dry_run=0
    _force=0
    _lock_wait=0
    _skip_unchanged=0
    while [ $# -gt 0 ]; do
        case $1 in
            --stages)        _want=$2; shift 2 ;;
            --skip)          _skip=$_skip,$2; shift 2 ;;
            --skip-deploy)   _skip=$_skip,images,migrate,deploy; shift ;;
            --ref)           _ref=$2; shift 2 ;;
            --advisory)      _advisory_run=$2; shift 2 ;;
            --dry-run)       _dry_run=1; shift ;;
            --force)         _force=1; shift ;;
            --lock-wait)     _lock_wait=$2; shift 2 ;;
            --skip-unchanged) _skip_unchanged=1; shift ;;
            *)               ci_die "unknown option: $1 (see --help)" ;;
        esac
    done

    CI_REF=$_ref
    CI_DRY_RUN=$_dry_run
    CI_SKIP_UNCHANGED=$_skip_unchanged
    export CI_DRY_RUN CI_REF CI_SKIP_UNCHANGED

    # Resolve the run's stage list; ordering always follows CI_STAGES.
    _run_list=''
    for st in $(printf '%s' "$CI_STAGES" | tr ',' ' '); do
        if [ -n "$_want" ]; then
            case ",$_want," in
                *",$st,"*) ;;
                *) continue ;;
            esac
        fi
        case ",$_skip," in
            *",$st,"*) ci_info "stage [$st] skipped by request" ;;
            *) _run_list="$_run_list $st" ;;
        esac
    done
    [ -n "$_run_list" ] || ci_die "no stages selected (check --stages/--skip)"

    # --- concurrency lock (F5: the SAME lock deploy/scripts/deploy.sh takes) --
    # Canonical path: /opt/apexmail/.deploy.lock (APEXMAIL_DEPLOY_LOCK
    # overrides BOTH sides — deploy.sh resolves the identical variable).
    # Previously the pipeline locked ci/runs/.locks/pipeline.lock while a
    # manual deploy.sh held /opt/apexmail/.deploy.lock: the two were NOT
    # mutual, so a pipeline run and a hotfix deploy could interleave the
    # build, the migrator and `compose up`.
    # On hosts where the canonical dir cannot be created/written (e.g. a dev
    # machine without /opt/apexmail — deploy.sh cannot run there anyway),
    # fall back to a repo-local lock so concurrent pipeline runs still
    # exclude each other.
    if [ "$_force" = 1 ]; then
        ci_warn "--force: running without the deploy lock"
    else
        APEXMAIL_DEPLOY_LOCK="${APEXMAIL_DEPLOY_LOCK:-${CI_DEPLOY_DIR:-/opt/apexmail}/.deploy.lock}"
        _lock_dir=$(dirname "$APEXMAIL_DEPLOY_LOCK")
        if ! mkdir -p "$_lock_dir" 2>/dev/null || [ ! -w "$_lock_dir" ]; then
            ci_warn "deploy lock dir not writable ($_lock_dir) — using repo-local lock (not mutual with deploy.sh, which cannot run on this host)"
            APEXMAIL_DEPLOY_LOCK="$LOCK_DIR/deploy.lock"
            mkdir -p "$LOCK_DIR"
        fi
        export APEXMAIL_DEPLOY_LOCK
        if ! ci_lock_file_acquire "$APEXMAIL_DEPLOY_LOCK" "$_lock_wait"; then
            ci_info "another run holds the deploy lock ($APEXMAIL_DEPLOY_LOCK) — nothing to do"
            exit "$CI_EXIT_OK"
        fi
    fi

    prepare_run() {
        RUN_ID=$(date -u '+%Y%m%dT%H%M%S')
        RUN_DIR="$RUNS_DIR/${RUN_ID}_$$"
        mkdir -p "$RUN_DIR/stages" "$RUNS_DIR/.locks"
        chmod 700 "$RUN_DIR" 2>/dev/null || true
        CI_RUN_ID=$RUN_ID
        export RUN_DIR RUNS_DIR CI_RUN_ID
        printf '%s\n' "$RUN_DIR" >"$RUNS_DIR/latest"
    }
    prepare_run

    cleanup() {
        ci_ephem_cleanup
        ci_lock_release
    }
    trap cleanup EXIT
    trap 'ci_warn "interrupted"; exit 130' INT TERM

    # Record what this run is testing (the fetch stage refines the sha/remote).
    CI_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')
    CI_REPO_URL=$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || printf 'unknown')
    export CI_SHA CI_REPO_URL CI_DEPLOY_DIR CI_RUN_ID
    manifest_init
    ci_info "run $CI_RUN_ID start ref=$CI_REF sha=$CI_SHA stages:$(printf '%s' "$_run_list" | tr -d ' ')"
    [ "$_dry_run" = 1 ] && ci_warn "DRY-RUN mode: infrastructure actions are echoed only"

    # execute_stage <name> — returns 0; prints EXACTLY the final status word
    # on stdout (progress goes to stderr) so callers can capture it cleanly.
    execute_stage() {
        _es_st=$1
        _es_script="$CI_DIR/stages/$_es_st.sh"
        if [ ! -x "$_es_script" ]; then
            ci_err "stage script missing or not executable: $_es_script" >&2
            manifest_stage "$_es_st" fail 1 "$(date +%s)" "$(date +%s)"
            printf 'fail\n'
            return 0
        fi
        eval "_es_tmo=\${CI_TIMEOUT_$_es_st:-600}"
        _es_is_adv=0
        case ",$CI_ADVISORY_STAGES," in *",$_es_st,"*) _es_is_adv=1 ;; esac
        case ",$_advisory_run," in *",$_es_st,"*) _es_is_adv=1 ;; esac

        CI_STAGE_LOG="$RUN_DIR/stages/$_es_st.log"
        : >"$CI_STAGE_LOG"
        export CI_STAGE_NAME=$_es_st
        export CI_STAGE_LOG
        ci_info "── stage [$_es_st] start (timeout ${_es_tmo}s) ──" >&2
        _es_start=$(date +%s)
        _es_rc=0
        ci_timeout "$_es_tmo" sh "$_es_script" >>"$CI_STAGE_LOG" 2>&1 || _es_rc=$?
        _es_end=$(date +%s)
        _es_status=ok
        [ "$_es_rc" -ne 0 ] && _es_status=fail
        [ "$_es_rc" -eq "$CI_EXIT_SKIP" ] && _es_status=skip
        [ "$_es_rc" -eq "$CI_EXIT_UNCHANGED" ] && _es_status=unchanged
        [ "$_es_rc" -eq "$CI_EXIT_TIMEOUT" ] && _es_status=timeout
        if [ "$_es_status" = fail ] && [ "$_es_is_adv" = 1 ]; then
            _es_status=advisory-fail
        fi
        manifest_stage "$_es_st" "$_es_status" "$_es_rc" "$_es_start" "$_es_end"
        ci_info "── stage [$_es_st] $_es_status (exit $_es_rc, $(( _es_end - _es_start ))s) ──" >&2
        printf '%s\n' "$_es_status"
    }

    _overall=ok
    _failed_stage=''
    _last=''
    for st in $_run_list; do
        _status=$(execute_stage "$st")
        _last=$st
        case $_status in
            ok|skip|advisory-fail) ;;
            unchanged)
                # fetch detected no new work (CI_SKIP_UNCHANGED): green no-op.
                ci_info "nothing to do since the last green run"
                break
                ;;
            *)
                _overall=$_status
                _failed_stage=$st
                break   # stop the line at the first hard failure
                ;;
        esac
    done

    # The failure reporter always runs (even after a hard failure stopped the
    # line), unless it already ran as the last stage of this run.
    if [ "$_overall" != ok ] && [ "$_last" != notify ]; then
        ci_info "running notify stage to record the failure"
        execute_stage notify >/dev/null
    fi

    manifest_finish "$_overall"
    if [ "$_overall" = ok ]; then
        rm -f "$CI_DIR/.last-failure" 2>/dev/null || true
        # Remember the sha so --skip-unchanged polls can no-op cheaply — but
        # only when this run actually exercised the full CI lane (partial
        # --stages runs must not mark an untested sha as good).
        case " $_run_list " in
            *" test "*|*" security "*)
                [ "$_status" = unchanged ] || printf '%s\n' "$CI_SHA" >"$RUNS_DIR/.last-good-sha"
                ;;
        esac
    fi
    cleanup
    trap - EXIT

    if [ "$_overall" = ok ]; then
        ci_info "run $CI_RUN_ID: OK"
        exit "$CI_EXIT_OK"
    fi
    ci_err "run $CI_RUN_ID: $_overall (stage: $_failed_stage) — see $RUN_DIR"
    exit "$CI_EXIT_FAIL"
}

# --- selftest ---------------------------------------------------------------------
# Dry-run the whole stage graph through the REAL runner (lock, timeout, log,
# manifest) with CI_DRY_RUN=1 so no infrastructure is touched, then assert the
# machinery itself: syntax, shellcheck, contracts, manifest validity, timeout
# enforcement, lock exclusivity.
cmd_selftest() {
    _sf_fail=0
    ci_info "selftest (1/6): syntax + shellcheck of every ci/ script"
    for f in "$CI_DIR/pipeline.sh" "$CI_DIR/lib.sh" "$CI_DIR/check-pr.sh" \
             "$CI_DIR/install.sh" "$CI_DIR"/stages/*.sh "$CI_DIR"/units/*.sh; do
        [ -f "$f" ] || continue
        sh -n "$f" 2>/dev/null || { ci_err "sh -n failed: $f"; _sf_fail=1; }
    done
    if command -v shellcheck >/dev/null 2>&1; then
        for f in "$CI_DIR/pipeline.sh" "$CI_DIR/lib.sh" "$CI_DIR/check-pr.sh" \
                 "$CI_DIR/install.sh" "$CI_DIR"/stages/*.sh "$CI_DIR"/units/*.sh; do
            [ -f "$f" ] || continue
            shellcheck -S error "$f" || { ci_err "shellcheck failed: $f"; _sf_fail=1; }
        done
    else
        ci_warn "shellcheck not installed — syntax-only check"
    fi

    ci_info "selftest (2/6): stage contract (exists, executable, defines stage_main)"
    for st in $(printf '%s' "$CI_STAGES" | tr ',' ' '); do
        s="$CI_DIR/stages/$st.sh"
        [ -x "$s" ] || { ci_err "missing/not executable: $s"; _sf_fail=1; }
        grep -q 'stage_main' "$s" 2>/dev/null || { ci_err "no stage_main in $s"; _sf_fail=1; }
    done

    ci_info "selftest (3/6): full dry-run through the real runner"
    if ! "$CI_DIR/pipeline.sh" run --dry-run --stages "$CI_STAGES" --lock-wait 10; then
        ci_err "dry-run pipeline run failed"
        _sf_fail=1
    fi

    ci_info "selftest (4/6): manifest + per-stage logs of the dry run are valid"
    _latest=$(ls -1 "$RUNS_DIR" 2>/dev/null | grep -E '^[0-9]{8}T[0-9]{6}' | sort -r | head -1 || true)
    if [ -z "$_latest" ]; then
        ci_err "no run dir produced"
        _sf_fail=1
    else
        if command -v jq >/dev/null 2>&1; then
            jq -e '.stages | length > 0' "$RUNS_DIR/$_latest/manifest.json" >/dev/null 2>&1 \
                || { ci_err "manifest.json invalid"; _sf_fail=1; }
        fi
        for st in $(printf '%s' "$CI_STAGES" | tr ',' ' '); do
            [ -f "$RUNS_DIR/$_latest/stages/$st.log" ] \
                || { ci_err "missing log for stage $st"; _sf_fail=1; }
        done
    fi

    ci_info "selftest (5/6): timeout wrapper stops a runaway command"
    _sf_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-selftest.XXXXXX")
    printf '#!/bin/sh\nsleep 30\n' >"$_sf_tmp/slow.sh"
    chmod +x "$_sf_tmp/slow.sh"
    _sf_rc=0
    ci_timeout 2 "$_sf_tmp/slow.sh" || _sf_rc=$?
    if [ "$_sf_rc" -eq 0 ]; then
        ci_err "slow command unexpectedly succeeded"
        _sf_fail=1
    elif [ "$_sf_rc" -ne "$CI_EXIT_TIMEOUT" ] && [ "$_sf_rc" -lt 128 ]; then
        ci_err "unexpected timeout exit code $_sf_rc"
        _sf_fail=1
    fi
    rm -rf "$_sf_tmp"

    ci_info "selftest (6/6): run lock excludes a concurrent holder"
    if ci_lock_acquire selftest 0; then
        if CI_ROOT="$CI_DIR" sh -c '. "$CI_ROOT/lib.sh"; ci_lock_acquire selftest 1' >/dev/null 2>&1; then
            # With flock both acquires share fd 9 in THIS process; only the
            # child-process attempt above proves real exclusion.
            ci_warn "child acquired the held lock — investigate lock semantics"
            _sf_fail=1
        fi
        ci_lock_release
    else
        ci_err "could not acquire the selftest lock at all"
        _sf_fail=1
    fi

    if [ "$_sf_fail" -eq 0 ]; then
        ci_info "selftest: ALL OK"
        exit "$CI_EXIT_OK"
    fi
    ci_err "selftest: FAILED"
    exit "$CI_EXIT_FAIL"
}

# --- entry -------------------------------------------------------------------------
case "${1:-}" in
    run)      shift; cmd_run "$@" ;;
    status)   shift; cmd_status "$@" ;;
    list)     shift; cmd_list "$@" ;;
    selftest) shift; cmd_selftest "$@" ;;
    -h|--help|help|'') usage 0 ;;
    *)        usage 1 ;;
esac
