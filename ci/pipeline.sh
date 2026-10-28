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
#   --skip-unchanged   end early when HEAD already completed a green run under
#                      the current pipeline config (the timer's cheap poll)
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
  push-blessing <ssh-target>
               copy this machine's .gate-blessing.json to the deploy host
               (the split CI model: gates run here, the host deploys)

run options:
  --stages a,b,c      run only these stages (in CI_STAGES order)
  --skip a,b          skip these stages
  --skip-deploy       shorthand for --skip images,migrate,deploy
  --ref REF           git ref the run validates (default: main)
  --advisory a,b      these stages may fail without failing the run
  --skip-unchanged    end early when HEAD already passed a green run under the
                      current pipeline config (the timer's cheap poll)
  --dry-run           echo infrastructure actions instead of executing
  --force             run without the pipeline lock
  --lock-wait SECS    wait up to SECS for the lock (default 0)
USAGE
    exit "${1:-0}"
}

# --- blessing contract (audit SM14 F3 + P1) -----------------------------------------
# A .last-good-sha blessing is RELEASE EVIDENCE: fetch.sh skip-unchanged
# no-ops every later poll for the recorded sha, so "blessed" must mean "the
# FULL stage line — including images/migrate/deploy/verify — ran and every
# stage actually finished ok in THIS run". These helpers are top-level (not
# cmd_run-internal) so `selftest` can exercise the contract directly.
#
# The stages a FULL blessing must have ACTUALLY passed — status ok — this
# run. Anything else (skip, advisory-fail, timeout, unchanged, fail, or a
# stage that never ran) must never be recorded as passed.
REQUIRED_BLESS_STAGES="validate ui test security"

# A blessing is RELEASE EVIDENCE that a sha was BUILT, MIGRATED, DEPLOYED and
# VERIFIED — fetch.sh's --skip-unchanged no-ops every later poll for a blessed
# sha, so a blessing written by a gates-only run (`--stages
# validate,ui,test,security`, or the documented `--skip-deploy`) would make
# the host timer permanently skip a commit that was never deployed (audit
# P1). Membership therefore requires the FULL stage line (CI_STAGES), not
# just the four gate stages; blessing_membership_missing reports which stages
# a run did not include.
blessing_membership_missing() {
    _bm_found=0
    for _bm_st in $(printf '%s' "$CI_STAGES" | tr ',' ' '); do
        case " $1 " in
            *" $_bm_st "*) ;;
            *) printf '%s\n' "$_bm_st"; _bm_found=$((_bm_found + 1)) ;;
        esac
    done
    [ "$_bm_found" -gt 0 ]
}

# blessing_statuses_ok <"stage=status" ...> — print the required stages whose
# recorded status is exactly `ok`, one per line.
blessing_statuses_ok() {
    for _bs_req in $REQUIRED_BLESS_STAGES; do
        for _bs_pair in "$@"; do
            if [ "$_bs_pair" = "$_bs_req=ok" ]; then
                printf '%s\n' "$_bs_req"
                break
            fi
        done
    done
}

# blessing_refused_reason <"stage=status" ...> — print one "<stage>: <status>"
# line for every required stage that did NOT finish ok (nothing when all
# did). Exit status: 0 = refusal reasons found, 1 = blessing allowed.
blessing_refused_reason() {
    _br_found=0
    for _br_req in $REQUIRED_BLESS_STAGES; do
        _br_status=not-run
        for _br_pair in "$@"; do
            case $_br_pair in
                "$_br_req="*) _br_status=${_br_pair#"$_br_req="} ;;
            esac
        done
        if [ "$_br_status" != ok ]; then
            printf '%s: %s\n' "$_br_req" "$_br_status"
            _br_found=$((_br_found + 1))
        fi
    done
    [ "$_br_found" -gt 0 ]
}

# blessing_lanes_statuses <manifest.json> — "<lane>=<status>,..." for every
# sub-lane row in ci/required-lanes.txt, sourced from the run manifest's
# recorded per-check lanes (ci_check / ci_lane_record write them). Stage rows
# in the file are skipped: their statuses travel in gateStagesStatuses.
# Lanes that never ran record as not-run — gate_blessing_refusal refuses them.
blessing_lanes_statuses() {
    _bls_manifest=$1
    _bls_file=$CI_ROOT/required-lanes.txt
    [ -f "$_bls_file" ] || return 0
    _bls_out=''
    for _bls_row in $(grep -v '^#' "$_bls_file" | grep -v '^$'); do
        case $_bls_row in
            *.*) ;;
            *) continue ;;
        esac
        _bls_val=not-run
        if command -v jq >/dev/null 2>&1 && [ -f "$_bls_manifest" ]; then
            _bls_val=$(jq -r --arg id "$_bls_row" \
                '[.stages[].lanes[]? | select(.id == $id) | .status] | last // "not-run"' \
                "$_bls_manifest" 2>/dev/null)
            [ -n "$_bls_val" ] || _bls_val=not-run
        fi
        if [ -n "$_bls_out" ]; then
            _bls_out="$_bls_out,$_bls_row=$_bls_val"
        else
            _bls_out="$_bls_row=$_bls_val"
        fi
    done
    printf '%s' "$_bls_out"
}

# blessing_passed_json <"stage=status" ...> — the passedStages JSON array of
# the required stages that genuinely finished ok (audit SM14 F3: derived
# from the run's ACTUAL per-stage statuses, never a hardcoded list).
blessing_passed_json() {
    _bp_json=''
    for _bp_st in $(blessing_statuses_ok "$@"); do
        if [ -z "$_bp_json" ]; then
            _bp_json="\"$_bp_st\""
        else
            _bp_json="$_bp_json,\"$_bp_st\""
        fi
    done
    printf '[%s]' "$_bp_json"
}

# --- list -------------------------------------------------------------------------
cmd_list() {
    printf '%-10s %-8s %-9s %s\n' STAGE TIMEOUT ADVISORY SCRIPT
    for st in $(printf '%s' "$CI_STAGES" | tr ',' ' '); do
        adv=no
        case ",$CI_ADVISORY_STAGES," in *",$st,"*) adv=yes ;; esac
        tmo=''
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
    _latest=$(cd "$RUNS_DIR" 2>/dev/null && \
        ls -1d [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]* 2>/dev/null \
        | sort -r | head -1 || true)
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
        _es_tmo=600
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
        # GitHub lane status (audit 2026-10-27 item 5, step 1 of the fix
        # order): publish `apexmail/<lane>` contexts so required status
        # checks can later be pinned to them. Fail-open by design.
        ci_github_status_publish "$_es_st" "$_es_status"
        ci_info "── stage [$_es_st] $_es_status (exit $_es_rc, $(( _es_end - _es_start ))s) ──" >&2
        printf '%s\n' "$_es_status"
    }

    _overall=ok
    _failed_stage=''
    _last=''
    # Audit SM14 F3: record EVERY stage's actual outcome ("stage=status")
    # so the blessing can be derived from what really ran, not from the
    # requested stage list. execute_stage prints exactly the manifest's
    # status word (ok/skip/advisory-fail/unchanged/timeout/fail).
    _statuses=''
    for st in $_run_list; do
        _status=$(execute_stage "$st")
        _statuses="$_statuses $st=$_status"
        _last=$st
        case $_status in
            ok|skip|advisory-fail) ;;
            unchanged)
                # fetch detected no new work (CI_SKIP_UNCHANGED): green no-op.
                # The existing .last-good-sha blessing (same sha, same config
                # hash) stays authoritative — nothing new is claimed here.
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
        # ONLY when this run exercised EVERY stage of the line (CI_STAGES,
        # deploy path included) AND every one of them actually finished ok.
        # Three independent guards (commit 24234a5e added the first;
        # audit SM14 F3 the second; audit P1 the third):
        #   1. MEMBERSHIP — the FULL stage line must have been requested, not
        #      just the four gate stages: a gates-only or --skip-deploy run
        #      would otherwise bless a sha that was never built, migrated,
        #      deployed or verified, and the 5-minute timer would then no-op
        #      for it forever;
        #   2. OUTCOMES — a stage that ended skip/advisory-fail/timeout (via
        #      --advisory, CI_ADVISORY_STAGES in /etc/apexmail/pipeline.conf,
        #      or a hard timeout) is NOT a pass: writing passedStages for it
        #      would let fetch.sh skip-unchanged no-op every later poll for a
        #      sha whose security/ui lane never really went green.
        _required_stages_full=true
        _bless_missing=$(blessing_membership_missing "$_run_list" || true)
        if [ -n "$_bless_missing" ]; then
            _required_stages_full=false
            ci_warn "NOT blessing $CI_SHA — this run did not exercise the FULL stage line (missing: $(printf '%s' "$_bless_missing" | tr '\n' ' '))"
            ci_warn "a blessing records a DEPLOYED + VERIFIED sha; run the full line (default CI_STAGES) on the deploy host to bless"
        fi
        # A DRY-RUN "passes" without executing a single gate — it must never
        # create or refresh a blessing, or the next real --skip-unchanged
        # poll would no-op on evidence that was only echoed (audit SM14 F3
        # family: blessings record what RAN).
        _bless_allowed=true
        if [ "${CI_DRY_RUN:-0}" = 1 ]; then
            ci_info "dry-run: .last-good-sha blessing deliberately NOT written (nothing executed)"
            _bless_allowed=false
        fi
        if [ "$_required_stages_full" = true ] && [ "$_bless_allowed" = true ]; then
            # shellcheck disable=SC2086  # _statuses is an intentional
            # "stage=status" word list (statuses are single shell words).
            _bless_refused=$(blessing_refused_reason $_statuses || true)
            if [ -n "$_bless_refused" ]; then
                ci_warn "NOT blessing $CI_SHA — a required stage did not finish ok:"
                printf '%s\n' "$_bless_refused" | while IFS= read -r _br_line; do
                    ci_warn "  blessing refused: $_br_line"
                done
                ci_warn "run recorded $_overall, but .last-good-sha is left untouched (skip-unchanged keeps honouring the previous blessing)"
            else
                _pipeline_hash=$(ci_pipeline_config_hash)
                printf '{"sha":"%s","pipelineConfigHash":"%s","passedStages":%s,"completedAt":"%s"}\n' \
                    "$CI_SHA" "$_pipeline_hash" "$(blessing_passed_json $_statuses)" \
                    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                    >"$RUNS_DIR/.last-good-sha"
            fi
            # Gate-side line (the CI machine — the split CI model, 2026-10-16):
            # also record the .gate-blessing.json the deploy host's fetch
            # requires. Every stage of THIS line's actual status is recorded;
            # the deploy host refuses the sha unless validate/docs/ui/test/
            # security all read ok under the current pipeline config.
            case ",${CI_STAGES:-}," in
                *,test,*)
                    _gb_statuses=''
                    for _gb_st in $_run_list; do
                        _gb_val='not-run'
                        # shellcheck disable=SC2086  # stage=status word list
                        for _gb_pair in $_statuses; do
                            case $_gb_pair in
                                "$_gb_st="*) _gb_val=${_gb_pair#"$_gb_st="} ;;
                            esac
                        done
                        if [ -n "$_gb_statuses" ]; then
                            _gb_statuses="$_gb_statuses,$_gb_st=$_gb_val"
                        else
                            _gb_statuses="$_gb_st=$_gb_val"
                        fi
                    done
                    _gb_lanes=$(blessing_lanes_statuses "$RUN_DIR/manifest.json")
                    _gb_completed=$(date -u +%Y-%m-%dT%H:%M:%SZ)
                    # I20: the blessing is SIGNED over commit+config+stages+
                    # lanes+timestamp with the shared key; the deploy host
                    # verifies signature AND freshness. No key configured on
                    # the CI machine => an unsigned blessing is written AND A
                    # WARNING IS PRINTED (every verifying host will refuse it).
                    _gb_sig=$(ci_blessing_sign "$(ci_blessing_canonical "$CI_SHA" "$_pipeline_hash" "$_gb_statuses" "$_gb_lanes" "$_gb_completed")")
                    if [ -z "$_gb_sig" ]; then
                        ci_warn "NO CI_BLESSING_SIGNING_KEY configured — the blessing is UNSIGNED and verifying deploy hosts will refuse it"
                    fi
                    printf '{"sha":"%s","pipelineConfigHash":"%s","gateStagesStatuses":"%s","requiredLanesStatuses":"%s","signature":"%s","machine":"%s","completedAt":"%s"}\n' \
                        "$CI_SHA" "$_pipeline_hash" "$_gb_statuses" "$_gb_lanes" "$_gb_sig" \
                        "$(hostname 2>/dev/null || printf 'ci-machine')" \
                        "$_gb_completed" \
                        >"$RUNS_DIR/.gate-blessing.json"
                    ci_info "gate blessing recorded: $RUNS_DIR/.gate-blessing.json ($_gb_statuses)"
                    [ -z "$_gb_lanes" ] || ci_info "required lanes: $_gb_lanes"
                    ci_info "push it to the deploy host with: ci/pipeline.sh push-blessing <ssh-target>"
                    ;;
            esac
        fi
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
#
# selftest_contract <step> <total> <label> <script> — run one ci/tests/*.sh
# synthetic fixture as a numbered selftest step. These fixtures extract the
# REAL production functions from ci/stages/*.sh and prove their contracts on
# throwaway fixtures (no network, no host mutation); on failure the fixture's
# tail is echoed so the failing assertion is visible inline. A missing or
# non-executable fixture is a selftest FAILURE — an unwired contract is an
# untested contract. Sets the caller's _sf_fail.
selftest_contract() {
    _sct_step=$1 _sct_total=$2 _sct_label=$3 _sct_script=$4
    ci_info "selftest ($_sct_step/$_sct_total): $_sct_label"
    if [ ! -x "$_sct_script" ]; then
        ci_err "ci/tests/$(basename "$_sct_script") missing/not executable — $_sct_label is untested"
        _sf_fail=1
        return
    fi
    _sct_log=$(mktemp "${TMPDIR:-/tmp}/apexmail-selftest.XXXXXX")
    if sh "$_sct_script" >"$_sct_log" 2>&1; then
        ci_info "PASS: $_sct_label"
    else
        ci_err "$_sct_label FAILED — re-run: sh $_sct_script"
        tail -n 12 "$_sct_log" >&2 || true
        _sf_fail=1
    fi
    rm -f "$_sct_log"
}

cmd_selftest() {
    _sf_fail=0
    ci_info "selftest (1/15): syntax + shellcheck of every ci/ script"
    for f in "$CI_DIR/pipeline.sh" "$CI_DIR/lib.sh" "$CI_DIR/check-pr.sh" \
             "$CI_DIR/install.sh" "$CI_DIR"/stages/*.sh "$CI_DIR"/units/*.sh; do
        [ -f "$f" ] || continue
        sh -n "$f" 2>/dev/null || { ci_err "sh -n failed: $f"; _sf_fail=1; }
    done
    if command -v shellcheck >/dev/null 2>&1; then
        for f in "$CI_DIR/pipeline.sh" "$CI_DIR/lib.sh" "$CI_DIR/check-pr.sh" \
                 "$CI_DIR/install.sh" "$CI_DIR"/stages/*.sh "$CI_DIR"/units/*.sh; do
            [ -f "$f" ] || continue
            # -S warning matches the repo-wide static-lint gate the test
            # stage runs over every tracked script; ci/ must clear the same
            # bar it enforces.
            shellcheck -S warning "$f" || { ci_err "shellcheck failed: $f"; _sf_fail=1; }
        done
    else
        ci_warn "shellcheck not installed — syntax-only check"
    fi

    ci_info "selftest (2/15): stage contract (exists, executable, defines stage_main)"
    for st in $(printf '%s' "$CI_STAGES" | tr ',' ' '); do
        s="$CI_DIR/stages/$st.sh"
        [ -x "$s" ] || { ci_err "missing/not executable: $s"; _sf_fail=1; }
        grep -q 'stage_main' "$s" 2>/dev/null || { ci_err "no stage_main in $s"; _sf_fail=1; }
    done

    ci_info "selftest (3/15): test-stage lane contract (lanes + flags present)"
    # The SDK/satellite/static-lint lanes (F-wave enterprise coverage): the
    # lane functions must exist in the test stage and their required-by-
    # default flags in pipeline.conf — checked the same way the stage
    # contract above is, so a refactor cannot silently drop a lane.
    _ts="$CI_DIR/stages/test.sh"
    for fn in run_sdk_tests run_satellite_crates run_static_lint_gates \
              run_pre_commit_lane provision_contrast_node_modules \
              run_dogfood_lane \
              lane_tool_status provision_composer_vendor provision_sdk_python_venv; do
        grep -q "$fn()" "$_ts" 2>/dev/null || { ci_err "test stage lost lane/helper: $fn"; _sf_fail=1; }
    done
    for fl in CI_SDK_CHECK CI_SATELLITE_CHECK CI_STATIC_LINT_CHECK CI_SDK_VENV_DIR \
              CI_PRE_COMMIT_CHECK CI_CONTRAST_GATE_CHECK \
              CI_DOGFOOD_CHECK CI_DOGFOOD_LIVE; do
        grep -q "$fl" "$CI_DIR/pipeline.conf" 2>/dev/null \
            || { ci_err "pipeline.conf lost flag: $fl"; _sf_fail=1; }
    done
    [ -f "$REPO_ROOT/.hadolint.yaml" ] \
        || { ci_err ".hadolint.yaml missing (hadolint gate config)"; _sf_fail=1; }

    # 2026-09-10 enterprise lanes: the artifacts the new gates depend on must
    # exist and be well-formed — checked statically so the selftest stays
    # infrastructure-free, exactly like the sections around it.
    ci_info "selftest (4/15): enterprise-lane artifacts (coverage baseline, migration lint, deny/trivy triage)"
    _base=$CI_ROOT/coverage-baseline.txt
    if [ ! -f "$_base" ]; then
        ci_err "missing ci/coverage-baseline.txt (coverage ratchet gate)"
        _sf_fail=1
    else
        _base_v=$(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$_base" | head -n 1)
        case $_base_v in
            ''|*[!0-9.]*) ci_err "invalid baseline '$_base_v' in $_base (expected a single float)"; _sf_fail=1 ;;
        esac
    fi
    [ -f "$REPO_ROOT/services/mail-server/deny.toml" ] \
        || { ci_err "missing services/mail-server/deny.toml (cargo-deny licenses gate)"; _sf_fail=1; }
    [ -f "$REPO_ROOT/trivy-secret.yaml" ] \
        || { ci_err "missing trivy-secret.yaml (trivy fs secret triage)"; _sf_fail=1; }
    [ -f "$REPO_ROOT/.trivyignore" ] \
        || { ci_err "missing .trivyignore (trivy vulnerability triage)"; _sf_fail=1; }
    for _flag in CI_SEMGREP_CHECK CI_TRIVY_FS_CHECK CI_COVERAGE_CHECK CI_MIGRATION_LINT_CHECK; do
        grep -q "{$_flag:=" "$CI_ROOT/pipeline.conf" 2>/dev/null \
            || { ci_err "pipeline.conf does not define $_flag"; _sf_fail=1; }
    done
    if command -v python3 >/dev/null 2>&1; then
        # Syntax-check the migration linter, then RUN it: it is a pure static
        # check over the tracked SQL chain (~1s, no infrastructure), so the
        # selftest proves the lane end-to-end.
        python3 -m py_compile "$REPO_ROOT/tools/migration_lint.py" 2>/dev/null \
            || { ci_err "tools/migration_lint.py does not compile"; _sf_fail=1; }
        if ! python3 "$REPO_ROOT/tools/migration_lint.py" >/dev/null 2>&1; then
            ci_err "migration SQL lint reports violations (run: python3 tools/migration_lint.py)"
            _sf_fail=1
        fi
    else
        ci_warn "python3 missing — migration-lint selftest skipped"
    fi

    ci_info "selftest (5/15): full dry-run through the real runner"
    if ! "$CI_DIR/pipeline.sh" run --dry-run --stages "$CI_STAGES" --lock-wait 10; then
        ci_err "dry-run pipeline run failed"
        _sf_fail=1
    fi

    ci_info "selftest (6/15): manifest + per-stage logs of the dry run are valid"
    _latest=$(cd "$RUNS_DIR" 2>/dev/null && \
        ls -1d [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]* 2>/dev/null \
        | sort -r | head -1 || true)
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

    ci_info "selftest (7/15): timeout wrapper stops a runaway command"
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

    ci_info "selftest (8/15): run lock excludes a concurrent holder"
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

    ci_info "selftest (9/15): RUSTSEC ledger lockstep (audit SM14 F11)"
    # CI_CARGO_AUDIT_IGNORES (pipeline.conf) mirrors
    # services/mail-server/deny.toml [advisories].ignore EXACTLY. The lists
    # only LOOK equal to a naive grep (pipeline.conf mentions IDs in
    # comments); this assertion parses BOTH and fails on any drift.
    if command -v awk >/dev/null 2>&1 && [ -f "$REPO_ROOT/services/mail-server/deny.toml" ]; then
        _sl_deny_ids=$(awk '
            /^\[advisories\]/   { in_adv = 1; next }
            /^\[/               { in_adv = 0 }
            in_adv && /^ignore = \[/ { in_ign = 1; next }
            in_adv && in_ign && /^\]/ { in_ign = 0 }
            in_adv && in_ign {
                line = $0
                while (match(line, /"(RUSTSEC|CVE|GHSA)-[A-Za-z0-9.-]+"/)) {
                    print substr(line, RSTART + 1, RLENGTH - 2)
                    line = substr(line, RSTART + RLENGTH)
                }
            }' "$REPO_ROOT/services/mail-server/deny.toml" | sort)
        _sl_conf_ids=$(printf '%s\n' $CI_CARGO_AUDIT_IGNORES | sort)
        _sl_a=$(mktemp "${TMPDIR:-/tmp}/apexmail-selftest.XXXXXX")
        _sl_b=$(mktemp "${TMPDIR:-/tmp}/apexmail-selftest.XXXXXX")
        printf '%s\n' "$_sl_deny_ids" >"$_sl_a"
        printf '%s\n' "$_sl_conf_ids" >"$_sl_b"
        if cmp -s "$_sl_a" "$_sl_b"; then
            _sl_n=$(printf '%s\n' "$_sl_deny_ids" | grep -c . || true)
            ci_info "PASS: RUSTSEC ledgers in EXACT lockstep ($_sl_n entries)"
        else
            ci_err "RUSTSEC ledgers DIVERGED: services/mail-server/deny.toml \
[advisories].ignore vs CI_CARGO_AUDIT_IGNORES (pipeline.conf) — restore EXACT \
lockstep (CI_CARGO_AUDIT_IGNORES in pipeline.conf). '-' = deny.toml, '+' = pipeline.conf:"
            diff -u "$_sl_a" "$_sl_b" >&2 || true
            _sf_fail=1
        fi
        rm -f "$_sl_a" "$_sl_b"
        # Fourth ledger (audit P3): scripts/security-audit.sh carries its own
        # --ignore list (the pre-commit hook path) and nothing asserted it
        # matched. Parse its RUSTSEC ids and require the same lockstep.
        if [ -f "$REPO_ROOT/scripts/security-audit.sh" ]; then
            _sl_hook_ids=$(grep -oE '(RUSTSEC|CVE|GHSA)-[A-Za-z0-9.-]+' \
                "$REPO_ROOT/scripts/security-audit.sh" | sort -u)
            _sl_c=$(mktemp "${TMPDIR:-/tmp}/apexmail-selftest.XXXXXX")
            _sl_d=$(mktemp "${TMPDIR:-/tmp}/apexmail-selftest.XXXXXX")
            printf '%s\n' "$_sl_hook_ids" >"$_sl_c"
            printf '%s\n' "$_sl_conf_ids" >"$_sl_d"
            if cmp -s "$_sl_c" "$_sl_d"; then
                ci_info "PASS: scripts/security-audit.sh ledger matches CI_CARGO_AUDIT_IGNORES"
            else
                ci_err "RUSTSEC ledgers DIVERGED: scripts/security-audit.sh --ignore \
list vs CI_CARGO_AUDIT_IGNORES (pipeline.conf) — restore EXACT lockstep"
                diff -u "$_sl_c" "$_sl_d" >&2 || true
                _sf_fail=1
            fi
            rm -f "$_sl_c" "$_sl_d"
        fi
    else
        ci_warn "deny.toml missing — RUSTSEC lockstep selftest skipped"
    fi

    ci_info "selftest (10/15): blessing contract (audit SM14 F3 outcomes + P1 membership)"
    # A .last-good-sha blessing must require every required stage to have
    # ACTUALLY finished ok: advisory-fail/skip/timeout/fail/not-run can never
    # bless, and passedStages is derived from the real statuses.
    if blessing_refused_reason validate=ok ui=ok test=ok security=ok >/dev/null; then
        ci_err "blessing contract: refused an all-ok run"
        _sf_fail=1
    fi
    for _bl_bad in advisory-fail skip timeout fail not-run unchanged; do
        if ! blessing_refused_reason validate=ok ui=ok test=ok "security=$_bl_bad" >/dev/null; then
            ci_err "blessing contract: ALLOWED a blessing with security=$_bl_bad"
            _sf_fail=1
        fi
    done
    _bl_json=$(blessing_passed_json validate=ok ui=ok test=ok security=ok)
    [ "$_bl_json" = '["validate","ui","test","security"]' ] \
        || { ci_err "blessing contract: passedStages JSON wrong: $_bl_json"; _sf_fail=1; }
    _bl_json=$(blessing_passed_json validate=ok ui=skip test=ok security=ok)
    [ "$_bl_json" = '["validate","test","security"]' ] \
        || { ci_err "blessing contract: passedStages must only list ACTUAL ok stages, got: $_bl_json"; _sf_fail=1; }

    # Membership (audit P1, re-scoped by the split CI model 2026-10-16): the
    # DEPLOY line must be fully exercised before it can write .last-good-sha,
    # so a gates-only run must report the deploy stages missing; both the
    # deploy line and the gate line must accept their own full runs.
    _bl_saved_stages=$CI_STAGES
    CI_STAGES='fetch,images,migrate,deploy,verify,notify'
    _bl_gates_only=$(blessing_membership_missing "validate ui test security" || true)
    for _bl_need in images migrate deploy verify; do
        printf '%s\n' "$_bl_gates_only" | grep -qx "$_bl_need" \
            || { ci_err "blessing membership: a gates-only run did NOT report '$_bl_need' as missing on the deploy line"; _sf_fail=1; }
    done
    _bl_full=$(printf '%s' "$CI_STAGES" | tr ',' ' ')
    if blessing_membership_missing "$_bl_full" >/dev/null; then
        ci_err "blessing membership: the FULL deploy line was reported incomplete"
        _sf_fail=1
    fi
    CI_STAGES=$_bl_saved_stages
    _bl_full=$(printf '%s' "$CI_STAGES" | tr ',' ' ')
    if blessing_membership_missing "$_bl_full" >/dev/null; then
        ci_err "blessing membership: the full gate line was reported incomplete"
        _sf_fail=1
    fi

    # Gate-blessing contract (the split model): an empty runs dir, a blessing
    # for another sha, a stale pipeline-config hash and a non-ok gate stage
    # must all refuse; a fresh, complete blessing for HEAD under the CURRENT
    # config must allow. Exercised against the real gate_blessing_refusal.
    _gbb_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-gate-bless.XXXXXX")
    # Every sub-lane row of required-lanes.txt recorded ok — what a real
    # green run's blessing carries (built from the file, so this fixture
    # tracks the ledger instead of drifting from it). Signed with an
    # EPHEMERAL key so the I20 verification path is exercised for real.
    _gbb_all_ok=$(sed -e '/^#/d' -e '/^$/d' "$CI_DIR/required-lanes.txt" |
        grep '\.' | sed 's/$/=ok/' | paste -sd, -)
    _gbb_saved_key=${CI_BLESSING_SIGNING_KEY:-}
    CI_BLESSING_SIGNING_KEY=selftest-ephemeral-blessing-key
    export CI_BLESSING_SIGNING_KEY
    _gbb_now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    _gbb_hash=$(ci_pipeline_config_hash)
    _gbb_stages="fetch=ok,validate=ok,docs=ok,ui=ok,test=ok,security=ok"
    _gbb_sign() {
        ci_blessing_sign "$(ci_blessing_canonical deadbeef "$_gbb_hash" "$_gbb_stages" "$1" "$2")"
    }
    _gbb_write() { # <lanes> <completedAt> [signature]
        printf '{"sha":"deadbeef","pipelineConfigHash":"%s","gateStagesStatuses":"%s","requiredLanesStatuses":"%s","signature":"%s","machine":"t","completedAt":"%s"}\n' \
            "$_gbb_hash" "$_gbb_stages" "$1" "${3:-}" "$2" >"$_gbb_tmp/.gate-blessing.json"
    }
    _gbb_tmp=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-gate-bless.XXXXXX")
    if ! gate_blessing_refusal "$_gbb_tmp" deadbeef >/dev/null; then
        ci_err "gate blessing: an EMPTY runs dir was accepted"
        _sf_fail=1
    fi
    # complete, signed, fresh => ACCEPTED
    _gbb_write "$_gbb_all_ok" "$_gbb_now" "$(_gbb_sign "$_gbb_all_ok" "$_gbb_now")"
    if gate_blessing_refusal "$_gbb_tmp" deadbeef >/dev/null; then
        ci_err "gate blessing: a fresh signed complete blessing for HEAD was refused"
        _sf_fail=1
    fi
    # wrong sha => refused
    if ! gate_blessing_refusal "$_gbb_tmp" cafebabe >/dev/null; then
        ci_err "gate blessing: a blessing for ANOTHER sha was accepted for HEAD"
        _sf_fail=1
    fi
    # stale config hash => refused
    _gbb_saved_hash=$_gbb_hash
    _gbb_hash=stale
    _gbb_write "$_gbb_all_ok" "$_gbb_now" "$(_gbb_sign "$_gbb_all_ok" "$_gbb_now")"
    if ! gate_blessing_refusal "$_gbb_tmp" deadbeef >/dev/null; then
        ci_err "gate blessing: a blessing under a STALE pipeline config was accepted"
        _sf_fail=1
    fi
    _gbb_hash=$_gbb_saved_hash
    # failing stage => refused
    _gbb_stages_bad="fetch=ok,validate=ok,docs=ok,ui=ok,test=advisory-fail,security=ok"
    printf '{"sha":"deadbeef","pipelineConfigHash":"%s","gateStagesStatuses":"%s","requiredLanesStatuses":"%s","signature":"%s","machine":"t","completedAt":"%s"}\n' \
        "$_gbb_hash" "$_gbb_stages_bad" "$_gbb_all_ok" \
        "$(ci_blessing_sign "$(ci_blessing_canonical deadbeef "$_gbb_hash" "$_gbb_stages_bad" "$_gbb_all_ok" "$_gbb_now")")" \
        "$_gbb_now" >"$_gbb_tmp/.gate-blessing.json"
    if ! gate_blessing_refusal "$_gbb_tmp" deadbeef >/dev/null; then
        ci_err "gate blessing: a blessing with test=advisory-fail was accepted"
        _sf_fail=1
    fi
    # one required lane failed => refused
    _gbb_one_bad=$(printf '%s' "$_gbb_all_ok" | sed 's/validate.stub-ban=ok/validate.stub-ban=fail/')
    _gbb_write "$_gbb_one_bad" "$_gbb_now" "$(_gbb_sign "$_gbb_one_bad" "$_gbb_now")"
    if ! gate_blessing_refusal "$_gbb_tmp" deadbeef >/dev/null; then
        ci_err "gate blessing: a blessing with validate.stub-ban=fail was accepted"
        _sf_fail=1
    fi
    # unsigned => refused (I20)
    _gbb_write "$_gbb_all_ok" "$_gbb_now" ""
    if ! gate_blessing_refusal "$_gbb_tmp" deadbeef >/dev/null; then
        ci_err "gate blessing: an UNSIGNED blessing was accepted"
        _sf_fail=1
    fi
    # tampered lanes (signature over the ORIGINAL lanes) => refused (I20)
    _gbb_write "$_gbb_all_ok" "$_gbb_now" "$(_gbb_sign "$_gbb_one_bad" "$_gbb_now")"
    if ! gate_blessing_refusal "$_gbb_tmp" deadbeef >/dev/null; then
        ci_err "gate blessing: a TAMPERED blessing (signature/content mismatch) was accepted"
        _sf_fail=1
    fi
    # stale completedAt => refused (I20 anti-replay)
    _gbb_old="2020-01-01T00:00:00Z"
    _gbb_write "$_gbb_all_ok" "$_gbb_old" "$(_gbb_sign "$_gbb_all_ok" "$_gbb_old")"
    if ! gate_blessing_refusal "$_gbb_tmp" deadbeef >/dev/null; then
        ci_err "gate blessing: a STALE blessing (anti-replay window exceeded) was accepted"
        _sf_fail=1
    fi
    # no key on the verifying host => everything refused (fail closed)
    CI_BLESSING_SIGNING_KEY=
    unset CI_BLESSING_SIGNING_KEY
    _gbb_write "$_gbb_all_ok" "$_gbb_now" "$(_gbb_sign_noop="")" ""
    if ! gate_blessing_refusal "$_gbb_tmp" deadbeef >/dev/null; then
        ci_err "gate blessing: a blessing was accepted on a host with NO signing key"
        _sf_fail=1
    fi
    CI_BLESSING_SIGNING_KEY=$_gbb_saved_key
    export CI_BLESSING_SIGNING_KEY
    rm -rf "$_gbb_tmp"

    # Synthetic-repository / runtime-policy fixtures (ci/tests/*.selftest.sh):
    # each one extracts the REAL functions from the stage under test and runs
    # them against a throwaway fixture. All five are wired below — before
    # 2026-10-13 only the rollback contract was, and the other four silently
    # rotted (their HEAD-anchored teeth probes kept comparing against a HEAD
    # that had meanwhile absorbed the fixes).
    selftest_contract 11 15 "verify-stage rollback contract (synthetic image fixture)" \
        "$CI_DIR/tests/rollback-selftest.sh"
    selftest_contract 12 15 "fetch-stage history + pushed-HEAD contract (synthetic repository fixture)" \
        "$CI_DIR/tests/fetch-selftest.sh"
    selftest_contract 13 15 "security-stage gitleaks full-history guard (shallow-clone fixture)" \
        "$CI_DIR/tests/gitleaks-shallow-selftest.sh"
    selftest_contract 14 15 "REQUIRED-lane missing-runtime policy (empty-PATH fixture)" \
        "$CI_DIR/tests/missing-runtime-selftest.sh"
    selftest_contract 15 15 "validate-stage backup-service coverage (synthetic input fixture)" \
        "$CI_DIR/tests/validate-coverage-selftest.sh"

    if [ "$_sf_fail" -eq 0 ]; then
        ci_info "selftest: ALL OK"
        exit "$CI_EXIT_OK"
    fi
    ci_err "selftest: FAILED"
    exit "$CI_EXIT_FAIL"
}

# --- push-blessing (the split CI model, 2026-10-16) ---------------------------------
# cmd_push_blessing <ssh-target> — copy this machine's .gate-blessing.json to
# the deploy host's runs dir, where the deploy-side fetch stage reads it.
# Nothing is deployed by this command; it only delivers the gate evidence.
cmd_push_blessing() {
    _pb_target=${1:-}
    if [ -z "$_pb_target" ]; then
        ci_err "usage: ci/pipeline.sh push-blessing <ssh-target>  (e.g. root@95.216.226.51)"
        exit "$CI_EXIT_FAIL"
    fi
    _pb_file=$RUNS_DIR/.gate-blessing.json
    if [ ! -f "$_pb_file" ]; then
        ci_err "no $_pb_file — run the gate line green on this machine first (ci/pipeline.sh run)"
        exit "$CI_EXIT_FAIL"
    fi
    _pb_sha=$(sed -n 's/.*"sha":"\([^"]*\)".*/\1/p' "$_pb_file" | head -n1)
    _pb_dest="${CI_DEPLOY_DIR:-/opt/apexmail}/ci/runs/.gate-blessing.json"
    ci_info "pushing gate blessing for ${_pb_sha:-?} to $_pb_target:$_pb_dest"
    scp -q "$_pb_file" "$_pb_target:$_pb_dest" \
        || { ci_err "scp failed ($_pb_target) — is ssh reachable from this machine?"; exit "$CI_EXIT_FAIL"; }
    ci_info "gate blessing delivered — the deploy host's next timer tick deploys $_pb_sha"
    exit "$CI_EXIT_OK"
}

# --- entry -------------------------------------------------------------------------
case "${1:-}" in
    run)      shift; cmd_run "$@" ;;
    status)   shift; cmd_status "$@" ;;
    list)     shift; cmd_list "$@" ;;
    selftest) shift; cmd_selftest "$@" ;;
    push-blessing) shift; cmd_push_blessing "$@" ;;
    -h|--help|help|'') usage 0 ;;
    *)        usage 1 ;;
esac
