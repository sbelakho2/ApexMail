#!/bin/sh
# =============================================================================
# ci/woodpecker/stage.sh — run ONE ci/ stage inside a CI executor container.
# =============================================================================
# Woodpecker (https://woodpecker-ci.org) starts each step as a container with
# the repository cloned into the workspace. The gates themselves are NOT
# reimplemented in YAML: this wrapper reconstructs the environment
# `ci/pipeline.sh` gives a stage (see the stage contract at the top of
# pipeline.sh) and runs the same script the host pipeline runs, so the
# executor and the deploy host can never drift.
#
# Usage:  ci/woodpecker/stage.sh <validate|test|security> [more stages...]
#
# Exit codes: 0 ok (including a stage that legitimately SKIPS, e.g. a
# host-only gate in a container), 1 failure (a stage TIMEOUT is a failure —
# same contract as the host path). The stage's own log is echoed so the
# executor's step output shows the real gate output.
#
# Audit SM14 F4: the executor path used to run the stage script BARE
# (`sh "$_script"`), silently dropping the timeout contract the host runner
# enforces (ci_timeout + the CI_TIMEOUT_* budgets; exit 124 = timeout) — a
# hung nextest/cargo run parked the pipeline indefinitely. It now wraps the
# stage in the SAME ci_timeout with the SAME budgets, via lib.sh.
#
# Audit SM14 F14: ONE run dir per PIPELINE (ci/runs/wp<pipeline-number>,
# resolved by ci/woodpecker/run-dir.sh so the notify-github steps grep
# exactly this pipeline's logs), and the notify stage never runs on the
# executor path — so this wrapper prunes the wp* run dirs itself
# (ci_prune_wp_runs) the way ci_prune_runs bounds ci/runs/ on the host.
# =============================================================================
set -eu

REPO_ROOT=${CI_WORKSPACE:-$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)}
export REPO_ROOT
CI_ROOT=$REPO_ROOT/ci
export CI_ROOT

[ "$#" -ge 1 ] || { echo "usage: $0 <stage> [stage...]" >&2; exit 2; }

# lib.sh provides ci_timeout, the CI_EXIT_* contract and the pipeline
# defaults (pipeline.conf is sourced inside it, idempotently — the
# CI_TIMEOUT_* budgets below come from there, exactly like the host path).
# shellcheck source=../lib.sh
. "$CI_ROOT/lib.sh"

# A run directory per PIPELINE, not per invocation (audit SM14 F14): every
# step of pipeline N resolves the identical ci/runs/wp<N>, and the
# notify-github steps in .woodpecker.yml source the same file to grep ONLY
# this pipeline's stage logs (Woodpecker steps are separate containers, so
# exported variables do not survive between steps — the file is the shared
# definition).
# shellcheck source=run-dir.sh
. "$CI_ROOT/woodpecker/run-dir.sh"
RUN_DIR=${CI_RUN_DIR:-$WP_RUN_DIR}
mkdir -p "$RUN_DIR/stages"
export RUN_DIR

export CI_REF=${CI_REF:-${CI_COMMIT_BRANCH:-main}}
export CI_SHA=${CI_SHA:-${CI_COMMIT_SHA:-}}
export CI_DEPLOY_DIR=${CI_DEPLOY_DIR:-/opt/apexmail}
export CI_DRY_RUN=${CI_DRY_RUN:-0}
# Executor containers are NOT the deploy host: host-only stages skip (75)
# instead of failing, exactly as they do on a developer machine.
export CI_ADVISORY_STAGES=${CI_ADVISORY_STAGES:-}

_rc=0
for _stage in "$@"; do
    _script=$CI_ROOT/stages/$_stage.sh
    if [ ! -f "$_script" ]; then
        echo "FAIL: no such stage script: $_script" >&2
        _rc=1
        continue
    fi
    CI_STAGE_NAME=$_stage
    CI_STAGE_LOG=$RUN_DIR/stages/$_stage.log
    export CI_STAGE_NAME CI_STAGE_LOG
    : >"$CI_STAGE_LOG"
    # The SAME per-stage budget the host runner enforces (CI_TIMEOUT_<stage>
    # from pipeline.conf; default 600s) — audit SM14 F4.
    _stage_tmo=600
    eval "_stage_tmo=\${CI_TIMEOUT_$_stage:-600}"
    echo "── stage [$_stage] (timeout ${_stage_tmo}s) ────────────────────"
    _stage_rc=0
    ci_timeout "$_stage_tmo" sh "$_script" >>"$CI_STAGE_LOG" 2>&1 || _stage_rc=$?
    # Always show the gate output: on success it is the evidence, on failure
    # it is the diagnosis.
    cat "$CI_STAGE_LOG"
    case $_stage_rc in
        0)
            echo "── stage [$_stage]: OK ─────────────────────────────────────"
            ;;
        75)
            # CI_EXIT_SKIP: the stage is intentionally not applicable here
            # (e.g. a deploy-host-only gate). A skip is not a failure.
            echo "── stage [$_stage]: SKIPPED (not applicable in this environment) ──"
            ;;
        124)
            # CI_EXIT_TIMEOUT: ci_timeout killed the stage at its budget —
            # a timeout is a FAILURE (the host path reports it identically).
            echo "── stage [$_stage]: TIMEOUT after ${_stage_tmo}s ──────────" >&2
            _rc=1
            ;;
        *)
            echo "── stage [$_stage]: FAILED (exit $_stage_rc) ───────────────" >&2
            _rc=1
            ;;
    esac
done

# The notify stage owns ci/runs pruning on the host path but NEVER runs on
# the Woodpecker pipeline, so the executor prunes its own wp* run dirs here
# (newest CI_KEEP_RUNS kept; the CURRENT run dir is never deleted) — audit
# SM14 F14.
ci_prune_wp_runs "${CI_KEEP_RUNS:-30}"

exit "$_rc"
