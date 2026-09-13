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
# host-only gate in a container), 1 failure. The stage's own log is echoed so
# the executor's step output shows the real gate output.
# =============================================================================
set -eu

REPO_ROOT=${CI_WORKSPACE:-$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)}
export REPO_ROOT
CI_ROOT=$REPO_ROOT/ci
export CI_ROOT

[ "$#" -ge 1 ] || { echo "usage: $0 <stage> [stage...]" >&2; exit 2; }

# A run directory per invocation, mirroring ci/runs/<UTC-ts>/.
_stamp=$(date -u +%Y%m%dT%H%M%SZ)
RUN_DIR=${CI_RUN_DIR:-$CI_ROOT/runs/$_stamp}
mkdir -p "$RUN_DIR/stages"
export RUN_DIR

export CI_REF=${CI_REF:-${CI_COMMIT_BRANCH:-main}}
export CI_SHA=${CI_SHA:-${CI_COMMIT_SHA:-}}
export CI_DEPLOY_DIR=${CI_DEPLOY_DIR:-/opt/apexmail}
export CI_DRY_RUN=${CI_DRY_RUN:-0}
# Executor containers are NOT the deploy host: host-only stages skip (75)
# instead of failing, exactly as they do on a developer machine.
export CI_ADVISORY_STAGES=${CI_ADVISORY_STAGES:-}

# pipeline.conf holds the stage list, timeouts and every gate flag. It is
# POSIX sh and is safe to source repeatedly.
. "$CI_ROOT/pipeline.conf"

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
    echo "── stage [$_stage] ─────────────────────────────────────────────"
    _stage_rc=0
    sh "$_script" >>"$CI_STAGE_LOG" 2>&1 || _stage_rc=$?
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
        *)
            echo "── stage [$_stage]: FAILED (exit $_stage_rc) ───────────────" >&2
            _rc=1
            ;;
    esac
done
exit "$_rc"
