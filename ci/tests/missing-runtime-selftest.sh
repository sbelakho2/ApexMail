#!/bin/sh
# =============================================================================
# ci/tests/missing-runtime-selftest.sh — fixture for the REQUIRED lanes'
# missing-runtime policy (audit P2 item 8).
# =============================================================================
# Proves lane_tool_status() (ci/lib.sh) fails closed for a REQUIRED lane and
# honours the explicit advisory override, that the fixed stages route their
# python3/zola lanes through it, and that the pre-fix ui.sh guard silently
# returned success when python3 was absent (teeth).
#
# python3 is hidden by running the functions with PATH pointed at an empty
# directory (command -v / test / printf are shell builtins, so the shim
# needs no external tooling).
# =============================================================================
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
CI_ROOT=$REPO_ROOT/ci
_work=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-missing-runtime-selftest.XXXXXX")
trap 'rm -rf "$_work"' EXIT
mkdir -p "$_work/empty-path"

_fail=0
_ok()  { printf 'ok   %s\n' "$*"; }
_bad() { printf 'FAIL %s\n' "$*" >&2; _fail=$((_fail + 1)); }

# lane_tool_status with python3 unavailable. REPO_ROOT must be pre-set so
# lib.sh skips its `dirname`-based derivation (the empty PATH).
_run_lane() { # <flag> [CI_MISSING_TOOLS]
    _flag=$1 _missing=${2:-}
    PATH="$_work/empty-path" CI_ROOT="$CI_ROOT" CI_REPO_ROOT="$REPO_ROOT" \
        CI_MISSING_TOOLS="${_missing}" CI_DEPLOY_DIR=/nonexistent-ci-deploy-dir \
        /bin/sh -c '
            set -eu
            . "$CI_ROOT/lib.sh"
            lane_tool_status python3 test-lane "'"$_flag"'"
        ' 2>"$_work/lane.err"
}

_out="$(_run_lane required || true)"
if [ "$_out" = fail ]; then
    _ok "lane_tool_status: REQUIRED lane reports fail when python3 is missing"
else
    _bad "lane_tool_status: REQUIRED lane reported '${_out:-empty}' instead of fail"
fi

_out="$(_run_lane advisory || true)"
if [ "$_out" = skip ]; then
    _ok "lane_tool_status: advisory override reports skip (bounded triage window)"
else
    _bad "lane_tool_status: advisory lane reported '${_out:-empty}' instead of skip"
fi

_rc=0
_run_lane required fail >/dev/null 2>&1 || _rc=$?
if [ "$_rc" -ne 0 ]; then
    _ok "lane_tool_status: CI_MISSING_TOOLS=fail dies on the spot (deploy-host fail closed)"
else
    _bad "lane_tool_status: CI_MISSING_TOOLS=fail did not hard-stop"
fi

# --- the fixed stages use the shared policy ---------------------------------
grep -q 'lane_tool_status python3 ui-gates' "$CI_ROOT/stages/ui.sh" \
    && _ok "ui.sh routes its python3 gates through lane_tool_status" \
    || _bad "ui.sh does not use lane_tool_status"
grep -q 'lane_tool_status python3 validate-python-gates' "$CI_ROOT/stages/validate.sh" \
    && _ok "validate.sh routes its python3 gates through lane_tool_status" \
    || _bad "validate.sh does not use lane_tool_status"
grep -q 'lane_tool_status python3 repo-python-gates' "$CI_ROOT/stages/test.sh" \
    && _ok "test.sh routes its python3 gates through lane_tool_status" \
    || _bad "test.sh does not use lane_tool_status"
grep -q 'lane_tool_status python3 i18n-gate' "$CI_ROOT/stages/test.sh" \
    && _ok "test.sh i18n gate uses lane_tool_status + the pinned ci_zola" \
    || _bad "test.sh i18n gate still warn-skips"
grep -q 'ci_zola 2>/dev/null' "$CI_ROOT/stages/test.sh" \
    && _ok "test.sh i18n gate uses the pinned ci_zola" \
    || _bad "test.sh i18n gate still shells out to the host zola"
grep -q 'CI_MARKETING_VALIDATION:-required' "$CI_ROOT/stages/validate.sh" \
    && _ok "validate.sh zola gates fail closed when the marketing validation is REQUIRED" \
    || _bad "validate.sh zola gates still warn-skip"

# --- teeth: the pre-fix ui.sh guard returned success without python3 ---------
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" cat-file -e HEAD:ci/stages/ui.sh 2>/dev/null; then
    git -C "$REPO_ROOT" show HEAD:ci/stages/ui.sh > "$_work/old-ui.sh"
    sed -n '/command -v python3 >\/dev\/null 2>&1 || {/,/^    }$/p' "$_work/old-ui.sh" > "$_work/old-guard-body.sh"
    if [ -s "$_work/old-guard-body.sh" ]; then
        {
            printf 'old_guard() {\n'
            cat "$_work/old-guard-body.sh"
            printf '}\n'
        } > "$_work/old-guard.sh"
        _rc=0
        PATH="$_work/empty-path" CI_ROOT="$CI_ROOT" CI_REPO_ROOT="$REPO_ROOT" \
            CI_DEPLOY_DIR=/nonexistent-ci-deploy-dir \
            /bin/sh -c '
                set -eu
                CI_EXIT_OK=0
                ci_warn() { printf "[warn] %s\n" "$*" >&2; }
                . "'"$_work"'/old-guard.sh"
                old_guard
            ' >/dev/null 2>"$_work/old.err" || _rc=$?
        if [ "$_rc" -eq 0 ]; then
            _ok "teeth: pre-fix ui.sh guard returns 0 with python3 absent (silent skip reproduced)"
        else
            _bad "teeth: pre-fix guard unexpectedly failed (exit $_rc)"
        fi
        if grep -q 'all six ui gates skipped' "$_work/old.err"; then
            _ok "teeth: pre-fix guard logged the skip warning"
        else
            _bad "teeth: pre-fix guard produced no skip warning"
        fi
    else
        _bad "teeth: could not extract the pre-fix ui.sh guard"
    fi
else
    echo "skip teeth probe: git/HEAD:ci/stages/ui.sh unavailable" >&2
fi

if [ "$_fail" -eq 0 ]; then
    echo "missing-runtime-selftest: ALL OK"
    exit 0
fi
echo "missing-runtime-selftest: $_fail assertion(s) FAILED" >&2
exit 1
