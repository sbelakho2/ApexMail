#!/bin/sh
# =============================================================================
# ci/tests/validate-coverage-selftest.sh — fixture for the backup-service
# coverage check in ci/stages/validate.sh (audit P2 item 7).
# =============================================================================
# Runs the REAL backup_service_coverage() extracted from validate.sh against
# synthetic copies of the three input files:
#
#   1. the current tree PASSES (every *-backup compose service is in both
#      STACK_SERVICES and VERIFY_SERVICES);
#   2. removing a backup service from the deploy list FAILS;
#   3. removing it from the verify list FAILS;
#   4. TEETH: at HEAD the two lists did not cover redis-backup/
#      analytics-backup and no checker existed — the silent-never-run bug.
# =============================================================================
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
_work=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-coverage-selftest.XXXXXX")
trap 'rm -rf "$_work"' EXIT

_fail=0
_ok()  { printf 'ok   %s\n' "$*"; }
_bad() { printf 'FAIL %s\n' "$*" >&2; _fail=$((_fail + 1)); }

_fixture="$_work/fixture"
mkdir -p "$_fixture/repo" "$_fixture/ci/stages"
cp "$REPO_ROOT/docker-compose.prod.yml" "$_fixture/repo/docker-compose.prod.yml"
cp "$REPO_ROOT/ci/stages/deploy.sh" "$_fixture/ci/stages/deploy.sh"
cp "$REPO_ROOT/ci/stages/verify.sh" "$_fixture/ci/stages/verify.sh"

sed -n '/^backup_service_coverage()/,/^}/p' "$REPO_ROOT/ci/stages/validate.sh" > "$_work/check.sh"
if ! grep -q '^backup_service_coverage()' "$_work/check.sh"; then
    _bad "could not extract backup_service_coverage() from validate.sh"
fi

_run_check() { # returns the function's exit code; output in $_work/check.log
    REPO_ROOT="$_fixture/repo" CI_ROOT="$_fixture/ci" /bin/sh -c '
        set -eu
        CI_EXIT_OK=0; CI_EXIT_FAIL=1
        ci_info() { printf "[info] %s\n" "$*"; }
        ci_err()  { printf "[ERROR] %s\n" "$*" >&2; }
        . "'"$_work"'/check.sh"
        backup_service_coverage
    ' >"$_work/check.log" 2>&1
}

# --- 1. current tree passes --------------------------------------------------
_rc=0; _run_check || _rc=$?
if [ "$_rc" -eq 0 ] && grep -q 'PASS: backup-service coverage' "$_work/check.log"; then
    _ok "coverage: current lists cover every *-backup compose service"
else
    _bad "coverage: the current tree FAILS its own check — $(tail -3 "$_work/check.log")"
fi

# --- 2. deploy list missing a backup service ---------------------------------
cp "$REPO_ROOT/ci/stages/deploy.sh" "$_fixture/ci/stages/deploy.sh"
sed -i '' 's/redis-backup analytics-backup/analytics-backup/' "$_fixture/ci/stages/deploy.sh" 2>/dev/null \
    || sed -i 's/redis-backup analytics-backup/analytics-backup/' "$_fixture/ci/stages/deploy.sh"
_rc=0; _run_check || _rc=$?
if [ "$_rc" -ne 0 ] && grep -q "backup service 'redis-backup' is in docker-compose.prod.yml but NOT in ci/stages/deploy.sh" "$_work/check.log"; then
    _ok "coverage: a backup service missing from STACK_SERVICES fails the check"
else
    _bad "coverage: did not catch the missing deploy-list entry (exit $_rc)"
fi

# --- 3. verify list missing a backup service ---------------------------------
cp "$REPO_ROOT/ci/stages/deploy.sh" "$_fixture/ci/stages/deploy.sh"
cp "$REPO_ROOT/ci/stages/verify.sh" "$_fixture/ci/stages/verify.sh"
sed -i '' 's/redis-backup analytics-backup/redis-backup/' "$_fixture/ci/stages/verify.sh" 2>/dev/null \
    || sed -i 's/redis-backup analytics-backup/redis-backup/' "$_fixture/ci/stages/verify.sh"
_rc=0; _run_check || _rc=$?
if [ "$_rc" -ne 0 ] && grep -q "backup service 'analytics-backup' is in docker-compose.prod.yml but NOT in ci/stages/verify.sh" "$_work/check.log"; then
    _ok "coverage: a backup service missing from VERIFY_SERVICES fails the check"
else
    _bad "coverage: did not catch the missing verify-list entry (exit $_rc)"
fi
cp "$REPO_ROOT/ci/stages/verify.sh" "$_fixture/ci/stages/verify.sh"

# --- 4. teeth: the PRE-FIX revision had the gap and no checker ---------------
# The fix is committed, so HEAD no longer reproduces the bug — the teeth probe
# anchors on the PARENT of the commit that introduced the checker (resolved
# dynamically via -S; no hardcoded sha). A shallow or absent history skips
# loudly instead of failing on a premise it cannot test.
_teeth_rev=''
if command -v git >/dev/null 2>&1; then
    _teeth_fix=$(git -C "$REPO_ROOT" log --format=%H -S 'backup_service_coverage' \
        -- ci/stages/validate.sh 2>/dev/null | tail -n 1)
    if [ -n "$_teeth_fix" ]; then
        _teeth_rev=$(git -C "$REPO_ROOT" rev-parse -q --verify "${_teeth_fix}^" 2>/dev/null) || _teeth_rev=''
    fi
fi
if [ -n "$_teeth_rev" ]; then
    if git -C "$REPO_ROOT" show "${_teeth_rev}:ci/stages/validate.sh" | grep -q 'backup_service_coverage'; then
        _bad "teeth: pre-fix revision $_teeth_rev already carried the coverage check"
    else
        _ok "teeth: pre-fix revision had no backup-service coverage check"
    fi
    if git -C "$REPO_ROOT" show "${_teeth_rev}:ci/stages/deploy.sh" | sed -n '/^STACK_SERVICES=/,/"$/p' | grep -q 'redis-backup'; then
        _bad "teeth: pre-fix STACK_SERVICES unexpectedly listed redis-backup"
    else
        _ok "teeth: pre-fix STACK_SERVICES omitted redis-backup/analytics-backup (bug reproduced)"
    fi
else
    echo "skip teeth probe: pre-fix revision not resolvable (shallow or absent history)" >&2
fi

if [ "$_fail" -eq 0 ]; then
    echo "validate-coverage-selftest: ALL OK"
    exit 0
fi
echo "validate-coverage-selftest: $_fail assertion(s) FAILED" >&2
exit 1
