#!/bin/sh
# =============================================================================
# ci/tests/gitleaks-shallow-selftest.sh — fixture for the security stage's
# full-history guard (audit P2 item 10).
# =============================================================================
# Runs the REAL gitleaks_history_guard() extracted from
# ci/stages/security.sh against a synthetic shallow clone and a full clone:
#
#   1. shallow + CI_GITLEAKS_CHECK=required (the default) FAILS the lane;
#   2. shallow + CI_GITLEAKS_CHECK=advisory continues with a warning (the
#      bounded triage override);
#   3. a full checkout passes the guard.
#
# No network: local file:// shallow clone under mktemp.
# =============================================================================
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
_work=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-gitleaks-selftest.XXXXXX")
trap 'rm -rf "$_work"' EXIT

_fail=0
_ok()  { printf 'ok   %s\n' "$*"; }
_bad() { printf 'FAIL %s\n' "$*" >&2; _fail=$((_fail + 1)); }

GIT="git -c user.email=selftest@example.invalid -c user.name=selftest -c commit.gpgsign=false"
mkdir -p "$_work/src"
$GIT -C "$_work/src" init -q -b main
printf 'one\n' > "$_work/src/f.txt"; $GIT -C "$_work/src" add f.txt; $GIT -C "$_work/src" commit -q -m one
printf 'two\n' > "$_work/src/f.txt"; $GIT -C "$_work/src" commit -qam two

sed -n '/^gitleaks_history_guard()/,/^}/p' "$REPO_ROOT/ci/stages/security.sh" > "$_work/guard.sh"
if ! grep -q '^gitleaks_history_guard()' "$_work/guard.sh"; then
    _bad "could not extract gitleaks_history_guard() from security.sh"
fi

_run_guard() { # <repo> <flag> ; returns guard's exit code, output in $_work/guard.log
    REPO_ROOT="$1" CI_GITLEAKS_CHECK="$2" bash -c '
        set -eu
        CI_EXIT_OK=0; CI_EXIT_FAIL=1
        ci_info() { printf "[info] %s\n" "$*"; }
        ci_warn() { printf "[warn] %s\n" "$*" >&2; }
        ci_err()  { printf "[ERROR] %s\n" "$*" >&2; }
        . "'"$_work"'/guard.sh"
        gitleaks_history_guard
    ' >"$_work/guard.log" 2>&1
}

$GIT clone -q --depth 1 "file://$_work/src" "$_work/shallow" 2>/dev/null
$GIT clone -q "file://$_work/src" "$_work/full" 2>/dev/null

_rc=0; _run_guard "$_work/shallow" required || _rc=$?
if [ "$_rc" -ne 0 ] && grep -q 'shallow checkout' "$_work/guard.log"; then
    _ok "required: shallow checkout fails the full-history gate"
else
    _bad "required: shallow checkout was accepted (exit $_rc)"
fi

_rc=0; _run_guard "$_work/shallow" advisory || _rc=$?
if [ "$_rc" -eq 0 ] && grep -q 'CI_GITLEAKS_CHECK=advisory' "$_work/guard.log"; then
    _ok "advisory: shallow checkout continues under the explicit triage override"
else
    _bad "advisory: unexpected disposition (exit $_rc)"
fi

_rc=0; _run_guard "$_work/full" required || _rc=$?
if [ "$_rc" -eq 0 ]; then
    _ok "full checkout passes the guard"
else
    _bad "full checkout was rejected (exit $_rc)"
fi

if [ "$_fail" -eq 0 ]; then
    echo "gitleaks-shallow-selftest: ALL OK"
    exit 0
fi
echo "gitleaks-shallow-selftest: $_fail assertion(s) FAILED" >&2
exit 1
