#!/bin/sh
# =============================================================================
# ci/tests/fetch-selftest.sh — synthetic-repository fixture for the fetch
# stage's history/pushed-HEAD guarantees (audit P2 item 10, P3 item 19).
# =============================================================================
# Builds a throwaway origin with 3 commits, shallow-clones it (`--depth 1`,
# the old bootstrap) and runs the REAL production functions extracted from
# ci/stages/fetch.sh:
#
#   1. ensure_full_history() turns the shallow clone back into a full one;
#   2. TEETH: the plain `git fetch --no-tags origin main` of the pre-fix code
#      leaves it at depth 1 — the bug the fix removes;
#   3. prove_head_pushed() REJECTS a locally-present but unpushed commit when
#      CI_REF is a raw sha (the old FETCH_HEAD test accepted it);
#   4. it still accepts the pushed branch tip.
#
# No network, no host mutation: local file:// clones under mktemp.
# =============================================================================
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
_work=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-fetch-selftest.XXXXXX")
if [ "${FETCH_SELFTEST_KEEP:-0}" = 1 ]; then
    echo "fetch-selftest: keeping workdir $_work" >&2
else
    trap 'rm -rf "$_work"' EXIT
fi

_fail=0
_ok()  { printf 'ok   %s\n' "$*"; }
_bad() { printf 'FAIL %s\n' "$*" >&2; _fail=$((_fail + 1)); }

GIT="git -c user.email=selftest@example.invalid -c user.name=selftest -c commit.gpgsign=false"

# --- synthetic origin: 3 commits on main -------------------------------------
mkdir -p "$_work/src"
$GIT -C "$_work/src" init -q -b main
for _i in 1 2 3; do
    printf 'commit %s\n' "$_i" > "$_work/src/file.txt"
    $GIT -C "$_work/src" add file.txt
    $GIT -C "$_work/src" commit -q -m "commit $_i"
done

# --- shallow clone -----------------------------------------------------------
_make_shallow() { # <dst>
    rm -rf "$1"
    $GIT clone -q --depth 1 "file://$_work/src" "$1" 2>/dev/null
    [ "$(git -C "$1" rev-parse --is-shallow-repository)" = true ]
}

_extract_fn() { # <file> <fn> <out>
    sed -n "/^${2}()/,/^}/p" "$1" >"$3"
    grep -q "^${2}()" "$3"
}

if ! _extract_fn "$REPO_ROOT/ci/stages/fetch.sh" ensure_full_history "$_work/efh.sh" \
   || ! _extract_fn "$REPO_ROOT/ci/stages/fetch.sh" prove_head_pushed "$_work/php.sh"; then
    _bad "could not extract fetch.sh functions"
fi

# --- 1. ensure_full_history unshallows ---------------------------------------
if _make_shallow "$_work/host1"; then
    REPO_ROOT="$_work/host1" CI_REF=main bash -c '
        set -eu
        ci_info() { printf "[info] %s\n" "$*"; }
        ci_warn() { printf "[warn] %s\n" "$*" >&2; }
        ci_err()  { printf "[ERROR] %s\n" "$*" >&2; }
        ci_run_logged() { "$@"; }
        . "'"$_work"'/efh.sh"
        ensure_full_history origin main
    ' >"$_work/unshallow.log" 2>&1 || true
    if [ "$(git -C "$_work/host1" rev-parse --is-shallow-repository)" = false ] \
       && [ "$(git -C "$_work/host1" rev-list --count HEAD)" -eq 3 ]; then
        _ok "ensure_full_history: shallow clone repaired to full history (3 commits)"
    else
        _bad "ensure_full_history: clone still shallow or wrong depth — $(cat "$_work/unshallow.log")"
    fi
else
    _bad "fixture: could not create a shallow clone"
fi

# --- 2. teeth: HEAD's plain fetch leaves it shallow --------------------------
if _make_shallow "$_work/host2"; then
    $GIT -C "$_work/host2" fetch --no-tags origin main 2>/dev/null || true
    if [ "$(git -C "$_work/host2" rev-parse --is-shallow-repository)" = true ] \
       && [ "$(git -C "$_work/host2" rev-list --count HEAD)" -eq 1 ]; then
        _ok "teeth: plain 'git fetch --no-tags origin main' stays at depth 1 (bug reproduced)"
    else
        _bad "teeth: the pre-fix fetch path unexpectedly deepened the clone"
    fi
else
    _bad "fixture: could not create the second shallow clone"
fi

# --- 3+4. prove_head_pushed: unpushed local sha rejected ---------------------
if _make_shallow "$_work/host3"; then
    $GIT -C "$_work/host3" fetch -q --no-tags --unshallow origin main
    # a locally-created commit that was never pushed
    printf 'unpushed\n' > "$_work/host3/local.txt"
    $GIT -C "$_work/host3" add local.txt
    $GIT -C "$_work/host3" commit -q -m "local only"
    _local_sha=$(git -C "$_work/host3" rev-parse HEAD)

    _rc=0
    REPO_ROOT="$_work/host3" CI_REF="$_local_sha" CI_REPO_URL=origin bash -c '
        set -eu
        ci_info() { printf "[info] %s\n" "$*"; }
        ci_warn() { printf "[warn] %s\n" "$*" >&2; }
        ci_err()  { printf "[ERROR] %s\n" "$*" >&2; }
        ci_run_logged() { "$@"; }
        . "'"$_work"'/php.sh"
        prove_head_pushed "'"$_local_sha"'"
    ' >"$_work/pushed.log" 2>&1 || _rc=$?
    if [ "$_rc" -ne 0 ]; then
        _ok "prove_head_pushed: rejects a locally-present unpushed sha"
    else
        _bad "prove_head_pushed: accepted an unpushed sha"
    fi

    # The pre-fix test: `git fetch origin <sha>` short-circuits locally, so
    # FETCH_HEAD IS the sha and the ancestor test passes (the audit's probe).
    $GIT -C "$_work/host3" fetch -q --no-tags origin "$_local_sha" 2>/dev/null || true
    if git -C "$_work/host3" merge-base --is-ancestor "$_local_sha" FETCH_HEAD 2>/dev/null; then
        _ok "teeth: the raw FETCH_HEAD ancestor test accepts the unpushed sha (bug reproduced)"
    else
        _bad "teeth: the pre-fix FETCH_HEAD test unexpectedly rejected the sha"
    fi

    # pushed tip accepted under the branch-name CI_REF
    _tip=$(git -C "$_work/host3" rev-parse origin/main)
    _rc=0
    REPO_ROOT="$_work/host3" CI_REF=main CI_REPO_URL=origin bash -c '
        set -eu
        ci_info() { printf "[info] %s\n" "$*"; }
        ci_warn() { printf "[warn] %s\n" "$*" >&2; }
        ci_err()  { printf "[ERROR] %s\n" "$*" >&2; }
        ci_run_logged() { "$@"; }
        . "'"$_work"'/php.sh"
        prove_head_pushed "'"$_tip"'"
    ' >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        _ok "prove_head_pushed: accepts the pushed branch tip"
    else
        _bad "prove_head_pushed: rejected the pushed branch tip"
    fi
else
    _bad "fixture: could not create the third shallow clone"
fi

if [ "$_fail" -eq 0 ]; then
    echo "fetch-selftest: ALL OK"
    exit 0
fi
echo "fetch-selftest: $_fail assertion(s) FAILED" >&2
exit 1
