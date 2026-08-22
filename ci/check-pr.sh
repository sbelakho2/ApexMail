#!/bin/sh
# =============================================================================
# ci/check-pr.sh — the PR-validation substitute (branch protection, offline).
# =============================================================================
# GitHub gave every PR a row of required status checks. Without GitHub, the
# equivalents are:
#   * THIS script — run the merge-blocking stages (validate + test + security)
#     against any ref, before merging or pushing:
#         ci/check-pr.sh              # current HEAD
#         ci/check-pr.sh feature-xyz  # a branch (validated in a temp worktree)
#         ci/check-pr.sh <sha>
#   * the pre-push hook example (ci/hooks/pre-push.example) — runs the fast
#     subset on every push; install with:
#         cp ci/hooks/pre-push.example .git/hooks/pre-push && chmod +x .git/hooks/pre-push
#   * the timer on the deploy host runs the same stages against main and
#     REFUSES to deploy when they fail — the real enforcement point.
#
# Options:
#   --skip-security   run validate+test only (faster pre-merge loop)
#   --fast            validate only (what the pre-push hook uses)
#   --allow-dirty     do not refuse on a dirty working tree
#
# Exit 0 = all requested stages green (exit 75 "skip" counts as green here:
# infrastructure intentionally absent, e.g. Trivy with no images built).
# =============================================================================
set -eu

CI_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=lib.sh
. "$CI_DIR/lib.sh"

_ref=HEAD
_stages=validate,test,security
_allow_dirty=0
while [ $# -gt 0 ]; do
    case $1 in
        --skip-security) _stages=validate,test; shift ;;
        --fast)          _stages=validate; shift ;;
        --allow-dirty)   _allow_dirty=1; shift ;;
        -*)              ci_die "unknown option: $1" ;;
        *)               _ref=$1; shift ;;
    esac
done

# --- resolve the ref -------------------------------------------------------------
_sha=$(git -C "$REPO_ROOT" rev-parse --verify "$_ref" 2>/dev/null) \
    || ci_die "ref '$_ref' not found in $REPO_ROOT"
ci_info "check-pr: validating $_sha ($_ref)"

# --- dirty-tree guard ---------------------------------------------------------------
if [ "$_allow_dirty" = 0 ] && [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null | head -5)" ]; then
    ci_err "working tree is dirty — the validation would not test the tree you see."
    ci_err "commit/stash first, or pass --allow-dirty (results may not match the working tree)."
    exit "$CI_EXIT_FAIL"
fi

# --- detached worktree for refs other than HEAD --------------------------------------
# HEAD validates in place; anything else gets a throwaway worktree under
# ci/runs (removed on exit). This never touches branches or the index.
_wt=''
cleanup() {
    [ -n "$_wt" ] && git -C "$REPO_ROOT" worktree remove --force "$_wt" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ "$_ref" != HEAD ]; then
    _wt=$RUNS_DIR/.checkpr-$$
    mkdir -p "$RUNS_DIR"
    git -C "$REPO_ROOT" worktree add --detach --quiet "$_wt" "$_sha" \
        || ci_die "could not create a worktree for $_sha"
    if [ -d "$_wt/ci" ]; then
        CI_DIR=$_wt/ci        # validate the ref's own pipeline, not ours
    fi
    export CI_REPO_ROOT=$_wt
    ci_info "validating in worktree $_wt"
fi

# --- run the stages through the real runner -------------------------------------------
rc=0
"$CI_DIR/pipeline.sh" run --stages "$_stages" --ref "$_ref" || rc=$?
cleanup
trap - EXIT

if [ "$rc" -eq "$CI_EXIT_SKIP" ]; then
    rc=0
fi
exit "$rc"
