#!/bin/sh
# =============================================================================
# ci/stages/fetch.sh — stage 1: sync + provenance.
# =============================================================================
# Replaces the "checkout" steps of every GitHub workflow, plus the provenance
# guarantees GitHub gave us implicitly (the workflow always ran on a pushed
# SHA): on the deploy host this fetches origin/<CI_REF> over the deploy key
# and REFUSES to deploy anything that is not pushed to the remote.
#
# What it does:
#   1. Loads the deploy-key SSH config from ci/deploy-key.env when present
#      (created by `ci/install.sh deploy-key`; HTTPS clones need nothing).
#   2. git fetch --no-tags origin <CI_REF>.
#   3. Asserts the current HEAD is an ancestor of origin/<CI_REF> (i.e. HEAD
#      is pushed). A dirty working tree is a warning, not a failure.
#   4. Records sha / remote / dirty-state into the run dir for the manifest
#      and later stages.
# Skips (exit 75) when the tree is not a git checkout and CI_ALLOW_NO_GIT=1
# (e.g. an rsync'd host tree); fails otherwise.
# =============================================================================
set -eu

. "${CI_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)}/lib.sh"

stage_main() {
    if ! git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        if [ "${CI_ALLOW_NO_GIT:-0}" = 1 ]; then
            ci_warn "not a git checkout — CI_ALLOW_NO_GIT=1, recording unknown sha"
            printf 'unknown\n' >"$RUN_DIR/sha"
            return "$CI_EXIT_OK"
        fi
        ci_die "REPO_ROOT is not a git checkout (set CI_ALLOW_NO_GIT=1 for rsync'd trees)"
    fi

    # Deploy key (optional): written by ci/install.sh deploy-key as
    #   GIT_SSH_COMMAND="ssh -i /root/.ssh/apexmail_deploy_key -o IdentitiesOnly=yes"
    if [ -f "$CI_ROOT/deploy-key.env" ]; then
        # shellcheck disable=SC1090
        . "$CI_ROOT/deploy-key.env"
        export GIT_SSH_COMMAND
        ci_info "using deploy key from ci/deploy-key.env"
    fi

    _fetch_remote=${CI_REPO_URL:-origin}
    ci_info "fetching $_fetch_remote/$CI_REF"
    if ! ci_run_logged git -C "$REPO_ROOT" fetch --no-tags "$_fetch_remote" "$CI_REF"; then
        ci_die "git fetch failed — check network/deploy key (ci/README.md § deploy key)"
    fi

    _head=$(git -C "$REPO_ROOT" rev-parse HEAD)
    _remote_sha=$(git -C "$REPO_ROOT" rev-parse FETCH_HEAD 2>/dev/null || printf '')

    # HEAD must be contained in the remote branch (it is pushed).
    if git -C "$REPO_ROOT" merge-base --is-ancestor "$_head" FETCH_HEAD 2>/dev/null; then
        ci_info "HEAD $_head is pushed (contained in $_fetch_remote/$CI_REF @ ${_remote_sha:-?})"
    else
        ci_err "HEAD $_head is NOT pushed to $_fetch_remote/$CI_REF"
        ci_err "the pipeline refuses to build/deploy unpushed commits — push first"
        return "$CI_EXIT_FAIL"
    fi

    # Cheap-poll support: with CI_SKIP_UNCHANGED=1 (the systemd timer), a
    # sha that already completed a green run ends the run right here in
    # seconds instead of re-running the full lane every 5 minutes.
    if [ "${CI_SKIP_UNCHANGED:-0}" = 1 ]; then
        _last_good=''
        [ -f "$RUNS_DIR/.last-good-sha" ] && _last_good=$(head -n1 "$RUNS_DIR/.last-good-sha")
        _dirty=0
        [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null | head -1)" ] && _dirty=1
        if [ "$_head" = "$_last_good" ] && [ "$_dirty" = 0 ]; then
            ci_info "sha $_head already completed a green run and the tree is clean — nothing to do"
            exit "$CI_EXIT_UNCHANGED"
        fi
    fi

    if [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null | head -20)" ]; then
        ci_warn "working tree is dirty — deployed artifacts may not match the recorded sha"
        git -C "$REPO_ROOT" status --porcelain 2>/dev/null | head -20 >>"$CI_STAGE_LOG" || true
    fi

    printf '%s\n' "$_head" >"$RUN_DIR/sha"
    printf 'sha=%s\nremote_ref=%s/%s\nremote_sha=%s\ntime=%s\n' \
        "$_head" "$_fetch_remote" "$CI_REF" "${_remote_sha:-unknown}" "$(_ci_ts)" \
        >"$RUN_DIR/provenance.txt"
    ci_info "recorded sha $_head"
    return "$CI_EXIT_OK"
}

stage_main
