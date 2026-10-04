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
    # Bounded retries: on hosts with intermittent DNS (observed: "Could not
    # resolve host" transiently resolving fine seconds later), a single
    # attempt fails the whole pipeline on infrastructure noise. External
    # audit 2026-10-02 follow-up.
    _fetch_ok=""
    for _fetch_attempt in 1 2 3 4; do
        if ci_run_logged git -C "$REPO_ROOT" fetch --no-tags "$_fetch_remote" "$CI_REF"; then
            _fetch_ok="1"
            break
        fi
        [ "$_fetch_attempt" -lt 4 ] && ci_warn "git fetch attempt $_fetch_attempt failed — retrying" && sleep 5
    done
    if [ -z "$_fetch_ok" ]; then
        ci_die "git fetch failed after 4 attempts — check network/deploy key (ci/README.md § deploy key)"
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

    # External audit (2026-10-02) item 13: branch protection IS release
    # evidence — the required `woodpecker` status context, required approvals
    # and CODEOWNERS enforcement are what make a green run a mechanical merge
    # blocker instead of a convention. Stage 01 is THE single chokepoint: it
    # runs on EVERY pipeline run (including --skip-unchanged polls, so a
    # protection regression is caught within one 5-minute poll even with no
    # new commits), and it is checked BEFORE the cheap-poll exit below.
    # Missing-tool policy is ci_have_tool's (ci/lib.sh): gh absent under
    # CI_MISSING_TOOLS=fail OR on the deploy host fails the stage closed;
    # elsewhere it degrades to a loud skip. scripts/verify-branch-protection.sh
    # implements the same policy for standalone runs. Dry-run (selftest)
    # logs the check and skips it, exactly like every ci_check under ci_dry.
    if ci_dry; then
        ci_info "check (dry-run): branch protection on main (woodpecker status, approvals, CODEOWNERS, push restriction)"
    elif [ ! -f "$REPO_ROOT/scripts/verify-branch-protection.sh" ]; then
        ci_err "scripts/verify-branch-protection.sh missing — the branch-protection gate cannot be verified (external audit 2026-10-02 item 13)"
        return "$CI_EXIT_FAIL"
    elif ! command -v gh >/dev/null 2>&1; then
        if [ "${CI_MISSING_TOOLS:-auto}" = fail ] || ci_on_deploy_host; then
            ci_err "gh missing — branch protection cannot be verified and the CI_MISSING_TOOLS policy is fail-closed here (external audit 2026-10-02 item 13). Install gh + a token with push access (GITHUB_TOKEN), see ci/README.md §13"
            return "$CI_EXIT_FAIL"
        fi
        ci_warn "gh missing — branch-protection verification skipped (install gh + GITHUB_TOKEN for the release gate; ci/README.md §13)"
    else
        _bp_rc=0
        # bash, not sh: the script is bash (its own shebang AND a re-exec
        # guard make `sh` invocation safe too, but invoke it as what it is).
        bash "$REPO_ROOT/scripts/verify-branch-protection.sh" \
            --branch "${CI_BRANCH_PROTECTION_BRANCH:-main}" || _bp_rc=$?
        case $_bp_rc in
            0) ci_info "PASS: branch protection on main verified (woodpecker status, approvals, CODEOWNERS, push restriction)" ;;
            "$CI_EXIT_SKIP")
                ci_warn "branch-protection verification SKIP (gh absent per the script's policy) — the release gate is degraded" ;;
            *)
                ci_err "branch protection on main does not meet the release requirements (see the script's table above) — external audit 2026-10-02 item 13"
                return "$CI_EXIT_FAIL" ;;
        esac
    fi

    # Cheap-poll support: with CI_SKIP_UNCHANGED=1 (the systemd timer), a
    # sha that already completed a green run ends the run right here in
    # seconds instead of re-running the full lane every 5 minutes.
    if [ "${CI_SKIP_UNCHANGED:-0}" = 1 ]; then
        # The blessing is a release-gate MANIFEST (see pipeline.sh): sha +
        # pipeline-config hash + the stages that passed. A partial-lane run
        # can no longer write one, and a manifest from a DIFFERENT pipeline
        # configuration (or a naked sha from an old format) does not bless.
        _last_good=''
        _last_config=''
        [ -f "$RUNS_DIR/.last-good-sha" ] && {
            _last_good=$(sed -n 's/.*"sha":"\([^"]*\)".*/\1/p' "$RUNS_DIR/.last-good-sha" | head -n1)
            _last_config=$(sed -n 's/.*"pipelineConfigHash":"\([^"]*\)".*/\1/p' "$RUNS_DIR/.last-good-sha" | head -n1)
        }
        # Audit SM14 F10: the hash is computed by ONE shared helper
        # (ci/lib.sh ci_pipeline_config_hash) — the same file set the
        # blessing writer hashed, widened beyond pipeline.conf+stages to
        # lib.sh, the Woodpecker adapter layer, .woodpecker.yml and every
        # tools/*.py gate checker — so a checker-policy change invalidates
        # existing blessings exactly like a stage-script change does.
        _pipeline_hash=$(ci_pipeline_config_hash)
        _dirty=0
        [ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null | head -1)" ] && _dirty=1
        if [ -n "$_last_config" ] && [ "$_last_config" = "$_pipeline_hash" ] \
            && [ "$_head" = "$_last_good" ] && [ "$_dirty" = 0 ]; then
            ci_info "sha $_head completed a green run under the CURRENT pipeline config and the tree is clean — nothing to do"
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
