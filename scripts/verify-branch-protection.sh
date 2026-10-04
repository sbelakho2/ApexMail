#!/usr/bin/env bash
# =============================================================================
# scripts/verify-branch-protection.sh — external audit (2026-10-02) item #13.
# =============================================================================
# Branch protection on `main` is RELEASE EVIDENCE, not a convention: the
# required `woodpecker` commit-status context is what turns a green CI run
# into a mechanical merge blocker, required approvals + CODEOWNERS
# enforcement are what stop a self-approved bypass of that gate. This script
# queries the GitHub branch-protection API via `gh api` and FAILS unless the
# protections actually exist on the branch:
#
#   1. required status check context 'woodpecker'          (required_status_checks)
#   2. required approving reviews >= 1                     (required_pull_request_reviews)
#   3. CODEOWNERS enforced: require_code_owner_reviews=true
#   4. a direct-push restriction is honestly present: the API's
#      `restrictions` object is set, OR `dismiss_stale_reviews` is true.
#      Only fields the API actually returns are consulted — nothing is
#      invented; every row of the table below is labelled VERIFIED (checked
#      against the live response), MISSING (response contradicts the
#      requirement) or UNVERIFIABLE (the response needed was not readable).
#
# It is wired into ci/stages/fetch.sh — stage 01, the single chokepoint every
# pipeline run passes through — so a protection regression fails the release
# lane within one poll (5 min) even when no new commits arrive. See
# ci/README.md §13.
#
# Exit codes: 0 = all required protections verified · 1 = failed or
# unverifiable (fail closed: unverifiable is never a pass) · 75 = gh absent
# and the CI_MISSING_TOOLS policy allows degrading (the escape hatch for
# environments without gh; under CI_MISSING_TOOLS=fail a missing gh is a
# hard failure, matching ci/lib.sh's ci_have_tool policy).
#
# Usage:
#   scripts/verify-branch-protection.sh [--repo OWNER/REPO] [--branch NAME]
#
# Repo resolution order: --repo → $GH_REPO → parsed from the `origin` git
# remote. Branch: --branch → $VERIFY_BRANCH → main.
# Auth: gh's own credentials (GH_TOKEN / GITHUB_TOKEN / keyring). Reading
# branch protection requires push access; admin on the repository is the
# documented way to always see it.
# =============================================================================
set -euo pipefail

# Re-exec under real bash when this file is not being parsed by one. This
# script IS bash (the work order says so: arrays, process substitution), but
# `sh script` must never silently mis-parse it: bash invoked as sh (macOS
# /bin/sh, `bash --posix`) rejects process substitution at PARSE time — and
# bash 3.2-as-sh then exits 0 on the syntax error, which would invert this
# fail-closed gate into a silent pass. dash (Linux /bin/sh) has no
# BASH_VERSION at all. Both are detected below, before any bash-only syntax;
# SHELLOPTS lists `posix` exactly when bash runs in sh mode.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi
case :${SHELLOPTS:-}: in
    *:posix:*) exec bash "$0" "$@" ;;
esac

REPO_OPT=''
BRANCH_OPT=''
usage() {
    cat <<'USAGE'
Usage: scripts/verify-branch-protection.sh [--repo OWNER/REPO] [--branch NAME]

Verifies GitHub branch protection on the release branch (default: main):
  * required status check context 'woodpecker'
  * required approving reviews >= 1
  * require_code_owner_reviews == true (CODEOWNERS enforced)
  * direct-push restriction: restrictions set OR dismiss_stale_reviews true

Exit: 0 verified | 1 failed/unverifiable | 75 gh absent (policy-allowed skip).
Env: GH_REPO, VERIFY_BRANCH, GITHUB_TOKEN, CI_MISSING_TOOLS.
USAGE
    exit "${1:-0}"
}
while [ $# -gt 0 ]; do
    case $1 in
        --repo)   REPO_OPT=${2:?--repo needs a value}; shift 2 ;;
        --branch) BRANCH_OPT=${2:?--branch needs a value}; shift 2 ;;
        -h|--help) usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 1 ;;
    esac
done

REPO=${REPO_OPT:-${GH_REPO:-}}
BRANCH=${BRANCH_OPT:-${VERIFY_BRANCH:-main}}

# --- resolve OWNER/REPO from the git remote when not given explicitly --------
if [ -z "$REPO" ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    _url=$(git remote get-url origin 2>/dev/null || true)
    case $_url in
        *github.com:*) REPO=${_url#*github.com:} ;;
        *github.com/*) REPO=${_url#*github.com/} ;;
    esac
    REPO=${REPO%.git}
fi
if [ -z "$REPO" ]; then
    echo "FATAL: cannot determine OWNER/REPO — pass --repo OWNER/REPO or set GH_REPO" >&2
    exit 1
fi

# --- the gh escape hatch (CI_MISSING_TOOLS policy, as ci/lib.sh) --------------
CI_MISSING_TOOLS=${CI_MISSING_TOOLS:-auto}
if ! command -v gh >/dev/null 2>&1; then
    if [ "$CI_MISSING_TOOLS" = fail ]; then
        echo "FAIL: gh is absent and CI_MISSING_TOOLS=fail — branch protection cannot be verified (fail closed; external audit 2026-10-02 item 13)" >&2
        exit 1
    fi
    echo "SKIP: gh is absent (CI_MISSING_TOOLS=$CI_MISSING_TOOLS) — branch-protection verification skipped; install gh + authenticate (GITHUB_TOKEN) to gate release" >&2
    exit 75
fi
command -v jq >/dev/null 2>&1 || {
    echo "FATAL: jq is absent — needed to parse the GitHub API response" >&2
    exit 1
}

# --- one API call, cached for every row of the table ---------------------------
TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/apexmail-branchprot.XXXXXX")
trap 'rm -rf "$TMPDIR"' EXIT
_api_rc=0
gh api "repos/$REPO/branches/$BRANCH/protection" \
    >"$TMPDIR/protection.json" 2>"$TMPDIR/protection.err" || _api_rc=$?
if [ "$_api_rc" -ne 0 ]; then
    _hint=$(tr '\n' ' ' <"$TMPDIR/protection.err" | cut -c1-200)
    echo "" >&2
    echo "branch protection: $REPO@$BRANCH (external audit 2026-10-02 item 13)" >&2
    echo "  protection API        GET $REPO/branches/$BRANCH/protection   UNVERIFIABLE  (gh api exit $_api_rc: ${_hint:-no output})" >&2
    echo "  required status check 'woodpecker'                            UNVERIFIABLE  (protection unreadable)" >&2
    echo "  approving reviews >= 1                                        UNVERIFIABLE  (protection unreadable)" >&2
    echo "  CODEOWNERS enforced                                           UNVERIFIABLE  (protection unreadable)" >&2
    echo "  direct-push restriction                                       UNVERIFIABLE  (protection unreadable)" >&2
    echo "" >&2
    echo "VERDICT: FAIL — the protection response is not readable, so NOTHING is verified." >&2
    echo "A 404 means the branch is NOT protected, or the token cannot read protection" >&2
    echo "(push access required; admin always can). Fail-closed: unverifiable is not a pass." >&2
    exit 1
fi

# --- parse (objects-with-.enabled and legacy bare booleans both accepted) ------
# Fields printed in this fixed TSV order:
#  1 woodpecker_required      2 woodpecker_evidence   3 strict
#  4 review_count             5 code_owner_reviews    6 dismiss_stale_reviews
#  7 restrictions_set         8 restrictions_evidence 9 enforce_admins
# 10 linear_history           11 required_signatures  12 allow_force_pushes
# 13 allow_deletions          14 has_reviews_section
read -r WOODPECKER_REQUIRED WOODPECKER_EVIDENCE STRICT REVIEW_COUNT CODE_OWNER \
    DISMISS_STALE RESTRICTIONS_SET RESTRICTIONS_EVIDENCE ENFORCE_ADMINS \
    LINEAR_HISTORY SIGNATURES FORCE_PUSHES DELETIONS HAS_REVIEWS \
    < <(jq -r '
        def en(f): (if (.[f] | type) == "boolean" then .[f] else ((.[f].enabled) // false) end);
        def reviews: (.required_pull_request_reviews // {});
        def contexts: ((.required_status_checks.contexts // []) + [(.required_status_checks.checks // [])[].context] | unique);
        [
            (contexts | index("woodpecker") != null),
            (contexts | join(",")),
            (.required_status_checks.strict // false),
            (reviews.required_approving_review_count // 0),
            (reviews.require_code_owner_reviews // false),
            (reviews.dismiss_stale_reviews // false),
            (.restrictions != null),
            (if .restrictions == null then "none"
             else ([([.restrictions.users[]?.login] | join(",")),
                    ([.restrictions.teams[]?.slug] | join(",")),
                    ([.restrictions.apps[]?.slug] | join(","))] | join("/")) end),
            en("enforce_admins"),
            en("required_linear_history"),
            en("required_signatures"),
            en("allow_force_pushes"),
            en("allow_deletions"),
            (.required_pull_request_reviews != null)
        ] | @tsv' "$TMPDIR/protection.json")

# --- verdict -------------------------------------------------------------------
FAILURES=()
_status_woodpecker=VERIFIED
_status_reviews=VERIFIED
_status_codeowner=VERIFIED
_status_push=VERIFIED
if [ "$WOODPECKER_REQUIRED" != true ]; then
    _status_woodpecker=MISSING
    FAILURES+=("required status check context 'woodpecker' is not required (contexts/checks: ${WOODPECKER_EVIDENCE:-none})")
fi
if [ "$REVIEW_COUNT" -lt 1 ] 2>/dev/null; then
    _status_reviews=MISSING
    FAILURES+=("required approving reviews < 1 (got: $REVIEW_COUNT)")
fi
if [ "$CODE_OWNER" != true ]; then
    _status_codeowner=MISSING
    FAILURES+=("CODEOWNERS not enforced (require_code_owner_reviews=$CODE_OWNER)")
fi
if [ "$RESTRICTIONS_SET" != true ] && [ "$DISMISS_STALE" != true ]; then
    _status_push=MISSING
    FAILURES+=("no direct-push restriction (restrictions unset AND dismiss_stale_reviews=false — anyone with write access can push main)")
fi

# --- the table -----------------------------------------------------------------
printf '\n'
printf 'Branch protection: %s @ %s — external audit 2026-10-02 item 13\n' "$REPO" "$BRANCH"
printf '%s\n' '---------------------------------------------------------------------------------------------'
printf '%-28s %-42s %-13s %s\n' 'CHECK' 'REQUIREMENT' 'STATUS' 'EVIDENCE (live API response)'
printf '%s\n' '---------------------------------------------------------------------------------------------'
printf '%-28s %-42s %-13s %s\n' 'protection API readable' 'GET .../protection returns 200' 'VERIFIED' 'required_* fields parsed'
printf '%-28s %-42s %-13s %s\n' "required status check" "context 'woodpecker' required" "$_status_woodpecker" \
    "contexts/checks: ${WOODPECKER_EVIDENCE:-none} (strict=$STRICT)"
printf '%-28s %-42s %-13s %s\n' 'required approvals' 'required_approving_review_count >= 1' "$_status_reviews" \
    "count=$REVIEW_COUNT (reviews section present: $HAS_REVIEWS)"
printf '%-28s %-42s %-13s %s\n' 'CODEOWNERS enforcement' 'require_code_owner_reviews == true' "$_status_codeowner" \
    "require_code_owner_reviews=$CODE_OWNER"
printf '%-28s %-42s %-13s %s\n' 'direct-push restriction' 'restrictions set OR dismiss_stale_reviews' "$_status_push" \
    "restrictions=$RESTRICTIONS_EVIDENCE, dismiss_stale_reviews=$DISMISS_STALE"
printf '%-28s %-42s %-13s %s\n' 'enforce_admins (info)' 'informational — admins bound?' 'INFO' \
    "enabled=$ENFORCE_ADMINS (false = admins bypass every rule above)"
printf '%-28s %-42s %-13s %s\n' 'required_linear_history (info)' 'informational' 'INFO' "enabled=$LINEAR_HISTORY"
printf '%-28s %-42s %-13s %s\n' 'required_signatures (info)' 'informational' 'INFO' "enabled=$SIGNATURES"
printf '%-28s %-42s %-13s %s\n' 'allow_force_pushes (info)' 'informational (false is safe)' 'INFO' "enabled=$FORCE_PUSHES"
printf '%-28s %-42s %-13s %s\n' 'allow_deletions (info)' 'informational (false is safe)' 'INFO' "enabled=$DELETIONS"
printf '%s\n' '---------------------------------------------------------------------------------------------'

if [ "${#FAILURES[@]}" -gt 0 ]; then
    printf 'VERDICT: FAIL — %d required protection(s) missing:\n' "${#FAILURES[@]}" >&2
    for _f in "${FAILURES[@]}"; do
        printf '  * %s\n' "$_f" >&2
    done
    printf 'A green pipeline on an unprotected branch is a convention, not a gate (fix in GitHub → Settings → Branches, or: gh api -X PUT repos/%s/branches/%s/protection ...)\n' "$REPO" "$BRANCH" >&2
    exit 1
fi
printf 'VERDICT: PASS — required status check, approvals, CODEOWNERS and a direct-push restriction are all enforced.\n'
exit 0
