#!/bin/sh
# =============================================================================
# tools/post_github_status.sh — post a SHA-bound commit status to GitHub.
# =============================================================================
# External audit item 6: the repo host must SHOW that a commit passed the
# mandatory gates. Branch protection on main requires the commit-status
# context `woodpecker` (see ci/README.md §12); Woodpecker's own built-in
# status may be absent or named differently, so the pipeline posts the
# required context EXPLICITLY via this script:
#
#   POST {GITHUB_API_URL}/repos/{owner}/{repo}/statuses/{sha}
#   {"state": ..., "context": ..., "description": ..., "target_url": ...}
#
# Curl-only (no new dependencies). All inputs come from the environment, with
# Woodpecker-variable fallbacks so it works unchanged on the CI executor and
# from a developer machine:
#
#   GITHUB_TOKEN           required token (repo:status scope). ABSENT -> the
#                          script exits 0 with a loud skip line, so local /
#                          manual / secret-less runs never fail because of it.
#   GITHUB_STATUS_STATE    success | failure | pending | error   (required)
#   GITHUB_STATUS_CONTEXT  status context (default: "woodpecker" — EXACTLY
#                          the context branch protection requires)
#   STATUS_DESCRIPTION     summary line (default derived; truncated to the
#                          GitHub 140-char limit)
#   STATUS_TARGET_URL      link shown in the GitHub UI (default: the
#                          Woodpecker run URL — CI_PIPELINE_URL, with legacy
#                          CI_PIPELINE_LINK / CI_BUILD_LINK fallbacks; omitted
#                          when nothing is known)
#   GITHUB_API_URL         default https://api.github.com (GHES override)
#
# Commit SHA:    CI_SHA -> GITHUB_SHA -> CI_COMMIT_SHA -> `git rev-parse HEAD`.
# Owner/repo:    CI_REPO_OWNER + CI_REPO_NAME -> GITHUB_REPOSITORY /
#                CI_REPO ("owner/name") -> parsed from `git remote get-url`
#                (https and ssh forms).
#
# Dry-run: POST_GITHUB_STATUS_DRY_RUN=1 prints the request instead of sending.
# Exit codes: 0 = posted (or loud skip / dry-run), 1 = the status was NOT
# posted (bad input or the API refused), 2 = usage error.
# =============================================================================
set -eu

STATE=${GITHUB_STATUS_STATE:-}
CONTEXT=${GITHUB_STATUS_CONTEXT:-woodpecker}
TOKEN=${GITHUB_TOKEN:-}
API_BASE=${GITHUB_API_URL:-https://api.github.com}
TARGET_URL=${STATUS_TARGET_URL:-}
DESCRIPTION=${STATUS_DESCRIPTION:-}

# --- the loud skip: no token, no status, no failure --------------------------
if [ -z "$TOKEN" ]; then
    printf '%s\n' \
        "post_github_status: GITHUB_TOKEN is not set — SKIPPING the commit status (add the Woodpecker secret to enable; see ci/README.md §12)" >&2
    exit 0
fi

# --- state validation ----------------------------------------------------------
case "$STATE" in
    success|failure|pending|error) ;;
    *)
        printf '%s\n' \
            "post_github_status: GITHUB_STATUS_STATE must be success|failure|pending|error (got '${STATE:-<empty>}')" >&2
        exit 2
        ;;
esac

# --- commit sha ------------------------------------------------------------------
SHA=${CI_SHA:-${GITHUB_SHA:-${CI_COMMIT_SHA:-}}}
if [ -z "$SHA" ]; then
    SHA=$(git rev-parse HEAD 2>/dev/null || true)
fi
if [ -z "$SHA" ]; then
    printf '%s\n' "post_github_status: no commit SHA (set CI_SHA/GITHUB_SHA or run inside a git checkout)" >&2
    exit 2
fi

# --- owner/repo discovery ----------------------------------------------------------
REPO_SLUG=${CI_REPO:-${GITHUB_REPOSITORY:-}}
if [ -z "$REPO_SLUG" ] && [ -n "${CI_REPO_OWNER:-}" ] && [ -n "${CI_REPO_NAME:-}" ]; then
    REPO_SLUG="$CI_REPO_OWNER/$CI_REPO_NAME"
fi
if [ -z "$REPO_SLUG" ]; then
    # Monorepo fallback: parse the git remote (https://github.com/o/r(.git),
    # git@github.com:o/r(.git), ssh://git@host/o/r(.git)); strip a trailing
    # .git separately (the capture class must allow dots for owner names).
    _remote=$(git remote get-url origin 2>/dev/null || git remote get-url "$(git remote 2>/dev/null | head -n 1)" 2>/dev/null || true)
    REPO_SLUG=$(printf '%s' "$_remote" \
        | sed -n 's#.*[:/]\([A-Za-z0-9_.-]*/[A-Za-z0-9_.-]*\)$#\1#p' \
        | sed -e 's/\.git$//')
fi
if [ -z "$REPO_SLUG" ]; then
    printf '%s\n' "post_github_status: cannot determine owner/repo (set CI_REPO_OWNER/CI_REPO_NAME, GITHUB_REPOSITORY or add a git remote)" >&2
    exit 2
fi

# --- target url (the Woodpecker run) -------------------------------------------------
if [ -z "$TARGET_URL" ]; then
    TARGET_URL=${CI_PIPELINE_URL:-${CI_PIPELINE_LINK:-${CI_BUILD_LINK:-}}}
fi

# --- description ----------------------------------------------------------------------
if [ -z "$DESCRIPTION" ]; then
    DESCRIPTION="woodpecker release gates: $STATE"
fi
# GitHub caps the description at 140 chars.
DESCRIPTION=$(printf '%s' "$DESCRIPTION" | cut -c 1-140)

# --- JSON payload (curl-only: escape the two strings that could break it) --------
_json_escape() {
    # Backslash, double-quote and control chars are impossible after the
    # tr below; this keeps the payload valid without jq.
    printf '%s' "$1" | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}
CONTEXT_J=$( _json_escape "$CONTEXT")
DESC_J=$(    _json_escape "$DESCRIPTION")
PAYLOAD="{\"state\":\"$STATE\",\"context\":\"$CONTEXT_J\",\"description\":\"$DESC_J\""
if [ -n "$TARGET_URL" ]; then
    PAYLOAD="$PAYLOAD,\"target_url\":\"$( _json_escape "$TARGET_URL")\""
fi
PAYLOAD="$PAYLOAD}"

API_URL="$API_BASE/repos/$REPO_SLUG/statuses/$SHA"

if [ "${POST_GITHUB_STATUS_DRY_RUN:-0}" = "1" ]; then
    printf 'post_github_status (dry-run): POST %s\n%s\n' "$API_URL" "$PAYLOAD"
    exit 0
fi

# --- post (3 attempts — a GitHub API blip must not lose the evidence) ----------
_tmp=$(mktemp "${TMPDIR:-/tmp}/apexmail-status.XXXXXX")
trap 'rm -f "$_tmp"' EXIT
_http_code=""
_attempt=1
while [ "$_attempt" -le 3 ]; do
    _http_code=$(curl -sS --max-time 30 -o "$_tmp" -w '%{http_code}' \
        -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        "$API_URL" 2>"$_tmp.curl" || true)
    case "$_http_code" in
        201)
            printf '%s\n' "post_github_status: $STATE '$CONTEXT' posted on $REPO_SLUG@$SHA (target: ${TARGET_URL:-none})"
            exit 0
            ;;
        404|403|401|422)
            # Non-transient: retrying cannot help — show the API's words.
            break
            ;;
        *)
            # Transient (5xx, network): brief backoff, then retry.
            sleep 5
            ;;
    esac
    _attempt=$((_attempt + 1))
done

{
    printf '%s\n' "post_github_status: FAILED to post '$CONTEXT' = $STATE on $REPO_SLUG@$SHA (HTTP $_http_code)"
    sed -n '1,5p' "$_tmp" 2>/dev/null || true
    sed -n '1,2p' "$_tmp.curl" 2>/dev/null || true
} >&2
rm -f "$_tmp.curl" 2>/dev/null || true
exit 1
