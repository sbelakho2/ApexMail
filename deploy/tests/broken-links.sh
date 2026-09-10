#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# broken-links.sh — Internal and external link checker for production builds.
# Crawls every production route and checks internal links (200/301),
# external links (accessible), anchors, redirect chains, and broken resources.
# Non-zero exit on critical broken links.
#
# Link/anchor extraction is POSIX ERE (no `grep -P`: BSD grep on dev
# machines has no -P, and the minified build emits UNQUOTED attribute
# values like href=/pricing/ — the old quoted-only PCRE silently matched
# nothing and the check vacuously passed with "Total links: 0").
# =============================================================================
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly TIMESTAMP
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly REPORT_FILE="${SCRIPT_DIR}/.broken-links-report.json"

: "${BUILD_DIR:=../apps/marketing-zola/public}"
: "${BASE_URL:=https://apexmail.ee}"
: "${TIMEOUT:=15}"
: "${MAX_REDIRECTS:=5}"

CRITICAL_FAILURES=0
TOTAL_LINKS=0
TOTAL_FAILED=0

# External-URL result cache: the same external link (twitter, linkedin, the
# API docs…) appears on EVERY page's footer, and re-curling it per source
# page both slowed the run into minutes and hammered third parties. Each
# unique absolute URL is fetched ONCE; the per-source JSON records reuse the
# cached code/effective-url/redirect-count. Format: url \t code \t eff \t red.
CHECK_CACHE="$(mktemp "${TMPDIR:-/tmp}/apexmail-broken-links.XXXXXX")"
RESULTS_JSONL="$(mktemp "${TMPDIR:-/tmp}/apexmail-broken-links.XXXXXX")"
trap 'rm -f "$CHECK_CACHE" "$RESULTS_JSONL"' EXIT

# fetch_url_meta <url> — print "code|effective_url|redirect_count".
fetch_url_meta() {
    local url="$1" output
    output="$(curl -sS -o /dev/null -w '%{http_code}|%{url_effective}|%{num_redirects}' \
        --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
        -L --max-redirs "$MAX_REDIRECTS" \
        "$url" 2>/dev/null)" || {
        printf '000|%s|0' "$url"; return 0
    }
    printf '%s' "$output"
}

# record_for_meta <url> <source> <element> <meta> — classify "code|eff|red"
# and emit the JSON result record (shared by cached and fresh fetches).
record_for_meta() {
    local url="$1" source="$2" element="$3" meta="$4"
    local http_code effective_url redirect_count
    IFS='|' read -r http_code effective_url redirect_count <<< "$meta"

    local status="ok"
    local issue=""

    case "$http_code" in
        2*) status="ok" ;;
        301|308)
            status="ok"
            if [[ "$redirect_count" -gt "$MAX_REDIRECTS" ]]; then
                status="warn"; issue="redirect chain too long"
            fi
            ;;
        # 429 means the endpoint EXISTS and answered — it throttled us
        # (often our own nginx limit_req under a bulk check). A rate-limit
        # response is not a broken link; it is a retry-shaped warning.
        429) status="warn"; issue="HTTP 429 (rate limited — endpoint exists, throttled this check)" ;;
        4*) status="fail"; issue="HTTP $http_code (client error)"; CRITICAL_FAILURES=$((CRITICAL_FAILURES+1)) ;;
        5*) status="warn"; issue="HTTP $http_code (server error)" ;;
        000) status="fail"; issue="unreachable"; CRITICAL_FAILURES=$((CRITICAL_FAILURES+1)) ;;
        *)   status="warn"; issue="HTTP $http_code" ;;
    esac

    jq -n --arg url "$url" --arg source "$source" --arg element "$element" \
        --arg status "$status" --arg http_code "$http_code" \
        --arg effective_url "$effective_url" --arg issue "$issue" \
        --arg checked_at "$TIMESTAMP" \
        '{url:$url,source:$source,element:$element,status:$status,http_code:$http_code,effective_url:$effective_url,issue:$issue,checked_at:$checked_at}'
}

# check_url <url> <source> <element> — cached wrapper around fetch_url_meta.
# The cache key is the URL WITHOUT its query string: the cookie-consent form
# action carries a per-page return_to=… query, and one endpoint must not be
# re-fetched (and re-rate-limited) once per page.
check_url() {
    local url="$1" source="$2" element="$3"
    local cache_key="${url%%\?*}"
    local meta
    meta="$(awk -F'\t' -v u="$cache_key" '$1 == u { print $2 "|" $3 "|" $4; exit }' "$CHECK_CACHE" 2>/dev/null || true)"
    if [[ -z "$meta" ]]; then
        meta="$(fetch_url_meta "$url")"
        printf '%s\t%s\t%s\t%s\n' "$cache_key" "${meta%%|*}" "$(printf '%s' "$meta" | cut -d'|' -f2)" "$(printf '%s' "$meta" | cut -d'|' -f3)" >> "$CHECK_CACHE"
    fi
    record_for_meta "$url" "$source" "$element" "$meta"
}

# Internal link (leading '/', not protocol-relative): resolve against the
# local BUILD_DIR so CI checks the artifact under test instead of the live
# production site. A link with no corresponding local artifact is reported
# as broken; only external http(s) links are checked over the network.
check_internal_link() {
    local link="$1" source="$2"
    local path="$link"
    path="${path%%\#*}"
    path="${path%%\?*}"
    local candidate
    for candidate in "${BUILD_DIR}${path}" \
                     "${BUILD_DIR}${path%/}/index.html" \
                     "${BUILD_DIR}${path%/}.html"; do
        if [[ -f "$candidate" || -d "$candidate" ]]; then
            jq -n --arg url "${BASE_URL}${link}" --arg source "$source" --arg element "$link" \
                --arg status "ok" --arg http_code "200" \
                --arg effective_url "${BASE_URL}${link}" --arg issue "" \
                --arg checked_at "$TIMESTAMP" \
                '{url:$url,source:$source,element:$element,status:$status,http_code:$http_code,effective_url:$effective_url,issue:$issue,checked_at:$checked_at}'
            return 0
        fi
    done
    jq -n --arg url "${BASE_URL}${link}" --arg source "$source" --arg element "$link" \
        --arg status "fail" --arg http_code "404" \
        --arg effective_url "${BASE_URL}${link}" --arg issue "not found in local build (BUILD_DIR)" \
        --arg checked_at "$TIMESTAMP" \
        '{url:$url,source:$source,element:$element,status:$status,http_code:$http_code,effective_url:$effective_url,issue:$issue,checked_at:$checked_at}'
}

extract_links() {
    local html_file="$1" route="$2"
    grep -oE '(href|src)=("[^"]*"|[^" >]+)' "$html_file" 2>/dev/null | \
        sed -E 's/^(href|src)=//; s/^"//; s/"$//' | \
        grep -v '^#' | grep -v '^mailto:' | grep -v '^tel:' | grep -v '^javascript:' | \
        sort -u | while read -r link; do
            local full_url
            if [[ "$link" =~ ^https?:// ]]; then
                full_url="$link"
            elif [[ "$link" =~ ^// ]]; then
                full_url="https:$link"
            else
                full_url="${BASE_URL}${link}"
            fi
            echo "$full_url|$route|$link"
        done
}

main() {
    local routes_file="${SCRIPT_DIR}/.routes.txt"

    # Collect routes — crawl built HTML
    find "${BUILD_DIR}" -name '*.html' -not -name '404.html' | \
        sed "s|${BUILD_DIR}||" | sed 's|index.html$||' | sort -u > "$routes_file"

    echo "=== ApexMail Broken-Link Check ==="
    echo "Routes found: $(wc -l < "$routes_file" | tr -d ' ')"

    while IFS= read -r route; do
        local html_file="${BUILD_DIR}${route}index.html"
        [[ -f "$html_file" ]] || html_file="${BUILD_DIR}${route}.html"
        [[ -f "$html_file" ]] || continue

        [[ -z "$route" ]] && route="/"

        while IFS='|' read -r url source element; do
            [[ -z "$url" ]] && continue
            TOTAL_LINKS=$((TOTAL_LINKS+1))
            local r
            local path_form=""
            if [[ "$element" == /* && "$element" != //* ]]; then
                path_form="$element"
            elif [[ "$url" == "$BASE_URL"/* ]]; then
                # An absolute link to our own canonical domain (canonical,
                # og:url, hreflang alternates — every page carries a handful)
                # is an INTERNAL link: resolve it against the local build,
                # never against production. Curling them per page hammered
                # the live nginx into answering 429s.
                path_form="${url#"$BASE_URL"}"
            fi
            if [[ -n "$path_form" ]]; then
                case "$path_form" in
                    # Edge-proxied dynamic routes (the nginx marketing vhost
                    # forwards /api/… to the status-server): no static build
                    # artifact exists BY DESIGN — verify over the network.
                    /api/*)
                        r="$(check_url "$url" "$source" "$element")" ;;
                    *)
                        r="$(check_internal_link "$path_form" "$source")" ;;
                esac
            else
                r="$(check_url "$url" "$source" "$element")"
            fi
            # Records accumulate as JSONL on disk — a shell string of one
            # JSON object per (page, link) pair grows past ARG_MAX and the
            # final jq call dies with "Argument list too long".
            printf '%s\n' "$r" >> "$RESULTS_JSONL"
            local st
            st="$(echo "$r" | jq -r '.status')"
            if [[ "$st" == "fail" ]]; then
                TOTAL_FAILED=$((TOTAL_FAILED+1))
                echo "  FAIL: $url (from $source) — $(echo "$r" | jq -r '.issue')"
            elif [[ "$st" == "warn" ]]; then
                echo "  WARN: $url (from $source) — $(echo "$r" | jq -r '.issue')"
            fi
        done < <(extract_links "$html_file" "$route")
    done < "$routes_file"

    # Check anchors
    echo ""
    echo "=== Anchor Validation ==="
    while read -r f; do
        local anchors
        anchors="$(grep -oE 'id=("[^"]*"|[^" >]+)' "$f" 2>/dev/null | sed -E 's/^id=//; s/"//g' || true)"
        local href_anchors
        href_anchors="$(grep -oE 'href=("#[^"]*"|#[^" >]+)' "$f" 2>/dev/null | sed -E 's/^href=#?//; s/"//g' || true)"
        while read -r a; do
            [[ -z "$a" ]] && continue
            if ! echo "$anchors" | grep -qFx "$a"; then
                echo "  BROKEN ANCHOR: #$a in $(echo "$f" | sed "s|${BUILD_DIR}||")"
                TOTAL_FAILED=$((TOTAL_FAILED+1))
            fi
        done <<< "$href_anchors"
    done < <(find "${BUILD_DIR}" -name '*.html')

    # Derive the critical count from the collected results: check_url runs in
    # a command-substitution subshell, so its CRITICAL_FAILURES increments
    # would otherwise never reach this shell.
    CRITICAL_FAILURES="$(jq -s '[.[] | select(.status == "fail")] | length' "$RESULTS_JSONL")"

    # Save report
    jq -n --slurpfile results "$RESULTS_JSONL" \
        --arg checked_at "$TIMESTAMP" \
        --argjson total_links "$TOTAL_LINKS" \
        --argjson total_failed "$TOTAL_FAILED" \
        --argjson critical "$CRITICAL_FAILURES" \
        '{checked_at:$checked_at,total_links:$total_links,failed:$total_failed,critical:$critical,results:($results[0] // [])}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Total links: $TOTAL_LINKS"
    echo "Failed: $TOTAL_FAILED"
    echo "Critical: $CRITICAL_FAILURES"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL_FAILURES" -eq 0 ]]
}

main "$@"
