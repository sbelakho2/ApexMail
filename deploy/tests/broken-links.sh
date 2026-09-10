#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# broken-links.sh — Internal and external link checker for production builds.
# Crawls every production route and checks internal links (200/301),
# external links (accessible), anchors, redirect chains, and broken resources.
# Non-zero exit on critical broken links.
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

check_url() {
    local url="$1" source="$2" element="$3"
    local http_code effective_url redirect_count
    local output
    output="$(curl -sS -o /dev/null -w '%{http_code}|%{url_effective}|%{num_redirects}' \
        --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
        -L --max-redirs "$MAX_REDIRECTS" \
        "$url" 2>/dev/null)" || {
        http_code="000"; effective_url="$url"; redirect_count="0"
    }
    IFS='|' read -r http_code effective_url redirect_count <<< "$output"

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
    grep -oP '(?:href|src)="([^"]+)"' "$html_file" 2>/dev/null | \
        sed 's/.*="//;s/"$//' | \
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
    local results="[]"
    local routes_file="${SCRIPT_DIR}/.routes.txt"

    # Collect routes — crawl built HTML
    find "${BUILD_DIR}" -name '*.html' -not -name '404.html' | \
        sed "s|${BUILD_DIR}||" | sed 's|index.html$||' | sort -u > "$routes_file"

    echo "=== ApexMail Broken-Link Check ==="
    echo "Routes found: $(wc -l < "$routes_file")"

    while IFS= read -r route; do
        local html_file="${BUILD_DIR}${route}index.html"
        [[ -f "$html_file" ]] || html_file="${BUILD_DIR}${route}.html"
        [[ -f "$html_file" ]] || continue

        [[ -z "$route" ]] && route="/"

        while IFS='|' read -r url source element; do
            TOTAL_LINKS=$((TOTAL_LINKS+1))
            local r
            if [[ "$element" == /* && "$element" != //* ]]; then
                r="$(check_internal_link "$element" "$source")"
            else
                r="$(check_url "$url" "$source" "$element")"
            fi
            results="$(echo "$results" | jq ". + [$r]")"
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
        anchors="$(grep -oP 'id="([^"]+)"' "$f" 2>/dev/null | sed 's/id="//;s/"$//' || true)"
        local href_anchors
        href_anchors="$(grep -oP 'href="#([^"]+)"' "$f" 2>/dev/null | sed 's/href="#//;s/"$//' || true)"
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
    CRITICAL_FAILURES="$(echo "$results" | jq '[.[] | select(.status == "fail")] | length')"

    # Save report
    jq -n --argjson results "$results" \
        --arg checked_at "$TIMESTAMP" \
        --argjson total_links "$TOTAL_LINKS" \
        --argjson total_failed "$TOTAL_FAILED" \
        --argjson critical "$CRITICAL_FAILURES" \
        '{checked_at:$checked_at,total_links:$total_links,failed:$total_failed,critical:$critical,results:$results}' \
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
