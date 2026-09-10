#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# seo-validate.sh — SEO metadata and structured data validation.
# Checks: unique titles, unique descriptions, canonicals, OG tags, Twitter
# cards, JSON-LD validity, sitemap integrity, robots.txt, indexing controls.
# =============================================================================
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly TIMESTAMP
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly REPORT_FILE="${SCRIPT_DIR}/.seo-validation-report.json"

: "${BUILD_DIR:=../apps/marketing-zola/public}"
: "${BASE_URL:=https://apexmail.ee}"

CRITICAL=0
WARNINGS=0
ISSUES="[]"

add_issue() {
    local file="$1" severity="$2" message="$3"
    ISSUES="$(echo "$ISSUES" | jq --arg file "$file" --arg severity "$severity" \
        --arg message "$message" --arg checked_at "$TIMESTAMP" \
        '. + [{file:$file,severity:$severity,message:$message,checked_at:$checked_at}]')"
    case "$severity" in
        critical) CRITICAL=$((CRITICAL+1)) ;;
        warning) WARNINGS=$((WARNINGS+1)) ;;
    esac
}

extract_meta() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local title
    # Flatten newlines first: built HTML can split the title across lines.
    title="$(tr '\n' ' ' < "$file" | grep -oP '<title>\K[^<]+' || true)"
    local desc
    desc="$(grep -oP '<meta\s+name="description"\s+content="([^"]+)"' "$file" 2>/dev/null | grep -oP 'content="\K[^"]+' || echo "")"
    local canonical
    canonical="$(grep -oP '<link\s+rel="canonical"\s+href="([^"]+)"' "$file" 2>/dev/null | grep -oP 'href="\K[^"]+' || echo "")"
    local og_title
    og_title="$(grep -oP '<meta\s+property="og:title"\s+content="([^"]+)"' "$file" 2>/dev/null | grep -oP 'content="\K[^"]+' || echo "")"
    local og_desc
    og_desc="$(grep -oP '<meta\s+property="og:description"\s+content="([^"]+)"' "$file" 2>/dev/null | grep -oP 'content="\K[^"]+' || echo "")"
    local og_image
    og_image="$(grep -oP '<meta\s+property="og:image"\s+content="([^"]+)"' "$file" 2>/dev/null | grep -oP 'content="\K[^"]+' || echo "")"
    local robots
    robots="$(grep -oP '<meta\s+name="robots"\s+content="([^"]+)"' "$file" 2>/dev/null | grep -oP 'content="\K[^"]+' || echo "index, follow")"
    local jsonld
    # grep -c prints "0" and exits 1 on zero matches — `|| echo 0` would
    # append a second 0 ("0\n0") and break the jq --argjson call below.
    jsonld="$(grep -c 'application/ld+json' "$file" 2>/dev/null || true)"
    jsonld="${jsonld:-0}"

    jq -n --arg path "$path" --arg title "$title" --arg desc "$desc" \
        --arg canonical "$canonical" --arg og_title "$og_title" \
        --arg og_desc "$og_desc" --arg og_image "$og_image" \
        --arg robots "$robots" --argjson jsonld "$jsonld" \
        '{path:$path,title:$title,description:$desc,canonical:$canonical,og_title:$og_title,og_description:$og_desc,og_image:$og_image,robots:$robots,jsonld_blocks:$jsonld}'
}

main() {
    echo "=== ApexMail SEO & Metadata Validation ==="

    local titles_seen=""
    local descriptions_seen=""

    while read -r file; do
        local meta
        meta="$(extract_meta "$file")"
        local path title desc canonical og_title og_desc og_image robots jsonld
        path="$(echo "$meta" | jq -r '.path')"
        title="$(echo "$meta" | jq -r '.title')"
        desc="$(echo "$meta" | jq -r '.description')"
        canonical="$(echo "$meta" | jq -r '.canonical')"
        og_title="$(echo "$meta" | jq -r '.og_title')"
        og_desc="$(echo "$meta" | jq -r '.og_description')"
        og_image="$(echo "$meta" | jq -r '.og_image')"
        robots="$(echo "$meta" | jq -r '.robots')"
        jsonld="$(echo "$meta" | jq -r '.jsonld_blocks')"

        echo "  $path"

        # Check title
        if [[ -z "$title" ]]; then
            add_issue "$path" "critical" "Missing page title"
        elif echo "$titles_seen" | grep -qFx "$title"; then
            add_issue "$path" "warning" "Duplicate title: $title"
        else
            titles_seen="$titles_seen"$'\n'"$title"
        fi

        # Check description
        if [[ -z "$desc" ]]; then
            add_issue "$path" "warning" "Missing meta description"
        elif echo "$descriptions_seen" | grep -qFx "$desc"; then
            add_issue "$path" "warning" "Duplicate description"
        else
            descriptions_seen="$descriptions_seen"$'\n'"$desc"
        fi

        # Check canonical
        if [[ -z "$canonical" ]]; then
            add_issue "$path" "warning" "Missing canonical URL"
        elif [[ "$canonical" != "${BASE_URL}"* ]]; then
            add_issue "$path" "warning" "Canonical not on production domain: $canonical"
        fi

        # Check OG
        if [[ -z "$og_title" ]]; then
            add_issue "$path" "warning" "Missing og:title"
        fi
        if [[ -z "$og_desc" ]]; then
            add_issue "$path" "warning" "Missing og:description"
        fi
        if [[ -z "$og_image" ]]; then
            add_issue "$path" "warning" "Missing og:image"
        fi

        # Check robots
        if echo "$robots" | grep -q "noindex"; then
            add_issue "$path" "warning" "Page has noindex"
        fi

        # Check JSON-LD
        if [[ "$jsonld" -eq 0 ]] && [[ "$path" == "/" || "$path" == "/index.html" ]]; then
            add_issue "$path" "warning" "Homepage missing JSON-LD structured data"
        fi
    done < <(find "${BUILD_DIR}" -name '*.html' -not -name '404.html' | sort)

    # Check sitemap
    echo ""
    echo "=== Sitemap Check ==="
    if [[ -f "${BUILD_DIR}/sitemap.xml" ]]; then
        local sitemap_urls
        sitemap_urls="$(grep -c '<url>' "${BUILD_DIR}/sitemap.xml" 2>/dev/null || true)"
        sitemap_urls="${sitemap_urls:-0}"
        echo "  Sitemap URLs: $sitemap_urls"

        grep 'noindex' "${BUILD_DIR}/sitemap.xml" 2>/dev/null && \
            add_issue "/sitemap.xml" "critical" "Sitemap contains noindex pages" || true
    else
        add_issue "/sitemap.xml" "warning" "Sitemap not found"
    fi

    # Check robots.txt
    if [[ -f "${BUILD_DIR}/robots.txt" ]]; then
        if grep -q 'Disallow: /' "${BUILD_DIR}/robots.txt" 2>/dev/null; then
            add_issue "/robots.txt" "critical" "robots.txt disallows all"
        fi
    else
        add_issue "/robots.txt" "warning" "robots.txt not found"
    fi

    jq -n --argjson issues "$ISSUES" \
        --arg checked_at "$TIMESTAMP" \
        --argjson critical "$CRITICAL" \
        --argjson warnings "$WARNINGS" \
        '{checked_at:$checked_at,critical:$critical,warnings:$warnings,issues:$issues}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical: $CRITICAL"
    echo "Warnings: $WARNINGS"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
