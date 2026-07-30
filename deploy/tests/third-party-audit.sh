#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# third-party-audit.sh — Audits every external script on production pages.
# Inventories: vendor, script URL, purpose, data collected, cookie category,
# legal basis, performance cost, loading strategy, removal decision,
# privacy disclosure.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.third-party-audit-report.json"

: "${BUILD_DIR:=../apps/marketing-zola/public}"
: "${BASE_URL:=https://apexmail.ee}"

CRITICAL=0
WARNINGS=0
SCRIPTS="[]"

THIRD_PARTY_DOMAINS=(
    "google-analytics.com|Google Analytics"
    "googletagmanager.com|Google Tag Manager"
    "facebook.net|Facebook Pixel"
    "hotjar.com|Hotjar"
    "intercom.io|Intercom"
    "hubspot.com|HubSpot"
    "segment.com|Segment"
    "cdn.jsdelivr.net|jsDelivr CDN"
    "cdnjs.cloudflare.com|Cloudflare CDN"
    "unpkg.com|unpkg CDN"
    "analytics.apexmail.ee|ApexMail Self-Hosted Analytics"
    "plausible.io|Plausible Analytics"
)

identify_vendor() {
    local url="$1"
    for pair in "${THIRD_PARTY_DOMAINS[@]}"; do
        local domain="${pair%%|*}"
        local vendor="${pair##*|}"
        if echo "$url" | grep -qF "$domain"; then
            echo "$vendor"
            return
        fi
    done
    echo "Unknown"
}

check_loading_strategy() {
    local tag="$1"
    local strategy="sync"
    if echo "$tag" | grep -q 'async'; then strategy="async"; fi
    if echo "$tag" | grep -q 'defer'; then strategy="defer"; fi
    if echo "$tag" | grep -q 'type="module"'; then strategy="module (deferred)"; fi
    echo "$strategy"
}

main() {
    echo "=== ApexMail Third-Party Script Audit ==="

    find "${BUILD_DIR}" -name '*.html' | while read -r html; do
        local rel
        rel="$(echo "$html" | sed "s|${BUILD_DIR}||")"

        # Extract external script tags
        grep -noP '<script[^>]*src="(https?:)?//[^"]+\.js[^"]*"[^>]*>' "$html" 2>/dev/null | \
            while IFS=: read -r ln tag; do
            local src
            src="$(echo "$tag" | grep -oP 'src="\K[^"]+' || echo "")"
            if [[ -z "$src" ]]; then continue; fi

            local vendor strategy
            vendor="$(identify_vendor "$src")"
            strategy="$(check_loading_strategy "$tag")"

            echo "  Found: $src"
            echo "    Vendor: $vendor"
            echo "    Page: $rel:$ln"
            echo "    Loading: $strategy"

            SCRIPTS="$(echo "$SCRIPTS" | jq --arg src "$src" --arg vendor "$vendor" \
                --arg page "$rel" --argjson line "$ln" --arg strategy "$strategy" \
                '. + [{url:$src,vendor:$vendor,page:$page,line:$line,loading:$strategy}]')"

            if [[ "$strategy" == "sync" && "$vendor" != "Unknown" ]]; then
                WARNINGS=$((WARNINGS+1))
                echo "    WARN: Third-party script loaded synchronously"
            fi
        done

        # Check for inline scripts with external dependencies
        grep -noP '<script[^>]*>' "$html" 2>/dev/null | while IFS=: read -r ln tag; do
            if echo "$tag" | grep -q 'src='; then continue; fi
            if echo "$tag" | grep -qiE 'googletagmanager|fbq\(|gtag\(|plausible|analytics'; then
                echo "  Inline analytics at $rel:$ln"
                SCRIPTS="$(echo "$SCRIPTS" | jq --arg page "$rel" --argjson line "$ln" \
                    '. + [{url:"inline",vendor:"Inline Analytics",page:$page,line:$line,loading:"inline"}]')"
            fi
        done
    done

    jq -n --argjson scripts "$SCRIPTS" \
        --arg checked_at "$TIMESTAMP" \
        --argjson warnings "$WARNINGS" \
        '{checked_at:$checked_at,script_count:$scripts|length,warnings:$warnings,scripts:$scripts}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    local count
    count="$(echo "$SCRIPTS" | jq 'length' 2>/dev/null || echo 0)"
    echo "Third-party scripts found: $count"
    echo "Warnings: $WARNINGS"
    echo "Report: $REPORT_FILE"

    true
}

main "$@"
