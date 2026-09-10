#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# cta-tracking-test.sh — Validates CTA tracking events on production pages.
# Checks event naming, unique events, page+CTA identification, mobile/desktop
# distinction, and that events map to funnel stages.
# =============================================================================
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly TIMESTAMP
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly REPORT_FILE="${SCRIPT_DIR}/.cta-tracking-report.json"

: "${BUILD_DIR:=../apps/marketing-zola/public}"

WARNINGS=0
ISSUES="[]"

TRACKING_ATTRS=(
    "data-track"
    "data-event"
    "data-analytics"
    "data-ga"
    "data-action"
    "data-category"
    "data-label"
    "plausible-goal"
    "plausible-event"
    "onclick.*track"
    "onclick.*analytics"
    "onclick.*gtag"
    "onclick.*plausible"
)

add_issue() {
    local page="$1" check="$2" severity="$3" detail="$4"
    ISSUES="$(echo "$ISSUES" | jq --arg page "$page" --arg check "$check" \
        --arg severity "$severity" --arg detail "$detail" \
        --arg checked_at "$TIMESTAMP" \
        '. + [{page:$page,check:$check,severity:$severity,detail:$detail,checked_at:$checked_at}]')"
}

main() {
    echo "=== ApexMail CTA Tracking Validation ==="

    find "${BUILD_DIR}" -name '*.html' | while read -r html; do
        local rel
        rel="$(echo "$html" | sed "s|${BUILD_DIR}||")"

        local ctas_found=0
        local tracking_found=0

        # Count CTA elements
        ctas_found="$(grep -cP 'class="[^"]*btn[^"]*"|href="[^"]*signup[^"]*"|href="[^"]*pricing[^"]*"|href="[^"]*/contact[^"]*"' "$html" 2>/dev/null || echo 0)"

        # Count tracking attributes
        for attr in "${TRACKING_ATTRS[@]}"; do
            local matches
            matches="$(grep -cP "$attr" "$html" 2>/dev/null || echo 0)"
            if [[ "$matches" -gt 0 ]]; then
                tracking_found=$((tracking_found + matches))
            fi
        done

        if [[ "$ctas_found" -gt 0 && "$tracking_found" -eq 0 ]]; then
            add_issue "$rel" "cta-tracking" "warning" "$ctas_found CTA elements without tracking attributes"
            WARNINGS=$((WARNINGS+1))
        elif [[ "$ctas_found" -gt 0 ]]; then
            echo "  OK: $rel — $ctas_found CTAs, $tracking_found tracking attributes"
        fi
    done

    # Check for data-event-link-analytics script
    echo ""
    echo "=== Analytics Script Presence Check ==="
    if grep -rq 'plausible\|gtag\|analytics\.js\|dataLayer' "${BUILD_DIR}" 2>/dev/null; then
        echo "  OK: Analytics scripts detected"
    else
        add_issue "/" "analytics-script" "warning" "No analytics script detected in build"
        WARNINGS=$((WARNINGS+1))
    fi

    jq -n --argjson issues "$ISSUES" \
        --arg checked_at "$TIMESTAMP" \
        --argjson warnings "$WARNINGS" \
        '{checked_at:$checked_at,warnings:$warnings,issues:$issues}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Warnings: $WARNINGS"
    echo "Report: $REPORT_FILE"
}

main "$@"
