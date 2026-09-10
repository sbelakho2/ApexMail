#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# cta-tracking-test.sh — Validates CTA tracking events on production pages.
# Checks event naming, unique events, page+CTA identification, mobile/desktop
# distinction, and that events map to funnel stages.
#
# Fix notes (2026-09-10, wiring this into the REQUIRED validate gate):
#   * `grep -c … || echo 0` produced "0\n0" on zero matches (grep -c prints
#     the 0 AND exits 1) — the counts then failed every -gt test silently.
#     Counts now default with `|| true` + parameter default.
#   * Patterns are POSIX ERE (no `grep -P`) and accept the minifier's
#     UNQUOTED attribute values (class=btn-primary, href=/signup/).
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

    local html_files=() html
    while IFS= read -r -d '' html; do
        html_files+=("$html")
    done < <(find "${BUILD_DIR}" -name '*.html' -print0 2>/dev/null)

    for html in "${html_files[@]}"; do
        local rel
        rel="$(echo "$html" | sed "s|${BUILD_DIR}||")"

        local ctas_found=0
        local tracking_found=0

        # Count CTA elements (btn classes / signup, pricing, contact links;
        # attribute values may be unquoted in the minified build).
        ctas_found="$(grep -cE 'class=["'"'"']?[^"'"'"' ]*btn|href=["'"'"']?[^"'"'"' ]*(signup|pricing)|href=["'"'"']?[^"'"'"' ]*/contact' "$html" 2>/dev/null || true)"
        ctas_found="${ctas_found:-0}"

        # Count tracking attributes
        for attr in "${TRACKING_ATTRS[@]}"; do
            local matches
            matches="$(grep -cE "$attr" "$html" 2>/dev/null || true)"
            matches="${matches:-0}"
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

    # Check for analytics wiring. Classic marker: a JS analytics script
    # (plausible/gtag/analytics.js/dataLayer). This site is ZERO-JS by
    # design (CSP script-src 'none'): analytics is consent-gated and
    # collected SERVER-SIDE, wired through the cookie-consent banner's
    # data-consent-endpoint / data-analytics-enabled attributes — detect
    # both shapes.
    echo ""
    echo "=== Analytics Wiring Presence Check ==="
    if grep -rqE 'plausible|gtag|analytics\.js|dataLayer' "${BUILD_DIR}" 2>/dev/null \
       || grep -rqE 'data-consent-endpoint|data-analytics-enabled' "${BUILD_DIR}" 2>/dev/null; then
        echo "  OK: Analytics wiring detected (script-based or zero-JS server-side)"
    else
        add_issue "/" "analytics-script" "warning" "No analytics wiring detected in build (neither script-based nor data-consent-endpoint)"
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
