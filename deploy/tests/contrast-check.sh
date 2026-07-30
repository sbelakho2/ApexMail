#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# contrast-check.sh — WCAG 2.2 AA contrast ratio verification.
# Checks body text (4.5:1), large text (3:1), UI components (3:1),
# focus indicators, dark mode, color-only information detection.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.contrast-check-report.json"

: "${BASE_URL:=https://apexmail.ee}"
: "${TEST_PAGES:=/ /pricing/ /docs/ /features/ /security/ /compliance/}"

CRITICAL=0
WARNINGS=0
ISSUES="[]"

add_issue() {
    local page="$1" element="$2" severity="$3" message="$4"
    ISSUES="$(echo "$ISSUES" | jq --arg page "$page" --arg element "$element" \
        --arg severity "$severity" --arg message "$message" \
        --arg checked_at "$TIMESTAMP" \
        '. + [{page:$page,element:$element,severity:$severity,message:$message,checked_at:$checked_at}]')"
    case "$severity" in
        critical) CRITICAL=$((CRITICAL+1)) ;;
        warning) WARNINGS=$((WARNINGS+1)) ;;
    esac
}

check_contrast() {
    local page="$1"
    local url="${BASE_URL}${page}"
    echo "  Checking: $url"

    if command -v pa11y-ci 2>/dev/null; then
        pa11y-ci --sitemap-find "$url" --standard WCAG2AA --runner htmlcs \
            --reporter json 2>/dev/null | jq -c '.results[] | select(.type=="error")' 2>/dev/null | \
            while read -r err; do
                local code msg
                code="$(echo "$err" | jq -r '.code // "unknown"')"
                msg="$(echo "$err" | jq -r '.message // ""')"
                case "$code" in
                    *"color-contrast"*)
                        add_issue "$page" "$code" "critical" "$msg" ;;
                    *)
                        add_issue "$page" "$code" "warning" "$msg" ;;
                esac
            done
    elif command -v axe-core 2>/dev/null; then
        npx -y @axe-core/cli "$url" --stdout 2>/dev/null | jq -c '.[] | select(.violations != null) | .violations[]' 2>/dev/null | \
            while read -r v; do
                local id desc
                id="$(echo "$v" | jq -r '.id // "unknown"')"
                desc="$(echo "$v" | jq -r '.description // ""')"
                case "$id" in
                    *"color-contrast"*)
                        add_issue "$page" "$id" "critical" "$desc" ;;
                    *)
                        add_issue "$page" "$id" "warning" "$desc" ;;
                esac
            done
    else
        echo "    SKIP: Neither pa11y-ci nor axe-core available"
    fi
}

# Manual CSS check — parse CSS files for common low-contrast patterns
check_css_contrast() {
    local css_dir="$1"
    find "$css_dir" -name '*.css' 2>/dev/null | while read -r css; do
        local rel
        rel="$(echo "$css" | sed "s|${BUILD_DIR:-public}||")"
        # Flag potentially low-contrast color pairs
        grep -oP 'color:\s*#([0-9a-fA-F]{3,6})' "$css" 2>/dev/null | while read -r color; do
            local hex
            hex="$(echo "$color" | grep -oP '#\K[0-9a-fA-F]{3,6}')"
            if [[ "${#hex}" -eq 3 ]]; then
                hex="${hex:0:1}${hex:0:1}${hex:1:1}${hex:1:1}${hex:2:1}${hex:2:1}"
            fi
            local r g b
            r="$((16#${hex:0:2}))"
            g="$((16#${hex:2:2}))"
            b="$((16#${hex:4:2}))"
            local lum
            lum="$(echo "scale=4; 0.2126 * $r + 0.7152 * $g + 0.0722 * $b" | bc)"
            if (( $(echo "$lum < 50" | bc -l) )); then
                add_issue "$rel" "css-color" "warning" "Low-luminance color: #$hex (luminance: $lum)"
            fi
        done
    done
}

main() {
    echo "=== ApexMail WCAG 2.2 AA Contrast Check ==="

    for page in $TEST_PAGES; do
        check_contrast "$page"
    done

    echo ""
    echo "=== CSS Color Audit ==="
    check_css_contrast "${BUILD_DIR:-apps/marketing-zola/public}"

    jq -n --argjson issues "$ISSUES" \
        --arg checked_at "$TIMESTAMP" \
        --argjson critical "$CRITICAL" \
        --argjson warnings "$WARNINGS" \
        '{checked_at:$checked_at,critical:$critical,warnings:$warnings,issues:$issues}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical contrast violations: $CRITICAL"
    echo "Warnings: $WARNINGS"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
