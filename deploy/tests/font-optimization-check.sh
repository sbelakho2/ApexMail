#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# font-optimization-check.sh — Font optimization audit.
# Checks: font family count, weight count, font-display usage, preloading,
# unused variants, fallback definitions, layout shift prevention.
# =============================================================================
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly TIMESTAMP
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly REPORT_FILE="${SCRIPT_DIR}/.font-optimization-report.json"

: "${BUILD_DIR:=../apps/marketing-zola/public}"

CRITICAL=0
WARNINGS=0
ISSUES="[]"

add_issue() {
    local file="$1" check="$2" severity="$3" detail="$4"
    ISSUES="$(echo "$ISSUES" | jq --arg file "$file" --arg check "$check" \
        --arg severity "$severity" --arg detail "$detail" \
        --arg checked_at "$TIMESTAMP" \
        '. + [{file:$file,check:$check,severity:$severity,detail:$detail,checked_at:$checked_at}]')"
}

check_css_fonts() {
    echo "=== CSS Font Audit ==="
    find "${BUILD_DIR}" -name '*.css' 2>/dev/null | while read -r css; do
        local rel
        rel="$(echo "$css" | sed "s|${BUILD_DIR}||")"

        # Count font-family usage
        local families
        families="$(grep -oP "font-family:\s*'?\"?([^'\";,]+)" "$css" 2>/dev/null | sed 's/font-family:\s*['\''\"]//g' | sed 's/['\''\"].*//' | sort -u || echo "")"
        local family_count
        family_count="$(echo "$families" | grep -c '.' 2>/dev/null || echo 0)"

        if [[ "$family_count" -gt 3 ]]; then
            add_issue "$rel" "font-families" "warning" "$family_count font families (target: <=3)"
            WARNINGS=$((WARNINGS+1))
        fi

        # Check font-display
        if ! grep -q 'font-display' "$css" 2>/dev/null; then
            add_issue "$rel" "font-display" "critical" "No font-display defined — fonts may block render"
            CRITICAL=$((CRITICAL+1))
        fi

        # Count font weights
        local weights
        weights="$(grep -oP 'font-weight:\s*\d+' "$css" 2>/dev/null | grep -oP '\d+' | sort -u || echo "")"
        local weight_count
        weight_count="$(echo "$weights" | grep -c '.' 2>/dev/null || echo 0)"

        if [[ "$weight_count" -gt 6 ]]; then
            add_issue "$rel" "font-weights" "warning" "$weight_count font weights (consider subsetting)"
            WARNINGS=$((WARNINGS+1))
        fi

        # Check for fallback fonts
        grep 'font-family' "$css" 2>/dev/null | while read -r ff_line; do
            if ! echo "$ff_line" | grep -q ','; then
                add_issue "$rel" "fallback" "warning" "font-family missing fallback stack"
                WARNINGS=$((WARNINGS+1))
            fi
        done
    done
}

check_html_preload() {
    echo "=== Font Preload Audit ==="
    find "${BUILD_DIR}" -name '*.html' | while read -r html; do
        local rel
        rel="$(echo "$html" | sed "s|${BUILD_DIR}||")"

        local preload_count
        preload_count="$(grep -cP 'rel="preload".*font' "$html" 2>/dev/null || echo 0)"
        local font_ref_count
        font_ref_count="$(grep -cP '@font-face|url\(.*\.(woff2?|ttf|otf)' "$html" 2>/dev/null || echo 0)"

        if [[ "$font_ref_count" -gt 0 && "$preload_count" -eq 0 ]]; then
            add_issue "$rel" "preload" "warning" "Fonts referenced but not preloaded"
            WARNINGS=$((WARNINGS+1))
        fi

        # Check for excessive preloads
        if [[ "$preload_count" -gt 3 ]]; then
            add_issue "$rel" "preload" "warning" "$preload_count font preloads (consider limiting to critical fonts)"
            WARNINGS=$((WARNINGS+1))
        fi
    done
}

check_font_formats() {
    echo "=== Font Format Audit ==="
    local font_count
    font_count="$(find "${BUILD_DIR}" \( -name '*.woff2' -o -name '*.woff' -o -name '*.ttf' -o -name '*.otf' \) 2>/dev/null | wc -l)"
    echo "  Detected font files: $font_count"

    find "${BUILD_DIR}" \( -name '*.ttf' -o -name '*.otf' \) 2>/dev/null | while read -r font; do
        local rel
        rel="$(echo "$font" | sed "s|${BUILD_DIR}||")"
        add_issue "$rel" "format" "warning" "Legacy font format: .ttf/.otf — consider .woff2"
        WARNINGS=$((WARNINGS+1))
    done
}

main() {
    echo "=== ApexMail Font Optimization Check ==="

    check_css_fonts
    check_html_preload
    check_font_formats

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
