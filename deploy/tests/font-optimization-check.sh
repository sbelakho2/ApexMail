#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# font-optimization-check.sh — Font optimization audit.
# Checks: font family count, weight count, font-display usage, preloading,
# unused variants, fallback definitions, layout shift prevention.
#
# Fix notes (2026-09-10, wiring this into the REQUIRED validate gate):
#   * Counter/report updates previously ran inside `find | while read`
#     pipelines — a SUBSHELL — so ISSUES/CRITICAL/WARNINGS were always
#     discarded and the report came out empty (vacuous green). Files are
#     collected into arrays first and the loops run in this shell.
#   * font-display is required only of stylesheets that DECLARE @font-face:
#     demanding it of e.g. no-js.css (which has none) is a false critical.
#   * Patterns are POSIX ERE — no `grep -P` (BSD grep has no -P).
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
    case "$severity" in
        critical) CRITICAL=$((CRITICAL+1)) ;;
        warning) WARNINGS=$((WARNINGS+1)) ;;
    esac
}

# Count occurrences of $2 in $1, tolerating grep -c's exit 1 on zero hits
# (`|| echo 0` appends a second 0 and breaks arithmetic).
count_in() {
    local n
    n="$(grep -c "$2" "$1" 2>/dev/null || true)"
    printf '%s' "${n:-0}"
}

check_css_fonts() {
    echo "=== CSS Font Audit ==="
    local css_files=() css rel
    while IFS= read -r -d '' css; do
        css_files+=("$css")
    done < <(find "${BUILD_DIR}" -name '*.css' -print0 2>/dev/null)

    for css in "${css_files[@]}"; do
        rel="$(echo "$css" | sed "s|${BUILD_DIR}||")"

        # Count @font-face declarations
        local font_face_count
        font_face_count="$(count_in "$css" '@font-face')"

        # Count font-family usage
        local families
        families="$(grep -oE 'font-family:[^;}>]+' "$css" 2>/dev/null \
            | sed -E "s/font-family:[[:space:]]*['\"]?//; s/['\"].*//" | sort -u || true)"
        local family_count
        family_count="$(echo "$families" | grep -c '.' || true)"
        family_count="${family_count:-0}"

        if [[ "$family_count" -gt 3 ]]; then
            add_issue "$rel" "font-families" "warning" "$family_count font families (target: <=3)"
        fi

        # font-display is only required of stylesheets that actually load
        # fonts via @font-face — a sheet without font faces cannot block
        # render on a font download.
        if [[ "$font_face_count" -gt 0 ]] && ! grep -q 'font-display' "$css" 2>/dev/null; then
            add_issue "$rel" "font-display" "critical" "No font-display defined — fonts may block render"
        fi

        # Count font weights
        local weights
        weights="$(grep -oE 'font-weight:[[:space:]]*[0-9]+' "$css" 2>/dev/null \
            | grep -oE '[0-9]+' | sort -u || true)"
        local weight_count
        weight_count="$(echo "$weights" | grep -c '.' || true)"
        weight_count="${weight_count:-0}"

        if [[ "$weight_count" -gt 6 ]]; then
            add_issue "$rel" "font-weights" "warning" "$weight_count font weights (consider subsetting)"
        fi

        # Check for fallback fonts
        local ff_line
        while IFS= read -r ff_line; do
            [[ -z "$ff_line" ]] && continue
            if ! echo "$ff_line" | grep -q ','; then
                add_issue "$rel" "fallback" "warning" "font-family missing fallback stack"
            fi
        done < <(grep 'font-family' "$css" 2>/dev/null || true)
    done
}

check_html_preload() {
    echo "=== Font Preload Audit ==="
    local html_files=() html rel
    while IFS= read -r -d '' html; do
        html_files+=("$html")
    done < <(find "${BUILD_DIR}" -name '*.html' -print0 2>/dev/null)

    for html in "${html_files[@]}"; do
        rel="$(echo "$html" | sed "s|${BUILD_DIR}||")"

        local preload_count
        # A preload link whose payload is a font (attribute order varies:
        # "…as=font crossorigin rel=preload type=font/woff2").
        preload_count="$(grep -oE '<link[^>]*rel=["'"'"']?preload["'"'"']?[^>]*>' "$html" 2>/dev/null | grep -c 'font' || true)"
        preload_count="${preload_count:-0}"
        local font_ref_count
        font_ref_count="$(grep -cE '@font-face|url\(.*\.(woff2?|ttf|otf)' "$html" 2>/dev/null || true)"
        font_ref_count="${font_ref_count:-0}"

        if [[ "$font_ref_count" -gt 0 && "$preload_count" -eq 0 ]]; then
            add_issue "$rel" "preload" "warning" "Fonts referenced but not preloaded"
        fi

        # Check for excessive preloads
        if [[ "$preload_count" -gt 3 ]]; then
            add_issue "$rel" "preload" "warning" "$preload_count font preloads (consider limiting to critical fonts)"
        fi
    done
}

check_font_formats() {
    echo "=== Font Format Audit ==="
    local font_count
    font_count="$(find "${BUILD_DIR}" \( -name '*.woff2' -o -name '*.woff' -o -name '*.ttf' -o -name '*.otf' \) 2>/dev/null | wc -l | tr -d ' ')"
    echo "  Detected font files: $font_count"

    local font_files=() font rel
    while IFS= read -r -d '' font; do
        font_files+=("$font")
    done < <(find "${BUILD_DIR}" \( -name '*.ttf' -o -name '*.otf' \) -print0 2>/dev/null)

    for font in "${font_files[@]}"; do
        rel="$(echo "$font" | sed "s|${BUILD_DIR}||")"
        add_issue "$rel" "format" "warning" "Legacy font format: .ttf/.otf — consider .woff2"
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
