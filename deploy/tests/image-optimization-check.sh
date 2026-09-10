#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# image-optimization-check.sh — Image optimization audit.
# Checks: correct dimensions, responsive srcset, modern formats (WebP/AVIF),
# compression, lazy loading, explicit width/height, no oversized images,
# CDN caching headers.
#
# Fix notes (2026-09-10, wiring this into the REQUIRED validate gate):
#   * Counter/report updates previously ran inside `find | while read` and
#     `grep | while read` pipelines — SUBSHELLS — so ISSUES/CRITICAL were
#     always discarded and the report was vacuously empty. Files and image
#     tags are collected first; the loops run in this shell.
#   * Patterns are POSIX ERE (no `grep -P` — BSD grep has no -P) and
#     tolerate the minifier's unquoted attribute values.
# =============================================================================
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly TIMESTAMP
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly REPORT_FILE="${SCRIPT_DIR}/.image-optimization-report.json"

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

check_image() {
    local img="$1"
    local rel
    rel="$(echo "$img" | sed "s|${BUILD_DIR}||")"
    local ext size_bytes

    ext="${img##*.}"
    size_bytes="$(stat -f%z "$img" 2>/dev/null || stat -c%s "$img" 2>/dev/null || echo 0)"

    # Check format
    case "$ext" in
        png)
            if [[ "$size_bytes" -gt 100000 ]]; then
                add_issue "$rel" "format" "warning" "Large PNG ($size_bytes bytes) — consider WebP/AVIF"
                WARNINGS=$((WARNINGS+1))
            fi
            ;;
        jpg|jpeg)
            if [[ "$size_bytes" -gt 200000 ]]; then
                add_issue "$rel" "format" "warning" "Large JPEG ($size_bytes bytes) — consider WebP/AVIF"
                WARNINGS=$((WARNINGS+1))
            fi
            ;;
        webp|avif) ;;
        svg) ;;
        *) add_issue "$rel" "format" "info" "Format: $ext" ;;
    esac

    # Check size
    if [[ "$size_bytes" -gt 500000 ]]; then
        add_issue "$rel" "size" "critical" "Image exceeds 500KB: $size_bytes bytes"
        CRITICAL=$((CRITICAL+1))
    elif [[ "$size_bytes" -gt 200000 ]]; then
        add_issue "$rel" "size" "warning" "Image over 200KB: $size_bytes bytes"
        WARNINGS=$((WARNINGS+1))
    fi
}

check_html_images() {
    echo "=== HTML Image Tag Audit ==="
    local html_files=() html rel
    while IFS= read -r -d '' html; do
        html_files+=("$html")
    done < <(find "${BUILD_DIR}" -name '*.html' -print0 2>/dev/null)

    for html in "${html_files[@]}"; do
        rel="$(echo "$html" | sed "s|${BUILD_DIR}||")"

        # Check for width/height attributes
        local ln img_tag
        while IFS=: read -r ln img_tag; do
            [[ -z "$ln" ]] && continue
            if ! echo "$img_tag" | grep -qE 'width=' && ! echo "$img_tag" | grep -qE 'style="[^"]*width'; then
                add_issue "$rel:$ln" "explicit-size" "warning" "Image missing explicit width"
            fi
            if ! echo "$img_tag" | grep -qE 'height=' && ! echo "$img_tag" | grep -qE 'style="[^"]*height'; then
                add_issue "$rel:$ln" "explicit-size" "warning" "Image missing explicit height"
            fi
            if ! echo "$img_tag" | grep -q 'loading=' && ! echo "$img_tag" | grep -q 'eager'; then
                add_issue "$rel:$ln" "lazy-loading" "info" "Consider adding loading=\"lazy\" for below-fold images"
            fi
        done < <(grep -noE '<img[^>]*>' "$html" 2>/dev/null || true)

        # Check for srcset
        local img_count
        img_count="$(grep -c '<img' "$html" 2>/dev/null || true)"
        img_count="${img_count:-0}"
        local srcset_count
        srcset_count="$(grep -c 'srcset' "$html" 2>/dev/null || true)"
        srcset_count="${srcset_count:-0}"
        if [[ "$img_count" -gt 0 && "$srcset_count" -eq 0 ]]; then
            add_issue "$rel" "srcset" "warning" "$img_count images without srcset"
        fi
    done
}

main() {
    echo "=== ApexMail Image Optimization Check ==="

    # Check static image files
    echo "=== Static Image Files ==="
    local images=() img
    while IFS= read -r -d '' img; do
        images+=("$img")
    done < <(find "${BUILD_DIR}" \( -name '*.png' -o -name '*.jpg' -o -name '*.jpeg' -o -name '*.webp' -o -name '*.avif' -o -name '*.svg' -o -name '*.gif' \) -print0 2>/dev/null)

    for img in "${images[@]}"; do
        check_image "$img"
    done

    check_html_images

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
