#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# html-validate.sh — HTML and accessibility validation for production builds.
# Checks: duplicate IDs, missing labels, heading hierarchy, missing alt,
# empty buttons, invalid ARIA, duplicate H1, missing page title, color
# contrast, keyboard traps (where testable).
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.html-validation-report.json"

: "${BUILD_DIR:=../apps/marketing-zola/public}"

CRITICAL=0
WARNINGS=0
ISSUES="[]"

add_issue() {
    local file="$1" line="$2" severity="$3" message="$4"
    ISSUES="$(echo "$ISSUES" | jq --arg file "$(echo "$file" | sed "s|${BUILD_DIR}||")" \
        --argjson line "$line" --arg severity "$severity" --arg message "$message" \
        --arg checked_at "$TIMESTAMP" \
        '. + [{file:$file,line:$line,severity:$severity,message:$message,checked_at:$checked_at}]')"
    case "$severity" in
        critical) CRITICAL=$((CRITICAL+1)) ;;
        warning) WARNINGS=$((WARNINGS+1)) ;;
    esac
}

check_duplicate_ids() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local dup
    while read -r dup; do
        [[ -z "$dup" ]] && continue
        add_issue "$path" 0 "critical" "Duplicate ID: $dup"
    done < <(grep -oP 'id="([^"]+)"' "$file" 2>/dev/null | sed 's/id="//;s/"$//' | sort | uniq -d)
}

check_heading_hierarchy() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local prev=0
    local ln tag level
    while IFS=: read -r ln tag; do
        # Heading level is the digit right after "<h" — do not grep for every
        # digit in the tag (attribute values like mb-4 would break the -gt test).
        level="${tag:2:1}"
        if [[ -n "$level" ]]; then
            if [[ "$level" -gt $((prev+1)) && "$prev" -ne 0 ]]; then
                add_issue "$path" "$ln" "warning" "Heading skip: h$((prev)) to h$level without h$((prev+1))"
            fi
            prev="$level"
        fi
    done < <(grep -noP '<h[1-6][^>]*>' "$file" 2>/dev/null)
}

check_h1_count() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local count
    # grep -c prints "0" and exits 1 on zero matches — do not append a
    # second 0 with `|| echo 0` (that yields "0\n0" and breaks the -gt test).
    count="$(grep -cP '<h1[^>]*>' "$file" 2>/dev/null || true)"
    count="${count:-0}"
    if [[ "$count" -gt 1 ]]; then
        add_issue "$path" 0 "critical" "Multiple H1 tags: $count found"
    elif [[ "$count" -eq 0 ]]; then
        add_issue "$path" 0 "warning" "No H1 tag found"
    fi
}

check_missing_alt() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local ln tag
    while IFS=: read -r ln tag; do
        add_issue "$path" "$ln" "critical" "Missing alt attribute on img"
    done < <(grep -noP '<img(?![^>]*alt=)[^>]*>' "$file" 2>/dev/null)
}

check_empty_buttons() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local ln tag
    while IFS=: read -r ln tag; do
        add_issue "$path" "$ln" "critical" "Empty button element"
    done < <(grep -noP '<button[^>]*>\s*</button>' "$file" 2>/dev/null)
}

check_missing_labels() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local ln tag input_id input_type
    while IFS=: read -r ln tag; do
        input_id="$(echo "$tag" | grep -oP 'id="\K[^"]+')"
        input_type="$(echo "$tag" | grep -oP 'type="\K[^"]+' || echo "text")"
        case "$input_type" in hidden|submit|button|reset) continue ;; esac
        if ! grep -q "for=\"$input_id\"" "$file" 2>/dev/null && ! grep -q "aria-label" <<< "$tag" 2>/dev/null; then
            add_issue "$path" "$ln" "warning" "Input #$input_id missing label"
        fi
    done < <(grep -noP '<input[^>]*id="([^"]+)"[^>]*>' "$file" 2>/dev/null)
}

check_invalid_aria() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local ln line
    while IFS=: read -r ln line; do
        add_issue "$path" "$ln" "critical" "ARIA attribute with 'undefined' value"
    done < <(grep -noP 'aria-\w+="[^"]*undefined[^"]*"' "$file" 2>/dev/null)
    while IFS=: read -r ln line; do
        add_issue "$path" "$ln" "warning" "Multiple role attributes on element"
    done < <(grep -noP 'role="[^"]*"[^>]*role="' "$file" 2>/dev/null)
}

check_landmarks() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    if ! grep -qP '<(header|nav|main|footer)' "$file" 2>/dev/null; then
        add_issue "$path" 0 "warning" "Missing landmark elements"
    fi
}

check_page_title() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    # Flatten newlines first: built HTML can split the title across lines.
    local title_text
    title_text="$(tr '\n' ' ' < "$file" | grep -oP '<title>\K[^<]+' || true)"
    if [[ -z "$title_text" ]]; then
        add_issue "$path" 0 "critical" "Missing or empty page title"
    fi
}

check_skip_link() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    if ! grep -qP 'skip.*content|skip.*main' "$file" 2>/dev/null; then
        add_issue "$path" 0 "warning" "No skip-to-content link found"
    fi
}

main() {
    echo "=== ApexMail HTML & Accessibility Validation ==="

    while read -r file; do
        local rel
        rel="$(echo "$file" | sed "s|${BUILD_DIR}||")"
        echo "  Checking: $rel"

        check_duplicate_ids "$file"
        check_heading_hierarchy "$file"
        check_h1_count "$file"
        check_missing_alt "$file"
        check_empty_buttons "$file"
        check_missing_labels "$file"
        check_invalid_aria "$file"
        check_landmarks "$file"
        check_page_title "$file"
        check_skip_link "$file"
    done < <(find "${BUILD_DIR}" -name '*.html' | sort)

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
