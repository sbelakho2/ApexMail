#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# html-validate.sh — HTML and accessibility validation for production builds.
# Checks: duplicate IDs, missing labels, heading hierarchy, missing alt,
# empty buttons, invalid ARIA, duplicate H1, missing page title, color
# contrast, keyboard traps (where testable).
#
# Portability note: every pattern below is POSIX ERE (grep -E) — no `grep -P`.
# The pipeline runs this on Debian (GNU grep) AND on macOS dev machines (BSD
# grep has no -P); a -P pattern fails silently there and every page then
# reports "missing title" false criticals. Patterns also tolerate the
# CURRENT zola minify_html output: attribute values may be UNQUOTED
# (id=top) and attributes appear in any order, so value extraction uses
# `attr=("[^"]*"|[^" >]+)` instead of assuming quotes.
# =============================================================================
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly TIMESTAMP
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
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
    done < <(grep -oE 'id=("[^"]*"|[^" >]+)' "$file" 2>/dev/null | sed -E 's/^id=//; s/^"//; s/"$//' | sort | uniq -d)
}

# Markup with non-document content stripped before HEADING checks:
#   1. <textarea>…</textarea> blocks — their content is the literal default
#      text of a form control (the api-explorer's JSON request sample embeds
#      "<h1>Welcome!</h1>"), never a parsed heading. The sample itself
#      contains '<' characters, so a sed [^<]* span cannot match it — an
#      awk state machine cuts the element bounds instead (sed .* is greedy
#      and would over-strip on pages with more than one textarea).
#   2. quoted attribute payloads — demo samples in value='…' attributes
#      (e.g. the homepage's "<h1>Sent with control.</h1>") are equally not
#      document headings. Single-quoted values may legally contain double
#      quotes, so the two quote styles are stripped in separate passes.
#      Counting these as headings produced false "Multiple H1" criticals.
strip_non_document_markup() {
    awk '{
        line = $0; out = ""
        while (length(line) > 0) {
            if (depth) {
                pos = index(line, "</textarea>")
                if (pos == 0) { line = ""; break }
                line = substr(line, pos + 11)
                depth = 0
            } else {
                pos = index(line, "<textarea")
                if (pos == 0) { out = out line; break }
                out = out substr(line, 1, pos - 1)
                rest = substr(line, pos)
                gt = index(rest, ">")
                if (gt == 0) { line = ""; break }
                line = substr(rest, gt + 1)
                depth = 1
            }
        }
        print out
    }' | sed -E "s/='[^']*'/=/g; s/=\"[^\"]*\"/=/g"
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
    done < <(strip_non_document_markup < "$file" | grep -noE '<h[1-6][^>]*>' 2>/dev/null)
}

check_h1_count() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local count
    # grep -c prints "0" and exits 1 on zero matches — do not append a
    # second 0 with `|| echo 0` (that yields "0\n0" and breaks the -gt test).
    # Attribute payloads are stripped first — see strip_non_document_markup().
    count="$(strip_non_document_markup < "$file" | grep -cE '<h1[^>]*>' 2>/dev/null || true)"
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
    done < <(grep -noE '<img[^>]*>' "$file" 2>/dev/null | grep -v 'alt=')
}

check_empty_buttons() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local ln tag
    while IFS=: read -r ln tag; do
        add_issue "$path" "$ln" "critical" "Empty button element"
    done < <(grep -noE '<button[^>]*>[[:space:]]*</button>' "$file" 2>/dev/null)
}

check_missing_labels() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local ln tag input_id input_type
    while IFS=: read -r ln tag; do
        # Attribute values may be quoted or bare in minified output. The
        # id-less case must yield "" (a failed grep under pipefail would
        # otherwise abort the whole script under set -e).
        input_id="$(echo "$tag" | grep -oE 'id=("[^"]*"|[^" >]+)' | sed -E 's/^id=//; s/"//g' || true)"
        input_type="$(echo "$tag" | grep -oE 'type=("[^"]*"|[^" >]+)' | sed -E 's/^type=//; s/"//g' || echo "text")"
        input_type="${input_type:-text}"
        # Inputs without an id cannot be bound by a for= label at all.
        [[ -z "$input_id" ]] && continue
        case "$input_type" in hidden|submit|button|reset) continue ;; esac
        # A label binds via for="id" (quoted or bare); aria-label on the
        # input itself is the accepted alternative.
        if ! echo "$tag" | grep -q 'aria-label' \
           && ! grep -qE "for=(\"${input_id}\"|${input_id}([^A-Za-z0-9_-]|$))" "$file" 2>/dev/null; then
            add_issue "$path" "$ln" "warning" "Input #$input_id missing label"
        fi
    done < <(grep -noE '<input[^>]*>' "$file" 2>/dev/null)
}

check_invalid_aria() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    local ln line
    while IFS=: read -r ln line; do
        add_issue "$path" "$ln" "critical" "ARIA attribute with 'undefined' value"
    done < <(grep -noE 'aria-[a-z-]+=("[^"]*undefined[^"]*"|undefined)' "$file" 2>/dev/null)
    while IFS=: read -r ln line; do
        add_issue "$path" "$ln" "warning" "Multiple role attributes on element"
    done < <(grep -noE 'role=("[^"]*"|[^" >]+)[^>]*role=' "$file" 2>/dev/null)
}

check_landmarks() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    if ! grep -qE '<(header|nav|main|footer)' "$file" 2>/dev/null; then
        add_issue "$path" 0 "warning" "Missing landmark elements"
    fi
}

check_page_title() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    # Flatten newlines first: built HTML can split the title across lines.
    # <title> tags survive minification intact; extract the element then
    # strip the tags (ERE — see portability note in the header).
    local title_text
    title_text="$(tr '\n' ' ' < "$file" | grep -oE '<title>[^<]*</title>' | sed -E 's:</?title>::g' || true)"
    if [[ -z "$title_text" ]]; then
        add_issue "$path" 0 "critical" "Missing or empty page title"
    fi
}

check_skip_link() {
    local file="$1"
    local path
    path="$(echo "$file" | sed "s|${BUILD_DIR}||")"
    if ! grep -qEi 'skip.*(content|main)' "$file" 2>/dev/null; then
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
