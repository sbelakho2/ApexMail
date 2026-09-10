#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# content-voice-check.sh — Content voice and tone audit.
# Searches for vague SaaS language: enterprise-grade, world-class,
# best-in-class, seamless, effortless, powerful, robust, cutting-edge,
# revolutionary, unmatched, lightning-fast, built for scale, secure-by-design,
# developer-first.
# Flags terms needing justification or removal.
#
# Enforcement: exits non-zero when untriaged flags exceed
# CONTENT_VOICE_MAX_FLAGS (default 0) — as a REQUIRED validate gate the
# report must stay clean; raise the budget only for a bounded triage
# window. Patterns are POSIX ERE: "term::exc1,exc2" flags the term on lines
# that do NOT mention any exception word (the old PCRE negative lookaheads
# needed `grep -P`, which BSD grep does not implement).
# =============================================================================
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly TIMESTAMP
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly REPORT_FILE="${SCRIPT_DIR}/.content-voice-report.json"

: "${BUILD_DIR:=../apps/marketing-zola/public}"
: "${CONTENT_VOICE_MAX_FLAGS:=0}"

VAGUE_TERMS=(
    "enterprise-grade"
    "world-class"
    "best-in-class"
    "seamless::integration,migration"
    "effortless::migration"
    "powerful::API,tool,feature"
    "robust::API,monitoring,security,infrastructure"
    "cutting-edge"
    "revolutionary"
    "unmatched::feature"
    "lightning-fast"
    "built for scale"
    "secure by design"
    "developer-first::API"
    "industry-leading"
    "state-of-the-art"
    "game-changing"
    "next-generation"
)

TOTAL_FLAGS=0
FLAGS="[]"

add_flag() {
    local file="$1" line="$2" term="$3" context="$4"
    FLAGS="$(echo "$FLAGS" | jq --arg file "$file" --argjson line "$line" \
        --arg term "$term" --arg context "$context" \
        --arg checked_at "$TIMESTAMP" \
        '. + [{file:$file,line:$line,term:$term,context:$context,checked_at:$checked_at}]')"
    TOTAL_FLAGS=$((TOTAL_FLAGS+1))
}

main() {
    echo "=== ApexMail Content Voice & Tone Audit ==="

    # bash-3 compatible (macOS /bin/bash) collection, then loops in the main
    # shell: (1) pipelines would run the loop body in a subshell, so
    #     add_flag's updates to FLAGS/TOTAL_FLAGS were lost and the report was
    #     always empty; (2) under `set -o pipefail` a matchless grep (exit 1)
    #     killed the whole script mid-run.
    local htmls=()
    while IFS= read -r -d '' html; do
        htmls+=("$html")
    done < <(find "${BUILD_DIR}" -name '*.html' -print0 2>/dev/null)

    for term in "${VAGUE_TERMS[@]}"; do
        # "term::exception,exception" — the term pattern plus the words that
        # justify its use on a line (e.g. "powerful" next to "API"). A line
        # matching the term AND an exception is not flagged.
        local pattern="${term%%::*}"
        local exceptions="${term##*::}"
        [[ "$exceptions" == "$term" ]] && exceptions=""
        for html in "${htmls[@]}"; do
            local rel
            rel="$(echo "$html" | sed "s|${BUILD_DIR}||")"
            local matches
            if [[ -n "$exceptions" ]]; then
                matches="$(grep -niE "$pattern" "$html" 2>/dev/null | grep -viE "$exceptions" || true)"
            else
                matches="$(grep -niE "$pattern" "$html" 2>/dev/null || true)"
            fi
            while IFS=: read -r ln content; do
                [[ -z "$ln" ]] && continue
                local ctx
                # Trim with sed — xargs chokes on unmatched quotes in content.
                ctx="$(echo "$content" | sed 's/<[^>]*>//g' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | cut -c1-120)"
                echo "  $rel:$ln — \"$ctx\""
                add_flag "$rel" "$ln" "$pattern" "$ctx"
            done <<< "$matches"
        done
    done

    jq -n --argjson flags "$FLAGS" \
        --arg checked_at "$TIMESTAMP" \
        --argjson total_flags "$TOTAL_FLAGS" \
        '{checked_at:$checked_at,total_flags:$total_flags,flags:$flags}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Vague term occurrences flagged: $TOTAL_FLAGS"
    echo "Report: $REPORT_FILE"

    # Enforcement (REQUIRED gate): fail when untriaged flags exceed the
    # budget. Triage means fixing the copy or extending an exception above —
    # not silencing the exit code.
    if [[ "$TOTAL_FLAGS" -gt "$CONTENT_VOICE_MAX_FLAGS" ]]; then
        echo "FAIL: $TOTAL_FLAGS vague-language flags exceed the budget of $CONTENT_VOICE_MAX_FLAGS" >&2
        exit 1
    fi
    true
}

main "$@"
