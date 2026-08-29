#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# content-voice-check.sh — Content voice and tone audit.
# Searches for vague SaaS language: enterprise-grade, world-class,
# best-in-class, seamless, effortless, powerful, robust, cutting-edge,
# revolutionary, unmatched, lightning-fast, built for scale, secure-by-design,
# developer-first.
# Flags terms needing justification or removal.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.content-voice-report.json"

: "${BUILD_DIR:=../apps/marketing-zola/public}"

VAGUE_TERMS=(
    "enterprise-grade"
    "world-class"
    "best-in-class"
    "seamless(?!.*integration|.*migration)"
    "effortless(?!.*migration)"
    "powerful(?!.*API|.*tool|.*feature)"
    "robust(?!.*API|.*monitoring|.*security|.*infrastructure)"
    "cutting-edge"
    "revolutionary"
    "unmatched(?!.*feature)"
    "lightning-fast"
    "built for scale"
    "secure by design"
    "developer-first"
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
        for html in "${htmls[@]}"; do
            local rel
            rel="$(echo "$html" | sed "s|${BUILD_DIR}||")"
            while IFS=: read -r ln content; do
                local ctx
                ctx="$(echo "$content" | sed 's/<[^>]*>//g' | xargs | cut -c1-120)"
                echo "  $rel:$ln — \"$ctx\""
                add_flag "$rel" "$ln" "$term" "$ctx"
            done < <(grep -nPi "$term" "$html" 2>/dev/null || true)
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

    true
}

main "$@"
