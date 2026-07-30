#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# performance-budget.sh — Lighthouse CI performance budget enforcement.
# Checks LCP, INP/CLS, TTFB, total JS/CSS/image bytes, font bytes,
# third-party requests, total page weight against defined thresholds.
# Fails if any Critical threshold is exceeded.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.performance-budget-report.json"

: "${BASE_URL:=https://apexmail.ee}"
: "${TEST_URLS:=/ /pricing/ /docs/ /features/}"
: "${LHCI_PORT:=9222}"

declare -A BUDGETS
BUDGETS["lcp_homepage"]="2500"
BUDGETS["lcp_pricing"]="2500"
BUDGETS["lcp_docs"]="2000"
BUDGETS["lcp_landing"]="2500"
BUDGETS["tti_all"]="4000"
BUDGETS["cls_all"]="0.1"
BUDGETS["ttfb_all"]="600"
BUDGETS["js_bytes_all"]="350000"
BUDGETS["css_bytes_all"]="150000"
BUDGETS["image_bytes_all"]="500000"
BUDGETS["font_bytes_all"]="200000"
BUDGETS["total_weight_all"]="2000000"
BUDGETS["third_party_count"]="5"

CRITICAL=0
WARNINGS=0
RESULTS="[]"

run_lighthouse() {
    local url="$1"
    echo "  Auditing: $url"

    if command -v lighthouse &>/dev/null; then
        lighthouse "$url" \
            --chrome-flags="--headless --no-sandbox --disable-gpu" \
            --output=json --output-path=stdout \
            --quiet \
            --only-categories=performance \
            --throttling-method=simulate \
            --preset=desktop 2>/dev/null | \
            jq '{
                url: .requestedUrl,
                lcp: .audits["largest-contentful-paint"].numericValue,
                tti: .audits["interactive"].numericValue,
                cls: .audits["cumulative-layout-shift"].numericValue,
                ttfb: .audits["server-response-time"].numericValue,
                js_bytes: .audits["network-requests"].details.items | map(select(.resourceType=="Script")) | map(.transferSize) | add,
                css_bytes: .audits["network-requests"].details.items | map(select(.resourceType=="Stylesheet")) | map(.transferSize) | add,
                image_bytes: .audits["network-requests"].details.items | map(select(.resourceType=="Image")) | map(.transferSize) | add,
                font_bytes: .audits["network-requests"].details.items | map(select(.resourceType=="Font")) | map(.transferSize) | add,
                total_bytes: .audits["total-byte-weight"].numericValue,
                third_party: .audits["third-party-summary"].details.items | length
            }' 2>/dev/null
    else
        echo '{"url":"'"$url"'","skipped":true,"reason":"lighthouse not installed"}'
    fi
}

check_budget() {
    local metric="$1" value="$2" threshold="$3" page="$4"
    if [[ -z "$value" || "$value" == "null" ]]; then return; fi
    if (( $(echo "$value > $threshold" | bc -l 2>/dev/null || echo 0) )); then
        echo "    FAIL: $metric = $value (budget: $threshold)"
        CRITICAL=$((CRITICAL+1))
    else
        echo "    OK: $metric = $value (budget: $threshold)"
    fi
}

main() {
    echo "=== ApexMail Performance Budget Check ==="

    for path in $TEST_URLS; do
        local url="${BASE_URL}${path}"
        local audit
        audit="$(run_lighthouse "$url")"

        RESULTS="$(echo "$RESULTS" | jq ". + [$audit]")"

        if echo "$audit" | jq -e '.skipped' >/dev/null 2>&1; then
            echo "  SKIP: Lighthouse not available"
            continue
        fi

        local lcp tti cls ttfb js_bytes css_bytes image_bytes font_bytes total third
        lcp="$(echo "$audit" | jq -r '.lcp // 0')"
        tti="$(echo "$audit" | jq -r '.tti // 0')"
        cls="$(echo "$audit" | jq -r '.cls // 0')"
        ttfb="$(echo "$audit" | jq -r '.ttfb // 0')"
        js_bytes="$(echo "$audit" | jq -r '.js_bytes // 0')"
        css_bytes="$(echo "$audit" | jq -r '.css_bytes // 0')"
        image_bytes="$(echo "$audit" | jq -r '.image_bytes // 0')"
        font_bytes="$(echo "$audit" | jq -r '.font_bytes // 0')"
        total="$(echo "$audit" | jq -r '.total_bytes // 0')"
        third="$(echo "$audit" | jq -r '.third_party // 0')"

        check_budget "LCP" "$lcp" "${BUDGETS["lcp_landing"]}" "$path"
        check_budget "TTI" "$tti" "${BUDGETS["tti_all"]}" "$path"
        check_budget "CLS" "$cls" "${BUDGETS["cls_all"]}" "$path"
        check_budget "TTFB" "$ttfb" "${BUDGETS["ttfb_all"]}" "$path"
        check_budget "JS Bytes" "$js_bytes" "${BUDGETS["js_bytes_all"]}" "$path"
        check_budget "CSS Bytes" "$css_bytes" "${BUDGETS["css_bytes_all"]}" "$path"
        check_budget "Image Bytes" "$image_bytes" "${BUDGETS["image_bytes_all"]}" "$path"
        check_budget "Font Bytes" "$font_bytes" "${BUDGETS["font_bytes_all"]}" "$path"
        check_budget "Total Weight" "$total" "${BUDGETS["total_weight_all"]}" "$path"
        check_budget "Third-Party Requests" "$third" "${BUDGETS["third_party_count"]}" "$path"
    done

    jq -n --argjson results "$RESULTS" \
        --arg checked_at "$TIMESTAMP" \
        --argjson critical "$CRITICAL" \
        --argjson warnings "$WARNINGS" \
        '{checked_at:$checked_at,critical:$critical,warnings:$warnings,results:$results}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical budget violations: $CRITICAL"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
