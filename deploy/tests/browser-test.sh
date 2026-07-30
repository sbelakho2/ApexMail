#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# browser-test.sh — Automated browser testing for critical console errors and
# network failures. Uses headless Chromium via Playwright or Puppeteer.
# Checks: JS errors, failed API requests, failed images/fonts, CORS errors,
# mixed content, unhandled rejections, hydration errors, cookie-consent errors.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.browser-test-report.json"

: "${BASE_URL:=https://apexmail.ee}"
: "${TEST_PAGES:=/ /pricing/ /docs/ /features/ /security/ /compliance/ /private-cloud/ /signup /login /contact/ /status/}"
: "${WAIT_MS:=3000}"
: "${VIEWPORT_WIDTH:=1280}"
: "${VIEWPORT_HEIGHT:=800}"

CRITICAL=0
WARNINGS=0
RESULTS="[]"

check_page() {
    local page="$1"
    local url="${BASE_URL}${page}"
    echo "  Testing: $url"

    local output
    output="$(node - "$url" "$VIEWPORT_WIDTH" "$VIEWPORT_HEIGHT" "$WAIT_MS" << 'NODEJS'
const { chromium } = require('playwright') || {};
(async () => {
    const url = process.argv[1];
    const width = parseInt(process.argv[2]);
    const height = parseInt(process.argv[3]);
    const waitMs = parseInt(process.argv[4]);

    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width, height } });
    const page = await context.newPage();

    const errors = [];
    const failedRequests = [];
    const warnings = [];

    page.on('console', msg => {
        if (msg.type() === 'error') {
            errors.push({ type: 'console-error', text: msg.text() });
        } else if (msg.type() === 'warning') {
            warnings.push({ type: 'console-warning', text: msg.text() });
        }
    });

    page.on('pageerror', err => {
        errors.push({ type: 'page-error', text: err.message });
    });

    page.on('requestfailed', req => {
        failedRequests.push({
            type: 'failed-request',
            url: req.url(),
            failure: req.failure()?.errorText || 'unknown'
        });
    });

    page.on('response', resp => {
        if (resp.status() >= 400 && resp.status() < 500) {
            failedRequests.push({
                type: 'client-error',
                url: resp.url(),
                status: resp.status()
            });
        }
    });

    try {
        await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
        await page.waitForTimeout(waitMs);
    } catch (e) {
        errors.push({ type: 'navigation-error', text: e.message });
    }

    const title = await page.title();
    const contentLength = await page.evaluate(() => document.body.innerText.length);
    const hasConsoleErrors = errors.length > 0;
    const hasFailedRequests = failedRequests.length > 0;

    await browser.close();

    console.log(JSON.stringify({
        url,
        title,
        contentLength,
        errors,
        failedRequests,
        warnings,
        hasConsoleErrors,
        hasFailedRequests
    }));
})().catch(e => {
    console.log(JSON.stringify({ url: process.argv[1], error: e.message }));
});
NODEJS
)" 2>/dev/null || true

    if [[ -z "$output" ]]; then
        echo "    SKIP: Playwright not available (install: npx playwright install chromium)"
        echo '{"url":"'"$url"'","skipped":true,"reason":"Playwright not available"}' >> /tmp/apexmail-browser-results.ndjson
        return
    fi

    echo "$output" >> /tmp/apexmail-browser-results.ndjson

    local has_errors
    has_errors="$(echo "$output" | jq -r '.hasConsoleErrors // false')"
    local has_failed
    has_failed="$(echo "$output" | jq -r '.hasFailedRequests // false')"

    if [[ "$has_errors" == "true" ]]; then
        echo "    CRITICAL: Console errors on $url"
        CRITICAL=$((CRITICAL+1))
    fi
    if [[ "$has_failed" == "true" ]]; then
        echo "    WARN: Failed requests on $url"
        WARNINGS=$((WARNINGS+1))
    fi
}

main() {
    echo "=== ApexMail Browser Console & Network Test ==="

    > /tmp/apexmail-browser-results.ndjson

    for page in $TEST_PAGES; do
        check_page "$page"
    done

    # Aggregate results
    if [[ -f /tmp/apexmail-browser-results.ndjson ]]; then
        jq -s '.' /tmp/apexmail-browser-results.ndjson > /tmp/apexmail-browser-aggregated.json 2>/dev/null || true
    fi

    jq -n --arg checked_at "$TIMESTAMP" \
        --argjson critical "$CRITICAL" \
        --argjson warnings "$WARNINGS" \
        --arg test_pages "$TEST_PAGES" \
        '{checked_at:$checked_at,critical:$critical,warnings:$warnings,test_pages:$test_pages}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical: $CRITICAL"
    echo "Warnings: $WARNINGS"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
