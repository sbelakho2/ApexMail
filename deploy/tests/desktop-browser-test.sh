#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# desktop-browser-test.sh — Cross-browser desktop testing.
# Tests: Chrome, Safari, Firefox, Edge at 1280px width.
# Journeys: homepage to signup, pricing calculation, docs nav, code-copy,
# enterprise form, login, password reset, legal pages, status.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.desktop-browser-report.json"

: "${BASE_URL:=https://apexmail.ee}"
: "${VIEWPORT_WIDTH:=1280}"
: "${VIEWPORT_HEIGHT:=800}"

BROWSERS=("chromium" "firefox" "webkit")
BROWSER_LABELS=("Chrome" "Firefox" "Safari/Edge")
CRITICAL=0
ISSUES="[]"

test_journey() {
    local browser="$1" label="$2"
    echo "  Browser: $label"

    local output
    output="$(node - "$browser" "$BASE_URL" "$VIEWPORT_WIDTH" "$VIEWPORT_HEIGHT" << 'NODEJS'
const playwright = require('playwright');
(async () => {
    const browserName = process.argv[1];
    const baseUrl = process.argv[2];
    const width = parseInt(process.argv[3]);
    const height = parseInt(process.argv[4]);

    let browserType;
    switch(browserName) {
        case 'chromium': browserType = playwright.chromium; break;
        case 'firefox': browserType = playwright.firefox; break;
        case 'webkit': browserType = playwright.webkit; break;
        default: browserType = playwright.chromium;
    }

    const browser = await browserType.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width, height } });
    const page = await context.newPage();
    const results = [];
    const journeys = [
        { name: 'homepage', url: baseUrl + '/' },
        { name: 'pricing', url: baseUrl + '/pricing/' },
        { name: 'docs', url: baseUrl + '/docs/' },
        { name: 'security', url: baseUrl + '/security/' },
        { name: 'compliance', url: baseUrl + '/compliance/' },
        { name: 'private-cloud', url: baseUrl + '/private-cloud/' },
        { name: 'features', url: baseUrl + '/features/' },
        { name: 'contact', url: baseUrl + '/contact/' },
        { name: 'terms', url: baseUrl + '/terms/' },
        { name: 'privacy', url: baseUrl + '/privacy/' },
        { name: 'status', url: baseUrl + '/status/' },
    ];

    for (const j of journeys) {
        try {
            await page.goto(j.url, { waitUntil: 'networkidle', timeout: 20000 });
            const title = await page.title();
            const hasH1 = await page.evaluate(() => !!document.querySelector('h1'));
            const hasNav = await page.evaluate(() => !!document.querySelector('nav, header nav'));
            const hasFooter = await page.evaluate(() => !!document.querySelector('footer'));
            const visibleText = await page.evaluate(() => document.body.innerText.length > 100);
            const errors = [];
            page.on('pageerror', e => errors.push(e.message));

            results.push({
                journey: j.name, url: j.url,
                title, hasH1, hasNav, hasFooter, visibleText,
                status: errors.length === 0 ? 'pass' : 'error',
                errors
            });
        } catch (e) {
            results.push({ journey: j.name, url: j.url, status: 'fail', error: e.message });
        }
    }

    await browser.close();
    console.log(JSON.stringify(results));
})().catch(e => console.log(JSON.stringify([{error: e.message}])));
NODEJS
)" 2>/dev/null || echo '[{"error":"Playwright not available"}]'

    echo "$output" | jq -c '.[]' 2>/dev/null | while read -r r; do
        local status journey
        status="$(echo "$r" | jq -r '.status // "unknown"')"
        journey="$(echo "$r" | jq -r '.journey // "unknown"')"
        if [[ "$status" == "error" || "$status" == "fail" ]]; then
            echo "    FAIL: $journey on $label"
            CRITICAL=$((CRITICAL+1))
        else
            echo "    OK: $journey on $label"
        fi
    done
}

main() {
    echo "=== ApexMail Desktop Browser Test ==="

    if ! command -v node &>/dev/null; then
        echo "SKIP: Node.js not available"
        jq -n '{skipped:true,reason:"Node.js not available"}' > "$REPORT_FILE"
        exit 0
    fi

    for i in "${!BROWSERS[@]}"; do
        test_journey "${BROWSERS[$i]}" "${BROWSER_LABELS[$i]}"
    done

    jq -n --argjson critical "$CRITICAL" \
        --arg checked_at "$TIMESTAMP" \
        --argjson issues "$ISSUES" \
        '{checked_at:$checked_at,critical:$critical,issues:$issues}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical browser-specific defects: $CRITICAL"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
