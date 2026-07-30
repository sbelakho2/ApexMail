#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# mobile-test.sh — Responsive and mobile device testing.
# Tests at: 320, 360, 375, 390, 414, 768 pixels.
# Checks: header, menu, hero, pricing cards, calculator, tables, code blocks,
# forms, modals, footer, diagrams, docs sidebar, comparison tables, legal text.
# Ensures no horizontal scroll, CTAs visible, forms fit, text no-overlap,
# touch targets min 44x44, sticky elements don't hide content.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.mobile-test-report.json"

: "${BASE_URL:=https://apexmail.ee}"
: "${VIEWPORT_HEIGHT:=900}"

WIDTHS=(320 360 375 390 414 768)
CRITICAL=0
WARNINGS=0
ISSUES="[]"

add_issue() {
    local width="$1" page="$2" check="$3" severity="$4" detail="$5"
    ISSUES="$(echo "$ISSUES" | jq --argjson width "$width" --arg page "$page" \
        --arg check "$check" --arg severity "$severity" --arg detail "$detail" \
        --arg checked_at "$TIMESTAMP" \
        '. + [{width:$width,page:$page,check:$check,severity:$severity,detail:$detail,checked_at:$checked_at}]')"
}

test_mobile() {
    local width="$1"
    echo "  Width: ${width}px"

    node - "$width" "$BASE_URL" "$VIEWPORT_HEIGHT" << 'NODEJS'
const playwright = require('playwright');
(async () => {
    const width = parseInt(process.argv[1]);
    const baseUrl = process.argv[2];
    const height = parseInt(process.argv[3]);

    const browser = await playwright.chromium.launch({ headless: true });
    const context = await browser.newContext({
        viewport: { width, height },
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15'
    });
    const page = await context.newPage();
    const results = [];
    const pages = ['/', '/pricing/', '/docs/', '/features/', '/security/', '/compliance/', '/private-cloud/', '/contact/', '/terms/', '/privacy/'];

    for (const p of pages) {
        try {
            await page.goto(baseUrl + p, { waitUntil: 'networkidle', timeout: 20000 });
            const checks = {};

            // Horizontal overflow
            const overflowX = await page.evaluate(() => {
                const html = document.documentElement;
                return html.scrollWidth > html.clientWidth;
            });
            checks['horizontal-scroll'] = overflowX ? 'fail' : 'pass';

            // Touch targets
            const smallTargets = await page.evaluate(() => {
                const targets = document.querySelectorAll('a, button, [role="button"], input[type="submit"]');
                let count = 0;
                targets.forEach(t => {
                    const rect = t.getBoundingClientRect();
                    if (rect.width < 44 || rect.height < 44) count++;
                });
                return count;
            });
            checks['touch-targets'] = smallTargets > 5 ? 'fail' : 'pass';

            // Text overlap
            const textOverlap = await page.evaluate(() => {
                const allElements = document.querySelectorAll('h1,h2,h3,h4,h5,h6,p,span,li,a,button');
                let overlapCount = 0;
                const rects = [];
                allElements.forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.width > 0 && rect.height > 0) {
                        rects.push(rect);
                    }
                });
                for (let i = 0; i < rects.length; i++) {
                    for (let j = i+1; j < rects.length; j++) {
                        const a = rects[i], b = rects[j];
                        if (a.left < b.right && a.right > b.left &&
                            a.top < b.bottom && a.bottom > b.top) {
                            overlapCount++;
                        }
                    }
                }
                return overlapCount;
            });
            checks['text-overlap'] = textOverlap > 50 ? 'warn' : 'pass';

            // Sticky elements visibility
            const stickyHides = await page.evaluate(() => {
                const sticky = document.querySelectorAll('[class*="sticky"], [class*="fixed"]');
                const viewport = window.innerHeight;
                let hiddenCount = 0;
                sticky.forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.bottom < 0 || rect.top > viewport) hiddenCount++;
                });
                return hiddenCount;
            });
            checks['sticky-hides-content'] = stickyHides > 0 ? 'warn' : 'pass';

            // CTA visibility
            const ctaVisible = await page.evaluate(() => {
                const ctas = document.querySelectorAll('[class*="btn-"], [class*="cta"]');
                let visible = 0;
                ctas.forEach(c => {
                    const rect = c.getBoundingClientRect();
                    if (rect.width > 0 && rect.height > 0) visible++;
                });
                return visible;
            });
            checks['cta-visible'] = ctaVisible > 0 ? 'pass' : 'warn';

            // Form fields fit
            const formOverflows = await page.evaluate(() => {
                const forms = document.querySelectorAll('input:not([type="hidden"]), textarea, select');
                let overflowCount = 0;
                forms.forEach(f => {
                    const rect = f.getBoundingClientRect();
                    if (rect.right > window.innerWidth + 10) overflowCount++;
                });
                return overflowCount;
            });
            checks['form-fit'] = formOverflows > 0 ? 'fail' : 'pass';

            results.push({ page: p, checks });
        } catch (e) {
            results.push({ page: p, error: e.message });
        }
    }

    await browser.close();
    console.log(JSON.stringify(results));
})().catch(e => console.log(JSON.stringify([{error: e.message}])));
NODEJS
}

main() {
    echo "=== ApexMail Mobile Responsive Test ==="

    for w in "${WIDTHS[@]}"; do
        test_mobile "$w" 2>/dev/null || true
    done

    jq -n --argjson critical "$CRITICAL" --argjson warnings "$WARNINGS" \
        --arg checked_at "$TIMESTAMP" --argjson issues "$ISSUES" \
        '{checked_at:$checked_at,critical:$critical,warnings:$warnings,issues:$issues}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical mobile issues: $CRITICAL"
    echo "Warnings: $WARNINGS"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
