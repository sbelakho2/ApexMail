/**
 * Full Screenshot Test — Every page across all 3 apps
 *
 * Web Console  (26 pages)  → http://127.0.0.1:3010
 * Control Plane (23 pages) → http://127.0.0.1:3020
 * Marketing    (20 pages)  → http://127.0.0.1:3003
 *
 * Run with:
 *   pnpm --filter @apexmail/testing exec playwright test \
 *     --config=playwright.screenshot-all.config.ts --update-snapshots
 */

import { test, expect, type Page, type Route } from '@playwright/test';

// ─── Environment ────────────────────────────────────────────────────────────────

const WEB_URL = process.env.WEB_URL || 'http://127.0.0.1:3010';
const CP_URL = process.env.CONTROL_PLANE_URL || 'http://127.0.0.1:3020';
const MKT_URL = process.env.MARKETING_URL || 'http://127.0.0.1:3003';
const E2E_BYPASS_KEY = process.env.E2E_BYPASS_KEY || 'apexmail-e2e-bypass-key';
const FIXED_TIME = '2025-02-01T12:00:00.000Z';

// ─── Route Manifests ────────────────────────────────────────────────────────────

const WEB_PUBLIC_ROUTES = [
    { path: '/login', name: 'login' },
    { path: '/signup', name: 'signup' },
    { path: '/forgot-password', name: 'forgot-password' },
];

const WEB_AUTH_ROUTES = [
    { path: '/dashboard', name: 'dashboard' },
    { path: '/ai-insights', name: 'ai-insights' },
    { path: '/billing', name: 'billing' },
    { path: '/campaigns', name: 'campaigns' },
    { path: '/campaigns/new', name: 'campaigns-new' },
    { path: '/compliance', name: 'compliance' },
    { path: '/contacts', name: 'contacts' },
    { path: '/help', name: 'help' },
    { path: '/lists', name: 'lists' },
    { path: '/reports', name: 'reports' },
    { path: '/settings', name: 'settings' },
    { path: '/settings/billing', name: 'settings-billing' },
    { path: '/settings/dedicated-ips', name: 'settings-dedicated-ips' },
    { path: '/settings/team', name: 'settings-team' },
    { path: '/templates', name: 'templates' },
];

const WEB_STORYBOOK_ROUTES = [
    { path: '/storybook/buttons', name: 'storybook-buttons' },
    { path: '/storybook/cards', name: 'storybook-cards' },
    { path: '/storybook/icons', name: 'storybook-icons' },
    { path: '/storybook/inputs', name: 'storybook-inputs' },
    { path: '/storybook/modals', name: 'storybook-modals' },
    { path: '/storybook/tables', name: 'storybook-tables' },
    { path: '/storybook/typography', name: 'storybook-typography' },
];

const CP_PUBLIC_ROUTES = [
    { path: '/login', name: 'login' },
];

const CP_AUTH_ROUTES = [
    { path: '/', name: 'home' },
    { path: '/analytics', name: 'analytics' },
    { path: '/audit', name: 'audit' },
    { path: '/autopilot', name: 'autopilot' },
    { path: '/calendar', name: 'calendar' },
    { path: '/campaigns', name: 'campaigns' },
    { path: '/compliance', name: 'compliance' },
    { path: '/content', name: 'content' },
    { path: '/crm', name: 'crm' },
    { path: '/features', name: 'features' },
    { path: '/gdpr', name: 'gdpr' },
    { path: '/inbox', name: 'inbox' },
    { path: '/ip-warmer', name: 'ip-warmer' },
    { path: '/leads', name: 'leads' },
    { path: '/revenue', name: 'revenue' },
    { path: '/risk', name: 'risk' },
    { path: '/sales', name: 'sales' },
    { path: '/secrets', name: 'secrets' },
    { path: '/settings', name: 'settings' },
    { path: '/support', name: 'support' },
    { path: '/system', name: 'system' },
    { path: '/tenants', name: 'tenants' },
];

const MKT_ROUTES = [
    { path: '/', name: 'home' },
    { path: '/acceptable-use', name: 'acceptable-use' },
    { path: '/api-console', name: 'api-console' },
    { path: '/case-studies', name: 'case-studies' },
    { path: '/compare/amazon-ses', name: 'compare-amazon-ses' },
    { path: '/compare/postmark', name: 'compare-postmark' },
    { path: '/compare/resend', name: 'compare-resend' },
    { path: '/compare/sendgrid', name: 'compare-sendgrid' },
    { path: '/compliance', name: 'compliance' },
    { path: '/cookies', name: 'cookies' },
    { path: '/dpa', name: 'dpa' },
    { path: '/features', name: 'features' },
    { path: '/forensic', name: 'forensic' },
    { path: '/pricing', name: 'pricing' },
    { path: '/pricing/calculator', name: 'pricing-calculator' },
    { path: '/privacy', name: 'privacy' },
    { path: '/private-cloud', name: 'private-cloud' },
    { path: '/sla', name: 'sla' },
    { path: '/status', name: 'status' },
    { path: '/terms', name: 'terms' },
];

// ─── Helpers ────────────────────────────────────────────────────────────────────

async function stabilize(page: Page) {
    // Freeze time to prevent flaky diffs from clocks / relative timestamps
    await page.addInitScript((fixedTime: string) => {
        const fixed = new Date(fixedTime).getTime();
        const OrigDate = Date;
        const g = globalThis as typeof globalThis & { Date: DateConstructor };
        g.Date = class extends OrigDate {
            constructor(...args: unknown[]) {
                if (args.length === 0) return new OrigDate(fixed);
                return new OrigDate(...(args as ConstructorParameters<typeof OrigDate>));
            }
            static now() { return fixed; }
            static parse = OrigDate.parse;
            static UTC = OrigDate.UTC;
        } as unknown as DateConstructor;
        window.setInterval = (() => 0) as unknown as typeof window.setInterval;
    }, FIXED_TIME);

    await page.emulateMedia({ reducedMotion: 'reduce' });

    // Kill CSS animations/transitions globally
    await page.addStyleTag({
        content: `
            *, *::before, *::after {
                transition-duration: 0s !important;
                animation-duration: 0s !important;
                animation-delay: 0s !important;
                scroll-behavior: auto !important;
                caret-color: transparent !important;
            }
        `,
    });
}

async function waitSettled(page: Page) {
    // Cap networkidle at 10s — persistent connections (WSS, long-poll) may never settle
    await Promise.race([
        page.waitForLoadState('networkidle'),
        page.waitForTimeout(10_000),
    ]).catch(() => {});
    // Wait for images with a hard cap so broken/slow images don't hang the test
    await Promise.race([
        page.evaluate(async () => {
            await Promise.all(
                Array.from(document.images).map(img => {
                    if (img.complete) return;
                    return new Promise<void>(r => {
                        img.addEventListener('load', () => r(), { once: true });
                        img.addEventListener('error', () => r(), { once: true });
                    });
                }),
            );
        }),
        page.waitForTimeout(8_000), // hard cap: don't wait longer than 8s for images
    ]).catch(() => {});
    // Pause videos
    await page.evaluate(() => {
        document.querySelectorAll('video').forEach(v => {
            try { v.pause(); v.currentTime = 0; } catch { /* ok */ }
        });
    }).catch(() => {});
    // Blur any focused element to avoid blinking cursors
    await page.evaluate(() => {
        if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    }).catch(() => {});
    await page.waitForTimeout(400);
}

async function snap(page: Page, url: string, name: string) {
    // Block external resources that hang page load (e.g. mCaptcha from unpkg)
    await page.route('**unpkg.com**', (r: Route) => r.abort());
    await page.route('**cdn.**', (r: Route) => r.abort());
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    // Wait for load with a cap so external resources don't hang us
    await Promise.race([
        page.waitForLoadState('load'),
        page.waitForTimeout(10_000),
    ]).catch(() => {});
    await waitSettled(page);
    await expect(page).toHaveScreenshot(name, { fullPage: true, timeout: 15_000 });
}

/** Mock every common API hit so authed pages render with synthetic data. */
async function mockAllApis(page: Page) {
    const json = (body: unknown) => ({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(body),
    });

    // Auth / session
    await page.route('**/api/auth/me', (r: Route) => r.fulfill(json({ id: 'u_1', email: 'admin@apexmail.local', name: 'Test Admin', role: 'admin' })));
    await page.route('**/api/csrf', (r: Route) => r.fulfill(json({ token: 'csrf-test' })));
    await page.route('**/v1/auth/me', (r: Route) => r.fulfill(json({ id: 'u_1', email: 'admin@apexmail.local' })));

    // Dashboard / analytics
    await page.route('**/api/v1/analytics/dashboard**', (r: Route) => r.fulfill(json({
        dashboard: {
            period: { since: '2025-01-01T00:00:00Z', until: '2025-02-01T00:00:00Z' },
            messages: { total: 120_000, queued: 1_200, sent: 118_800, delivered: 117_900, failed: 900 },
            engagement: {
                sent: 118_800, delivered: 117_900, opened: 54_321, clicked: 9_876, bounced: 900, complained: 21,
                rates: { delivery: '99.2', open: '45.7', click: '8.3', bounce: '0.8', complaint: '0.02' },
            },
            domains: { total: 6, verified: 5, pending: 1, failed: 0 },
            suppressions: { total: 1321, bounces: 900, complaints: 21, unsubscribes: 350, manual: 50 },
            health: { score: 94, grade: 'A' },
        },
    })));
    await page.route('**/api/v1/analytics/volume**', (r: Route) => r.fulfill(json({
        volume: [
            { date: '2025-01-01', sent: 3600, delivered: 3550, bounced: 50 },
            { date: '2025-01-08', sent: 4100, delivered: 4040, bounced: 60 },
            { date: '2025-01-15', sent: 5200, delivered: 5120, bounced: 80 },
            { date: '2025-01-22', sent: 4700, delivered: 4620, bounced: 80 },
            { date: '2025-01-29', sent: 6100, delivered: 6000, bounced: 100 },
        ],
    })));
    await page.route('**/api/v1/analytics/engagement**', (r: Route) => r.fulfill(json({
        engagement: [
            { date: '2025-01-01', opens: 1200, clicks: 160 },
            { date: '2025-01-08', opens: 1500, clicks: 210 },
            { date: '2025-01-15', opens: 1880, clicks: 260 },
            { date: '2025-01-22', opens: 1640, clicks: 240 },
            { date: '2025-01-29', opens: 2240, clicks: 310 },
        ],
    })));

    // Entity lists — provide realistic stubs so pages render tables
    await page.route('**/api/v1/messages**', (r: Route) => r.fulfill(json({ messages: [
        { id: 'msg_1', subject: 'January product update', status: 'delivered', sentAt: '2025-01-31T10:00:00Z', recipientCount: 12_450 },
        { id: 'msg_2', subject: 'Security bulletin', status: 'sent', sentAt: '2025-01-28T13:15:00Z', recipientCount: 9_800 },
    ] })));
    await page.route('**/api/v1/campaigns**', (r: Route) => r.fulfill(json({ campaigns: [
        { id: 'c_1', name: 'Winter Sale', status: 'sent', sentAt: '2025-01-15T10:00:00Z', recipients: 45_000, openRate: 42.1 },
        { id: 'c_2', name: 'Feature Launch', status: 'draft', created: '2025-01-20T08:00:00Z', recipients: 0, openRate: 0 },
    ] })));
    await page.route('**/api/v1/contacts**', (r: Route) => r.fulfill(json({ contacts: [
        { id: 'ct_1', email: 'john.doe@example.com', name: 'John Doe', status: 'subscribed', createdAt: '2024-06-01T00:00:00Z' },
        { id: 'ct_2', email: 'jane.smith@corp.io', name: 'Jane Smith', status: 'subscribed', createdAt: '2024-09-15T00:00:00Z' },
    ] })));
    await page.route('**/api/v1/lists**', (r: Route) => r.fulfill(json({ lists: [
        { id: 'l_1', name: 'Newsletter', memberCount: 28_400, createdAt: '2024-01-10T00:00:00Z' },
    ] })));
    await page.route('**/api/v1/templates**', (r: Route) => r.fulfill(json({ templates: [
        { id: 't_1', name: 'Welcome Email', type: 'transactional', updatedAt: '2025-01-20T00:00:00Z' },
    ] })));
    await page.route('**/api/v1/billing/**', (r: Route) => r.fulfill(json({ usage: { monthToDate: 42_100, projected: 128_000 } })));
    await page.route('**/api/v1/events/**', (r: Route) => r.fulfill(json({ events: [] })));

    // Control-plane specific
    await page.route('**/api/tenants**', (r: Route) => r.fulfill(json([
        { id: 't_1', name: 'Acme Mail', plan: 'professional', status: 'active', riskLevel: 'low', createdAt: '2022-05-02T12:15:00Z' },
        { id: 't_2', name: 'Northwind', plan: 'starter', status: 'trialing', riskLevel: 'medium', createdAt: '2023-11-18T08:40:00Z' },
    ])));
    await page.route('**/api/audit**', (r: Route) => r.fulfill(json({ entries: [] })));
    await page.route('**/api/features**', (r: Route) => r.fulfill(json({ features: [] })));
    await page.route('**/api/gdpr**', (r: Route) => r.fulfill(json({ requests: [] })));
    await page.route('**/api/secrets**', (r: Route) => r.fulfill(json({ secrets: [] })));
    await page.route('**/api/compliance**', (r: Route) => r.fulfill(json({ status: 'compliant' })));
    await page.route('**/api/risk**', (r: Route) => r.fulfill(json({ score: 22, level: 'low' })));
    await page.route('**/api/revenue**', (r: Route) => r.fulfill(json({ mrr: 84_200, arr: 1_010_400 })));
    await page.route('**/api/inbox**', (r: Route) => r.fulfill(json({ messages: [] })));
    await page.route('**/api/calendar**', (r: Route) => r.fulfill(json({ events: [] })));
    await page.route('**/api/warmup**', (r: Route) => r.fulfill(json({ ips: [] })));
    await page.route('**/api/content**', (r: Route) => r.fulfill(json({ items: [] })));
    await page.route('**/api/autopilot**', (r: Route) => r.fulfill(json({ rules: [] })));
    await page.route('**/api/sales**', (r: Route) => r.fulfill(json({ pipeline: [] })));
    await page.route('**/api/analytics**', (r: Route) => r.fulfill(json({ overview: {} })));
    await page.route('**/api/crm**', (r: Route) => r.fulfill(json({ leads: [] })));
    await page.route('**/api/leads**', (r: Route) => r.fulfill(json({ leads: [] })));
    await page.route('**/api/support**', (r: Route) => r.fulfill(json({ tickets: [] })));
    await page.route('**/api/system**', (r: Route) => r.fulfill(json({ status: 'healthy', uptime: 99.99 })));

    // Catch-all for any remaining API calls
    await page.route('**/api/**', async (route: Route) => {
        // Only intercept if nothing else matched (Playwright routes are LIFO)
        await route.fulfill(json({}));
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Web Console — 26 pages
// ═══════════════════════════════════════════════════════════════════════════════

test.describe('Web Console — Public Pages', () => {
    test.beforeEach(async ({ page }) => {
        await stabilize(page);
        // Mock API calls that public pages make (CSRF, auth check)
        await page.route('**/api/csrf', (r: Route) => r.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ token: 'csrf-test' }),
        }));
        await page.route('**/api/**', (r: Route) => r.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({}),
        }));
    });

    for (const route of WEB_PUBLIC_ROUTES) {
        test(`web:${route.name}`, async ({ page }) => {
            await snap(page, `${WEB_URL}${route.path}`, `web-${route.name}.png`);
        });
    }

    test('web:root-redirect', async ({ page }) => {
        await page.goto(`${WEB_URL}/`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
        await waitSettled(page);
        await expect(page).toHaveScreenshot('web-root.png', { fullPage: true, timeout: 15_000 });
    });
});

test.describe('Web Console — Authenticated Pages', () => {
    test.beforeEach(async ({ page }) => {
        await stabilize(page);
        await page.setExtraHTTPHeaders({
            'x-e2e-bypass-key': E2E_BYPASS_KEY,
            'Accept-Language': 'en-US',
        });
        await mockAllApis(page);
    });

    for (const route of WEB_AUTH_ROUTES) {
        test(`web:${route.name}`, async ({ page }) => {
            await snap(page, `${WEB_URL}${route.path}`, `web-${route.name}.png`);
        });
    }
});

test.describe('Web Console — Storybook', () => {
    test.beforeEach(async ({ page }) => {
        await stabilize(page);
        await page.setExtraHTTPHeaders({
            'x-e2e-bypass-key': E2E_BYPASS_KEY,
        });
    });

    for (const route of WEB_STORYBOOK_ROUTES) {
        test(`web:${route.name}`, async ({ page }) => {
            await snap(page, `${WEB_URL}${route.path}`, `web-${route.name}.png`);
        });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
// Control Plane — 23 pages
// ═══════════════════════════════════════════════════════════════════════════════

test.describe('Control Plane — Public Pages', () => {
    test.beforeEach(async ({ page }) => {
        await stabilize(page);
        // Mock API calls the login page makes (CSRF token fetch to Rust proxy)
        await page.route('**/api/csrf', (r: Route) => r.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ token: 'csrf-test' }),
        }));
    });

    for (const route of CP_PUBLIC_ROUTES) {
        test(`cp:${route.name}`, async ({ page }) => {
            await snap(page, `${CP_URL}${route.path}`, `cp-${route.name}.png`);
        });
    }
});

test.describe('Control Plane — Authenticated Pages', () => {
    test.beforeEach(async ({ page }) => {
        await stabilize(page);
        await page.setExtraHTTPHeaders({
            'x-e2e-bypass-key': E2E_BYPASS_KEY,
            'Accept-Language': 'en-US',
        });
        await mockAllApis(page);
    });

    for (const route of CP_AUTH_ROUTES) {
        test(`cp:${route.name}`, async ({ page }) => {
            await snap(page, `${CP_URL}${route.path}`, `cp-${route.name}.png`);
        });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
// Marketing — 20 pages
// ═══════════════════════════════════════════════════════════════════════════════

test.describe('Marketing — All Pages', () => {
    test.beforeEach(async ({ page }) => {
        await stabilize(page);
    });

    for (const route of MKT_ROUTES) {
        test(`mkt:${route.name}`, async ({ page }) => {
            await snap(page, `${MKT_URL}${route.path}`, `mkt-${route.name}.png`);
        });
    }
});
