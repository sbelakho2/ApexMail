import { test, expect } from '@playwright/test';

const WEB_URL = process.env.WEB_URL || 'http://127.0.0.1:3010';
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL || 'http://localhost:3020';
const E2E_BYPASS_KEY = process.env.E2E_BYPASS_KEY || 'apexmail-e2e-bypass-key';
const FIXED_VISUAL_TIME = '2025-02-01T12:00:00.000Z';

const viewports = {
    desktop: { width: 1440, height: 900 },
    laptop: { width: 1280, height: 800 },
    tablet: { width: 1024, height: 768 },
    mobile: { width: 390, height: 844 },
};

async function disableMotion(page: Parameters<typeof test>[0]['page']) {
    await page.addStyleTag({
        content: `
            *, *::before, *::after {
                transition-duration: 0s !important;
                animation-duration: 0s !important;
                animation-delay: 0s !important;
                scroll-behavior: auto !important;
            }
        `,
    });
}

async function freezeTime(page: Parameters<typeof test>[0]['page']) {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.addInitScript(fixedTime => {
        const fixed = new Date(fixedTime as string).getTime();
        const OriginalDate = Date;
        const globalDate = globalThis as typeof globalThis & { Date: DateConstructor };
        // @ts-expect-error - override Date in the browser context for stability
        globalDate.Date = class extends OriginalDate {
            constructor(...args: unknown[]) {
                if (args.length === 0) {
                    return new OriginalDate(fixed);
                }
                return new OriginalDate(...args);
            }

            static now() {
                return fixed;
            }
        } as DateConstructor;
    }, FIXED_VISUAL_TIME);
}

async function mockWebDashboardApis(page: Parameters<typeof test>[0]['page']) {
    await page.route('**/api/v1/analytics/dashboard**', async route => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                dashboard: {
                    period: {
                        since: '2025-01-01T00:00:00.000Z',
                        until: '2025-02-01T00:00:00.000Z',
                    },
                    messages: {
                        total: 120000,
                        queued: 1200,
                        sent: 118800,
                        delivered: 117900,
                        failed: 900,
                    },
                    engagement: {
                        sent: 118800,
                        delivered: 117900,
                        opened: 54321,
                        clicked: 9876,
                        bounced: 900,
                        complained: 21,
                        rates: {
                            delivery: '99.2',
                            open: '45.7',
                            click: '8.3',
                            bounce: '0.8',
                            complaint: '0.02',
                        },
                    },
                    domains: {
                        total: 6,
                        verified: 5,
                        pending: 1,
                        failed: 0,
                    },
                    suppressions: {
                        total: 1321,
                        bounces: 900,
                        complaints: 21,
                        unsubscribes: 350,
                        manual: 50,
                    },
                    health: {
                        score: 94,
                        grade: 'A',
                    },
                },
            }),
        });
    });

    await page.route('**/api/v1/analytics/volume**', async route => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                volume: [
                    { date: '2025-01-01', sent: 3600, delivered: 3550, bounced: 50 },
                    { date: '2025-01-06', sent: 4100, delivered: 4040, bounced: 60 },
                    { date: '2025-01-11', sent: 3800, delivered: 3740, bounced: 60 },
                    { date: '2025-01-16', sent: 5200, delivered: 5120, bounced: 80 },
                    { date: '2025-01-21', sent: 4700, delivered: 4620, bounced: 80 },
                    { date: '2025-01-26', sent: 5300, delivered: 5220, bounced: 80 },
                    { date: '2025-01-31', sent: 6100, delivered: 6000, bounced: 100 },
                ],
            }),
        });
    });

    await page.route('**/api/v1/analytics/engagement**', async route => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                engagement: [
                    { date: '2025-01-01', opens: 1200, clicks: 160 },
                    { date: '2025-01-06', opens: 1500, clicks: 210 },
                    { date: '2025-01-11', opens: 1320, clicks: 190 },
                    { date: '2025-01-16', opens: 1880, clicks: 260 },
                    { date: '2025-01-21', opens: 1640, clicks: 240 },
                    { date: '2025-01-26', opens: 1950, clicks: 275 },
                    { date: '2025-01-31', opens: 2240, clicks: 310 },
                ],
            }),
        });
    });

    await page.route('**/api/v1/messages**', async route => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                messages: [
                    {
                        id: 'msg_1001',
                        subject: 'January product update',
                        status: 'sent',
                        sentAt: '2025-01-31T10:00:00.000Z',
                        recipientCount: 12450,
                    },
                    {
                        id: 'msg_1002',
                        subject: 'Security bulletin',
                        status: 'delivered',
                        sentAt: '2025-01-29T18:30:00.000Z',
                        recipientCount: 9800,
                    },
                    {
                        id: 'msg_1003',
                        subject: 'Weekly digest',
                        status: 'sent',
                        sentAt: '2025-01-28T13:15:00.000Z',
                        recipientCount: 15400,
                    },
                    {
                        id: 'msg_1004',
                        subject: 'Transactional receipt',
                        status: 'delivered',
                        sentAt: '2025-01-27T08:20:00.000Z',
                        recipientCount: 4300,
                    },
                    {
                        id: 'msg_1005',
                        subject: 'Upcoming maintenance window',
                        status: 'scheduled',
                        scheduledAt: '2025-02-02T09:00:00.000Z',
                        recipientCount: 7600,
                    },
                ],
            }),
        });
    });
}

async function gotoAndSnap(page: Parameters<typeof test>[0]['page'], url: string, name: string) {
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(400);
    await page.evaluate(() => {
        if (document.activeElement instanceof HTMLElement) {
            document.activeElement.blur();
        }
    });
    await expect(page).toHaveScreenshot(name, { fullPage: true });
}

async function assertApexCardCompliance(
    page: Parameters<typeof test>[0]['page'],
    selector: string,
    minCount = 1,
) {
    const cards = page.locator(selector);
    await expect(cards.first()).toBeVisible({ timeout: 20000 });
    const totalCards = await cards.count();
    expect(totalCards).toBeGreaterThanOrEqual(minCount);

    const sampleCount = Math.min(totalCards, 4);
    for (let index = 0; index < sampleCount; index++) {
        const card = cards.nth(index);
        await expect(card).toBeVisible();

        const style = await card.evaluate(element => {
            const computed = window.getComputedStyle(element as HTMLElement);
            return {
                borderRadius: computed.borderRadius,
                boxShadow: computed.boxShadow,
                borderColor: computed.borderColor,
                backgroundColor: computed.backgroundColor,
                className: (element as HTMLElement).className,
            };
        });

        expect(style.className).toMatch(/apex-card|premium-card|bg-card/);
        expect(parseFloat(style.borderRadius)).toBeGreaterThanOrEqual(10);
        expect(style.boxShadow).not.toBe('none');
        expect(style.borderColor).not.toMatch(/rgba\(0, 0, 0, 0\)|transparent/);
        expect(style.backgroundColor).not.toMatch(/rgba\(0, 0, 0, 0\)|transparent/);
    }
}

test.describe('Web Console Visuals', () => {
    test.beforeEach(async ({ page }) => {
        await page.setExtraHTTPHeaders({ 'x-e2e-bypass-key': E2E_BYPASS_KEY });
        await freezeTime(page);
        await disableMotion(page);
    });

    for (const [viewportName, viewport] of Object.entries(viewports)) {
        test(`web login - ${viewportName}`, async ({ page }) => {
            await page.setViewportSize(viewport);
            await gotoAndSnap(page, `${WEB_URL}/login`, `web-login-${viewportName}.png`);
        });

        test(`web dashboard - ${viewportName}`, async ({ page }) => {
            await page.setViewportSize(viewport);
            await mockWebDashboardApis(page);
            await gotoAndSnap(page, `${WEB_URL}/dashboard`, `web-dashboard-${viewportName}.png`);
        });
    }

    test('web campaigns list', async ({ page }) => {
        await page.setViewportSize(viewports.desktop);
        await page.goto(`${WEB_URL}/campaigns`, { waitUntil: 'domcontentloaded' });
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(400);
        await page.addStyleTag({ content: '* { caret-color: transparent !important; }' });
        await page.evaluate(() => {
            if (document.activeElement instanceof HTMLElement) {
                document.activeElement.blur();
            }
        });
        await expect(page).toHaveScreenshot('web-campaigns.png', {
            fullPage: true,
            mask: [page.locator('tbody tr td:nth-child(5)')],
        });
    });

    test('web dashboard apex card compliance', async ({ page }) => {
        await page.setViewportSize(viewports.desktop);
        await mockWebDashboardApis(page);
        await page.goto(`${WEB_URL}/dashboard`, { waitUntil: 'domcontentloaded' });
        await page.waitForLoadState('networkidle');

        await assertApexCardCompliance(page, '[data-testid="metrics-grid"] > div', 4);

        const metricsGrid = page.locator('[data-testid="metrics-grid"]');
        await expect(metricsGrid).toHaveScreenshot('web-dashboard-metrics-apex-compliance.png');
    });

    test('web settings', async ({ page }) => {
        await page.setViewportSize(viewports.desktop);
        await gotoAndSnap(page, `${WEB_URL}/settings`, 'web-settings.png');
    });
});

test.describe('Control Plane Visuals', () => {
    test.beforeEach(async ({ page }) => {
        await page.setExtraHTTPHeaders({ 'x-e2e-bypass-key': E2E_BYPASS_KEY });
        await freezeTime(page);
        await disableMotion(page);
    });

    for (const [viewportName, viewport] of Object.entries(viewports)) {
        test(`control-plane login - ${viewportName}`, async ({ page }) => {
            await page.setViewportSize(viewport);
            await gotoAndSnap(page, `${CONTROL_PLANE_URL}/login`, `control-login-${viewportName}.png`);
        });

        test(`control-plane analytics - ${viewportName}`, async ({ page }) => {
            await page.setViewportSize(viewport);
            await gotoAndSnap(page, `${CONTROL_PLANE_URL}/analytics`, `control-analytics-${viewportName}.png`);
        });
    }

    test('control-plane tenants', async ({ page }) => {
        await page.setViewportSize(viewports.desktop);
        await page.route('**/api/tenants**', async route => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify([
                    {
                        id: 'tenant_001',
                        name: 'Acme Mail',
                        domain: 'acme-mail',
                        email: 'owner@acme.test',
                        plan: 'professional',
                        status: 'active',
                        riskLevel: 'low',
                        metrics: {
                            emailsSentMonth: 184200,
                            emailsSentTotal: 2198400,
                            domainsVerified: 3,
                            apiKeys: 4,
                            teamMembers: 12,
                        },
                        billing: {
                            mrr: 1499,
                            nextBillingDate: '2025-01-15T00:00:00.000Z',
                            paymentMethod: 'Visa **** 4242',
                        },
                        createdAt: '2022-05-02T12:15:00.000Z',
                        lastActiveAt: '2025-01-05T09:30:00.000Z',
                    },
                    {
                        id: 'tenant_002',
                        name: 'Northwind Messages',
                        domain: 'northwind',
                        email: 'ops@northwind.test',
                        plan: 'starter',
                        status: 'trialing',
                        riskLevel: 'medium',
                        metrics: {
                            emailsSentMonth: 48210,
                            emailsSentTotal: 391420,
                            domainsVerified: 1,
                            apiKeys: 2,
                            teamMembers: 6,
                        },
                        billing: {
                            mrr: 199,
                            nextBillingDate: '2025-01-22T00:00:00.000Z',
                            paymentMethod: 'ACH',
                        },
                        createdAt: '2023-11-18T08:40:00.000Z',
                        lastActiveAt: '2025-01-04T18:10:00.000Z',
                    },
                    {
                        id: 'tenant_003',
                        name: 'Helios Broadcast',
                        domain: 'helios',
                        email: 'security@helios.test',
                        plan: 'enterprise',
                        status: 'suspended',
                        riskLevel: 'high',
                        metrics: {
                            emailsSentMonth: 842900,
                            emailsSentTotal: 14293800,
                            domainsVerified: 0,
                            apiKeys: 18,
                            teamMembers: 42,
                        },
                        billing: {
                            mrr: 6800,
                            nextBillingDate: '2025-01-10T00:00:00.000Z',
                            paymentMethod: 'Invoice',
                        },
                        createdAt: '2021-07-09T17:05:00.000Z',
                        lastActiveAt: '2025-01-03T07:55:00.000Z',
                    },
                ]),
            });
        });
        await gotoAndSnap(page, `${CONTROL_PLANE_URL}/tenants`, 'control-tenants.png');
    });

    test('control-plane settings', async ({ page }) => {
        await page.setViewportSize(viewports.desktop);
        await gotoAndSnap(page, `${CONTROL_PLANE_URL}/settings`, 'control-settings.png');
    });

    test('control-plane analytics apex card compliance', async ({ page }) => {
        await page.setViewportSize(viewports.desktop);
        await page.goto(`${CONTROL_PLANE_URL}/analytics`, { waitUntil: 'domcontentloaded' });
        await page.waitForLoadState('networkidle');

        await assertApexCardCompliance(page, '.apex-card, .bg-card.border', 6);

        const cardsRegion = page.locator('main').first();
        await expect(cardsRegion).toHaveScreenshot('control-analytics-apex-card-compliance.png', {
            fullPage: false,
        });
    });
});
