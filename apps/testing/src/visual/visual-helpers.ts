import type { Page } from '@playwright/test';

export const viewports = {
    desktop: { width: 1920, height: 1080 },
    laptop: { width: 1440, height: 900 },
    tablet: { width: 768, height: 1024 },
    mobile: { width: 375, height: 667 },
};

export const themes = ['light', 'dark'] as const;

export async function authenticateUser(page: Page): Promise<void> {
    await safeGoto(page, '/dashboard');
    await page.waitForSelector('main', { timeout: 15000 });
    await page.waitForLoadState('networkidle');
}

export async function safeGoto(page: Page, url: string, attempts = 3): Promise<void> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
        try {
            await page.goto(url, { waitUntil: 'domcontentloaded' });
            return;
        } catch (error) {
            lastError = error;
            if (attempt < attempts) {
                await page.waitForTimeout(1000);
            }
        }
    }
    throw lastError;
}

export async function setTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
    await page.evaluate((currentTheme) => {
        document.documentElement.setAttribute('data-theme', currentTheme);
        document.documentElement.classList.toggle('dark', currentTheme === 'dark');
    }, theme);
}

export async function waitForCharts(page: Page): Promise<void> {
    await page.waitForFunction(() => {
        const charts = document.querySelectorAll('[data-testid^="chart-"]');
        return charts.length >= 2;
    }, { timeout: 20000 });
    await page.waitForTimeout(500);
}

export async function mockDashboardApis(page: Page): Promise<void> {
    await page.route(/\/api\/v1\/analytics\/dashboard/, async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                dashboard: {
                    period: { since: '2025-01-01T00:00:00.000Z', until: '2025-02-01T00:00:00.000Z' },
                    messages: { total: 120000, queued: 1200, sent: 118800, delivered: 117900, failed: 900 },
                    engagement: {
                        sent: 118800,
                        delivered: 117900,
                        opened: 54321,
                        clicked: 9876,
                        bounced: 900,
                        complained: 21,
                        rates: { delivery: '99.2', open: '45.7', click: '8.3', bounce: '0.8', complaint: '0.02' },
                    },
                    domains: { total: 6, verified: 5, pending: 1, failed: 0 },
                    suppressions: { total: 1321, bounces: 900, complaints: 21, unsubscribes: 350, manual: 50 },
                    health: { score: 94, grade: 'A' },
                },
            }),
        });
    });

    await page.route(/\/api\/v1\/analytics\/volume/, async (route) => {
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

    await page.route(/\/api\/v1\/analytics\/engagement/, async (route) => {
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

    await page.route(/\/api\/v1\/messages/, async (route) => {
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
                ],
            }),
        });
    });
}