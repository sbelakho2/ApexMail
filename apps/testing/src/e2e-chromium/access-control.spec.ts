import { test, expect } from '@playwright/test';
import { CONTROL_PLANE_URL, WEB_URL, createBypassContext } from './support.js';

test.describe('Chromium Access Control', () => {
    test('web protected route redirects to login without session', async ({ browser }) => {
        const context = await browser.newContext();
        const page = await context.newPage();

        await page.goto(`${WEB_URL}/dashboard`, { waitUntil: 'domcontentloaded' });
        await expect(page).toHaveURL(/\/login/);

        await context.close();
    });

    test('control-plane protected route redirects to login without session', async ({ browser }) => {
        const context = await browser.newContext();
        const page = await context.newPage();

        await page.goto(`${CONTROL_PLANE_URL}/analytics`, { waitUntil: 'domcontentloaded' });
        await expect(page).toHaveURL(/\/login/);

        await context.close();
    });

    test('web protected routes are reachable with test bypass header', async ({ browser }) => {
        const context = await createBypassContext(browser);
        const page = await context.newPage();

        const dashboardResponse = await page.goto(`${WEB_URL}/dashboard`, { waitUntil: 'domcontentloaded' });
        expect(dashboardResponse?.status()).toBe(200);
        expect(dashboardResponse?.headers()['x-e2e-bypass']).toBe('1');
        await expect(page).not.toHaveURL(/\/login/);

        await context.close();
    });

    test('control-plane protected routes are reachable with test bypass header', async ({ browser }) => {
        const context = await createBypassContext(browser);
        const page = await context.newPage();

        const analyticsResponse = await page.goto(`${CONTROL_PLANE_URL}/analytics`, { waitUntil: 'domcontentloaded' });
        expect(analyticsResponse?.status()).toBe(200);
        await expect(page).not.toHaveURL(/\/login/);
        await expect(page.getByRole('heading', { name: 'Analytics & Insights' })).toBeVisible();

        const revenueResponse = await page.goto(`${CONTROL_PLANE_URL}/revenue`, { waitUntil: 'domcontentloaded' });
        expect(revenueResponse?.status()).toBe(200);
        await expect(page).not.toHaveURL(/\/login/);

        await context.close();
    });

    test('invalid bypass header does not bypass auth', async ({ browser }) => {
        const context = await browser.newContext({
            extraHTTPHeaders: {
                'x-e2e-bypass-key': 'invalid-key',
            },
        });
        const page = await context.newPage();

        await page.goto(`${CONTROL_PLANE_URL}/analytics`, { waitUntil: 'domcontentloaded' });
        await expect(page).toHaveURL(/\/login/);

        await context.close();
    });
});
