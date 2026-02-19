import { test, expect } from '@playwright/test';
import { WEB_URL, createBypassPage, stripHash } from './support.js';

const WEB_ROUTES = [
    '/dashboard',
    '/campaigns',
    '/contacts',
    '/lists',
    '/templates',
    '/reports',
    '/billing',
    '/compliance',
    '/ai-insights',
    '/help',
    '/settings',
];

test.describe('Total E2E - Customer Console', () => {
    test('login page loads without bypass', async ({ page }) => {
        await page.goto(`${WEB_URL}/login`, { waitUntil: 'domcontentloaded' });
        await expect(page).toHaveURL(/\/login/);
        await expect(page.getByRole('heading', { name: /welcome back/i })).toBeVisible();
    });

    for (const route of WEB_ROUTES) {
        test(`route loads with bypass: ${route}`, async ({ browser }) => {
            const page = await createBypassPage(browser);

            const response = await page.goto(`${WEB_URL}${route}`, { waitUntil: 'domcontentloaded' });
            expect(response?.status()).toBe(200);
            expect(response?.headers()['x-e2e-bypass']).toBe('1');
            await expect(page).not.toHaveURL(/\/login/);
            await expect(page.getByRole('heading').first()).toBeVisible();

            const url = stripHash(page.url());
            expect(url).toContain(route);

            await page.context().close();
        });
    }
});
