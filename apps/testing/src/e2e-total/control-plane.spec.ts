import { test, expect } from '@playwright/test';
import { CONTROL_PLANE_URL, createBypassPage, stripHash } from './support.js';

const CONTROL_PLANE_ROUTES = [
    '/',
    '/analytics',
    '/revenue',
    '/risk',
    '/support',
    '/campaigns',
    '/compliance',
    '/crm',
    '/leads',
    '/audit',
    '/settings',
    '/system',
    '/tenants',
];

test.describe('Total E2E - Control Plane', () => {
    test('login page loads without bypass', async ({ page }) => {
        await page.goto(`${CONTROL_PLANE_URL}/login`, { waitUntil: 'domcontentloaded' });
        await expect(page).toHaveURL(/\/login/);
        await expect(page.getByRole('heading', { name: /control plane/i })).toBeVisible();
    });

    for (const route of CONTROL_PLANE_ROUTES) {
        test(`route loads with bypass: ${route}`, async ({ browser }) => {
            const page = await createBypassPage(browser);

            const response = await page.goto(`${CONTROL_PLANE_URL}${route}`, { waitUntil: 'domcontentloaded' });
            expect(response?.status()).toBe(200);
            expect(response?.headers()['x-e2e-bypass']).toBe('1');
            await expect(page).not.toHaveURL(/\/login/);
            await expect(page.getByRole('heading').first()).toBeVisible();

            const url = stripHash(page.url());
            expect(url).toContain(route === '/' ? CONTROL_PLANE_URL : route);

            await page.context().close();
        });
    }
});
