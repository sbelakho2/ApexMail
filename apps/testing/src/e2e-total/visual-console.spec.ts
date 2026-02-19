import { test, expect } from '@playwright/test';
import { WEB_URL, CONTROL_PLANE_URL, createBypassPage, stabilizePage } from './support.js';

test.describe('Total Visual - Console Pages', () => {
    test('customer login visual', async ({ page }) => {
        await page.goto(`${WEB_URL}/login`, { waitUntil: 'domcontentloaded' });
        await stabilizePage(page);
        await expect(page).toHaveScreenshot('web-login.png', { fullPage: true });
    });

    test('customer dashboard visual', async ({ browser }) => {
        const page = await createBypassPage(browser);
        await page.goto(`${WEB_URL}/dashboard`, { waitUntil: 'domcontentloaded' });
        await stabilizePage(page);
        await expect(page).toHaveScreenshot('web-dashboard.png', { fullPage: true });
        await page.context().close();
    });

    test('control-plane login visual', async ({ page }) => {
        await page.goto(`${CONTROL_PLANE_URL}/login`, { waitUntil: 'domcontentloaded' });
        await stabilizePage(page);
        await expect(page).toHaveScreenshot('control-plane-login.png', { fullPage: true });
    });

    test('control-plane analytics visual', async ({ browser }) => {
        const page = await createBypassPage(browser);
        await page.goto(`${CONTROL_PLANE_URL}/analytics`, { waitUntil: 'domcontentloaded' });
        await stabilizePage(page);
        await expect(page).toHaveScreenshot('control-plane-analytics.png', { fullPage: true });
        await page.context().close();
    });
});
