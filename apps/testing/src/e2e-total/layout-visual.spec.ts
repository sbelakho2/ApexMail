import { test, expect } from '@playwright/test';
import { WEB_URL, CONTROL_PLANE_URL, createBypassPage, stabilizePage, assertNoHorizontalOverflow } from './support.js';

const viewports = [
    { name: 'desktop', size: { width: 1440, height: 900 } },
    { name: 'tablet', size: { width: 1024, height: 768 } },
    { name: 'mobile', size: { width: 390, height: 844 } },
];

const webRoutes = [
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

const controlPlaneRoutes = [
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

test.describe('Total Visual Layout - Console', () => {
    for (const viewport of viewports) {
        for (const route of webRoutes) {
            test(`web layout ${viewport.name} ${route}`, async ({ browser }) => {
                const page = await createBypassPage(browser);
                await page.setViewportSize(viewport.size);
                await page.goto(`${WEB_URL}${route}`, { waitUntil: 'domcontentloaded' });
                await stabilizePage(page);
                await expect(page.getByRole('heading').first()).toBeVisible();
                await assertNoHorizontalOverflow(page, `web ${viewport.name} ${route}`);
                await expect(page).toHaveScreenshot(`web-${route.replace(/\//g, '_')}-${viewport.name}.png`, { fullPage: true });
                await page.context().close();
            });
        }

        for (const route of controlPlaneRoutes) {
            test(`control-plane layout ${viewport.name} ${route}`, async ({ browser }) => {
                const page = await createBypassPage(browser);
                await page.setViewportSize(viewport.size);
                await page.goto(`${CONTROL_PLANE_URL}${route}`, { waitUntil: 'domcontentloaded' });
                await stabilizePage(page);
                await expect(page.getByRole('heading').first()).toBeVisible();
                await assertNoHorizontalOverflow(page, `control-plane ${viewport.name} ${route}`);
                const screenshotOptions =
                    route === '/tenants' && viewport.name === 'tablet'
                        ? { fullPage: true, maxDiffPixels: 3500 }
                        : { fullPage: true };
                await expect(page).toHaveScreenshot(`control-plane-${route.replace(/\//g, '_') || 'root'}-${viewport.name}.png`, screenshotOptions);
                await page.context().close();
            });
        }
    }
});
