import { test, expect } from '@playwright/test';
import { CONTROL_PLANE_URL, WEB_URL, createBypassContext, stripHash } from './support.js';

const WEB_PUBLIC_ROUTES = ['/login'];

const WEB_PROTECTED_ROUTES = [
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
    '/forgot-password',
];

const CONTROL_PLANE_PUBLIC_ROUTES = ['/login'];

const CONTROL_PLANE_PROTECTED_ROUTES = [
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
    '/autopilot',
    '/content',
    '/gdpr',
    '/features',
    '/calendar',
    '/secrets',
    '/ip-warmer',
    '/inbox',
];

test.describe('Chromium Route Matrix', () => {
    for (const route of WEB_PUBLIC_ROUTES) {
        test(`web public route is reachable without bypass: ${route}`, async ({ browser }) => {
            const context = await browser.newContext();
            const page = await context.newPage();

            const response = await page.goto(`${WEB_URL}${route}`, { waitUntil: 'domcontentloaded' });
            expect(response).not.toBeNull();
            expect(response?.status()).toBe(200);
            await expect(page).toHaveURL(new RegExp(`${route.replace('/', '\\/')}$`));

            await context.close();
        });
    }

    for (const route of WEB_PROTECTED_ROUTES) {
        test(`web protected route enforces auth and allows e2e bypass: ${route}`, async ({ browser }) => {
            const anonymousContext = await browser.newContext();
            const anonymousPage = await anonymousContext.newPage();

            await anonymousPage.goto(`${WEB_URL}${route}`, { waitUntil: 'domcontentloaded' });
            await expect(anonymousPage).toHaveURL(/\/login/);
            await anonymousContext.close();

            const bypassContext = await createBypassContext(browser);
            const bypassPage = await bypassContext.newPage();

            const bypassResponse = await bypassPage.goto(`${WEB_URL}${route}`, { waitUntil: 'domcontentloaded' });
            expect(bypassResponse).not.toBeNull();
            expect(bypassResponse?.status()).toBe(200);
            expect(bypassResponse?.headers()['x-e2e-bypass']).toBe('1');
            await expect(bypassPage).not.toHaveURL(/\/login/);

            const finalUrl = stripHash(bypassPage.url());
            expect(finalUrl).toContain(route);
            await expect(bypassPage.getByRole('heading').first()).toBeVisible();

            await bypassContext.close();
        });
    }

    for (const route of CONTROL_PLANE_PUBLIC_ROUTES) {
        test(`control-plane public route is reachable without bypass: ${route}`, async ({ browser }) => {
            const context = await browser.newContext();
            const page = await context.newPage();

            const response = await page.goto(`${CONTROL_PLANE_URL}${route}`, { waitUntil: 'domcontentloaded' });
            expect(response).not.toBeNull();
            expect(response?.status()).toBe(200);
            await expect(page).toHaveURL(new RegExp(`${route.replace('/', '\\/')}$`));

            await context.close();
        });
    }

    for (const route of CONTROL_PLANE_PROTECTED_ROUTES) {
        test(`control-plane protected route enforces auth and allows e2e bypass: ${route}`, async ({ browser }) => {
            const anonymousContext = await browser.newContext();
            const anonymousPage = await anonymousContext.newPage();

            await anonymousPage.goto(`${CONTROL_PLANE_URL}${route}`, { waitUntil: 'domcontentloaded' });
            await expect(anonymousPage).toHaveURL(/\/login/);
            await anonymousContext.close();

            const bypassContext = await createBypassContext(browser);
            const bypassPage = await bypassContext.newPage();

            const bypassResponse = await bypassPage.goto(`${CONTROL_PLANE_URL}${route}`, { waitUntil: 'domcontentloaded' });
            expect(bypassResponse).not.toBeNull();
            expect(bypassResponse?.status()).toBe(200);
            expect(bypassResponse?.headers()['x-e2e-bypass']).toBe('1');
            expect(bypassResponse?.headers()['x-control-plane']).toBe('authenticated');
            await expect(bypassPage).not.toHaveURL(/\/login/);

            const finalUrl = stripHash(bypassPage.url());
            expect(finalUrl).toContain(route);
            await expect(bypassPage.getByRole('heading').first()).toBeVisible();

            await bypassContext.close();
        });
    }
});
