import { test, expect } from '@playwright/test';
import {
    API_URL,
    CONTROL_PLANE_URL,
    WEB_URL,
    assertSecurityHeaders,
    createBypassContext,
    probe,
} from './support.js';

test.describe('Chromium Protocol Hardening', () => {
    test('invalid bypass key cannot unlock protected routes', async ({ browser }) => {
        const context = await browser.newContext({
            extraHTTPHeaders: {
                'x-e2e-bypass-key': 'incorrect-bypass-key',
            },
        });

        const webPage = await context.newPage();
        await webPage.goto(`${WEB_URL}/dashboard`, { waitUntil: 'domcontentloaded' });
        await expect(webPage).toHaveURL(/\/login/);

        const controlPlanePage = await context.newPage();
        await controlPlanePage.goto(`${CONTROL_PLANE_URL}/analytics`, { waitUntil: 'domcontentloaded' });
        await expect(controlPlanePage).toHaveURL(/\/login/);

        await context.close();
    });

    test('bypass only changes auth gate and does not mask unknown routes', async ({ browser }) => {
        const bypassContext = await createBypassContext(browser);
        const page = await bypassContext.newPage();

        const response = await page.goto(`${CONTROL_PLANE_URL}/definitely-unknown-route`, { waitUntil: 'domcontentloaded' });
        expect(response).not.toBeNull();
        expect(response?.status()).toBe(404);
        await expect(page).not.toHaveURL(/\/login/);

        await bypassContext.close();
    });

    test('control-plane security headers remain active under bypass', async ({ browser }) => {
        const context = await createBypassContext(browser);
        const page = await context.newPage();

        const response = await page.goto(`${CONTROL_PLANE_URL}/system`, { waitUntil: 'domcontentloaded' });
        expect(response).not.toBeNull();
        expect(response?.status()).toBe(200);

        if (response) {
            assertSecurityHeaders(response, ['cache-control', 'x-control-plane', 'pragma']);
            expect(response.headers()['x-control-plane']).toBe('authenticated');
            expect(response.headers()['cache-control']).toContain('no-store');
        }

        await context.close();
    });

    test('api responds with hardened headers and consistent not-found payload', async ({ request }) => {
        const apiUp = await probe(`${API_URL}/health`);
        expect(apiUp).toBe(true);

        const health = await request.get(`${API_URL}/health`);
        expect(health.status()).toBe(200);

        const healthHeaders = health.headers();
        expect(healthHeaders['x-api-version']).toBeTruthy();
        expect(healthHeaders['x-frame-options']).toBeTruthy();
        expect(healthHeaders['x-content-type-options']).toBeTruthy();
        expect(healthHeaders['content-security-policy']).toContain("default-src 'none'");

        const notFound = await request.get(`${API_URL}/definitely-not-a-route`);
        expect(notFound.status()).toBe(404);
        const body = await notFound.json();
        expect(body.error).toBeTruthy();
        expect(body.error.code).toBe('NOT_FOUND');
        expect(String(body.error.message || '')).toContain('Route not found');
    });

    test('api mutation endpoints require authentication before business logic', async ({ request }) => {
        const apiUp = await probe(`${API_URL}/health`);
        expect(apiUp).toBe(true);

        const candidateMutations = [
            { method: 'POST', path: '/v1/messages' },
            { method: 'POST', path: '/v1/domains' },
            { method: 'POST', path: '/v1/templates' },
            { method: 'POST', path: '/v1/suppressions' },
        ] as const;

        for (const route of candidateMutations) {
            const response = route.method === 'POST'
                ? await request.post(`${API_URL}${route.path}`, { data: {} })
                : await request.get(`${API_URL}${route.path}`);

            expect([401, 403]).toContain(response.status());
            const text = await response.text();
            expect(text.length).toBeGreaterThan(0);
        }
    });
});
