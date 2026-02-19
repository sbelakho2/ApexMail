import { test, expect } from '@playwright/test';
import { CONTROL_PLANE_URL, WEB_URL, createBypassContext } from './support.js';

test.describe('Chromium Security Contracts', () => {
    test('web auth login endpoint enforces CSRF', async ({ request }) => {
        const response = await request.post(`${WEB_URL}/api/auth/login`, {
            data: {
                email: 'test@example.com',
                password: 'bad-password',
            },
        });

        expect(response.status()).toBe(403);
        const payload = await response.json();
        expect(String(payload.error || '')).toMatch(/csrf/i);
    });

    test('control-plane login endpoint enforces CSRF', async ({ request }) => {
        const response = await request.post(`${CONTROL_PLANE_URL}/api/auth/login`, {
            data: {
                email: 'owner@example.com',
                password: 'bad-password',
            },
        });

        expect(response.status()).toBe(403);
        const payload = await response.json();
        expect(String(payload.error || '')).toMatch(/csrf/i);
    });

    test('control-plane middleware still emits security headers when bypass is active', async ({ browser }) => {
        const context = await createBypassContext(browser);
        const page = await context.newPage();

        const response = await page.goto(`${CONTROL_PLANE_URL}/analytics`, { waitUntil: 'domcontentloaded' });
        expect(response).not.toBeNull();
        expect(response?.headers()['x-e2e-bypass']).toBe('1');
        expect(response?.headers()['x-frame-options']).toBe('DENY');
        expect(response?.headers()['x-control-plane']).toBe('authenticated');
        expect(response?.headers()['cache-control']).toContain('no-store');

        await context.close();
    });
});
