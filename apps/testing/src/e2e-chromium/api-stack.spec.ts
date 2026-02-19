import { test, expect } from '@playwright/test';
import { API_URL, probe } from './support.js';

test.describe('API Stack Contracts', () => {
    test('health endpoints and response headers are valid', async ({ request }) => {
        const apiUp = await probe(`${API_URL}/health`);
        expect(apiUp).toBe(true);

        const health = await request.get(`${API_URL}/health`);
        expect(health.status()).toBe(200);
        expect(health.headers()['x-api-version']).toBeTruthy();
        expect(health.headers()['x-frame-options']).toBeTruthy();
        expect(health.headers()['x-content-type-options']).toBeTruthy();
        expect(health.headers()['content-security-policy']).toContain("default-src 'none'");
        const healthBody = await health.json();
        expect(healthBody.status).toBe('ok');

        const live = await request.get(`${API_URL}/health/live`);
        expect(live.status()).toBe(200);
        const liveBody = await live.json();
        expect(liveBody.status).toBe('ok');

        const ready = await request.get(`${API_URL}/health/ready`);
        expect([200, 503]).toContain(ready.status());
        const readyBody = await ready.json();
        expect(['ready', 'not_ready', 'shutting_down']).toContain(readyBody.status);

        const deep = await request.get(`${API_URL}/health/deep`);
        expect([200, 503]).toContain(deep.status());
        const deepBody = await deep.json();
        expect(deepBody).toHaveProperty('status');

        const version = await request.get(`${API_URL}/health/version`);
        expect(version.status()).toBe(200);
        const versionBody = await version.json();
        expect(versionBody).toHaveProperty('version');
    });

    test('unknown routes return structured 404 payload', async ({ request }) => {
        const apiUp = await probe(`${API_URL}/health`);
        expect(apiUp).toBe(true);

        const response = await request.get(`${API_URL}/definitely-not-a-route`);
        expect(response.status()).toBe(404);

        const payload = await response.json();
        expect(payload.error).toBeTruthy();
        expect(payload.error.code).toBe('NOT_FOUND');
        expect(String(payload.error.message || '')).toContain('Route not found');
    });
});
