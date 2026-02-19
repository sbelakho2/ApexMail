import { test, expect } from '@playwright/test';
import { API_URL, probe } from './support.js';

const READ_ENDPOINTS = [
    '/v1/auth/me',
    '/v1/messages',
    '/v1/domains',
    '/v1/templates',
    '/v1/suppressions',
    '/v1/events',
    '/v1/analytics/dashboard',
    '/v1/webhooks',
    '/v1/support/tickets',
    '/v1/campaigns/sample/stats',
    '/v1/contacts',
    '/v1/automations',
    '/v1/scim/ServiceProviderConfig',
];

const MUTATION_ENDPOINTS = [
    { path: '/v1/messages', payload: {} },
    { path: '/v1/domains', payload: {} },
    { path: '/v1/templates', payload: {} },
    { path: '/v1/suppressions', payload: {} },
    { path: '/v1/webhooks', payload: {} },
    { path: '/v1/campaigns', payload: {} },
    { path: '/v1/contacts', payload: {} },
    { path: '/v1/automations', payload: {} },
] as const;

test.describe('API AuthZ Matrix', () => {
    test.beforeEach(async () => {
        const apiUp = await probe(`${API_URL}/health`);
        expect(apiUp).toBe(true);
    });

    test('read endpoints reject anonymous requests with auth errors', async ({ request }) => {
        for (const endpoint of READ_ENDPOINTS) {
            const response = await request.get(`${API_URL}${endpoint}`);
            expect([401, 403]).toContain(response.status());

            const text = await response.text();
            expect(text.length).toBeGreaterThan(0);
        }
    });

    test('read endpoints reject malformed bearer tokens', async ({ request }) => {
        for (const endpoint of READ_ENDPOINTS) {
            const response = await request.get(`${API_URL}${endpoint}`, {
                headers: {
                    Authorization: 'Bearer malformed.jwt.token',
                },
            });
            expect([401, 403]).toContain(response.status());

            const text = await response.text();
            expect(text.length).toBeGreaterThan(0);
        }
    });

    test('mutation endpoints reject anonymous requests before persistence logic', async ({ request }) => {
        for (const endpoint of MUTATION_ENDPOINTS) {
            const response = await request.post(`${API_URL}${endpoint.path}`, {
                data: endpoint.payload,
            });

            expect([401, 403]).toContain(response.status());
            const text = await response.text();
            expect(text.length).toBeGreaterThan(0);
        }
    });

    test('public login route validates payload shape', async ({ request }) => {
        const malformed = await request.post(`${API_URL}/v1/auth/login`, {
            data: {
                email: 'not-an-email',
                password: '',
            },
        });

        expect([400, 422]).toContain(malformed.status());
        const bodyText = await malformed.text();
        expect(bodyText.length).toBeGreaterThan(0);
    });

    test('public login rejects null-byte payloads', async ({ request }) => {
        const response = await request.post(`${API_URL}/v1/auth/login`, {
            data: {
                email: 'safe@example.com',
                password: 'bad\u0000password',
            },
        });

        expect([400, 422]).toContain(response.status());
        const bodyText = await response.text();
        expect(bodyText.length).toBeGreaterThan(0);
    });
});
