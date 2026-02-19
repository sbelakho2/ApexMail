import { test, expect } from '@playwright/test';

const MARKETING_URL = process.env.MARKETING_URL || 'http://localhost:3003';

const MARKETING_ROUTES = [
    '/',
    '/features',
    '/pricing',
    '/pricing/calculator',
    '/compliance',
    '/compare/sendgrid',
    '/compare/postmark',
    '/compare/amazon-ses',
    '/compare/resend',
    '/case-studies',
    '/private-cloud',
    '/api-console',
    '/status',
    '/terms',
    '/privacy',
    '/dpa',
    '/sla',
    '/acceptable-use',
    '/cookies',
];

test.describe('Marketing Site - Full Coverage', () => {
    for (const route of MARKETING_ROUTES) {
        test(`route loads: ${route}`, async ({ page }) => {
            const response = await page.goto(`${MARKETING_URL}${route}`, { waitUntil: 'domcontentloaded' });
            expect(response?.status()).toBe(200);
            await expect(page.getByRole('heading').first()).toBeVisible();
        });
    }
});
