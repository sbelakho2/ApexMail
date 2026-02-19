import { test, expect } from '@playwright/test';
import { auditLayout } from '../../e2e-utils/layout-audit.js';

const MARKETING_URL = process.env.MARKETING_URL || 'http://localhost:3003';

const routes = [
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

const viewports = [
    { name: 'desktop', size: { width: 1440, height: 900 } },
    { name: 'tablet', size: { width: 1024, height: 768 } },
    { name: 'mobile', size: { width: 390, height: 844 } },
];

function formatIssues(issues: ReturnType<typeof auditLayout> extends Promise<infer T> ? T['issues'] : never) {
    return issues.slice(0, 8).map((issue) => `${issue.type} ${issue.selector} ${issue.details}`).join('\n');
}

test.describe('Marketing Layout Regression', () => {
    for (const viewport of viewports) {
        for (const route of routes) {
            test(`layout ${viewport.name} ${route}`, async ({ page }) => {
                await page.setViewportSize(viewport.size);
                await page.goto(`${MARKETING_URL}${route}`, { waitUntil: 'domcontentloaded' });
                await expect(page.getByRole('heading').first()).toBeVisible();
                const result = await auditLayout(page);
                expect(result.issues, formatIssues(result.issues)).toHaveLength(0);
            });
        }
    }
});
