import { test, expect } from '@playwright/test';
import { auditLayout } from '../e2e-utils/layout-audit.js';
import { CONTROL_PLANE_URL, WEB_URL, createBypassPage } from './support.js';

const WEB_ROUTES = [
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

const VIEWPORTS = [
    { width: 1440, height: 900 },
    { width: 1024, height: 768 },
    { width: 390, height: 844 },
];

function formatIssues(issues: ReturnType<typeof auditLayout> extends Promise<infer T> ? T['issues'] : never) {
    return issues.slice(0, 8).map((issue) => `${issue.type} ${issue.selector} ${issue.details}`).join('\n');
}

test.describe('Total Visual Layout Audit - Customer Console', () => {
    for (const viewport of VIEWPORTS) {
        for (const route of WEB_ROUTES) {
            test(`layout audit ${route} ${viewport.width}x${viewport.height}`, async ({ browser }) => {
                const page = await createBypassPage(browser);
                await page.setViewportSize(viewport);
                await page.goto(`${WEB_URL}${route}`, { waitUntil: 'domcontentloaded' });

                const result = await auditLayout(page);
                expect(result.issues, formatIssues(result.issues)).toHaveLength(0);

                await page.context().close();
            });
        }
    }
});

test.describe('Total Visual Layout Audit - Control Plane', () => {
    for (const viewport of VIEWPORTS) {
        for (const route of CONTROL_PLANE_ROUTES) {
            test(`layout audit ${route} ${viewport.width}x${viewport.height}`, async ({ browser }) => {
                const page = await createBypassPage(browser);
                await page.setViewportSize(viewport);
                await page.goto(`${CONTROL_PLANE_URL}${route}`, { waitUntil: 'domcontentloaded' });

                const result = await auditLayout(page);
                expect(result.issues, formatIssues(result.issues)).toHaveLength(0);

                await page.context().close();
            });
        }
    }
});
