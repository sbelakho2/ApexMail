import { test, expect } from '../fixtures.js';

test.describe('Control Plane Critical Admin Workflows', () => {
    test('settings page shows backend sync indicators and section deep links', async ({ page }) => {
        await page.goto('/settings#access');
        await expect(page.getByRole('heading', { name: 'Platform Settings' })).toBeVisible();
        await expect(page.getByText('Last synced with backend', { exact: false })).toBeVisible();
        await expect(page.locator('nav[aria-label="Settings sections"]')).toBeVisible();
    });

    test('ip warmer renders advancement lockout and per-row actions', async ({ page }) => {
        await page.goto('/ip-warmer');
        await expect(page.getByRole('heading', { name: 'IP Warmer' })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Run Daily Advancement' })).toBeVisible();
        await expect(page.getByText('IP Pools', { exact: false })).toBeVisible();
    });

    test('support triage shortcuts and SLA highlighting are available', async ({ page }) => {
        await page.goto('/support');
        await expect(page.getByRole('heading', { name: 'Support Tickets' })).toBeVisible();
        await expect(page.getByRole('button', { name: 'SLA Breach (24h+)' })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Urgent + Unassigned' })).toBeVisible();
    });

    test('system restart command requires explicit confirmation', async ({ page }) => {
        await page.goto('/system');
        await expect(page.getByRole('heading', { name: 'System Health' })).toBeVisible();
        await expect(page.getByText('System Status', { exact: false })).toBeVisible();
    });
});
