import { expect, test } from '@playwright/test';

import { discoverUiRoutes } from '../support/discovery';

test.describe('control-plane sales console fail-first', () => {
  test.beforeEach(async ({}, testInfo) => {
    test.skip(!testInfo.project.name.includes('control-plane'), 'control-plane-only suite');
  });

  test('sales route exists and renders the operator connection shell', async ({ page }) => {
    const routes = await discoverUiRoutes();
    const controlPlaneRoutes = new Set(routes.filter((route) => route.app === 'control-plane').map((route) => route.path));

    expect(controlPlaneRoutes.has('/sales'), 'Expected /sales route in control-plane').toBe(true);

    const consoleErrors: string[] = [];
    page.on('console', (message) => {
      if (message.type() === 'error') {
        consoleErrors.push(message.text());
      }
    });

    const response = await page.goto('/sales', { waitUntil: 'domcontentloaded' });
    if (response) {
      expect(response.status()).toBeLessThan(500);
    }

    await expect(page.getByRole('heading', { name: /operator console/i })).toBeVisible();
    await expect(page.getByLabel(/api base url/i)).toBeVisible();
    await expect(page.getByLabel(/admin api key/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /^connect$/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /refresh/i })).toBeVisible();
    await expect(page.getByRole('heading', { name: /approval loop/i })).toBeVisible();
    await expect(page.getByRole('heading', { name: /launch campaign from selected leads/i })).toBeVisible();

    expect(consoleErrors).toEqual([]);
  });
});