import { expect, test } from '@playwright/test';

import { discoverUiRoutes } from '../support/discovery';

test.describe('control-plane audit ux fail-first', () => {
  test.beforeEach(async ({}, testInfo) => {
    test.skip(!testInfo.project.name.includes('control-plane'), 'control-plane-only suite');
  });

  test('audit route exists and renders filterable audit surface', async ({ page }) => {
    const routes = await discoverUiRoutes();
    const controlPlaneRoutes = new Set(routes.filter((route) => route.app === 'control-plane').map((route) => route.path));

    expect(controlPlaneRoutes.has('/audit'), 'Expected /audit route in control-plane').toBe(true);

    const consoleErrors: string[] = [];
    page.on('console', (message) => {
      if (message.type() === 'error') {
        consoleErrors.push(message.text());
      }
    });

    const response = await page.goto('/audit', { waitUntil: 'domcontentloaded' });
    if (response) {
      expect(response.status()).toBeLessThan(500);
    }

    await expect(page.locator('body')).toBeVisible();

    const hasSearch = await page.getByPlaceholder(/search/i).first().isVisible().catch(() => false);
    const hasTable = (await page.locator('table').count()) > 0;
    const hasHeading = (await page.locator('h1, h2').count()) > 0;

    expect(hasSearch || hasTable || hasHeading).toBe(true);
    expect(consoleErrors).toEqual([]);
  });
});
