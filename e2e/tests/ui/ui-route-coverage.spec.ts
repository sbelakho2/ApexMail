import { expect, test } from '@playwright/test';

import { discoverUiRoutes, materializeDynamicPath } from '../support/discovery';

function appForProject(projectName: string): string {
  if (projectName.includes('control-plane')) {
    return 'control-plane';
  }
  return 'web';
}

test('all discovered ui routes render without 5xx and without console errors', async ({ page }, testInfo) => {
  const app = appForProject(testInfo.project.name);
  const allRoutes = await discoverUiRoutes();
  const routes = allRoutes.filter((route) => route.app === app);

  expect(routes.length, `No routes discovered for app ${app}`).toBeGreaterThan(0);

  const consoleErrors: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error') {
      consoleErrors.push(message.text());
    }
  });

  for (const route of routes) {
    const concrete = materializeDynamicPath(route.path);
    const response = await page.goto(concrete, { waitUntil: 'domcontentloaded' });

    if (response) {
      expect(response.status(), `${app} ${concrete} should not hard fail`).toBeLessThan(500);
    }

    await expect(page.locator('body')).toBeVisible();
  }

  expect(consoleErrors, `Console errors detected in ${app}`).toEqual([]);
});
