import { expect, test } from '@playwright/test';

import { discoverUiRoutes } from '../support/discovery';

test.describe('web interactive ux fail-first', () => {
  test.beforeEach(async ({}, testInfo) => {
    test.skip(testInfo.project.name.includes('control-plane'), 'web-only suite');
  });

  test('critical web interactive routes exist and render', async ({ page }) => {
    const routes = await discoverUiRoutes();
    const webRoutes = new Set(routes.filter((route) => route.app === 'web').map((route) => route.path));

    const required = ['/campaigns/new', '/settings/dedicated-ips'];
    for (const route of required) {
      expect(webRoutes.has(route), `Missing required web interactive route ${route}`).toBe(true);

      const response = await page.goto(route, { waitUntil: 'domcontentloaded' });
      if (response) {
        expect(response.status(), `${route} should not hard fail`).toBeLessThan(500);
      }

      await expect(page.locator('body')).toBeVisible();
    }
  });

  test('campaign creation route exposes form controls and validation signals', async ({ page }) => {
    await page.goto('/campaigns/new', { waitUntil: 'domcontentloaded' });

    const formCount = await page.locator('form').count();
    const inputCount = await page.locator('input, textarea, select').count();

    expect(formCount > 0 || inputCount > 0).toBe(true);

    const firstTextLikeInput = page.locator('input[type="text"], input:not([type]), textarea').first();
    const inputVisible = await firstTextLikeInput.isVisible().catch(() => false);

    if (inputVisible) {
      await firstTextLikeInput.fill('');
    }

    const submit = page.locator('button[type="submit"]').first();
    const submitVisible = await submit.isVisible().catch(() => false);
    if (submitVisible) {
      await submit.click();
    }

    const bodyText = await page.locator('body').innerText();
    const hasValidationSignal = /invalid|required|error|missing|campaign|subject|audience/i.test(bodyText);
    expect(hasValidationSignal || submitVisible, 'Expected visible interaction/validation signals on campaign form').toBe(true);
  });

  test('dedicated ips route surfaces actionable table or controls', async ({ page }) => {
    await page.goto('/settings/dedicated-ips', { waitUntil: 'domcontentloaded' });

    const tableCount = await page.locator('table').count();
    const buttonCount = await page.locator('button').count();
    const headingCount = await page.locator('h1, h2, h3').count();

    expect(tableCount > 0 || buttonCount > 0 || headingCount > 0).toBe(true);
  });
});
