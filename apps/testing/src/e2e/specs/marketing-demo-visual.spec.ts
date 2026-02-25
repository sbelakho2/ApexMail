import { test, expect } from '@playwright/test';

/**
 * Visual regression coverage for primary marketing demo components.
 * Item 230: Add visual regression coverage for primary marketing demos.
 */

const BASE_URL = process.env.MARKETING_URL ?? 'http://localhost:3002';

test.describe('Marketing demo visual regressions', () => {
  test.beforeEach(async ({ page }) => {
    // Disable animations for stable snapshots
    await page.emulateMedia({ reducedMotion: 'reduce' });
  });

  test('API Sandbox Console — initial state', async ({ page }) => {
    await page.goto(`${BASE_URL}/api-console`);
    await page.waitForLoadState('networkidle');

    // Sandbox badge must be visible
    await expect(page.getByRole('note', { name: /sandbox/i })).toBeVisible();

    const console_ = page.locator('[data-demo-id="sandbox-send"]').first();
    await expect(console_).toBeVisible();

    await expect(page).toHaveScreenshot('api-console-initial.png', { fullPage: false, clip: { x: 0, y: 0, width: 1280, height: 800 } });
  });

  test('API Sandbox Console — after send', async ({ page }) => {
    await page.goto(`${BASE_URL}/api-console`);
    await page.waitForLoadState('networkidle');

    await page.click('[data-demo-id="sandbox-send"]');
    // Wait for simulated response (800ms + buffer)
    await page.waitForTimeout(1200);
    // Sandbox label should appear in response panel
    await expect(page.getByText(/sandbox — no email delivered/i)).toBeVisible();

    await expect(page).toHaveScreenshot('api-console-after-send.png', { fullPage: false, clip: { x: 0, y: 0, width: 1280, height: 800 } });
  });

  test('Compliance page — audit trail demo', async ({ page }) => {
    await page.goto(`${BASE_URL}/compliance`);
    await page.waitForLoadState('networkidle');

    // Sample events badge must be visible
    await expect(page.getByText(/sample events/i)).toBeVisible();

    await expect(page).toHaveScreenshot('compliance-audit-trail.png', { fullPage: false, clip: { x: 0, y: 0, width: 1280, height: 900 } });
  });

  test('Compliance page — RTBF demo', async ({ page }) => {
    await page.goto(`${BASE_URL}/compliance`);
    await page.waitForLoadState('networkidle');

    const rtbfButton = page.getByRole('button', { name: /rtbf/i });
    await expect(rtbfButton).toBeVisible();

    await expect(page).toHaveScreenshot('compliance-rtbf-initial.png', { fullPage: false, clip: { x: 0, y: 0, width: 1280, height: 800 } });
  });

  test('Private cloud — latency comparison (no competitor names)', async ({ page }) => {
    await page.goto(`${BASE_URL}/private-cloud`);
    await page.waitForLoadState('networkidle');

    // Must NOT contain competitor brand names in latency section
    const section = page.getByLabel('Relative latency comparison by deployment scenario');
    await expect(section).toBeVisible();
    const text = await section.textContent();
    expect(text).not.toMatch(/sendgrid|mailchimp|aws ses/i);

    await expect(page).toHaveScreenshot('private-cloud-latency.png', { fullPage: false, clip: { x: 0, y: 0, width: 1280, height: 700 } });
  });

  test('Home page — API preview (no fake send result)', async ({ page }) => {
    await page.goto(`${BASE_URL}`);
    await page.waitForLoadState('networkidle');

    // Old fake "Test email sent" message must not appear
    await expect(page.getByText(/test email sent/i)).not.toBeVisible();
    // New honest CTA button should appear
    await expect(page.getByRole('link', { name: /create free account/i }).first()).toBeVisible();

    await expect(page).toHaveScreenshot('home-api-preview.png', { fullPage: false, clip: { x: 0, y: 0, width: 1280, height: 900 } });
  });
});
