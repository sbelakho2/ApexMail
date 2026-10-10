import { test, expect } from '@playwright/test';

// The manual autofill qualification page
// (docs/autofill-qualification-protocol.md) must be completable in
// exactly the documented sequence. This spec performs that sequence
// end to end against the real fixture router:
//
//   Run A (negative control): solve, fill the real fields the way a
//   native fill would, Submit (the submit handler must POST without
//   navigating away), Check -> the decoy input stays empty and
//   honeypot_hit is false.
//   Run B (positive control): /honeypot-check consumed the verified
//   record, so reload for a fresh challenge, fill exactly the
//   authenticated decoy field via the page's positive-control button,
//   Check -> the proof stays valid and honeypot_hit is true.
//
// The page is served by the fixture router at /autofill-form and is
// deliberately outside the client-performance measurement source set.

test.describe('manual autofill qualification page', () => {
  test('the documented sequence survives submission and proves both decoy controls', async ({ page }) => {
    await page.goto('/autofill-form');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await page.locator('input[name="kiwi__token"]').inputValue();
    expect(token.length, 'the widget minted a token').toBeGreaterThan(0);

    // The legitimate fill (what a native autofill or password manager
    // writes into the real fields).
    await page.fill('input[name="email"]', 'user@example.com');
    await page.fill('input[name="username"]', 'user');
    await page.fill('input[name="password"]', 's3cret');

    // Submit must serialize and POST without navigating, so the page
    // (and the qualification controls) remain available.
    const submitRequest = page.waitForRequest('**/form-submit');
    await page.click('button[type="submit"]');
    const request = await submitRequest;
    const submitted = new URLSearchParams(request.postData() || '');
    expect(submitted.get('kiwi__token')).toBe(token);
    expect(submitted.get('email')).toBe('user@example.com');
    expect(submitted.get('username')).toBe('user');
    expect(submitted.get('password')).toBe('s3cret');
    await expect(page).toHaveURL(/\/autofill-form$/);
    await expect(page.locator('#autofill-out')).toContainText('submission captured');

    // Run A (negative control): the decoy stays empty and the proof is
    // valid with no honeypot hit.
    await page.click('#autofill-check');
    await expect(page.locator('#autofill-out')).toContainText('"honeypot_hit": false');
    const negative = await page.locator('#autofill-out').textContent();
    expect(negative).toContain('"ok": true');

    // Run B (positive control): the check consumed the record, so a
    // fresh challenge is mandatory before the deliberate decoy fill.
    await page.reload();
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    await page.click('#autofill-positive');
    await expect(page.locator('#autofill-out')).toContainText('filled the authenticated decoy field');
    await page.click('#autofill-check');
    await expect(page.locator('#autofill-out')).toContainText('"honeypot_hit": true');
    const positive = await page.locator('#autofill-out').textContent();
    expect(positive).toContain('"ok": true');
  });
});
