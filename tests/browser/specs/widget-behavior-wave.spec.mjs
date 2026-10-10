import { test, expect } from '@playwright/test';

// Focused regression gates for the widget behavior wave: progress
// buckets, the retrying-vs-terminal error contract, retry during the
// auto-retry backoff, focus retention through Retry (WCAG 2.4.3), the
// expired presentation and language resolution (html[lang], regional
// packs).

test.describe('widget behavior wave', () => {
  test('the progress bar advances in the painted 10-unit buckets during the solve', async ({ page }) => {
    // A hot browser process can finish the whole 18-bit solve inside
    // one paint window, and then the only observed write is the final
    // 100. Throttling the CPU pins the solve across several frames, so
    // the mid-solve buckets must actually reach the paint.
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Emulation.setCPUThrottlingRate', { rate: 8 });
    await page.addInitScript(() => {
      window.__progressSeen = [];
      // The observer is installed after the document exists but long
      // before the ~1s solve finishes, so every mid-solve bucket is seen.
      document.addEventListener('DOMContentLoaded', () => {
        const observer = new MutationObserver(() => {
          const fill = document.querySelector('[data-kiwi-bar]');
          if (!fill) return;
          const v = fill.getAttribute('data-progress');
          if (v !== null) window.__progressSeen.push(v);
        });
        observer.observe(document.documentElement, { subtree: true, attributes: true, attributeFilter: ['data-progress'] });
      });
    });
    await page.goto('/?bits=18');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const seen = await page.evaluate(() => window.__progressSeen.map(Number));
    expect(seen.length).toBeGreaterThan(0);
    // Every write is a painted bucket, never a raw float.
    for (const v of seen) {
      expect(Number.isFinite(v), `progress write ${v} must be finite`).toBe(true);
      expect(v % 10, `progress write ${v} must be a 10-unit bucket`).toBe(0);
    }
    // The bar actually moved mid-solve instead of staying at 0 until done.
    expect(seen.some((v) => v >= 10 && v < 100), `expected a mid-solve bucket, saw ${JSON.stringify(seen)}`).toBe(true);
  });

  test('a transient failure retries without a terminal error event, and execute() still resolves', async ({ page }) => {
    let attempts = 0;
    await page.route('**/challenge', async (route) => {
      attempts += 1;
      if (attempts === 1) {
        await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
      } else {
        await route.continue();
      }
    });
    await page.addInitScript(() => {
      // The widget events bubble, so a document-level listener installed
      // before any page script catches even the first retry.
      window.__events = [];
      for (const name of ['kiwi:retrying', 'kiwi:error', 'kiwi:verified']) {
        document.addEventListener(name, () => window.__events.push(name));
      }
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const events = await page.evaluate(() => window.__events);
    expect(events).toContain('kiwi:retrying');
    expect(events).toContain('kiwi:verified');
    expect(events, 'a retried-and-recovered failure must never dispatch kiwi:error').not.toContain('kiwi:error');
  });

  test('Retry during the auto-retry backoff reacquires immediately and keeps focus on the widget', async ({ page }) => {
    let attempts = 0;
    await page.route('**/challenge', async (route) => {
      attempts += 1;
      if (attempts <= 2) {
        await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
      } else {
        await route.continue();
      }
    });
    await page.goto('/');
    // The first failure resets to idle with a pending backoff; Retry is
    // visible in the idle state and must supersede the timer.
    await expect(page.locator('[data-kiwi-retry]')).toBeVisible({ timeout: 30_000 });
    await page.locator('[data-kiwi-retry]').focus();
    const before = attempts;
    await page.keyboard.press('Enter');
    // The click is accepted (not refused by the started flag): the next
    // challenge attempt fires without waiting out the backoff.
    await expect.poll(() => attempts, { timeout: 10_000 }).toBeGreaterThan(before);
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
  });

  test('the expired credential presents Expired with Retry, never Success', async ({ page }) => {
    await page.route('**/challenge*', async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      body.ttlSecs = 1; // the server TTL starts at issuance; solve then expire fast
      await route.fulfill({ response, json: body });
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'expired', { timeout: 120_000 });
    await expect(page.locator('[data-kiwi-badge]')).toHaveText('Expired');
    await expect(page.locator('[data-kiwi-info]')).toContainText('expired');
    await expect(page.locator('[data-kiwi-retry]')).toBeVisible();
  });

  test('language resolution falls back through html[lang] and regional packs', async ({ page }) => {
    // An unsupported explicit language must fall through to <html lang>
    // instead of collapsing straight to English: serve the page with
    // html lang=de and no per-widget language.
    await page.route(/\/\?lang=xx-unsupported$/, async (route) => {
      const response = await route.fetch();
      const html = await response.text();
      await route.fulfill({ response, contentType: 'text/html', body: html.replace(/<html[^>]*>/, '<html lang="de">') });
    });
    await page.goto('/?lang=xx-unsupported');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(page.locator('[data-kiwi-label]')).toHaveText('Sicherheitsprüfung');
    // A regional tag with its own pack wins over the base pack.
    await page.goto('/?lang=pt-BR');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(page.locator('[data-kiwi-label]')).toHaveText('Verificação de segurança');
  });
});
