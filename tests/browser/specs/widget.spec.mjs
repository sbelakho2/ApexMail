import { test, expect } from '@playwright/test';

test.describe('KiwiCaptcha browser solver', () => {
  async function solveAndVerify(page, algorithm) {
    await page.goto(`/?algorithm=${algorithm}`);
    const tokenInput = page.locator('[data-kiwi-token]');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await tokenInput.inputValue();
    expect(token.length).toBeGreaterThan(0);

    const resp = await page.request.post('http://127.0.0.1:8085/verify', {
      data: { token },
    });
    const body = await resp.json();
    expect(body.ok, `verify must accept the browser-solved ${algorithm} token (${body.code})`).toBe(true);
  }

  test('SHA-256 WASM solve verifies end-to-end', async ({ page }) => {
    await solveAndVerify(page, 'sha256');
  });

  test('SHA-256 JS fallback solves without WASM (strict CSP without wasm-unsafe-eval)', async ({ page }) => {
    // The strict-CSP page lacks 'wasm-unsafe-eval': WebAssembly compilation is
    // blocked, so the driver must fall back to the pure-JS SHA-256 solver.
    await page.goto('/?csp=strict');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 90_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });

  test('Argon2id WASM solve verifies end-to-end', async ({ page }) => {
    await solveAndVerify(page, 'argon2id');
  });

  test('external same-origin worker is used (data-kiwi-worker-src)', async ({ page }) => {
    // The standalone worker path (CSP-friendly: no blob:) never imports a
    // runtime itself: the driver derives the runtime URL from the worker's
    // own URL and supplies it through the { type: "glue" } handshake — a
    // missing or wrong derivation silently loses off-main-thread Argon.
    // This test pins the flag the driver sets when the external worker is
    // actually used and verifies the end-to-end solve through the
    // driver-directed runtime.
    await page.goto('/?worker=1&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const workerUsed = await page.evaluate(() => window.__kiwiWorkerUsed === true);
    expect(workerUsed, 'the external worker must be used for Argon2id').toBe(true);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
  });

  test('the legacy static worker receives the driver-derived runtime URL (never a relative probe)', async ({ page }) => {
    // The legacy data-kiwi-worker-src path (no integrity digest) must be
    // driven through the same protocol as files mode: the driver derives
    // the runtime URL from the worker's own URL ("kiwicaptcha-wasm.js"
    // next to the worker) and posts it via the glue handshake before the
    // solve. The worker's runtime load is the importScripts of exactly
    // that derived URL — the fixture serves it at /kiwicaptcha-wasm.js —
    // and no relative/unversioned probe is ever made.
    const runtimeRequests = [];
    page.on('request', (req) => {
      if (req.url().includes('/kiwicaptcha-wasm.js')) runtimeRequests.push(req.url());
    });
    await page.goto('/?worker=1&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
    // The worker's importScripts of the derived runtime URL is captured in
    // the page request stream; the legacy path must load exactly that
    // same-directory runtime.
    expect(runtimeRequests).toContain('http://127.0.0.1:8085/kiwicaptcha-wasm.js');
  });

  test('Privacy Strict: zero external requests and empty telemetry', async ({ page }) => {
    const external = [];
    page.on('request', (req) => {
      const url = new URL(req.url());
      if (url.origin !== 'http:\/\/127.0.0.1:8085') external.push(req.url());
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const parts = atob(token).split('.');
    expect(JSON.parse(parts[3])).toEqual({});
    expect(external).toEqual([]);
  });

  test('a solve that abandons at its deadline notifies the server once for the abandoned nonce', async ({ page }) => {
    // The abandonment path (the bounded search exhaustion or the solve
    // deadline) abandons the challenge: the driver must inform the
    // server (fire-and-forget, rate-limited) for the abandoned nonce
    // only. The retry flow re-acquires fresh challenges and the
    // per-widget cooldown keeps the notification bounded — never a
    // spam, and never a cancel for a nonce this widget did not abandon.
    // The abandonment is driven deterministically by the solve deadline:
    // a schema-valid argon2id challenge at the maximum in-contract
    // memory (mKib 65536 = 64 MiB, t 6) expires 500 ms into the solve —
    // a single memory-hard hash cannot complete inside the deadline
    // window on any current hardware, so every attempt abandons instead
    // of ever solving.
    const cancelBodies = [];
    await page.route('**/challenge/cancel', async (route) => {
      cancelBodies.push(route.request().postDataJSON() ?? {});
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{"cancelled":true}' });
    });
    let calls = 0;
    await page.route('**/challenge', async (route) => {
      calls++;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          nonce: 'exhaust-nonce-' + calls,
          salt: btoa(String(calls).padStart(16, '0')),
          prefix: 'x',
          algorithm: 'argon2id',
          targetBits: 10,
          mKib: 65536,
          t: 6,
          p: 1,
          ttlSecs: 1,
          minDurationMs: 0,
        }),
      });
    });
    await page.goto('/?algorithm=sha256');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 90_000 });
    expect(calls).toBeGreaterThanOrEqual(3); // the bounded retry flow re-acquired
    expect(cancelBodies.length).toBeGreaterThanOrEqual(1);
    expect(cancelBodies.length).toBeLessThanOrEqual(calls); // at most one per abandoned challenge
    expect(cancelBodies[0]).toEqual({ nonce: 'exhaust-nonce-1' }); // the first abandoned nonce
    const notified = cancelBodies.map((b) => b.nonce);
    expect(new Set(notified).size).toBe(notified.length); // once per nonce, never a re-acquired nonce
  });

  test('a normal solve sends no cancel request', async ({ page }) => {
    let cancelHits = 0;
    await page.route('**/challenge/cancel', async (route) => {
      cancelHits++;
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{"cancelled":true}' });
    });
    await page.goto('/?algorithm=sha256');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
    expect(cancelHits).toBe(0); // a successful solve never abandons a challenge
  });

  test('a fresh render stays under a bounded number of DOM nodes (< 40)', async ({ page }) => {
    // The widget markup is deliberately small: the container, the hidden
    // token input, the visible widget with its icon, track, timer and
    // status announcer, plus at most the retry button and the decoy
    // input the driver creates. A hard ceiling of 40 elements keeps the
    // widget cheap to render and bounds the DOM a page must carry per
    // captcha.
    await page.goto('/');
    await page.waitForSelector('#kiwicaptcha-root [data-kiwi-started="1"]');
    const idleCount = await page.evaluate(() => document.querySelector('#kiwicaptcha-root').querySelectorAll('*').length);
    expect(idleCount, `the freshly rendered widget must stay under 40 elements, got ${idleCount}`).toBeLessThan(40);
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const doneCount = await page.evaluate(() => document.querySelector('#kiwicaptcha-root').querySelectorAll('*').length);
    expect(doneCount, `the solved widget must stay under 40 elements, got ${doneCount}`).toBeLessThan(40);
  });
});
