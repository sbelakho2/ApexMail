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
    // The standalone worker path (CSP-friendly: no blob:) must load its WASM
    // glue via importScripts("kiwicaptcha-wasm.js") — a typo in that name
    // silently loses off-main-thread Argon. This test pins the flag the
    // driver sets when the external worker is actually used.
    await page.goto('/?worker=1&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const workerUsed = await page.evaluate(() => window.__kiwiWorkerUsed === true);
    expect(workerUsed, 'the external worker must be used for Argon2id').toBe(true);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    expect((await resp.json()).ok).toBe(true);
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

  test('a solve that exhausts its bounded search notifies the server once for the abandoned nonce', async ({ page }) => {
    // The exhaustion path (the bounded search cap) abandons the challenge:
    // the driver must inform the server (fire-and-forget, rate-limited) for
    // the abandoned nonce only. The retry flow re-acquires fresh challenges
    // and the per-widget cooldown keeps the notification bounded — never a
    // spam, and never a cancel for a nonce this widget did not abandon.
    const cancelBodies = [];
    await page.route('**/challenge/cancel', async (route) => {
      cancelBodies.push(route.request().postDataJSON() ?? {});
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{"cancelled":true}' });
    });
    let calls = 0;
    await page.route('**/challenge', async (route) => {
      calls++;
      // An unsolvable challenge (targetBits 255: the 5M-hash bounded search
      // can never find a match) — the solver exhausts and the widget fails
      // after the bounded retry flow.
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          nonce: 'exhaust-nonce-' + calls,
          salt: btoa(String(calls).padStart(16, '0')),
          prefix: 'x',
          targetBits: 255,
          algorithm: 'sha256',
          mKib: 0,
          t: 1,
          p: 1,
          ttlSecs: 120,
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
});
