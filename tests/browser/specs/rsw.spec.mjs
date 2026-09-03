import { test, expect } from '@playwright/test';

// The optional rsw time-lock rung end to end: the fixture issues an rsw
// challenge (algorithm rsw, sequential cost T from ?rsw_t=), the widget
// driver dispatches it to the worker asset, the worker performs the T
// sequential modular squarings in pure JS BigInt and reports the final
// value, and the driver mints the rsw token shape: counter 0 plus the
// final 512-hex proof segment. The fixture's /verify endpoint checks the
// proof against the trapdoor expectation and accepts it.
test.describe('KiwiCaptcha rsw sequential time-lock', () => {
  async function solveRsw(page, t, query) {
    await page.goto(`/?algorithm=rsw&rsw_t=${t}${query || ''}`);
    const tokenInput = page.locator('[data-kiwi-token]');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await tokenInput.inputValue();
    expect(token.length).toBeGreaterThan(0);
    // The rsw token shape: base64(nonce.0.duration.telemetry.512hex).
    const parts = atob(token).split('.');
    expect(parts.length).toBe(5);
    expect(parts[1]).toBe('0'); // no search counter exists for a time lock
    expect(parts[4]).toMatch(/^[0-9a-f]{512}$/);
    return token;
  }

  test('the worker solves the sequential time lock and the fixture verifies the proof', async ({ page }) => {
    // The legacy static-worker path (?worker=1) loads the fresh worker
    // asset from disk and derives the runtime URL, so the spec exercises
    // the real asset bytes without depending on the glue copy.
    const token = await solveRsw(page, 10000, '&worker=1');
    const workerUsed = await page.evaluate(() => window.__kiwiWorkerUsed === true);
    expect(workerUsed, 'the rsw solve must run in the same-origin worker').toBe(true);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    const body = await resp.json();
    expect(body.ok, `verify must accept the worker-solved rsw token (${body.code})`).toBe(true);
  });

  test('files mode solves an rsw challenge with the versioned worker asset', async ({ page }) => {
    // Files mode fetches the content-addressed worker and runtime assets
    // with their SRI pins and constructs a same-origin Worker from the
    // verified bytes; the rsw solver in the asset must solve it.
    const token = await solveRsw(page, 10000, '&assets=files');
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    const body = await resp.json();
    expect(body.ok, `files-mode rsw verify must accept the token (${body.code})`).toBe(true);
  });

  test('a tampered rsw proof never verifies', async ({ page }) => {
    // Mint a real rsw token through the widget, then flip one hex digit
    // of the proof: the fixture verifier recomputes the trapdoor
    // expectation and must reject the mismatch.
    const token = await solveRsw(page, 10000, '&worker=1');
    const parts = atob(token).split('.');
    let proof = parts[4];
    proof = (proof[0] === '0' ? '1' : '0') + proof.slice(1);
    parts[4] = proof;
    const tampered = btoa(parts.join('.'));
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token: tampered } });
    const body = await resp.json();
    expect(body.ok).toBe(false);
    expect(body.code).toBe('insufficient_work');
  });
});
