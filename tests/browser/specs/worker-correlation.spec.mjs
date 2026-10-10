import { test, expect } from '@playwright/test';

// The worker solve-request correlation contract (widget-risk.js):
//
//   - the solve request id comes from the correlation helper and never
//     from the presentation Math.random fallback: with
//     crypto.getRandomValues missing the worker path must fail closed
//     (no solve message is ever posted) and the driver solves in-page;
//   - a done frame is accepted only when it echoes the outstanding
//     request id AND carries a real solution shape: an integer counter
//     inside [0, MAX_SHA_HASHES);
//   - every frame after the first terminal one is ignored (duplicate
//     done, stale progress, wrong id).
//
// Only window.Worker is faked; the driver, the risk module, the fixture
// server and /verify are the real ones.

const scope = 'login';
// Mirrors protocol/limits.json solver_max_hashes (asserted there across
// PHP, Rust and the browser).
const MAX_SHA_HASHES = 20000000;

async function installFakeWorker(page, scenario) {
  await page.addInitScript(({ selected, maxShaHashes }) => {
    window.__kw = { created: 0, solves: [], terminated: 0, replies: 0, scenario: selected };
    class KiwiFakeWorker {
      constructor() {
        window.__kw.created += 1;
        this.onmessage = null;
      }
      addEventListener() {}
      terminate() {
        window.__kw.terminated += 1;
      }
      postMessage(msg) {
        if (!msg || typeof msg !== 'object' || msg.type !== 'solve') return;
        window.__kw.solves.push({ reqId: msg.reqId, algorithm: msg.algorithm, targetBits: msg.targetBits });
        const buildId = (window.KiwiCaptcha && window.KiwiCaptcha.protocolId) || '2026-09-r1';
        const send = (frame) => {
          window.__kw.replies += 1;
          setTimeout(() => {
            if (this.onmessage) this.onmessage({ data: frame });
          }, 0);
        };
        switch (window.__kw.scenario) {
          case 'accept':
            send({ v: 1, type: 'done', reqId: msg.reqId, counter: 3, buildId });
            break;
          case 'badCounters':
            for (const counter of [-1, NaN, 1.5, maxShaHashes, maxShaHashes + 1]) {
              send({ v: 1, type: 'done', reqId: msg.reqId, counter, buildId });
            }
            break;
          case 'missingReqId':
            send({ v: 1, type: 'done', counter: 5, buildId });
            break;
          case 'wrongReqId':
            send({ v: 1, type: 'done', reqId: 'q-foreign-request', counter: 5, buildId });
            break;
          case 'duplicate':
            send({ v: 1, type: 'done', reqId: msg.reqId, counter: 3, buildId });
            setTimeout(() => send({ v: 1, type: 'done', reqId: msg.reqId, counter: 7, buildId }), 50);
            break;
          default:
            break;
        }
      }
    }
    window.Worker = KiwiFakeWorker;
  }, { selected: scenario, maxShaHashes: MAX_SHA_HASHES });
}

async function openWorkerTier(page) {
  await page.goto('/?assets=files&worker=1&bits=4', { waitUntil: 'domcontentloaded' });
  await expect.poll(() => page.evaluate(() => window.__kw.solves.length), {
    message: 'the driver must dispatch the SHA solve to the worker tier',
  }).toBe(1);
}

function tokenCounter(token) {
  const parts = atob(token).split('.');
  return Number(parts[1]);
}

test.describe('Worker request correlation and done-shape validation', () => {
  test('an echoed done with a valid counter settles the solve (control)', async ({ page }) => {
    await installFakeWorker(page, 'accept');
    await openWorkerTier(page);
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 30_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(tokenCounter(token), 'the accepted worker counter must reach the token').toBe(3);
    const reqId = await page.evaluate(() => window.__kw.solves[0].reqId);
    expect(typeof reqId, 'the solve request must carry a request id').toBe('string');
    expect(reqId.length, 'the request id must carry 128 secure-random bits in base36').toBeGreaterThanOrEqual(12);
  });

  test('malformed counters are never accepted: negative, NaN, fractional, at and above the solver ceiling', async ({ page }) => {
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    await installFakeWorker(page, 'badCounters');
    await openWorkerTier(page);
    // All five frames carry the right request id but a nonsense counter.
    // They must be ignored: the widget stays solving (the pending worker
    // promise has not settled and the main-thread fallback waits for the
    // deadline), and the token is never minted from a bad frame.
    await expect.poll(() => page.evaluate(() => window.__kw.replies)).toBe(5);
    await page.waitForTimeout(500);
    expect(await page.locator('[data-kiwi-widget]').getAttribute('data-state')).toBe('solving');
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe('');
    expect(pageErrors, 'a malformed done must not raise a page error').toEqual([]);
  });

  test('a done without a request id is ignored', async ({ page }) => {
    await installFakeWorker(page, 'missingReqId');
    await openWorkerTier(page);
    await expect.poll(() => page.evaluate(() => window.__kw.replies)).toBe(1);
    await page.waitForTimeout(400);
    expect(await page.locator('[data-kiwi-widget]').getAttribute('data-state')).toBe('solving');
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe('');
  });

  test('a done with a foreign request id is ignored', async ({ page }) => {
    await installFakeWorker(page, 'wrongReqId');
    await openWorkerTier(page);
    await expect.poll(() => page.evaluate(() => window.__kw.replies)).toBe(1);
    await page.waitForTimeout(400);
    expect(await page.locator('[data-kiwi-widget]').getAttribute('data-state')).toBe('solving');
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe('');
  });

  test('a duplicate done after the first settle is ignored', async ({ page }) => {
    let challengePosts = 0;
    const pageErrors = [];
    page.on('request', (r) => {
      if (r.method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel')) challengePosts += 1;
    });
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    await installFakeWorker(page, 'duplicate');
    await openWorkerTier(page);
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 30_000 });
    // Give the second (duplicate) done frame time to arrive: the first
    // settle must stand and the duplicate must not restart the flow.
    await page.waitForTimeout(400);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(tokenCounter(token), 'the first settle must stand; the duplicate must not rewrite the token').toBe(3);
    expect(challengePosts, 'a duplicate done must never restart the flow with a second challenge').toBe(1);
    expect(pageErrors).toEqual([]);
  });

  test('missing crypto.getRandomValues fails the worker path closed and never posts a solve', async ({ page }) => {
    await installFakeWorker(page, 'none');
    await page.addInitScript(() => {
      try {
        Object.defineProperty(window.crypto, 'getRandomValues', { value: undefined, configurable: true });
      } catch (e) {
        window.crypto.getRandomValues = undefined;
      }
    });
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    await page.goto('/?assets=files&worker=1&bits=4', { waitUntil: 'domcontentloaded' });
    // The correlation RNG refuses to degrade: no solve message reaches
    // the worker. The driver falls back to the in-page solver, so the
    // widget still solves for real and the server accepts it.
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 30_000 });
    expect(await page.evaluate(() => window.__kw.solves.length), 'a missing getRandomValues must never produce a worker solve').toBe(0);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token, scope } });
    const body = await resp.json();
    expect(body.ok, `the in-page fallback solve must verify (got ${body.code})`).toBe(true);
    expect(pageErrors).toEqual([]);
  });
});
