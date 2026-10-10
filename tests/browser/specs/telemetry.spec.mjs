import { test, expect } from '@playwright/test';

// The lazy telemetry contract: an enabled telemetry mode (data-kiwi-telemetry="full"
// or "minimal" on the container) starts the lazy widget-telemetry.js
// module load opportunistically at init, but the challenge flow never
// awaits it. The session attaches only when the module registers before
// this generation's challenge request went out (the driver's requestSent
// flag, checked in the load's .then()); once the request is sent, the
// generation solves with the normal empty "{}" telemetry stub — never a
// half-session mid-solve. An unloadable module degrades to the same
// stub. The files tier delivers the module descriptor
// (data-kiwi-telemetry-src/-integrity), so these cases drive the real
// lazy load; the fixture emits the opt-in attribute through the
// ?telemetry=full|minimal knob.

const TELEMETRY_URL_MARKER = '/assets/telemetry.';

function telemetryRequests(page) {
  const requests = [];
  page.on('request', (request) => {
    if (request.url().includes(TELEMETRY_URL_MARKER)) requests.push(request);
  });
  return requests;
}

// The token wire shape: base64(nonce.counter.duration.telemetry[.evidence]).
// Segment 3 is the JSON telemetry blob.
function tokenTelemetry(token) {
  const parts = atob(token).split('.');
  expect(parts.length, 'the token must carry the telemetry segment').toBeGreaterThanOrEqual(4);
  return JSON.parse(parts[3]);
}

test.describe('Lazy telemetry module acquisition', () => {
  test('an enabled mode attaches the session BEFORE the request: the POST waits (bounded) for the module and the token carries the real session', async ({ page }) => {
    const held = [];
    await page.route('**/assets/telemetry*.js', async (route) => {
      held.push(route);
    });
    let challengeFired = false;
    page.on('request', (r) => {
      if (r.method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel')) challengeFired = true;
    });
    await page.goto('/?assets=files&telemetry=full', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held.length, 'the telemetry fetch must be in flight').toBe(1);

    // The session must attach before the request: the POST is held back
    // while the module load is in flight, so the token can never carry {}.
    await page.waitForTimeout(500);
    expect(challengeFired, 'the challenge POST must wait (bounded) for the telemetry module').toBe(false);

    for (const route of held.splice(0)) {
      await route.continue().catch(() => {});
    }
    await expect.poll(() => challengeFired, 'the POST fires once the module registered').toBe(true);
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    expect(tokenTelemetry(token).v, 'the token must carry the real v1 session, never the empty stub').toBe(1);
  });

  test('a hung or missing telemetry module degrades to the empty stub: three bounded attempts, no page error, the solve is unaffected', async ({ page }) => {
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    let hits = 0;
    await page.route('**/assets/telemetry*.js', async (route) => {
      hits++;
      await route.fulfill({ status: 404, contentType: 'application/javascript', body: 'not found' });
    });
    await page.goto('/?assets=files&telemetry=minimal');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect.poll(() => hits, 'the missing module must repeat through the bounded retries').toBe(3);

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the widget must solve without the telemetry module').toBeGreaterThan(0);
    expect(tokenTelemetry(token), 'the unloadable module must leave the empty telemetry stub').toEqual({});
    expect(pageErrors, 'the telemetry degradation must raise no page error').toEqual([]);

    const resp = await page.request.post('http://127.0.0.1:8085/verify', {
      data: { token, scope: 'login' },
    });
    const body = await resp.json();
    expect(body.ok, `the telemetry-off solve must verify (got ${body.code})`).toBe(true);
  });

  test('an enabled mode with the module present still loads exactly once and never delays the solve', async ({ page }) => {
    const requests = telemetryRequests(page);
    await page.goto('/?assets=files&telemetry=full');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect.poll(() => requests.length, 'the module must load exactly once').toBe(1);
    expect(requests[0].resourceType(), 'the module must ride a script element load').toBe('script');
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    // The session attaches before the request, so the token carries the
    // real telemetry record (never the empty stub) while the module
    // still loads exactly once.
    expect(tokenTelemetry(token).v).toBe(1);
  });
});

// The challenge-fetch deadline (data-kiwi-fetch-timeout-ms) bounds the
// challenge POST itself. It must never start before the pre-fetch
// telemetry wait: telemetry initialization carries its own independent
// 2 s budget, so a slow module can never consume (and abort) the
// configured challenge timeout.
test.describe('Challenge fetch timeout vs telemetry initialization', () => {
  test('telemetry slow (1500 ms) + fetch timeout 1000 ms + a fast server still succeeds', async ({ page }) => {
    await page.route('**/assets/telemetry*.js', async (route) => {
      await new Promise((r) => setTimeout(r, 1500));
      await route.continue().catch(() => {});
    });
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    await page.goto('/?assets=files&telemetry=minimal&fetch_timeout=1000', { waitUntil: 'domcontentloaded' });
    // The healthy challenge endpoint answers in milliseconds; the only
    // way this can fail is if the 1000 ms deadline had started before
    // the telemetry wait consumed it.
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the solve must complete despite the slow telemetry module').toBeGreaterThan(0);
    // The module still arrived inside its own budget, so the token
    // carries the real session rather than the empty stub.
    expect(tokenTelemetry(token).v).toBe(1);
    expect(pageErrors, 'the slow telemetry module must raise no page error').toEqual([]);
  });

  test('a challenge response slower than the configured timeout still aborts', async ({ page }) => {
    let delayed = 0;
    await page.route('**/challenge**', async (route) => {
      if (route.request().method() === 'POST' && !route.request().url().includes('/cancel')) {
        delayed++;
        await new Promise((r) => setTimeout(r, 3000));
      }
      await route.continue().catch(() => {});
    });
    await page.goto('/?assets=files&fetch_timeout=1000', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
    expect(delayed, 'the delayed challenge POST must have been attempted').toBeGreaterThanOrEqual(1);
  });

  test('reset during the telemetry wait cancels the stale generation before any challenge POST', async ({ page }) => {
    const held = [];
    const posts = [];
    await page.route('**/assets/telemetry*.js', (route) => {
      held.push(route);
    });
    page.on('request', (r) => {
      if (r.method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel')) posts.push(r.url());
    });
    await page.goto('/?assets=files&telemetry=minimal&fetch_timeout=1000', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held.length, 'the first telemetry load must be held').toBe(1);
    expect(posts, 'no challenge may be sent while telemetry is still pending').toEqual([]);

    // Reset while the first generation is still waiting on telemetry.
    const widgetId = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), widgetId);

    // Release the held module. Both generations resume from the same
    // in-flight load: the superseded one must return at its generation
    // check, and only the live generation may send a challenge.
    await held.shift().continue().catch(() => {});
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    expect(posts, 'exactly the live generation may send a challenge; the stale generation must not').toHaveLength(1);
  });

  test('destroy during the telemetry wait leaves no challenge POST behind', async ({ page }) => {
    const held = [];
    const posts = [];
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    await page.route('**/assets/telemetry*.js', (route) => {
      held.push(route);
    });
    page.on('request', (r) => {
      if (r.method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel')) posts.push(r.url());
    });
    await page.goto('/?assets=files&telemetry=minimal&fetch_timeout=1000', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held.length, 'the telemetry load must be held').toBe(1);

    const widgetId = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((id) => window.KiwiCaptcha.remove(id), widgetId);
    await expect(page.locator('#kiwicaptcha-root')).toHaveCount(0);
    for (const route of held.splice(0)) await route.continue().catch(() => {});
    await page.waitForTimeout(700);
    expect(posts, 'a destroyed widget must never send a challenge POST').toEqual([]);
    expect(pageErrors, 'destroy during the telemetry wait must raise no page error').toEqual([]);
  });
});
