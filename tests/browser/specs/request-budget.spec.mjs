import { test, expect } from '@playwright/test';

// Request-budget invariants of the widget lifecycle.
//
// The full lifecycle (challenge fetch, in-page solve, verification of
// the solved token) must issue exactly one network request to the API
// origin: the POST to the configured challenge endpoint. The solve runs
// in a blob-URL worker (no network), the verification is a server-side
// exchange driven by the page owner (in the fixture, an out-of-page
// request that never touches the page's own request stream), and the
// rendered decoy (honeypot) input is DOM-only: arming it, filling it
// and re-solving with it filled adds zero extra network requests,
// because the decoy evidence rides the existing challenge request
// body. Every lifecycle must cost exactly one request, decoy armed or
// not, filled or not.
//
// The count comes from the page's own request stream via
// page.on('request'), filtered to POST requests against the fixture
// origin, so out-of-page verification through page.request and the
// initial document GET are never counted. The listeners are attached
// before navigation so the driver's auto-run challenge fetch is
// counted. The fixture knobs are the same ones the other specs use:
// ?decoy=1 emits a server-issued decoy name.
//
// This spec is engine-agnostic (no chromium-only APIs) so the same
// assertions can be lifted into the three-engine lane if the suite is
// ever widened.

const CHALLENGE_POST = 1;
const LIFECYCLES_TWO = 2;

async function solve(page, timeout = 60_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

/** Count the page's own POST requests against the fixture origin. */
function trackPosts(page, origin) {
  const posts = [];
  page.on('request', (request) => {
    if (request.method() !== 'POST') return;
    const url = new URL(request.url());
    if (url.origin === origin) posts.push(request);
  });
  return posts;
}

// The authenticated decoy name is response-known (the fixture knows what
// it issued); the DOM never carries a tracking attribute.
function challengeDecoyName(page) {
  return page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'))
    .then((resp) => resp.json())
    .then((data) => data.decoy_field ?? null);
}

async function verifyToken(page, origin, token) {
  const resp = await page.request.post(`${origin}/verify`, { data: { token } });
  return { status: resp.status(), body: await resp.json() };
}

test.describe('KiwiCaptcha request budget', () => {
  test('a decoy-armed lifecycle issues exactly one API-origin request; the decoy adds zero', async ({ page }) => {
    const origin = test.info().project.use.baseURL;
    const posts = trackPosts(page, origin);
    const nameP = challengeDecoyName(page);
    await page.goto('/?decoy=1');

    await solve(page);
    expect(posts, 'the armed lifecycle must issue exactly one POST to the challenge endpoint').toHaveLength(CHALLENGE_POST);
    const [challengeReq] = posts;
    expect(new URL(challengeReq.url()).pathname, 'the single request must be the challenge fetch').toBe('/challenge');
    expect(challengeReq.postData(), 'the single request must carry the challenge request body').toContain('"scope"');

    // The decoy input is rendered (server-issued name) and filling it
    // adds no request: the evidence rides the next challenge request.
    const name = await nameP;
    expect(name, 'the armed issuance must render a decoy name').toBeTruthy();
    await page.evaluate((n) => {
      const el = document.querySelector(`input[name="${n}"]`);
      if (el) {
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(el, 'bot@example.com');
        el.dispatchEvent(new Event('input', { bubbles: true }));
      }
    }, name);
    expect(posts, 'filling the decoy must add zero requests').toHaveLength(CHALLENGE_POST);

    // Verification of the solved token is an out-of-page exchange and
    // must add zero page requests.
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok, 'the solved token must verify').toBe(true);
    expect(posts, 'the out-of-page verification must add zero page requests').toHaveLength(CHALLENGE_POST);
  });

  test('every lifecycle costs exactly one request; a decoy-disabled lifecycle costs the same', async ({ page }) => {
    const origin = test.info().project.use.baseURL;
    const posts = trackPosts(page, origin);
    const nameP = challengeDecoyName(page);
    await page.goto('/?decoy=1');

    await solve(page);
    expect(posts, 'the first armed lifecycle must cost exactly one request').toHaveLength(CHALLENGE_POST);
    const token1 = await page.locator('[data-kiwi-token]').inputValue();

    // A filled decoy survives the reset, and the re-solve still costs
    // exactly one request: the filled decoy rides the challenge body.
    const name = await nameP;
    await page.evaluate((n) => {
      const el = document.querySelector(`input[name="${n}"]`);
      if (el) el.value = 'bot@example.com';
    }, name);

    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      if (!w.dataset.kiwiStarted) {
        const retry = document.querySelector('[data-kiwi-retry]');
        if (retry) retry.click();
      }
    });
    await solve(page);
    expect(posts, 'two armed lifecycles (the second with the decoy filled) must cost exactly two requests').toHaveLength(LIFECYCLES_TWO);
    const token2 = await page.locator('[data-kiwi-token]').inputValue();
    expect(token2).not.toBe(token1);

    const first = await verifyToken(page, origin, token1);
    const second = await verifyToken(page, origin, token2);
    expect(first.body.ok, 'the first lifecycle token must verify').toBe(true);
    expect(second.body.ok, 'the re-solved lifecycle token must verify').toBe(true);
    expect(posts, 'verification stays out-of-page: zero added requests').toHaveLength(LIFECYCLES_TWO);

    // The decoy-disabled lifecycle costs the same single request: the
    // decoy adds zero network requests by construction.
    const plain = trackPosts(page, origin);
    await page.goto('/');
    await solve(page);
    expect(plain, 'a decoy-disabled lifecycle must cost exactly one request too').toHaveLength(CHALLENGE_POST);
  });
});
