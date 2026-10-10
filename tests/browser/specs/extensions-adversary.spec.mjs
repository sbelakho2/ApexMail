import { test, expect } from '@playwright/test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Browser extension and interception-layer adversaries. The scenarios
// mirror what extensions and interception layers actually do to a
// widget: DOM-mutating extensions (container wrapping and relocation,
// token and decoy input duplication and removal, attribute decoration),
// service-worker-style interception of the challenge fetch (forged and
// malformed responses, delayed responses, wrong content types),
// interception and duplication of the verify submission, page-script
// reads of the driver surface, and observer-driven reset and reissue
// races. Every scenario pins the same invariant: the server record is
// single-use and its answers are deterministic (never a 500), and the
// widget either produces a token that genuinely verifies or settles in
// a controlled state with no stale credential. The spec is
// engine-neutral: no engine-specific API, every wait is state-driven,
// so the integration lane can adopt it unchanged.
//
// The fixture knobs used here: ?decoy=pool arms the authenticated decoy
// issuance (protocol-v3 record with the signed grammar-shaped name),
// ?decoy=1 emits a response-only decoy name, POST /verify redeems a
// proof exactly once (the record file is removed on success), POST
// /honeypot-check mirrors the form-decoy evidence surface, and
// data-kiwi-fetch-timeout-ms bounds the challenge fetch on the served
// widget pages.
//
// One robustness deviation was found and fixed in the forged-challenge
// test: the driver used to solve any response that parses as JSON
// without validating the challenge shape, so a well-formed forged
// response (arbitrary nonce, targetBits 0) was minted into a token.
// The token never verified, because the server re-derives the proof
// from its own record keyed by the nonce, so no authorization was ever
// granted — but the widget reported 'done' instead of failing cleanly.
// The driver now validates the response shape and bounds (nonce,
// prefix, salt, targetBits, the algorithm parameter ranges) before
// solving, so a forged or malformed challenge enters the controlled
// bounded-retry failure state with no token minted; recovery acquires a
// fresh verifiable issuance.

const specDir = path.dirname(fileURLToPath(import.meta.url));

const DECOY_NAME_SHAPE = /^[a-z]+_[a-z]+_[a-z]+_[0-9a-f]{16}$/;

function assetPath(name) {
  const candidates = [
    path.resolve(specDir, '../../../packages/kiwicaptcha-wasm/assets', name),
    path.resolve(specDir, '../../../assets', name),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error(`cannot locate ${name}; tried ${candidates.join(', ')}`);
}

function decodeToken(token) {
  return Buffer.from(token, 'base64').toString('latin1');
}

function sha256Of(...chunks) {
  const h = crypto.createHash('sha256');
  for (const chunk of chunks) h.update(chunk);
  return h.digest();
}

function leadingZeroBits(buf) {
  let n = 0;
  for (const b of buf) {
    if (b === 0) {
      n += 8;
      continue;
    }
    for (let bit = 7; bit >= 0; bit--) {
      if (b & (1 << bit)) return n;
      n++;
    }
  }
  return n;
}

// A counter whose recomputed proof-of-work hash does NOT meet the
// challenge target, so the server rejects it deterministically rather
// than by luck of the hash.
function failingCounter(prefix, salt, targetBits, preferred) {
  const saltBytes = Buffer.from(salt, 'base64');
  const prefixBytes = Buffer.from(prefix, 'utf8');
  const candidates = [];
  if (Number.isInteger(preferred) && preferred >= 0) candidates.push(preferred);
  if (Number.isInteger(preferred) && preferred - 1 >= 0) candidates.push(preferred - 1);
  candidates.push(0, 1, 2, 3);
  for (const counter of candidates) {
    const hash = sha256Of(prefixBytes, Buffer.from(String(counter), 'utf8'), saltBytes);
    if (leadingZeroBits(hash) < targetBits) return counter;
  }
  throw new Error('no failing counter found for the challenge');
}

async function fixtureOrigin(page) {
  return page.evaluate(() => window.location.origin);
}

async function solve(page, timeout = 60_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

async function verifyToken(page, origin, token) {
  const resp = await page.request.post(`${origin}/verify`, {
    data: { token },
  });
  return { status: resp.status(), body: await resp.json() };
}

async function widgetId(page) {
  return page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
}

function tokenNonce(page, token) {
  return page.evaluate((t) => atob(t).split('.')[0], token);
}

function collectPageErrors(page) {
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  return errors;
}

// The next challenge response's decoy name; the promise must be
// registered before the navigation or reset that triggers the fetch.
function challengeDecoyName(page) {
  return page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'))
    .then((resp) => resp.json())
    .then((data) => data.decoy_field ?? null);
}

const WIDGET_MARKUP = `
    <div class="kiwi-widget" data-kiwi-widget data-state="idle">
      <div class="kiwi-icon-wrapper"><svg></svg><div class="kiwi-glow"></div></div>
      <div class="kiwi-main">
        <div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>
        <div class="kiwi-track" aria-hidden="true"><div class="kiwi-bar" data-kiwi-bar></div></div>
        <div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected</p><span class="kiwi-timer" data-kiwi-timer></span></div>
      </div>
    </div>`;

// A widget page served from the test origin with extra container
// attributes (the fixture index page cannot carry them).
async function serveWidgetPage(page, attrs) {
  const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
  const driver = fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
  const risk = fs.readFileSync(assetPath('widget-risk.js'), 'utf8');
  const attrStr = Object.entries(attrs)
    .map(([k, v]) => ` ${k}="${v}"`)
    .join('');
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<div class="kiwi-container" id="kiwicaptcha-root"${attrStr}>
  <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
${WIDGET_MARKUP}
</div>
<script>${glue}</script><script>${driver}</script><script>${risk}</script></body></html>`;
  await page.route('**/widget-test', (route) =>
    route.fulfill({ contentType: 'text/html', body: html })
  );
  await page.goto('/widget-test');
}

test.describe('KiwiCaptcha challenge-fetch interception adversaries', () => {
  test('a forged well-formed challenge fails the widget into the controlled failure; recovery solves fresh', async ({ page }) => {
    let challengePosts = 0;
    let cancelPosts = 0;
    page.on('request', (req) => {
      if (req.method() === 'POST' && req.url().includes('/challenge') && !req.url().includes('/cancel')) challengePosts++;
      if (req.method() === 'POST' && req.url().includes('/challenge/cancel')) cancelPosts++;
    });
    await page.route('**/challenge', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ nonce: 'forged-nonce-001', prefix: 'p', salt: 'c2FsdA==', targetBits: 0, algorithm: 'sha256' }),
      })
    );
    const errors = collectPageErrors(page);
    await page.goto('/');
    const origin = await fixtureOrigin(page);
    // The response shape gate refuses the forged challenge (targetBits 0
    // is outside the issuance contract): the widget settles in the
    // controlled failure state with no token minted and a bounded retry
    // flow — it never solves a response the server could not have
    // issued.
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 60_000 });
    expect(await page.locator('[data-kiwi-token]').inputValue(), 'no token may be minted from a forged challenge').toBe('');
    expect(challengePosts, 'the retry flow is bounded').toBeLessThanOrEqual(3);
    expect(cancelPosts, 'a forged body is not an abandonment').toBe(0);
    // The interceptor is removed: a fresh solve acquires a genuinely
    // verifiable token from the real issuance.
    await page.unroute('**/challenge');
    const wid = await widgetId(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const fresh = await page.locator('[data-kiwi-token]').inputValue();
    expect(await tokenNonce(page, fresh), 'the recovery solve must not reuse the forged nonce').not.toBe('forged-nonce-001');
    const result = await verifyToken(page, origin, fresh);
    expect(result.body.ok, 'the recovery token must verify').toBe(true);
    expect(errors).toHaveLength(0);
  });

  test('a replayed issuance is single-use: two tokens from one nonce share one redemption', async ({ page }) => {
    let captured = null;
    let calls = 0;
    await page.route('**/challenge', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      calls++;
      if (captured === null) captured = data;
      await route.fulfill({ response: resp });
    });
    await page.goto('/');
    await solve(page);
    const tokenA = await page.locator('[data-kiwi-token]').inputValue();
    const origin = await fixtureOrigin(page);
    // The interceptor now serves the captured issuance for every later
    // request, exactly like a service worker replaying a cached response.
    await page.unroute('**/challenge');
    await page.route('**/challenge', (route) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(captured) })
    );
    const wid = await widgetId(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const tokenB = await page.locator('[data-kiwi-token]').inputValue();
    expect(await tokenNonce(page, tokenB), 'the replayed issuance re-solves the same nonce').toBe(await tokenNonce(page, tokenA));
    const first = await verifyToken(page, origin, tokenB);
    expect(first.body.ok, 'the replay solve still redeems its single record').toBe(true);
    const second = await verifyToken(page, origin, tokenA);
    expect(second.status, 'the twin token answers deterministically, never a 500').toBe(200);
    expect(second.body.ok, 'one issuance grants exactly one redemption').toBe(false);
    expect(second.body.code).toBe('record_not_found');
  });

  test('malformed challenge bodies fail the widget into the controlled error state with bounded retries', async ({ page }) => {
    const bodies = [
      { label: 'a non-JSON body under application/json', contentType: 'application/json', body: '<html>forged</html>' },
      { label: 'a JSON object that is not a challenge', contentType: 'application/json', body: JSON.stringify({ foo: 1 }) },
      { label: 'a JSON object with an undecodable salt', contentType: 'application/json', body: JSON.stringify({ nonce: 'n', prefix: 'p', salt: '!!!', targetBits: 1 }) },
    ];
    let challengePosts = 0;
    let cancelPosts = 0;
    page.on('request', (req) => {
      if (req.method() === 'POST' && req.url().includes('/challenge') && !req.url().includes('/cancel')) challengePosts++;
      if (req.method() === 'POST' && req.url().includes('/challenge/cancel')) cancelPosts++;
    });
    for (const b of bodies) {
      await page.route('**/challenge', (route) =>
        route.fulfill({ status: 200, contentType: b.contentType, body: b.body })
      );
      await page.goto('/');
      const origin = await fixtureOrigin(page);
      const before = challengePosts;
      await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 60_000 });
      expect(await page.locator('[data-kiwi-token]').inputValue(), `${b.label}: no token from a malformed challenge`).toBe('');
      expect(challengePosts - before, `${b.label}: the retry flow is bounded`).toBeLessThanOrEqual(3);
      expect(cancelPosts, `${b.label}: a malformed body is not an abandonment`).toBe(0);
      // Recovery: with the interceptor off, a fresh solve verifies.
      await page.unroute('**/challenge');
      const wid = await widgetId(page);
      await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
      await solve(page);
      const token = await page.locator('[data-kiwi-token]').inputValue();
      const result = await verifyToken(page, origin, token);
      expect(result.body.ok, `${b.label}: the recovery solve must verify`).toBe(true);
      await page.goto('about:blank');
    }
  });

  test('a delayed challenge response aborts at the fetch timeout and the retry acquires a fresh challenge', async ({ page }) => {
    let calls = 0;
    let firstNonce = null;
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    await page.route('**/challenge', async (route) => {
      calls++;
      if (calls === 1) {
        const resp = await route.fetch();
        const data = await resp.json();
        firstNonce = data.nonce;
        await gate;
        try {
          await route.fulfill({ response: resp });
        } catch (e) {}
        return;
      }
      await route.continue();
    });
    let cancelPosts = 0;
    page.on('request', (req) => {
      if (req.method() === 'POST' && req.url().includes('/challenge/cancel')) cancelPosts++;
    });
    await serveWidgetPage(page, {
      'data-kiwi-endpoint': '/challenge',
      'data-kiwi-scope': 'login',
      'data-kiwi-fetch-timeout-ms': '1200',
    });
    const origin = await fixtureOrigin(page);
    // The first attempt is held past the fetch timeout; the bounded
    // retry solves a fresh challenge instead of the stale held one.
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(firstNonce, 'the first issuance must have been captured').toBeTruthy();
    expect(await tokenNonce(page, token), 'the token must come from the retried issuance').not.toBe(firstNonce);
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok).toBe(true);
    expect(cancelPosts, 'a transport timeout is not an abandonment: no cancel for the timed-out nonce').toBe(0);
    expect(calls).toBeGreaterThanOrEqual(2);
    release();
  });

  test('content-type is not a conformance gate: parseable JSON is accepted, unparseable is rejected', async ({ page }) => {
    // A well-formed challenge under a wrong content type is solved: the
    // driver's conformance gate is the JSON parse itself.
    await page.route('**/challenge', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      await route.fulfill({ contentType: 'text/plain', body: JSON.stringify(data) });
    });
    await page.goto('/');
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, 'the wrong content type alone must not break a conforming solve').toBe(true);
    // The same wrong content type with an unparseable body is a
    // controlled failure, never a token.
    await page.unroute('**/challenge');
    await page.route('**/challenge', (route) =>
      route.fulfill({ status: 200, contentType: 'text/plain', body: 'not json at all' })
    );
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 60_000 });
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe('');
  });
});

test.describe('KiwiCaptcha verify-submission interception adversaries', () => {
  test('duplicated parallel submissions: exactly one redemption, deterministic codes, never a 500', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const origin = await fixtureOrigin(page);
    const [a, b] = await Promise.all([
      verifyToken(page, origin, token),
      verifyToken(page, origin, token),
    ]);
    expect([a.status, b.status], 'both arrivals answer 200, never 500').toEqual([200, 200]);
    const oks = [a.body.ok, b.body.ok].filter(Boolean).length;
    expect(oks, 'exactly one parallel submission may redeem the single-use record').toBe(1);
    const loser = a.body.ok ? b : a;
    expect(loser.body.code, 'the losing arrival finds the record consumed').toBe('record_not_found');
    const third = await verifyToken(page, origin, token);
    expect(third.status).toBe(200);
    expect(third.body.ok).toBe(false);
    expect(third.body.code).toBe('record_not_found');
  });

  test('redirected and replayed submissions to the sibling routes stay deterministic and single-use', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    // An extension redirects the submission to the sibling evidence
    // route; the server answers deterministically and consumes the
    // record, so the later arrival at the verify route finds nothing.
    const redirected = await page.request.post(`${origin}/honeypot-check`, {
      data: { token },
    });
    expect(redirected.status()).toBe(200);
    expect((await redirected.json()).ok, 'the redirected body redeems on the sibling route').toBe(true);
    const replayed = await verifyToken(page, origin, token);
    expect(replayed.status).toBe(200);
    expect(replayed.body.ok, 'the consumed record is gone from every route').toBe(false);
    expect(replayed.body.code).toBe('record_not_found');
    // A form-encoded body at the JSON-only verify route is deterministic,
    // never a 500.
    const wid = await widgetId(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const token2 = await page.locator('[data-kiwi-token]').inputValue();
    const formResp = await page.request.post(`${origin}/verify`, {
      form: { kiwi__token: token2 },
    });
    expect(formResp.status(), 'a wrong wire shape answers deterministically, never a 500').toBe(200);
    expect((await formResp.json()).ok, 'a non-JSON verify body never verifies').toBe(false);
  });
});

test.describe('KiwiCaptcha DOM-mutating extension adversaries', () => {
  test('wrapping and moving the container with attribute decoration leaves the solve and the decoy intact', async ({ page }) => {
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    const nameP = challengeDecoyName(page);
    await page.route('**/challenge?*', async (route) => {
      const resp = await route.fetch();
      await gate;
      try {
        await route.fulfill({ response: resp });
      } catch (e) {}
    });
    await page.goto('/?decoy=pool');
    const origin = await fixtureOrigin(page);
    await page.waitForFunction(
      () => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'connecting',
      null,
      { timeout: 30_000 }
    );
    // Extension-style surgery while the challenge is in flight: the
    // container is wrapped in new elements, moved under a new section,
    // and the token input is decorated with attributes and a seeded
    // value.
    await page.evaluate(() => {
      const container = document.querySelector('.kiwi-container');
      const section = document.createElement('section');
      section.id = 'ext-section';
      const wrap = document.createElement('div');
      wrap.id = 'ext-wrap-1';
      wrap.setAttribute('data-ext', 'password-manager');
      const wrap2 = document.createElement('div');
      wrap2.id = 'ext-wrap-2';
      container.parentNode.insertBefore(section, container);
      wrap2.appendChild(container);
      wrap.appendChild(wrap2);
      section.appendChild(wrap);
      const token = document.querySelector('[data-kiwi-token]');
      token.setAttribute('autocomplete', 'off');
      token.value = 'extension-seeded-bogus';
      container.setAttribute('data-ext-id', 'pm-1');
    });
    release();
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token, 'the seeded value must be replaced by the real credential').not.toBe('extension-seeded-bogus');
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok, 'the moved widget must still verify').toBe(true);
    // The armed decoy renders inside the token host, which moved with
    // the container.
    const name = await nameP;
    expect(name).toMatch(DECOY_NAME_SHAPE);
    const facts = await page.evaluate((n) => {
      const token = document.querySelector('[data-kiwi-token]');
      const decoy = document.querySelector(`input[name="${n}"]`);
      return {
        decoyPresent: !!decoy,
        // The wrapped variants nest the input in a span, so the shared
        // host is proven by containment, not by parent equality.
        sameHost: !!(token && decoy && token.parentNode && token.parentNode.contains(decoy)),
        inMovedContainer: !!document.getElementById('ext-section').contains(token),
      };
    }, name);
    expect(facts.decoyPresent).toBe(true);
    expect(facts.sameHost, 'the decoy must share the token host after the move').toBe(true);
    expect(facts.inMovedContainer, 'the token must live inside the relocated container').toBe(true);
    // A reset and re-solve inside the moved structure still works end to
    // end.
    const wid = await widgetId(page);
    const name2P = challengeDecoyName(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const token2 = await page.locator('[data-kiwi-token]').inputValue();
    const result2 = await verifyToken(page, origin, token2);
    expect(result2.body.ok, 'the re-solve inside the wrapped structure must verify').toBe(true);
    expect(await name2P).toMatch(DECOY_NAME_SHAPE);
  });

  test('a duplicated token input is never written: the widget-owned field alone carries the credential', async ({ page }) => {
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    await page.route('**/challenge', async (route) => {
      const resp = await route.fetch();
      await gate;
      try {
        await route.fulfill({ response: resp });
      } catch (e) {}
    });
    await page.goto('/');
    const origin = await fixtureOrigin(page);
    await page.waitForFunction(
      () => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'connecting',
      null,
      { timeout: 30_000 }
    );
    // An extension duplicates the token input while the challenge is in
    // flight, before any credential exists to copy.
    await page.evaluate(() => {
      const owned = document.querySelector('[data-kiwi-token]');
      const dup = owned.cloneNode(false);
      dup.name = 'kiwi__token';
      dup.removeAttribute('data-kiwi-token');
      dup.setAttribute('autocomplete', 'on');
      dup.value = '';
      owned.parentNode.insertBefore(dup, owned.nextSibling);
    });
    release();
    await solve(page);
    const state = await page.evaluate(() => {
      const inputs = Array.from(document.querySelectorAll('input[name="kiwi__token"]'));
      return { owned: inputs[0].value, duplicate: inputs[1].value };
    });
    expect(state.owned.length).toBeGreaterThan(10);
    expect(state.duplicate, 'the duplicated input never receives the credential').toBe('');
    const result = await verifyToken(page, origin, state.owned);
    expect(result.body.ok).toBe(true);
    // A reset and re-solve writes only the owned input again.
    const wid = await widgetId(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const after = await page.evaluate(() => {
      const inputs = Array.from(document.querySelectorAll('input[name="kiwi__token"]'));
      return { first: inputs[0].value, second: inputs[1].value };
    });
    expect(after.first.length).toBeGreaterThan(10);
    expect(after.second, 'the duplicate stays empty across generations').toBe('');
    const result2 = await verifyToken(page, origin, after.first);
    expect(result2.body.ok).toBe(true);
    // A clone taken after the solve may carry the written value with it
    // (the value attribute snapshot); either way the pair grants exactly
    // one redemption: the record is already consumed.
    const snapshot = await page.evaluate(() => {
      const owned = document.querySelector('[data-kiwi-token]');
      const dup = owned.cloneNode(false);
      dup.name = 'kiwi__token';
      dup.removeAttribute('data-kiwi-token');
      return dup.value;
    });
    const dupResult = await verifyToken(page, origin, snapshot);
    expect(dupResult.status, 'the duplicated value answers deterministically, never a 500').toBe(200);
    expect(dupResult.body.ok, 'the duplicated value grants nothing beyond the first redemption').toBe(false);
    expect(dupResult.body.code).toBe('record_not_found');
  });

  test('removing the token input mid-lifecycle: the solve lands on the detached node and a re-solve recovers', async ({ page }) => {
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    await page.route('**/challenge?*', async (route) => {
      const resp = await route.fetch();
      await gate;
      try {
        await route.fulfill({ response: resp });
      } catch (e) {}
    });
    const errors = collectPageErrors(page);
    await page.goto('/?decoy=1');
    const origin = await fixtureOrigin(page);
    await page.waitForFunction(
      () => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'connecting',
      null,
      { timeout: 30_000 }
    );
    // An aggressive extension removes the token input (and any decoy)
    // while the challenge is in flight.
    await page.evaluate(() => {
      const token = document.querySelector('[data-kiwi-token]');
      token.parentNode.removeChild(token);
      document.querySelectorAll('input[aria-hidden="true"]').forEach((el) => el.parentNode.removeChild(el));
    });
    release();
    await solve(page);
    const wid = await widgetId(page);
    // The credential is solved into the detached node; the page shows no
    // token input and the private record stays honest.
    const gone = await page.evaluate(() => !document.querySelector('[data-kiwi-token]'));
    expect(gone).toBe(true);
    const apiToken = await page.evaluate((id) => window.KiwiCaptcha.getResponse(id), wid);
    expect(apiToken.length).toBeGreaterThan(10);
    const detachedResult = await verifyToken(page, origin, apiToken);
    expect(detachedResult.body.ok, 'the detached-node credential is a genuine verifiable token').toBe(true);
    // The rendered decoy is swept after the solve too; the widget stays
    // settled with no crash.
    await page.evaluate(() => {
      document.querySelectorAll('input[aria-hidden="true"]').forEach((el) => el.parentNode.removeChild(el));
    });
    expect(await page.evaluate((id) => window.KiwiCaptcha.getResponse(id), wid)).toBe(apiToken);
    // A fresh input re-inserted by the page is adopted by the next
    // generation.
    await page.evaluate(() => {
      const container = document.querySelector('.kiwi-container');
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'kiwi__token';
      input.setAttribute('data-kiwi-token', '');
      input.value = '';
      container.insertBefore(input, container.querySelector('[data-kiwi-widget]'));
    });
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(await tokenNonce(page, token), 'the re-adopted input carries a fresh nonce').not.toBe(await tokenNonce(page, apiToken));
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok, 'the re-adopted input carries a fresh verifiable token').toBe(true);
    expect(errors).toHaveLength(0);
  });

  test('an aggressive hidden-input sweeper cannot break the solve; the decoy evidence is page-layer only', async ({ page }) => {
    // A privacy-style extension sweeps every hidden input the widget
    // inserts, immediately after the insertion mutation. The sweeper is
    // installed before any page script so it cannot miss the insertion.
    await page.addInitScript(() => {
      const sweeper = new MutationObserver((mutations) => {
        for (const m of mutations) {
          for (const node of m.addedNodes) {
            if (node.nodeType !== 1) continue;
            // The input may arrive directly or inside a wrapper span that
            // was appended while detached, so both the node itself and
            // its subtree are swept.
            const targets = node.matches && node.matches('input[aria-hidden="true"]')
              ? [node]
              : (node.querySelectorAll ? Array.from(node.querySelectorAll('input[aria-hidden="true"]')) : []);
            for (const t of targets) t.remove();
          }
        }
      });
      window.__kiwiSweeper = sweeper;
      // The init script runs before the document element exists, so the
      // observer roots itself on the document node until parsing builds
      // the tree.
      sweeper.observe(document.documentElement || document, { childList: true, subtree: true });
    });
    const nameP = challengeDecoyName(page);
    await page.goto('/?decoy=pool');
    const origin = await fixtureOrigin(page);
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok, 'the sweep must not disturb the solve or the proof').toBe(true);
    const name = await nameP;
    expect(name).toMatch(DECOY_NAME_SHAPE);
    await expect.poll(async () =>
      page.evaluate(() => document.querySelectorAll('input[aria-hidden="true"]').length)
    ).toBe(0);
    // A reset and re-solve keeps working under the continuing sweep.
    const wid = await widgetId(page);
    const name2P = challengeDecoyName(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const token2 = await page.locator('[data-kiwi-token]').inputValue();
    const result2 = await verifyToken(page, origin, token2);
    expect(result2.body.ok).toBe(true);
    expect(await name2P).toMatch(DECOY_NAME_SHAPE);
  });
});

test.describe('KiwiCaptcha page-script sandbox adversaries', () => {
  test('reading the decoy name and the token from the page surface never yields a verifiable forged token', async ({ page }) => {
    const challenges = [];
    const nameP = challengeDecoyName(page);
    await page.route('**/challenge?*', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      challenges.push(data);
      await route.fulfill({ response: resp });
    });
    await page.goto('/?decoy=pool');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const name = await nameP;
    // The page script reads the decoy name and the credential through
    // the DOM and the public API; both are readable by design.
    const wid = await widgetId(page);
    const read = await page.evaluate((id) => {
      const api = window.KiwiCaptcha;
      const decoyFromDom = document.querySelector('input[aria-hidden="true"]')?.name ?? null;
      return {
        decoyFromDom,
        tokenFromApi: api.getResponse(id),
        protocol: api.protocolId,
      };
    }, wid);
    expect(read.decoyFromDom).toBe(name);
    expect(read.tokenFromApi).toBe(token);
    // Forged tokens built from those readings: a same-nonce counter the
    // re-derived proof deterministically fails, a nonce that was never
    // issued, and a token assembled from the global surface.
    const parts = decodeToken(token).split('.');
    const failing = failingCounter(challenges[0].prefix, challenges[0].salt, challenges[0].targetBits, Number(parts[1]));
    const forgedSameNonce = await page.evaluate(([tok, counter]) => {
      const plain = atob(tok).split('.');
      return btoa([plain[0], String(counter), plain[2], plain[3]].join('.'));
    }, [token, failing]);
    const neverIssued = await page.evaluate(() => btoa('00000000000000000000000000000000.1.5.{}'));
    const fromGlobals = await page.evaluate((proto) =>
      btoa(['00000000000000000000000000000001', '1', '5', JSON.stringify({ proto })].join('.')),
      read.protocol
    );
    for (const [label, t] of [
      ['same-nonce failing counter', forgedSameNonce],
      ['never-issued nonce', neverIssued],
      ['globals-forged token', fromGlobals],
    ]) {
      const r = await verifyToken(page, origin, t);
      expect(r.status, `${label}: never a 500`).toBe(200);
      expect(r.body.ok, `${label}: must not verify`).toBe(false);
      expect(['insufficient_work', 'record_not_found', 'malformed_token'], `${label}: deterministic code`).toContain(r.body.code);
    }
    // The real credential still verifies exactly once, and the record is
    // consumed afterwards.
    const real = await verifyToken(page, origin, token);
    expect(real.body.ok, 'the genuine credential verifies once despite the forgeries').toBe(true);
    const after = await verifyToken(page, origin, forgedSameNonce);
    expect(after.status).toBe(200);
    expect(after.body.code, 'the consumed record answers record_not_found').toBe('record_not_found');
  });

  test('a stolen token copied into a second form grants exactly one redemption', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const wid = await widgetId(page);
    // The page script steals the credential through the documented API
    // and duplicates it into a second form.
    const stolen = await page.evaluate((id) => window.KiwiCaptcha.getResponse(id), wid);
    await page.evaluate((tok) => {
      const form = document.createElement('form');
      form.id = 'second-form';
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'kiwi__token';
      input.value = tok;
      form.appendChild(input);
      document.body.appendChild(form);
    }, stolen);
    const wire = await page.evaluate(() => {
      const fd = new FormData(document.getElementById('second-form'));
      return fd.get('kiwi__token');
    });
    expect(wire).toBe(stolen);
    const first = await verifyToken(page, origin, stolen);
    expect(first.body.ok, 'the stolen copy redeems its single record').toBe(true);
    const second = await verifyToken(page, origin, stolen);
    expect(second.status, 'the duplicate submission answers deterministically, never a 500').toBe(200);
    expect(second.body.ok, 'the stolen copy grants nothing beyond the first redemption').toBe(false);
    expect(second.body.code).toBe('record_not_found');
  });
});

test.describe('KiwiCaptcha observer and reissue race adversaries', () => {
  test('a reset storm mid-fetch settles on the newest generation with a verifiable token', async ({ page }) => {
    const issued = [];
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    let cancelPosts = 0;
    page.on('request', (req) => {
      if (req.method() === 'POST' && req.url().includes('/challenge/cancel')) cancelPosts++;
    });
    await page.route('**/challenge', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      issued.push(data.nonce);
      await gate;
      try {
        await route.fulfill({ response: resp });
      } catch (e) {}
    });
    await page.goto('/');
    const origin = await fixtureOrigin(page);
    await page.waitForFunction(
      () => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'connecting',
      null,
      { timeout: 30_000 }
    );
    const wid = await widgetId(page);
    // Four public resets while every challenge is held: five generations
    // in flight, each superseding the one before it.
    await expect.poll(() => issued.length).toBe(1);
    for (let i = 0; i < 4; i++) {
      await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
      const blank = await page.evaluate(() => document.querySelector('[data-kiwi-token]').value);
      expect(blank, 'a reset must clear the credential synchronously').toBe('');
      await expect.poll(() => issued.length).toBe(i + 2);
    }
    release();
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(issued).toHaveLength(5);
    expect(await tokenNonce(page, token), 'the credential must come from the newest generation').toBe(issued[4]);
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok).toBe(true);
    expect(cancelPosts, 'an aborted generation is not an abandonment').toBe(0);
    const consistent = await page.evaluate((id) => ({
      dom: document.querySelector('[data-kiwi-token]').value,
      api: window.KiwiCaptcha.getResponse(id),
    }), wid);
    expect(consistent.dom, 'the private record and the DOM input must agree').toBe(consistent.api);
  });

  test('a long-poll reissue loop leaves no stale hidden state and recovers with a verifiable token', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const wid = await widgetId(page);
    // A page-layer poller resets the widget on every observed credential,
    // three times, then stops. Every sampled instant must keep the DOM
    // input and the private record consistent.
    const observations = await page.evaluate(async (id) => {
      const snapshots = [];
      let resets = 0;
      const poll = window.setInterval(() => {
        const api = window.KiwiCaptcha.getResponse(id);
        const dom = document.querySelector('[data-kiwi-token]').value;
        const state = document.querySelector('[data-kiwi-widget]').getAttribute('data-state');
        snapshots.push({ api, dom, state });
        if (api !== '' && resets < 3) {
          resets++;
          window.KiwiCaptcha.reset(id);
        }
      }, 40);
      while (resets < 3) {
        await new Promise((r) => setTimeout(r, 50));
      }
      window.clearInterval(poll);
      return { resets, snapshots };
    }, wid);
    expect(observations.resets, 'the poller must have exercised the reissue race').toBe(3);
    for (const s of observations.snapshots) {
      expect(s.api, 'the private record and the DOM input must move together').toBe(s.dom);
      if (s.api === '') {
        expect(s.state, 'an empty credential must never be reported done').not.toBe('done');
      }
    }
    // The final generation solves a fresh credential that verifies.
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok, 'the post-loop solve verifies').toBe(true);
    const consistent = await page.evaluate((id) => ({
      api: window.KiwiCaptcha.getResponse(id),
      dom: document.querySelector('[data-kiwi-token]').value,
    }), wid);
    expect(consistent.api).toBe(consistent.dom);
  });
});
