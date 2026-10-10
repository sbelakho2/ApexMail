import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Portable adversarial subset for the three-engine lane
// (playwright.a11y.config.mjs). The chromium-only adversarial.spec.mjs
// keeps the engine-specific torture cases (worker termination, forged
// postMessage floods, oversized payloads); this spec covers the decoy
// lifecycle and the autofill-compatibility surface that every engine
// must honor. It runs on Chromium + Firefox + WebKit with no
// engine-specific APIs and no reliance on engine timing; every wait is
// state-driven.
//
// The fixture knobs: ?decoy=pool arms the real authenticated decoy
// issuance (protocol-v3 record, signed grammar-prefix-plus-suffix
// name); ?decoy=1 emits a response-only decoy name composed
// deterministically from the nonce; ?decoyname=... overrides the
// emitted name with a fixed one (for ?decoy=pool it pins the
// authenticated armed name too, so a spec can force a deliberate
// collision with an application field); ?strategy=0..5 emits the
// non-authenticated rendering-strategy hint the driver honors when
// present. POST /honeypot-check mirrors the bundle validator's
// formDecoyEvidence. A non-empty value under the exact authenticated
// decoy name reports a hit, any other name is ignored. Evidence is
// additive: the proof outcome decides and the hit rides alongside it
// as signal, so the fixture answer for an exact-name fill is ok:true
// with the hit reported, a probabilistic observation and never a hard
// gate.
//
// The decoy name is never exposed through a DOM tracking attribute:
// tests learn it from the challenge response (the fixture knows what it
// issued), and the widget's private state is authoritative for cleanup.
//
// The decoy presentation is polymorphic: a bounded set of rendering
// strategies is chosen per challenge from the client-side `CSPRNG` (the
// fixture's strategy hint forces each variant deterministically). The
// assertions here pin the invariant surface every strategy keeps:
// one input, invisible to humans, non-interactive, off the autofill
// candidate surface, empty until a filler touches it.

const specDir = path.dirname(fileURLToPath(import.meta.url));

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

// The server-side armed naming space: a grammar prefix
// ({slot1}_{slot2}_{slot3}) plus the 16-lowercase-hex suffix, the shape
// the fixture's armed issuance picks from. The assertions here pin the
// rendered name to that shape.
const DECOY_NAME_SHAPE = /^[a-z]+_[a-z]+_[a-z]+_[0-9a-f]{16}$/;

// A fixed grammar-shaped name that is never the authenticated one for
// the wrong-name scenarios (the fixture ignores any name it did not
// issue).
const WRONG_DECOY_NAME = 'secondary_contact_phone';

const WIDGET_MARKUP = `
    <div class="kiwi-widget" data-kiwi-widget data-state="idle">
      <div class="kiwi-icon-wrapper"><svg></svg><div class="kiwi-glow"></div></div>
      <div class="kiwi-main">
        <div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>
        <div class="kiwi-track" aria-hidden="true"><div class="kiwi-bar" data-kiwi-bar></div></div>
        <div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected</p><span class="kiwi-timer" data-kiwi-timer></span></div>
      </div>
    </div>`;

// The fixture origin is derived from the live page so the same spec
// serves the default chromium lane (8085) and the three-engine lane
// (8087) without hard-coding a port. Call it only after the page has
// navigated: on about:blank the origin string is "null".
async function fixtureOrigin(page) {
  return page.evaluate(() => window.location.origin);
}

async function solve(page, timeout = 60_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

async function verifyToken(page, origin, token) {
  const resp = await page.request.post(`${origin}/verify`, { data: { token } });
  return { status: resp.status(), body: await resp.json() };
}

async function honeypotCheck(page, origin, form) {
  const resp = await page.request.post(`${origin}/honeypot-check`, { form });
  return { status: resp.status(), body: await resp.json() };
}

function tokenNonce(page, token) {
  return page.evaluate((t) => atob(t).split('.')[0], token);
}

// The next challenge response's authenticated decoy name. The promise
// must be registered before the navigation (or reset) that triggers the
// challenge fetch — the decoy name is response-known, never a DOM
// tracking attribute.
function challengeDecoyName(page) {
  return page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'))
    .then((resp) => resp.json())
    .then((data) => data.decoy_field ?? null);
}

// The fill path real autofill engines use: the native value setter
// (bypassing framework interception) plus bubbled input and change
// events, exactly like built-in autofill and password managers.
async function simulateAutofill(page, selector, value) {
  return page.evaluate(([sel, v]) => {
    const el = document.querySelector(sel);
    if (!el) return false;
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  }, [selector, value]);
}

function widgetMarkupFor(attrs) {
  const attrStr = Object.entries(attrs)
    .map(([k, v]) => ` ${k}="${v}"`)
    .join('');
  return `<div class="kiwi-container" id="kiwicaptcha-root"${attrStr}>
  <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
${WIDGET_MARKUP}
</div>`;
}

// A protected form page: real fields with autocomplete semantics, the
// widget container, and the token input all inside one form element.
async function serveFormPage(page, endpoint) {
  const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
  const driver = fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
  const risk = fs.readFileSync(assetPath('widget-risk.js'), 'utf8');
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<form id="f" action="/form-submit" method="post">
${widgetMarkupFor({
    'data-kiwi-endpoint': endpoint,
    'data-kiwi-scope': 'login',
  })}
  <label>Email <input type="email" name="email" autocomplete="email" /></label>
  <label>Username <input type="text" name="username" autocomplete="username" /></label>
  <label>Password <input type="password" name="password" autocomplete="current-password" /></label>
</form>
<script>${glue}</script><script>${driver}</script><script>${risk}</script></body></html>`;
  await page.route('**/autofill-form', (route) =>
    route.fulfill({ contentType: 'text/html', body: html })
  );
  await page.goto('/autofill-form');
}

async function serializedForm(page) {
  return page.evaluate(() => {
    const form = document.getElementById('f');
    const fd = new FormData(form);
    const out = {};
    for (const [k, v] of fd.entries()) out[k] = v;
    return out;
  });
}

// The invariant surface of every decoy rendering strategy: the input is
// invisible to humans (display none, the hidden attribute, or an
// offscreen position), never tabbed into, excluded from assistive tech,
// and never a candidate autofill field (autocomplete off or
// new-password, never a visible labelled control).
async function decoySurface(page, name) {
  return page.evaluate((n) => {
    const el = document.querySelector(`input[name="${n}"]`);
    if (!el) return null;
    const cs = getComputedStyle(el);
    return {
      type: el.getAttribute('type'),
      value: el.value,
      autocomplete: el.getAttribute('autocomplete'),
      tabindex: el.getAttribute('tabindex'),
      ariaHidden: el.getAttribute('aria-hidden'),
      display: cs.display,
      hidden: el.hasAttribute('hidden'),
      offscreen: cs.position === 'absolute',
      label: el.getAttribute('aria-label'),
    };
  }, name);
}

test.describe('KiwiCaptcha portable adversarial lifecycle', () => {
  test('decoy creation: one hidden non-interactive input named from the authenticated grammar', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await page.goto('/?decoy=pool');
    await solve(page);
    const name = await nameP;
    expect(name, 'the armed name must come from the server-side naming space').toMatch(DECOY_NAME_SHAPE);
    const decoy = page.locator(`input[name="${name}"]`);
    await expect(decoy).toHaveCount(1);
    await expect(decoy).toHaveAttribute('tabindex', '-1');
    await expect(decoy).toHaveAttribute('aria-hidden', 'true');
    const surface = await decoySurface(page, name);
    expect(surface.type).toBe('text');
    expect(surface.value).toBe('');
    expect(['off', 'new-password'], 'the decoy stays off the autofill candidate surface').toContain(surface.autocomplete);
    expect(
      surface.display === 'none' || surface.hidden || surface.offscreen,
      `the decoy must be invisible to humans (display=${surface.display}, hidden=${surface.hidden}, offscreen=${surface.offscreen})`
    ).toBe(true);
    const sameHost = await page.evaluate((n) => {
      const token = document.querySelector('[data-kiwi-token]');
      const d = document.querySelector(`input[name="${n}"]`);
      return !!(token && d && token.parentNode && token.parentNode.contains(d));
    }, name);
    expect(sameHost, 'the decoy must live in the same form host as the token').toBe(true);
  });

  test('decoy submission: the serialized payload and the real POST body carry the filled decoy', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await serveFormPage(page, '/challenge?decoy=pool');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name = await nameP;
    const token = await page.locator('[data-kiwi-token]').inputValue();
    await simulateAutofill(page, `input[name="${name}"]`, 'bot@example.com');
    await simulateAutofill(page, 'input[name="email"]', 'user@example.com');

    const serialized = await serializedForm(page);
    expect(serialized.email).toBe('user@example.com');
    expect(serialized.kiwi__token).toBe(token);
    expect(serialized[name]).toBe('bot@example.com');

    const submitRequest = page.waitForRequest('**/form-submit');
    await page.evaluate(() => document.getElementById('f').submit());
    const req = await submitRequest;
    const wire = req.postData() || '';
    const params = new URLSearchParams(wire);
    expect(params.get('kiwi__token')).toBe(token);
    expect(params.get(name)).toBe('bot@example.com');
    expect(params.get('email')).toBe('user@example.com');
  });

  test('authenticated decoy name: the exact fill reports additive evidence while the proof stays valid', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await serveFormPage(page, '/challenge?decoy=pool');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name = await nameP;
    const token = await page.locator('[data-kiwi-token]').inputValue();
    await simulateAutofill(page, `input[name="${name}"]`, 'bot@example.com');

    const result = await honeypotCheck(page, origin, {
      kiwi__token: token,
      [name]: 'bot@example.com',
    });
    expect(result.body, 'the exact armed decoy must be a server-side honeypot hit').toEqual({
      ok: true,
      honeypot_hit: true,
      decoy_field: name,
    });
    expect(result.body.ok, 'evidence is additive: the valid proof never becomes a ban').toBe(true);
  });

  test('a wrong decoy name is ignored: no false hit, the proof stays valid', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await serveFormPage(page, '/challenge?decoy=pool');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name = await nameP;
    const wrong = name === WRONG_DECOY_NAME ? 'alternate_contact_phone' : WRONG_DECOY_NAME;
    const token = await page.locator('[data-kiwi-token]').inputValue();
    await simulateAutofill(page, `input[name="${wrong}"]`, 'bot@example.com');

    const result = await honeypotCheck(page, origin, {
      kiwi__token: token,
      [wrong]: 'bot@example.com',
    });
    expect(result.body.ok, 'the proof itself must stay valid').toBe(true);
    expect(result.body.honeypot_hit, 'a mismatched name is not this challenge decoy').toBe(false);
    expect(result.body.decoy_field).toBe(name);
  });

  test('reset clears the rendered decoy; a re-solve renders exactly one fresh decoy', async ({ page }) => {
    // ?decoyname pins the fixture's emitted name (an armed-shape name),
    // so the rendered input is deterministic across engines and runs.
    await page.goto('/?decoy=1&decoyname=secondary_contact_number_a3f9c21d8e5b7401');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name1 = 'secondary_contact_number_a3f9c21d8e5b7401';
    const decoy = page.locator(`input[name="${name1}"]`);
    await expect(decoy).toHaveCount(1);
    await decoy.evaluate((el) => {
      el.value = 'bot@example.com';
    });

    // The reset removes the owned decoy node and the private state
    // synchronously. The public reset re-initializes immediately on the
    // current driver, so the widget moves on to a fresh solve; the
    // re-acquire click below stays a no-op while the widget is already
    // started and re-acquires after a state-only reset, so the test
    // holds under either lifecycle contract.
    const name2P = challengeDecoyName(page);
    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((id) => {
      window.KiwiCaptcha.reset(id);
      // The reset removes the owned decoy synchronously (the private
      // owned set, before the fresh initWidget starts its async
      // re-acquisition). The fixture pins
      // the decoy name, so the re-issued challenge re-renders a
      // same-named input asynchronously; asserting inside this same
      // evaluate observes the guaranteed-absent moment, never the
      // re-render race.
      const decoys = Array.from(document.querySelectorAll('input[aria-hidden="true"][tabindex="-1"]'));
      if (decoys.length !== 0) {
        throw new Error('the reset must remove the rendered decoy synchronously: found ' + decoys.length);
      }
    }, wid);
    await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      if (!w.dataset.kiwiStarted) {
        const retry = document.querySelector('[data-kiwi-retry]');
        if (retry) retry.click();
      }
    });
    await solve(page);
    const name2 = await name2P;
    expect(name2).toMatch(DECOY_NAME_SHAPE);
    await expect(page.locator(`input[name="${name2}"]`), 'exactly one fresh decoy input after the re-solve').toHaveCount(1);
    const remaining = await page.evaluate(() => document.querySelectorAll('input[aria-hidden="true"][tabindex="-1"]').length);
    expect(remaining, 'the form never accumulates decoy inputs').toBe(1);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok).toBe(true);
  });

  test('reissue replaces the stale decoy: a new per-issuance name removes the stale input', async ({ page }) => {
    const names = ['company_website_url', 'alternate_contact_phone'];
    let issued = 0;
    // The widget endpoint carries a query (?decoy=1), so the pattern
    // must span the query string to intercept the issuance.
    await page.route('**/challenge?*', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      data.decoy_field = names[issued % names.length];
      issued++;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
    });
    await page.goto('/?decoy=1');
    await solve(page);
    await expect(page.locator('input[name="company_website_url"]')).toHaveCount(1);
    const stale = page.locator('input[name="company_website_url"]');
    await stale.evaluate((el) => {
      el.value = 'stale';
    });

    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    const name2P = challengeDecoyName(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    expect(await name2P).toBe('alternate_contact_phone');
    await expect(page.locator('input[name="company_website_url"]'), 'the stale input must leave the form').toHaveCount(0);
    await expect(page.locator('input[name="alternate_contact_phone"]')).toHaveCount(1);
    const remaining = await page.evaluate(() => document.querySelectorAll('input[aria-hidden="true"][tabindex="-1"]').length);
    expect(remaining, 'the form must never accumulate stale honeypot fields').toBe(1);
  });

  test('BFCache round-trip: persisted pageshow clears state, the decoy and the token, with no auto-solve', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await page.goto('/?decoy=pool');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name = await nameP;
    await expect(page.locator(`input[name="${name}"]`)).toHaveCount(1);
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'idle');
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    await expect(page.locator(`input[name="${name}"]`), 'the restore must remove the rendered decoy').toHaveCount(0);
    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    expect(await page.evaluate((id) => window.KiwiCaptcha.getResponse(id), wid)).toBe('');
    // The restore must stay idle: a solved credential never returns by
    // itself, and the fresh solve needs an explicit interaction.
    await expect.poll(async () => {
      return page.evaluate(() => {
        const w = document.querySelector('[data-kiwi-widget]');
        return w.getAttribute('data-state') + '|' + document.querySelector('[data-kiwi-token]').value;
      });
    }, { timeout: 3000, intervals: [500] }).toBe('idle|');

    await page.locator('[data-kiwi-retry]').click();
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok, 'the post-restore solve must verify').toBe(true);
  });

  test('multiple widgets on one page: independent solves, tokens and decoys, isolated reset', async ({ page }) => {
    const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
    const driver = fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
  const risk = fs.readFileSync(assetPath('widget-risk.js'), 'utf8');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<form id="fa" action="/form-submit" method="post">
  <div class="kiwi-container" id="ca" data-kiwi-endpoint="/challenge?decoy=pool" data-kiwi-scope="login">
    <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
${WIDGET_MARKUP}
  </div>
</form>
<form id="fb" action="/form-submit" method="post">
  <div class="kiwi-container" id="cb" data-kiwi-endpoint="/challenge?decoy=pool" data-kiwi-scope="login">
    <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
${WIDGET_MARKUP}
  </div>
</form>
<script>${glue}</script><script>${driver}</script><script>${risk}</script></body></html>`;
    await page.route('**/multi-form', (route) =>
      route.fulfill({ contentType: 'text/html', body: html })
    );
    // The per-widget authenticated decoy names are collected from the
    // challenge responses and matched to their widgets by nonce (the
    // token each widget wrote carries the nonce of its own challenge).
    const challengeResponses = [];
    page.on('response', (resp) => {
      if (resp.request().method() === 'POST' && resp.url().includes('/challenge') && !resp.url().includes('/cancel')) {
        resp.json().then((d) => {
          if (d && typeof d.nonce === 'string') challengeResponses.push({ nonce: d.nonce, decoyField: d.decoy_field ?? null });
        }).catch(() => {});
      }
    });
    await page.goto('/multi-form');
    const origin = await fixtureOrigin(page);
    const widgets = page.locator('[data-kiwi-widget]');
    await expect(widgets).toHaveCount(2);
    await expect(widgets.nth(0)).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    await expect(widgets.nth(1)).toHaveAttribute('data-state', 'done', { timeout: 60_000 });

    const tokenA = await page.locator('#fa [data-kiwi-token]').inputValue();
    const tokenB = await page.locator('#fb [data-kiwi-token]').inputValue();
    expect(tokenA.length).toBeGreaterThan(10);
    expect(tokenB.length).toBeGreaterThan(10);
    expect(tokenA).not.toBe(tokenB);
    const resultA = await verifyToken(page, origin, tokenA);
    const resultB = await verifyToken(page, origin, tokenB);
    expect(resultA.body.ok).toBe(true);
    expect(resultB.body.ok).toBe(true);

    const state = await page.evaluate((shape) => {
      const nameA = document.querySelector('#ca input[aria-hidden="true"][tabindex="-1"]')?.name ?? null;
      const nameB = document.querySelector('#cb input[aria-hidden="true"][tabindex="-1"]')?.name ?? null;
      const inputA = document.querySelector(`#ca input[name="${nameA}"]`);
      const inputB = document.querySelector(`#cb input[name="${nameB}"]`);
      const tokenHostA = document.querySelector('#ca [data-kiwi-token]').parentNode;
      const tokenHostB = document.querySelector('#cb [data-kiwi-token]').parentNode;
      return {
        nameA, nameB,
        shapedA: shape.test(nameA),
        shapedB: shape.test(nameB),
        hostA: !!(inputA && tokenHostA.contains(inputA)),
        hostB: !!(inputB && tokenHostB.contains(inputB)),
      };
    }, DECOY_NAME_SHAPE);
    expect(state.shapedA).toBe(true);
    expect(state.shapedB).toBe(true);
    expect(state.hostA).toBe(true);
    expect(state.hostB).toBe(true);
    // The rendered names are the response-known names of the matching
    // challenges (each widget's token nonce identifies its response).
    const nonceA = await tokenNonce(page, tokenA);
    const nonceB = await tokenNonce(page, tokenB);
    const respFor = (nonce) => challengeResponses.find((r) => r.nonce === nonce)?.decoyField ?? null;
    expect(state.nameA).toBe(respFor(nonceA));
    expect(state.nameB).toBe(respFor(nonceB));
    expect(state.nameA).not.toBe(state.nameB);

    // A public reset of one widget must not touch the other: its token,
    // state and decoy stay live while the reset widget reacquires.
    const idA = await page.evaluate(() => document.querySelector('#ca [data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), idA);
    const untouched = await page.evaluate(() => ({
      stateB: document.querySelector('#cb [data-kiwi-widget]').getAttribute('data-state'),
      tokenB: document.querySelector('#fb [data-kiwi-token]').value,
    }));
    expect(untouched.stateB).toBe('done');
    expect(untouched.tokenB).toBe(tokenB);
    await expect(widgets.nth(0)).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const tokenA2 = await page.locator('#fa [data-kiwi-token]').inputValue();
    expect(tokenA2).not.toBe(tokenA);
    expect(await tokenNonce(page, tokenA2)).not.toBe(await tokenNonce(page, tokenA));
    const resultA2 = await verifyToken(page, origin, tokenA2);
    expect(resultA2.body.ok, 'the reset widget must verify its fresh token').toBe(true);
  });

  test('dynamic insertion and removal: observe() auto-inits a later widget and remove() cleans up', async ({ page }) => {
    await page.goto('/');
    const origin = await fixtureOrigin(page);
    await page.evaluate(() => window.KiwiCaptcha.observe(document.body));
    await page.evaluate((markup) => {
      const node = document.createElement('div');
      node.className = 'kiwi-container';
      node.id = 'dyn';
      node.setAttribute('data-kiwi-endpoint', '/challenge');
      node.setAttribute('data-kiwi-scope', 'login');
      node.innerHTML = '<input type="hidden" name="kiwi__token" data-kiwi-token value="" />' + markup;
      document.body.appendChild(node);
    }, WIDGET_MARKUP);
    const dynWidget = page.locator('#dyn [data-kiwi-widget]');
    await expect(dynWidget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const id = await page.evaluate(() => document.querySelector('#dyn [data-kiwi-widget]').dataset.kiwiInstance);
    const token = await page.locator('#dyn [data-kiwi-token]').inputValue();
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok).toBe(true);

    await page.evaluate((wid) => window.KiwiCaptcha.remove(wid), id);
    await expect(page.locator('#dyn'), 'remove() must take the container out of the DOM').toHaveCount(0);
    expect(await page.evaluate((wid) => window.KiwiCaptcha.getResponse(wid), id)).toBe('');

    // A fresh node inserted later is auto-initialized again by the
    // opt-in observer; the removed instance never leaks state into it.
    await page.evaluate((markup) => {
      const node = document.createElement('div');
      node.className = 'kiwi-container';
      node.id = 'dyn2';
      node.setAttribute('data-kiwi-endpoint', '/challenge');
      node.setAttribute('data-kiwi-scope', 'login');
      node.innerHTML = '<input type="hidden" name="kiwi__token" data-kiwi-token value="" />' + markup;
      document.body.appendChild(node);
    }, WIDGET_MARKUP);
    await expect(page.locator('#dyn2 [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token2 = await page.locator('#dyn2 [data-kiwi-token]').inputValue();
    const result2 = await verifyToken(page, origin, token2);
    expect(result2.body.ok).toBe(true);
  });

  test('abort isolation: a reset mid-fetch never writes the stale generation token', async ({ page }) => {
    const firstNonces = [];
    let calls = 0;
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    await page.route('**/challenge', async (route) => {
      calls++;
      if (calls === 1) {
        let resp = null;
        try {
          resp = await route.fetch();
          const data = await resp.json();
          firstNonces.push(data.nonce);
        } catch (e) {}
        await gate;
        if (resp) {
          try {
            await route.fulfill({ response: resp });
          } catch (e) {}
        }
        return;
      }
      await route.continue();
    });
    await page.goto('/');
    const origin = await fixtureOrigin(page);
    await page.waitForFunction(
      () => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'connecting',
      null,
      { timeout: 30_000 }
    );
    // The first challenge response is confirmed captured before the
    // reset, so the stale generation is provably in flight.
    await expect.poll(() => firstNonces.length).toBe(1);
    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    release();
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, origin, token);
    expect(result.body.ok).toBe(true);
    expect(calls, 'the abort must not spawn a retry storm').toBe(2);
    expect(await tokenNonce(page, token), 'the token must come from the fresh generation').not.toBe(firstNonces[0]);
  });
});

test.describe('KiwiCaptcha autofill and password-manager compatibility', () => {
  test('autofill-style fills: only the exact authenticated decoy name yields additive evidence', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await serveFormPage(page, '/challenge?decoy=pool');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name = await nameP;

    // Phase one: a password manager fills the real fields the way
    // native autofill does (value setter plus input and change events).
    // The decoy must stay empty and the verification carries no hit.
    const token1 = await page.locator('[data-kiwi-token]').inputValue();
    await simulateAutofill(page, 'input[name="email"]', 'user@example.com');
    await simulateAutofill(page, 'input[name="username"]', 'user');
    await simulateAutofill(page, 'input[name="password"]', 's3cret');
    expect(await page.locator(`input[name="${name}"]`).inputValue(), 'real-field fills must not touch the decoy').toBe('');
    let result = await honeypotCheck(page, origin, {
      kiwi__token: token1,
      email: 'user@example.com',
      username: 'user',
      password: 's3cret',
    });
    expect(result.body.ok).toBe(true);
    expect(result.body.honeypot_hit, 'filling real fields must never trip the decoy').toBe(false);
    expect(result.body.decoy_field).toBe(name);

    // Phase two: a filler that guesses another grammar name is ignored.
    const wrong = name === WRONG_DECOY_NAME ? 'alternate_contact_phone' : WRONG_DECOY_NAME;
    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    const name2P = challengeDecoyName(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const name2 = await name2P;
    const token2 = await page.locator('[data-kiwi-token]').inputValue();
    await page.evaluate((n) => {
      const input = document.createElement('input');
      input.type = 'text';
      input.name = n;
      document.getElementById('f').appendChild(input);
    }, wrong);
    await simulateAutofill(page, `input[name="${wrong}"]`, 'guessed@example.com');
    result = await honeypotCheck(page, origin, {
      kiwi__token: token2,
      [wrong]: 'guessed@example.com',
    });
    expect(result.body.ok).toBe(true);
    expect(result.body.honeypot_hit, 'a guessed grammar name is ignored server-side').toBe(false);
    expect(result.body.decoy_field).toBe(name2);

    // Phase three: the exact authenticated name fires the evidence,
    // additively — the valid proof keeps its ok:true verdict.
    const name3P = challengeDecoyName(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const name3 = await name3P;
    const token3 = await page.locator('[data-kiwi-token]').inputValue();
    await simulateAutofill(page, `input[name="${name3}"]`, 'bot@example.com');
    result = await honeypotCheck(page, origin, {
      kiwi__token: token3,
      [name3]: 'bot@example.com',
    });
    expect(result.body.ok, 'additive: the proof verdict stays valid').toBe(true);
    expect(result.body.honeypot_hit, 'the exact authenticated name is the evidence trigger').toBe(true);
    expect(result.body.decoy_field).toBe(name3);
  });

  test('autocomplete semantics: the decoy stays off the autofill candidate surface and out of the real-field names', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await serveFormPage(page, '/challenge?decoy=pool');
    await solve(page);
    const name = await nameP;
    expect(name).toMatch(DECOY_NAME_SHAPE);
    const decoy = page.locator(`input[name="${name}"]`);
    await expect(decoy).toHaveCount(1);
    await expect(decoy).toHaveAttribute('tabindex', '-1');
    await expect(decoy).toHaveAttribute('aria-hidden', 'true');
    const surface = await decoySurface(page, name);
    expect(surface.type).toBe('text');
    expect(surface.value).toBe('');
    expect(['off', 'new-password'], 'the decoy never becomes an autofill candidate').toContain(surface.autocomplete);
    expect(
      surface.display === 'none' || surface.hidden || surface.offscreen,
      `the decoy must stay invisible to humans (display=${surface.display}, hidden=${surface.hidden}, offscreen=${surface.offscreen})`
    ).toBe(true);
    // An offscreen strategy labels the field only as auxiliary, never
    // with a visible or meaningful name.
    if (surface.label !== null) {
      expect(surface.label).toBe('off-screen field');
    }

    // The serialized form carries the decoy only as its own empty name:
    // it is no candidate real field, and it never collides with one.
    const realFields = ['email', 'username', 'password', 'kiwi__token'];
    const serialized = await serializedForm(page);
    const keys = Object.keys(serialized);
    expect(keys).toContain(name);
    expect(realFields, 'the decoy name must not collide with real fields').not.toContain(name);
    expect(serialized[name]).toBe('');
    for (const field of realFields) {
      expect(serialized[field], `${field} must be present in the serialized payload`).toBeDefined();
    }
    expect(serialized.kiwi__token.length).toBeGreaterThan(10);
  });

  test('form-assistance DOM mutations: wrapping the form and adding attributes leave the lifecycle and evidence intact', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await serveFormPage(page, '/challenge?decoy=pool');
    await solve(page);
    const origin = await fixtureOrigin(page);
    // The pattern of a browser extension or password manager wrapping
    // the protected form and decorating it with its own attributes.
    await page.evaluate(() => {
      const form = document.getElementById('f');
      const wrap = document.createElement('div');
      wrap.id = 'ext-wrap';
      wrap.setAttribute('data-ext', 'password-manager');
      form.parentNode.insertBefore(wrap, form);
      wrap.appendChild(form);
      form.setAttribute('autocomplete', 'on');
      form.setAttribute('data-ext-id', 'pm-1');
      form.classList.add('ext-decorated');
    });

    // The lifecycle still works: a reset and re-solve completes with a
    // fresh verified token inside the wrapped form. The honeypot check
    // below consumes that token, so the proof validation and the decoy
    // evidence are asserted on the same single-use record.
    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    const name2P = challengeDecoyName(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();

    // The decoy evidence still fires for the exact authenticated name,
    // and the wrapped form still serializes the decoy next to the token.
    const name = await name2P;
    await simulateAutofill(page, `input[name="${name}"]`, 'bot@example.com');
    const hit = await honeypotCheck(page, origin, {
      kiwi__token: token,
      [name]: 'bot@example.com',
    });
    expect(hit.body.ok, 'the wrapped form proof must still validate').toBe(true);
    expect(hit.body.honeypot_hit).toBe(true);
    const serialized = await serializedForm(page);
    expect(serialized.kiwi__token).toBe(token);
    expect(serialized[name]).toBe('bot@example.com');
    const surface = await decoySurface(page, name);
    expect(['off', 'new-password'], 'the decoy keeps its autofill-neutral attribute').toContain(surface.autocomplete);
  });

  test('a FORCED same-name collision: the app field survives cleanup, the server answer stays deterministic', async ({ page }) => {
    // The 64-bit suffix makes an accidental collision cryptographically
    // impossible; this test forces one on purpose with the fixture's
    // name-pinning knob (?decoy=pool&decoyname=... pins the authenticated
    // armed name). A real application field carries the same name as the
    // Kiwi decoy, with a legitimate value.
    const PINNED = 'billing_address_line_a3f9c21d8e5b7401';
    const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
    const driver = fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
  const risk = fs.readFileSync(assetPath('widget-risk.js'), 'utf8');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<form id="f" action="/form-submit" method="post">
  <label>App field <input type="text" id="app-field" name="${PINNED}" value="legit app value" /></label>
  <div class="kiwi-container" id="kiwicaptcha-root" data-kiwi-endpoint="/challenge?decoy=pool&decoyname=${PINNED}" data-kiwi-scope="login">
    <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
${WIDGET_MARKUP}
  </div>
</form>
<script>${glue}</script><script>${driver}</script><script>${risk}</script></body></html>`;
    await page.route('**/collision-form', (route) =>
      route.fulfill({ contentType: 'text/html', body: html })
    );
    await page.goto('/collision-form');
    await solve(page);
    const origin = await fixtureOrigin(page);

    // The Kiwi decoy renders its OWN node next to the same-named app
    // field: exactly one owned node, and the app field keeps its value.
    const state = await page.evaluate((n) => {
      // The accessibility union selects exactly the Kiwi decoy: the app
      // field is a visible labelled control, never aria-hidden.
      const owned = document.querySelectorAll('#f input[aria-hidden="true"][tabindex="-1"]');
      const app = document.querySelector(`#app-field`);
      const decoyInput = document.querySelector(`#f input[aria-hidden="true"][tabindex="-1"]`);
      return {
        ownedCount: owned.length,
        totalSameName: document.querySelectorAll(`input[name="${n}"]`).length,
        appValue: app ? app.value : null,
        decoyName: decoyInput ? decoyInput.name : null,
      };
    }, PINNED);
    expect(state.ownedCount).toBe(1);
    expect(state.decoyName).toBe(PINNED);
    expect(state.totalSameName, 'the app field and the Kiwi decoy coexist under one name').toBe(2);
    expect(state.appValue, 'the application value must survive the decoy render').toBe('legit app value');

    // The application's legitimate value is never destroyed by Kiwi
    // cleanup: a reset removes only the owned decoy node — the same-named
    // app field stays in the form with its value.
    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    const afterReset = await page.evaluate(({ id, n }) => {
      // The reset removes the owned decoy synchronously (the private
      // owned set, before the fresh initWidget starts its async
      // re-acquisition). The fixture pins
      // the decoy name, so the re-issued challenge re-renders a
      // same-named input asynchronously; asserting inside this same
      // evaluate observes the guaranteed-absent moment, never the
      // re-render race.
      window.KiwiCaptcha.reset(id);
      const owned = document.querySelectorAll('#f input[aria-hidden="true"][tabindex="-1"]');
      const app = document.querySelector('#app-field');
      return {
        ownedCount: owned.length,
        sameNameCount: document.querySelectorAll(`input[name="${n}"]`).length,
        appValue: app ? app.value : null,
        appPresent: !!app,
      };
    }, { id: wid, n: PINNED });
    expect(afterReset.ownedCount, 'the reset removes only the owned decoy node').toBe(0);
    expect(afterReset.sameNameCount, 'the app field is the only same-named field after the reset').toBe(1);
    expect(afterReset.appPresent).toBe(true);
    expect(afterReset.appValue, 'the reset must never destroy the app field value').toBe('legit app value');

    // Server side: the forced collision reads as the parsed single value
    // (an order-dependent duplicate-form-key request parses to one
    // value) — the answer is deterministic, never a 500. With the app
    // value present, the parsed value is non-empty: the forced-collision
    // semantics read it as a hit, and the proof stays valid.
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await honeypotCheck(page, origin, {
      kiwi__token: token,
      [PINNED]: 'legit app value',
    });
    expect(result.body.ok, 'a forced collision must never break the proof verdict').toBe(true);
    expect(typeof result.body.honeypot_hit).toBe('boolean');
    expect(result.body.decoy_field).toBe(PINNED);
    // The raw duplicate-key wire body (the app value then the empty
    // decoy) parses last-wins deterministically under PHP semantics:
    // the empty decoy value is the parsed one — no hit, never a 500.
    const token2P = challengeDecoyName(page);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await solve(page);
    await token2P;
    const token2 = await page.locator('[data-kiwi-token]').inputValue();
    const wire = `kiwi__token=${encodeURIComponent(token2)}&${encodeURIComponent(PINNED)}=legit%20app%20value&${encodeURIComponent(PINNED)}=`;
    const rawResp = await page.request.post(`${origin}/honeypot-check`, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      data: wire,
    });
    expect(rawResp.status(), 'the duplicate-key wire body must answer deterministically, never a 500').toBe(200);
    const rawBody = await rawResp.json();
    expect(rawBody.ok).toBe(true);
    expect(rawBody.honeypot_hit).toBe(false);
  });

  test('an array-shaped parameter under the decoy name is deterministic, never a 500', async ({ page }) => {
    // billing_address_line[]=x under the exact authenticated decoy name:
    // an array-shaped parameter is not a scalar decoy value, so the
    // deterministic answer is no hit — the mirror of the bundle
    // validator's array-safe formDecoyEvidence.
    const PINNED = 'billing_address_line_a3f9c21d8e5b7401';
    await page.goto(`/?decoy=pool&decoyname=${PINNED}`);
    await solve(page);
    const origin = await fixtureOrigin(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const wire = `kiwi__token=${encodeURIComponent(token)}&${encodeURIComponent(PINNED)}[]=x`;
    const resp = await page.request.post(`${origin}/honeypot-check`, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      data: wire,
    });
    expect(resp.status(), 'an array-shaped decoy parameter must never 500').toBe(200);
    const body = await resp.json();
    expect(body.ok, 'the proof stays valid under an array-shaped decoy parameter').toBe(true);
    expect(body.honeypot_hit, 'an array-shaped parameter is no scalar decoy value').toBe(false);
    expect(body.decoy_field).toBe(PINNED);
  });
});
