import { test, expect } from '@playwright/test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Adversarial browser and runtime behavior: forged postMessage traffic,
// exposed-global tampering, cross-origin state reads, malformed and
// replayed token submissions, protocol downgrade attempts, decoy
// (honeypot) injection, solver-worker termination, BFCache round-trips
// and mid-flight fetch aborts. Every attack must be ignored, rejected
// or recovered from. The fixture answers with deterministic invalid
// responses, never a server error, and no stale token ever lands in
// the form.
//
// The fixture knobs this spec relies on: ?decoy=pool arms the real
// authenticated decoy issuance (protocol-v3 record with the signed
// decoy name, the mirror of the bundle's risk.decoy_v3_enabled path),
// and POST /honeypot-check mirrors the bundle validator's
// formDecoyEvidence: a non-empty value under the exact authenticated
// decoy name is a honeypot hit, any other name is ignored.

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

// The armed decoy names come from the server-side naming space: a
// grammar prefix (three underscore-joined vocabulary slots) plus the
// 16-lowercase-hex suffix; a name is a grammar member when it matches
// that shape within the [A-Za-z0-9_-]{1,64} bound.
function isGrammarDecoyName(name) {
  return typeof name === 'string' && /^[a-z]+_[a-z]+_[a-z]+_[0-9a-f]{16}$/.test(name) && name.length <= 64;
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
// challenge target. The server re-derives the hash from its own record,
// so a token carrying such a counter is rejected deterministically,
// never by luck of the hash.
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

// A widget page served from the test origin (127.0.0.1:8085) so
// window.location.origin resolves for the same-origin endpoint check.
async function serveWidgetPage(page, attrs) {
  const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
  const driver = fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
  const attrStr = Object.entries(attrs)
    .map(([k, v]) => ` ${k}="${v}"`)
    .join('');
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<div class="kiwi-container" id="kiwicaptcha-root"${attrStr}>
  <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
  <div class="kiwi-widget" data-kiwi-widget data-state="idle" role="status" aria-live="polite">
    <div class="kiwi-icon-wrapper"><svg></svg><div class="kiwi-glow"></div></div>
    <div class="kiwi-main">
      <div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>
      <div class="kiwi-track"><div class="kiwi-bar" data-kiwi-bar></div></div>
      <div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected</p><span class="kiwi-timer" data-kiwi-timer></span></div>
    </div>
  </div>
</div>
<script>${glue}</script><script>${driver}</script></body></html>`;
  await page.route('**/widget-test', (route) =>
    route.fulfill({ contentType: 'text/html', body: html })
  );
  await page.goto('/widget-test');
}

async function solve(page, timeout = 120_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

async function verifyToken(page, token) {
  const resp = await page.request.post('http://127.0.0.1:8085/verify', {
    data: { token },
  });
  return { status: resp.status(), body: await resp.json() };
}

// Capture every worker the driver constructs, so the spec can inject
// forged traffic into the live solver channel and terminate the worker
// mid-solve (a navigator-level kill the driver cannot intercept).
async function captureWorkers(page) {
  await page.addInitScript(() => {
    window.__kiwiWorkers = [];
    const NativeWorker = window.Worker;
    if (NativeWorker) {
      window.Worker = function (...args) {
        const w = new NativeWorker(...args);
        window.__kiwiWorkers.push(w);
        return w;
      };
      window.Worker.prototype = NativeWorker.prototype;
    }
  });
}

test.describe('KiwiCaptcha adversarial client-side protocol', () => {
  test('forged postMessage payloads to the window channel are ignored: no crash, no token, real solve intact', async ({ page }) => {
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    await page.route('**/challenge', async (route) => {
      await gate;
      await route.continue();
    });
    await page.goto('/?algorithm=argon2id');
    await page.waitForFunction(
      () => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'connecting',
      null,
      { timeout: 30_000 }
    );
    await page.evaluate(() => {
      const proto = window.KiwiCaptcha.protocolId;
      const big = 'x'.repeat(4 * 1024 * 1024);
      window.postMessage('garbage-string', '*');
      window.postMessage(null, '*');
      window.postMessage(4242, '*');
      window.postMessage({ v: 1, type: 'done', counter: 0, buildId: proto }, '*');
      window.postMessage({ type: 'kiwi-solution', nonce: 'forged', token: 'forged-token' }, '*');
      window.postMessage(big, '*');
      window.dispatchEvent(new MessageEvent('message', { data: { v: 1, type: 'done', counter: 0, buildId: proto } }));
    });
    await expect.poll(() => page.evaluate(() => 2 + 2)).toBe(4);
    const tokenInput = page.locator('[data-kiwi-token]');
    expect(await tokenInput.inputValue(), 'a forged message must not mint a token').toBe('');
    release();
    await solve(page);
    const token = await tokenInput.inputValue();
    expect(token.length).toBeGreaterThan(0);
    const result = await verifyToken(page, token);
    expect(result.body.ok, 'the real solve must still verify after the forged traffic').toBe(true);
  });

  test('forged messages into the live solver worker are schema-rejected and cannot mint a token', async ({ page }) => {
    await captureWorkers(page);
    await page.goto('/?algorithm=argon2id');
    await page.waitForFunction(
      () => window.__kiwiWorkers.length >= 1 && document.querySelector('[data-kiwi-token]').value === '',
      null,
      { timeout: 30_000 }
    );
    await page.evaluate(() => {
      const proto = window.KiwiCaptcha.protocolId;
      const worker = window.__kiwiWorkers[0];
      const big = 'x'.repeat(4 * 1024 * 1024);
      const post = (msg) => {
        try {
          worker.postMessage(msg);
        } catch (e) {}
      };
      post('not-an-object');
      post({ v: 2, type: 'solve', algorithm: 'sha256', prefix: 'p', prefixLen: 1, salt: 's', saltLen: 1, targetBits: 0, mKib: 0, t: 1, p: 1, startCounter: 0, maxHashes: 100 });
      post({ v: 1, type: 'done', counter: 0, buildId: proto });
      post({ v: 1, type: 'solve', prefix: 'p' });
      post({ v: 1, type: 'kiwi:forged', payload: {} });
      post(big);
    });
    const tokenInput = page.locator('[data-kiwi-token]');
    // One atomic read: the genuine solve can land between two separate
    // round trips (state read then token read), which would turn the
    // forged-done check into a false positive on a fast machine.
    const snap = await page.evaluate(() => ({
      state: document.querySelector('[data-kiwi-widget]').getAttribute('data-state'),
      token: document.querySelector('[data-kiwi-token]').value,
    }));
    if (snap.state !== 'done') {
      expect(snap.token, 'a forged done must not resolve the solve').toBe('');
    }
    await solve(page);
    const token = await tokenInput.inputValue();
    const result = await verifyToken(page, token);
    expect(result.body.ok, 'the worker solve must survive the forged inbound traffic').toBe(true);
  });

  test('out-of-order and late forged messages cannot replace a solved token', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const tokenInput = page.locator('[data-kiwi-token]');
    const token = await tokenInput.inputValue();
    const before = await page.evaluate(() => {
      const proto = window.KiwiCaptcha.protocolId;
      window.postMessage({ v: 1, type: 'done', counter: 0, buildId: proto }, '*');
      window.postMessage({ v: 1, type: 'ready', buildId: proto }, '*');
      window.postMessage({ type: 'kiwi:verified', detail: { token: 'forged-token' } }, '*');
      window.dispatchEvent(new MessageEvent('message', { data: { type: 'done', counter: 0, buildId: proto } }));
      const id = document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance;
      return window.KiwiCaptcha.getResponse(id);
    });
    expect(before, 'the solved credential must stay the real one').toBe(token);
    expect(await tokenInput.inputValue()).toBe(token);
    const result = await verifyToken(page, token);
    expect(result.body.ok).toBe(true);
  });

  test('tampering with the exposed KiwiCaptcha globals cannot downgrade the issued algorithm', async ({ page }) => {
    const bodies = [];
    await page.route('**/challenge', async (route) => {
      bodies.push(route.request().postDataJSON() ?? {});
      await route.continue();
    });
    // A preseeded fake global is overwritten by the driver, never used.
    await page.addInitScript(() => {
      window.KiwiCaptcha = { fake: true, protocolId: 'forged-preseed' };
    });
    await page.goto('/?algorithm=argon2id');
    await solve(page);
    expect(await page.evaluate(() => typeof window.KiwiCaptcha.render), 'the driver must install the real API over the preseeded fake').toBe('function');
    const widgetId = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    // Every informational mirror is tampered; the closure constants
    // and the DOM attribute govern the real flow.
    await page.evaluate(() => {
      const K = window.KiwiCaptcha;
      K.protocolId = 'forged';
      K.buildId = 'forged';
      K.workerSource = 'forged';
    });
    await page.evaluate((wid) => window.KiwiCaptcha.reset(wid), widgetId);
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, token);
    expect(result.body.ok, 'the tampered globals must not break the solve').toBe(true);
    for (const body of bodies) {
      expect(body.algorithm, 'every request must still ask for argon2id').toBe('argon2id');
    }
    expect(await page.evaluate(() => window.KiwiCaptcha.protocolId), 'the mirror stays tampered, the behavior must not').toBe('forged');
  });

  test('a cross-origin frame cannot read the widget state or its token', async ({ page }) => {
    await page.addInitScript(() => {
      window.__kiwiFrameProbe = null;
      window.addEventListener('message', (ev) => {
        if (ev.data && typeof ev.data.kiwiFrameProbe === 'string') {
          window.__kiwiFrameProbe = ev.data.kiwiFrameProbe;
        }
      });
    });
    const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
    const driver = fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
    await page.route('https://evil.test/frame.html', (route) =>
      route.fulfill({
        contentType: 'text/html',
        body: `<!DOCTYPE html><html><body><script>
let r = '';
try { parent.document.querySelector('[data-kiwi-token]'); r = 'dom-ok'; }
catch (e) { r = 'dom-' + e.name; }
try { const k = parent.KiwiCaptcha; r += '|api-' + (k ? typeof k : 'missing'); }
catch (e) { r += '|api-' + e.name; }
parent.postMessage({ kiwiFrameProbe: r }, '*');
<\/script></body></html>`,
      })
    );
    await page.route('**/frame-page', (route) =>
      route.fulfill({
        contentType: 'text/html',
        body: `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<iframe id="evil" src="https://evil.test/frame.html"></iframe>
<div class="kiwi-container" id="kiwicaptcha-root" data-kiwi-endpoint="/challenge" data-kiwi-scope="login">
  <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
  <div class="kiwi-widget" data-kiwi-widget data-state="idle" role="status" aria-live="polite">
    <div class="kiwi-icon-wrapper"><svg></svg><div class="kiwi-glow"></div></div>
    <div class="kiwi-main">
      <div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>
      <div class="kiwi-track"><div class="kiwi-bar" data-kiwi-bar></div></div>
      <div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected</p><span class="kiwi-timer" data-kiwi-timer></span></div>
    </div>
  </div>
</div>
<script>${glue}</script><script>${driver}</script></body></html>`,
      })
    );
    await page.goto('/frame-page');
    await solve(page);
    await page.waitForFunction(() => window.__kiwiFrameProbe !== null, null, { timeout: 30_000 });
    const probe = await page.evaluate(() => window.__kiwiFrameProbe);
    expect(probe, 'the cross-origin frame must be blocked from both the DOM and the API').toContain('dom-SecurityError');
    expect(probe).toContain('api-SecurityError');
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, token);
    expect(result.body.ok, 'the widget must solve normally next to the hostile frame').toBe(true);
  });
});

test.describe('KiwiCaptcha adversarial submission validation', () => {
  test('malformed token submissions are invalid with deterministic responses, never a server error', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const variants = [
      ['non-base64 characters', '!!!not-base64!!!'],
      ['valid base64 of random bytes', 'aGVsbG8='],
      ['truncated real token', token.slice(0, -5)],
      ['real token with trailing junk', token + '!'],
    ];
    for (const [label, t] of variants) {
      const result = await verifyToken(page, t);
      expect(result.status, `${label}: the fixture must answer 200, never 500`).toBe(200);
      expect(result.body.ok, `${label}: must not verify`).toBe(false);
      // The truncated token decodes to a pending nonce with the tail
      // missing, so the verifier answers malformed_token; the others
      // fail the nonce extraction before any record lookup.
      const expected = label === 'truncated real token' ? 'malformed_token' : 'record_not_found';
      expect(result.body.code, label).toBe(expected);
    }
  });

  test('token structure mutations are rejected (the downgrade surface carries no version)', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const mutations = await page.evaluate((tok) => {
      const plain = atob(tok);
      const dot1 = plain.indexOf('.');
      const dot2 = plain.indexOf('.', dot1 + 1);
      const dot3 = plain.indexOf('.', dot2 + 1);
      const nonce = plain.slice(0, dot1);
      const counter = plain.slice(dot1 + 1, dot2);
      const duration = plain.slice(dot2 + 1, dot3);
      const telemetry = plain.slice(dot3 + 1);
      const build = (parts) => btoa(parts.join('.'));
      return {
        missingTelemetry: build([nonce, counter, duration]),
        extraSegment: build([nonce, counter, duration, telemetry, 'extra']),
        arrayTelemetry: build([nonce, counter, duration, '[1,2,3]']),
        scalarTelemetry: build([nonce, counter, duration, '"str"']),
        reordered: build([counter, nonce, duration, telemetry]),
        shortNonce: build([nonce.slice(0, 40), counter, duration, telemetry]),
      };
    }, token);
    for (const [label, t] of Object.entries(mutations)) {
      const result = await verifyToken(page, t);
      expect(result.status, `${label}: never a 500`).toBe(200);
      expect(result.body.ok, `${label}: must not verify`).toBe(false);
      expect(['malformed_token', 'record_not_found'], `${label}: deterministic invalid code`).toContain(result.body.code);
    }
  });

  test('a nonce from another challenge cannot be redeemed', async ({ page }) => {
    const challenges = [];
    await page.route('**/challenge', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      challenges.push(data);
      await route.fulfill({ response: resp });
    });
    await page.goto('/');
    await solve(page);
    const tokenA = await page.locator('[data-kiwi-token]').inputValue();
    const widgetId = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((wid) => window.KiwiCaptcha.reset(wid), widgetId);
    await solve(page);
    const tokenB = await page.locator('[data-kiwi-token]').inputValue();
    expect(challenges).toHaveLength(2);
    const [challengeA, challengeB] = challenges;
    const partsA = decodeToken(tokenA).split('.');
    const partsB = decodeToken(tokenB).split('.');
    // The proof of work is re-derived from the challenged record, so a
    // foreign counter that fails the record's own target is rejected
    // without any luck of the hash.
    const foreignCounter = failingCounter(challengeB.prefix, challengeB.salt, challengeB.targetBits, Number(partsA[1]));
    const swapped = await page.evaluate(([a, b, counter]) => {
      const plainA = atob(a);
      const plainB = atob(b);
      const [nonceB, , durB, telB] = plainB.split('.');
      const [, , , telA] = plainA.split('.');
      return btoa([nonceB, String(counter), durB, telA].join('.'));
    }, [tokenA, tokenB, foreignCounter]);
    const result = await verifyToken(page, swapped);
    expect(result.status).toBe(200);
    expect(result.body.ok).toBe(false);
    expect(result.body.code, 'the foreign nonce must fail the challenged record proof').toBe('insufficient_work');
  });

  test('a replayed token is rejected after the first successful redemption', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const first = await verifyToken(page, token);
    expect(first.body.ok).toBe(true);
    const second = await verifyToken(page, token);
    expect(second.status).toBe(200);
    expect(second.body.ok).toBe(false);
    expect(second.body.code, 'the consumed record is gone: single-use redemption').toBe('record_not_found');
    const third = await verifyToken(page, token);
    expect(third.body.ok).toBe(false);
    expect(third.body.code).toBe('record_not_found');
  });

  test('counter tampering above the solver maximum or below the target is rejected', async ({ page }) => {
    const challenges = [];
    await page.route('**/challenge', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      challenges.push(data);
      await route.fulfill({ response: resp });
    });
    await page.goto('/');
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const legit = Number(decodeToken(token).split('.')[1]);
    const below = failingCounter(challenges[0].prefix, challenges[0].salt, challenges[0].targetBits, legit - 1);
    const cases = [
      { label: 'counter at the solver maximum', counter: 5000000, code: 'malformed_token' },
      { label: 'counter far above the solver maximum', counter: 999999999, code: 'malformed_token' },
      { label: 'counter below the target', counter: below, code: 'insufficient_work' },
    ];
    for (const c of cases) {
      const t = await page.evaluate(([tok, counter]) => {
        const plain = atob(tok).split('.');
        return btoa([plain[0], String(counter), plain[2], plain[3]].join('.'));
      }, [token, c.counter]);
      const result = await verifyToken(page, t);
      expect(result.status, `${c.label}: never a 500`).toBe(200);
      expect(result.body.ok, `${c.label}: must not verify`).toBe(false);
      expect(result.body.code, c.label).toBe(c.code);
    }
  });

  test('a protocol_version injected into the challenge response cannot downgrade the solve', async ({ page }) => {
    let version = 1;
    await page.route('**/challenge', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      // The challenge response carries no client-selectable protocol
      // field; the record governs. An injected version must change
      // nothing about the solve or the verification.
      data.protocol_version = version;
      if (version === 3) data.decoy_field = 'company_website';
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
    });
    for (const v of [1, 3]) {
      version = v;
      await page.goto('/');
      await solve(page);
      const token = await page.locator('[data-kiwi-token]').inputValue();
      const result = await verifyToken(page, token);
      expect(result.body.ok, `an injected protocol_version ${v} must not change the outcome`).toBe(true);
    }
  });

  test('a filled armed decoy field is detected server-side against the authenticated name', async ({ page }) => {
    const nameP = page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'))
      .then((resp) => resp.json())
      .then((d) => d.decoy_field ?? null);
    await page.goto('/?decoy=pool');
    await solve(page);
    const name = await nameP;
    expect(isGrammarDecoyName(name), 'the armed name must come from the server-side naming space').toBe(true);
    const decoy = page.locator(`input[name="${name}"]`);
    await expect(decoy).toHaveCount(1);
    await decoy.evaluate((el) => {
      el.value = 'bot@example.com';
    });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const resp = await page.request.post('http://127.0.0.1:8085/honeypot-check', { form: {
      kiwi__token: token,
      [name]: 'bot@example.com',
    } });
    const body = await resp.json();
    expect(body, 'the exact armed decoy must be a server-side honeypot hit').toEqual({
      ok: true,
      honeypot_hit: true,
      decoy_field: name,
    });
  });

  test('the wrong decoy name is ignored: no false honeypot hit, the proof stays valid', async ({ page }) => {
    const nameP = page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'))
      .then((resp) => resp.json())
      .then((d) => d.decoy_field ?? null);
    await page.goto('/?decoy=pool');
    await solve(page);
    const name = await nameP;
    const wrong = name === 'company_website' ? 'fax_number' : 'company_website';
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const resp = await page.request.post('http://127.0.0.1:8085/honeypot-check', { form: {
      kiwi__token: token,
      [wrong]: 'bot@example.com',
    } });
    const body = await resp.json();
    expect(body.ok, 'the proof itself must stay valid').toBe(true);
    expect(body.honeypot_hit, 'a mismatched name is not this challenge decoy').toBe(false);
    expect(body.decoy_field).toBe(name);
  });

  test('an injected decoy name the record does not authenticate never produces a hit', async ({ page }) => {
    await page.route('**/challenge', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      data.decoy_field = 'company_website';
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
    });
    await page.goto('/');
    await solve(page);
    const decoy = page.locator('input[name="company_website"]');
    await expect(decoy, 'the injected response renders its decoy input').toHaveCount(1);
    await decoy.evaluate((el) => {
      el.value = 'bot@example.com';
    });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const resp = await page.request.post('http://127.0.0.1:8085/honeypot-check', { form: {
      kiwi__token: token,
      company_website: 'bot@example.com',
    } });
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.honeypot_hit, 'an unauthenticated decoy name is ignored server-side').toBe(false);
    expect(body.decoy_field).toBeNull();
  });
});

test.describe('KiwiCaptcha adversarial runtime lifecycle', () => {
  test('killing the solver worker mid-solve recovers cleanly with no stale token write', async ({ page }) => {
    await captureWorkers(page);
    const nonces = [];
    const cancelBodies = [];
    page.on('response', async (resp) => {
      if (resp.url().includes('/challenge') && !resp.url().includes('/cancel')) {
        const data = await resp.json().catch(() => null);
        if (data && typeof data.nonce === 'string') nonces.push(data.nonce);
      }
    });
    page.on('request', (req) => {
      if (req.method() === 'POST' && req.url().includes('/cancel')) {
        cancelBodies.push(req.postDataJSON() ?? {});
      }
    });
    await page.goto('/?algorithm=argon2id&ttl=3');
    // The worker exists from the moment the challenge response arrives;
    // the 2.5-second solve window of ttl=3 guarantees the kill lands
    // mid-solve, before any token can be written.
    await page.waitForFunction(
      () => window.__kiwiWorkers.length >= 1 && document.querySelector('[data-kiwi-token]').value === '',
      null,
      { timeout: 30_000 }
    );
    // A navigator-level kill: terminate() fires no error event, so the
    // driver can only learn about the death through its own deadline.
    await page.evaluate(() => {
      window.__kiwiWorkers[0].terminate();
    });
    const tokenInput = page.locator('[data-kiwi-token]');
    expect(await tokenInput.inputValue(), 'the dead solve must not write a token').toBe('');
    // The bounded deadline and retry flow settle the widget in the
    // controlled done or failed state; it must never hang.
    await page.waitForFunction(() => {
      const st = document.querySelector('[data-kiwi-widget]').getAttribute('data-state');
      return st === 'done' || st === 'failed';
    }, null, { timeout: 60_000 });
    const state = await page.locator('[data-kiwi-widget]').getAttribute('data-state');
    const finalToken = await tokenInput.inputValue();
    if (state === 'done') {
      expect(finalToken.length).toBeGreaterThan(0);
      const result = await verifyToken(page, finalToken);
      expect(result.body.ok).toBe(true);
      const finalNonce = decodeToken(finalToken).split('.')[0];
      expect(nonces).toContain(finalNonce);
      expect(finalNonce, 'the recovered token must come from a fresh challenge').not.toBe(nonces[0]);
    } else {
      expect(finalToken).toBe('');
    }
    expect(nonces.length).toBeGreaterThanOrEqual(1);
    expect(cancelBodies.length).toBeGreaterThanOrEqual(1);
    expect(cancelBodies[0].nonce, 'the killed challenge is abandoned exactly once, first').toBe(nonces[0]);
  });

  test('a BFCache round-trip during an in-flight solve cancels the generation with no stale token write', async ({ page }) => {
    let calls = 0;
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    await page.route('**/challenge', async (route) => {
      calls++;
      if (calls === 1) {
        await gate;
        try {
          await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"late"}' });
        } catch (e) {}
        return;
      }
      await route.continue();
    });
    await page.goto('/');
    await page.waitForFunction(
      () => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'connecting',
      null,
      { timeout: 30_000 }
    );
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    });
    release();
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'idle');
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    await page.waitForTimeout(1200);
    await expect(page.locator('[data-kiwi-token]'), 'the late response must never write a token').toHaveValue('');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'idle');
    await page.locator('[data-kiwi-retry]').click();
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, token);
    expect(result.body.ok, 'the post-restore solve must verify').toBe(true);
    expect(calls, 'the abort must not spawn a retry storm').toBe(2);
  });

  test('aborting the challenge fetch mid-flight is a controlled error with no stale token', async ({ page }) => {
    let calls = 0;
    const firstNonces = [];
    await page.route('**/challenge', async (route) => {
      calls++;
      if (calls === 1) {
        const resp = await route.fetch();
        const data = await resp.json();
        firstNonces.push(data.nonce);
        await new Promise((r) => setTimeout(r, 1500));
        try {
          await route.fulfill({ response: resp });
        } catch (e) {}
        return;
      }
      await route.continue();
    });
    await page.goto('/');
    await page.waitForFunction(
      () => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'connecting',
      null,
      { timeout: 30_000 }
    );
    const widgetId = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    // The reset aborts the held request; the fresh generation solves a
    // new challenge, so the recovered token must never carry the aborted
    // generation's nonce.
    await page.evaluate((wid) => window.KiwiCaptcha.reset(wid), widgetId);
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, token);
    expect(result.body.ok).toBe(true);
    expect(calls).toBe(2);
    expect(firstNonces).toHaveLength(1);
    expect(decodeToken(token).split('.')[0], 'the token must come from the fresh generation').not.toBe(firstNonces[0]);
  });

  test('the abandonment notification targets the cancel path even when the endpoint carries a query', async ({ page }) => {
    const cancelUrls = [];
    let calls = 0;
    await page.route('**/challenge?*', async (route) => {
      calls++;
      // The abandonment is driven deterministically by the solve
      // deadline: a schema-valid argon2id challenge at the maximum
      // in-contract memory (mKib 65536 = 64 MiB, t 6) with a 1-second
      // TTL expires 500 ms into the solve, so the attempt always
      // abandons instead of solving.
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          nonce: 'exhaust-adv-' + calls,
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
    await page.route('**/challenge/cancel*', async (route) => {
      cancelUrls.push(route.request().url());
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{"cancelled":true}' });
    });
    await serveWidgetPage(page, {
      'data-kiwi-endpoint': '/challenge?ttl=5',
      'data-kiwi-scope': 'login',
    });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', {
      timeout: 90_000,
    });
    expect(calls).toBeGreaterThanOrEqual(3);
    expect(cancelUrls.length, 'the abandonment must reach the cancel route').toBeGreaterThanOrEqual(1);
    for (const url of cancelUrls) {
      expect(new URL(url).pathname, 'the cancel must hit /challenge/cancel, never a swallowed query').toBe('/challenge/cancel');
    }
  });

  test('a reset clears the rendered decoy input: stale honeypot fields never linger in the form', async ({ page }) => {
    const nameP = page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'))
      .then((resp) => resp.json())
      .then((d) => d.decoy_field ?? null);
    await page.goto('/?decoy=1');
    await solve(page);
    const name = await nameP;
    const decoy = page.locator(`input[name="${name}"]`);
    await expect(decoy).toHaveCount(1);
    await decoy.evaluate((el) => {
      el.value = 'bot@example.com';
    });
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    });
    await expect(decoy, 'the reset must remove the rendered decoy input').toHaveCount(0);
    // The response listener must be registered before the click: the
    // retry click reacquires synchronously, and a response that lands
    // between the click dispatch and a later listener attach would be
    // missed (a load-sensitive race on localhost).
    const freshNameP = page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'))
      .then((resp) => resp.json())
      .then((d) => d.decoy_field ?? null);
    await page.locator('[data-kiwi-retry]').click();
    await solve(page);
    const freshName = await freshNameP;
    await expect(page.locator(`input[name="${freshName}"]`), 'exactly one fresh decoy input after the re-solve').toHaveCount(1);
    await expect(page.locator(`input[name="${name}"]`)).toHaveCount(0);
  });
});
