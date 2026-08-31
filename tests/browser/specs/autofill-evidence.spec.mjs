import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Engine form-assistance evidence for the three-engine lane
// (playwright.a11y.config.mjs). The generic autofill surface of
// adversarial-portable.spec.mjs fills values with the native setter plus
// input and change events; this spec simulates the engine-specific fill
// paths beyond that generic shape and pins the same contract for each:
// the decoy never receives an autofilled value unless a test fills it
// deliberately, real fields never trip the decoy evidence, evidence
// stays additive (the proof verdict is never replaced by a ban) and the
// proof verifies.
//
// The simulations model documented browser behavior with portable DOM
// events, no engine-specific APIs:
// - Firefox-style built-in autofill heuristics: a candidate scan over
//   autocomplete tokens, names and label text, then per-field
//   focus / value / input / blur sequences.
// - WebKit-style form assistant: input composition events
//   (compositionstart / update / end) plus a value commit that lands
//   after blur.
// - Chromium-style autofill previews: values written with the native
//   setter and no events at all, then committed at submit.
// - The offscreen variant (autocomplete=new-password) is the highest
//   sensitivity surface: a visible-layout heuristic can consider it, so
//   every fill simulation runs against it and asserts it stays empty.
// - Accessibility tooling: an AT walks the accessibility tree, so the
//   aria-hidden decoy must be absent from the browser's own tree; the
//   locator aria snapshot is the portable window into that tree on all
//   three engines.
//
// The fixture knobs match the other portable specs: ?decoy=pool arms
// the real authenticated issuance and ?strategy=N (0-5) forces the
// rendering variant the driver honors when present. Evidence semantics
// use the fixture's /honeypot-check mirror: a non-empty value under the
// exact authenticated decoy name reports a hit, the proof outcome
// decides and the hit rides alongside it.

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

const WIDGET_MARKUP = `
    <div class="kiwi-widget" data-kiwi-widget data-state="idle">
      <div class="kiwi-icon-wrapper"><svg></svg><div class="kiwi-glow"></div></div>
      <div class="kiwi-main">
        <div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>
        <div class="kiwi-track" aria-hidden="true"><div class="kiwi-bar" data-kiwi-bar></div></div>
        <div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected</p><span class="kiwi-timer" data-kiwi-timer></span></div>
      </div>
    </div>`;

async function fixtureOrigin(page) {
  return page.evaluate(() => window.location.origin);
}

async function solve(page, timeout = 60_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

function challengeDecoyName(page) {
  return page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'))
    .then((resp) => resp.json())
    .then((data) => data.decoy_field ?? null);
}

async function honeypotCheck(page, origin, form) {
  const resp = await page.request.post(`${origin}/honeypot-check`, { form });
  return { status: resp.status(), body: await resp.json() };
}

// The generic fill path: the native value setter plus bubbled input and
// change events, the shape every engine fill converges to.
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

// A protected form page with real fields that carry autocomplete
// semantics, the widget container and the token input inside one form.
// The endpoint carries the decoy and strategy knobs so every engine
// scenario runs against a deterministic rendering variant.
async function serveFormPage(page, endpoint) {
  const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
  const driver = fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<form id="f" action="/form-submit" method="post">
  <div class="kiwi-container" id="kiwicaptcha-root"
    data-kiwi-endpoint="${endpoint}" data-kiwi-scope="login">
    <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
${WIDGET_MARKUP}
  </div>
  <label>Email <input type="email" name="email" autocomplete="email" /></label>
  <label>Username <input type="text" name="username" autocomplete="username" /></label>
  <label>Password <input type="password" name="password" autocomplete="current-password" /></label>
</form>
<script>${glue}</script><script>${driver}</script></body></html>`;
  await page.route('**/autofill-form', (route) =>
    route.fulfill({ contentType: 'text/html', body: html })
  );
  await page.goto('/autofill-form');
}

async function serializedForm(page) {
  return page.evaluate(() => {
    const fd = new FormData(document.getElementById('f'));
    const out = {};
    for (const [k, v] of fd.entries()) out[k] = v;
    return out;
  });
}

// The realistic candidate scan a form-fill heuristic runs before it
// fills: fields match by autocomplete token, exact name or label text
// against a login profile key set. A decoy is a candidate only when a
// heuristic would select it as a real field.
async function candidateScan(page, decoyName) {
  return page.evaluate((n) => {
    const keys = ['email', 'username', 'current-password', 'name', 'given-name', 'family-name', 'street-address', 'postal-code', 'tel', 'organization'];
    const norm = (s) => (s || '').trim().toLowerCase();
    const fields = Array.from(document.querySelectorAll('form input'));
    return {
      candidates: fields
        .filter((el) => {
          if (el.name === 'kiwi__token' || el.name === 'kiwi_request_binding') return false;
          if (el.getAttribute('autocomplete') === 'off') return false;
          const token = norm(el.getAttribute('autocomplete'));
          const name = norm(el.name);
          const label = norm(el.getAttribute('aria-label'));
          const labelText = norm((el.closest('label') || {}).textContent);
          return keys.some((k) => token === k || name === k || label === k || labelText === k);
        })
        .map((el) => el.name),
      decoySelected: fields.some((el) => el.name === n && keys.some((k) => k === norm(el.getAttribute('autocomplete')) || k === norm(el.name) || k === norm(el.getAttribute('aria-label')) || k === norm((el.closest('label') || {}).textContent))),
    };
  }, decoyName);
}

// Firefox-style heuristic fill: the engine matches fields up front, then
// focuses each target, writes the value (input events fire), and the
// change event lands on blur.
async function firefoxHeuristicFill(page) {
  return page.evaluate(() => {
    const values = { email: 'user@example.com', username: 'user', password: 's3cret' };
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    for (const [name, value] of Object.entries(values)) {
      const el = document.querySelector(`input[name="${name}"]`);
      el.focus();
      setter.call(el, value);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.blur();
    }
  });
}

// WebKit-style form assistant: the fill composes into the field (input
// composition events) and the final value commits only after blur, as
// the assistant applies the selection asynchronously.
async function webkitAssistantFill(page) {
  return page.evaluate(() => new Promise((resolve) => {
    const values = { email: 'user@example.com', username: 'user', password: 's3cret' };
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    const names = Object.keys(values);
    const compose = (i) => {
      if (i >= names.length) {
        resolve(true);
        return;
      }
      const el = document.querySelector(`input[name="${names[i]}"]`);
      el.focus();
      el.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true, data: '' }));
      setter.call(el, values[names[i]].slice(0, 2));
      el.dispatchEvent(new CompositionEvent('compositionupdate', { bubbles: true, data: values[names[i]].slice(0, 2) }));
      el.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true, data: values[names[i]] }));
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.blur();
      // The assistant commits the composed value after blur: the second
      // write is the commit a plain key sequence would produce.
      setTimeout(() => {
        setter.call(el, values[names[i]]);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        compose(i + 1);
      }, 25);
    };
    compose(0);
  }));
}

// Chromium-style autofill preview: values land in the DOM with the
// native setter and no events at all, then a single commit fires the
// input and change events right before submission.
async function chromiumPreviewFill(page) {
  return page.evaluate(() => {
    const values = { email: 'user@example.com', username: 'user', password: 's3cret' };
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    for (const [name, value] of Object.entries(values)) {
      setter.call(document.querySelector(`input[name="${name}"]`), value);
    }
    return true;
  });
}

async function commitAtSubmit(page) {
  return page.evaluate(() => {
    for (const name of ['email', 'username', 'password']) {
      const el = document.querySelector(`input[name="${name}"]`);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
    document.getElementById('f').submit();
  });
}

// The two-phase evidence pattern: a solve whose engine fill leaves the
// decoy empty and the real fields clean of any hit, then a fresh solve
// whose deliberate exact-name fill reports the hit additively with the
// proof still valid.
async function additiveEvidence(page, origin, name, decoyValue) {
  const token = await page.locator('[data-kiwi-token]').inputValue();
  const result = await honeypotCheck(page, origin, {
    kiwi__token: token,
    [name]: decoyValue,
  });
  expect(result.body.ok, 'the proof verdict stays valid alongside the evidence').toBe(true);
  expect(result.body.honeypot_hit, 'the exact authenticated name is the evidence trigger').toBe(true);
  expect(result.body.decoy_field).toBe(name);
}

async function resetForFreshSolve(page) {
  const name2P = challengeDecoyName(page);
  const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
  await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
  await solve(page);
  return name2P;
}

test.describe('KiwiCaptcha engine form-assistance evidence', () => {
  test('firefox-style heuristic autofill: the candidate scan and the focus blur fills stay off the decoy', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    // The offscreen variant is the sensitivity case: it is the only
    // strategy a visible-layout heuristic can even consider.
    await serveFormPage(page, '/challenge?decoy=pool&strategy=3');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name = await nameP;

    const scan = await candidateScan(page, name);
    expect(scan.candidates, 'the heuristic must select the real fields').toEqual(['email', 'username', 'password']);
    expect(scan.decoySelected, 'the offscreen decoy is never a heuristic candidate').toBe(false);

    await firefoxHeuristicFill(page);
    expect(await page.locator(`input[name="${name}"]`).inputValue(), 'the decoy never receives an autofilled value').toBe('');
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const clean = await honeypotCheck(page, origin, {
      kiwi__token: token,
      email: 'user@example.com',
      username: 'user',
      password: 's3cret',
    });
    expect(clean.body.ok, 'the proof verifies').toBe(true);
    expect(clean.body.honeypot_hit, 'real fields never trip the decoy evidence').toBe(false);

    const name2 = await resetForFreshSolve(page);
    await simulateAutofill(page, `input[name="${name2}"]`, 'bot@example.com');
    await additiveEvidence(page, origin, name2, 'bot@example.com');
  });

  test('webkit-style form assistant: composition events and the delayed post-blur commit never reach the decoy', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await serveFormPage(page, '/challenge?decoy=pool&strategy=3');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name = await nameP;

    await webkitAssistantFill(page);
    expect(await page.locator(`input[name="${name}"]`).inputValue(), 'the composition sequence must leave the decoy empty').toBe('');
    const serialized = await serializedForm(page);
    expect(serialized.email).toBe('user@example.com');
    expect(serialized.username).toBe('user');
    expect(serialized.password).toBe('s3cret');
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const clean = await honeypotCheck(page, origin, {
      kiwi__token: token,
      email: 'user@example.com',
      username: 'user',
      password: 's3cret',
    });
    expect(clean.body.ok, 'the proof verifies').toBe(true);
    expect(clean.body.honeypot_hit, 'real fields never trip the decoy evidence').toBe(false);

    const name2 = await resetForFreshSolve(page);
    await simulateAutofill(page, `input[name="${name2}"]`, 'bot@example.com');
    await additiveEvidence(page, origin, name2, 'bot@example.com');
  });

  test('chromium-style autofill preview: silent value writes committed at submit leave the decoy empty', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await serveFormPage(page, '/challenge?decoy=pool&strategy=3');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name = await nameP;

    await chromiumPreviewFill(page);
    expect(await page.locator(`input[name="${name}"]`).inputValue(), 'the preview must not touch the decoy').toBe('');
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const clean = await honeypotCheck(page, origin, {
      kiwi__token: token,
      email: 'user@example.com',
      username: 'user',
      password: 's3cret',
    });
    expect(clean.body.ok, 'the proof verifies').toBe(true);
    expect(clean.body.honeypot_hit, 'real fields never trip the decoy evidence').toBe(false);

    const name2 = await resetForFreshSolve(page);
    await simulateAutofill(page, `input[name="${name2}"]`, 'bot@example.com');
    await additiveEvidence(page, origin, name2, 'bot@example.com');

    // The submit path is the last phase: a fresh solve carries the
    // committed values on the wire while the decoy name travels with an
    // empty value, and the submit navigates the page away.
    const name3P = resetForFreshSolve(page);
    const name3 = await name3P;
    await chromiumPreviewFill(page);
    const submitRequest = page.waitForRequest('**/form-submit');
    await commitAtSubmit(page);
    const req = await submitRequest;
    const params = new URLSearchParams(req.postData() || '');
    expect(params.get('email')).toBe('user@example.com');
    expect(params.get('username')).toBe('user');
    expect(params.get('password')).toBe('s3cret');
    expect(params.get(name3), 'the decoy rides the payload only as its own empty name').toBe('');
  });

  test('offscreen decoy under every engine fill simulation: never a candidate, never autofilled', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await serveFormPage(page, '/challenge?decoy=pool&strategy=3');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name = await nameP;

    const surface = await page.evaluate((n) => {
      const el = document.querySelector(`input[name="${n}"]`);
      const cs = getComputedStyle(el);
      return {
        autocomplete: el.getAttribute('autocomplete'),
        position: cs.position,
        left: cs.left,
        tabindex: el.getAttribute('tabindex'),
        ariaHidden: el.getAttribute('aria-hidden'),
      };
    }, name);
    expect(surface.autocomplete, 'the offscreen variant carries the password-hint token').toBe('new-password');
    expect(surface.position).toBe('absolute');
    expect(surface.left).toBe('-9999px');
    expect(surface.tabindex).toBe('-1');
    expect(surface.ariaHidden).toBe('true');

    const scan = await candidateScan(page, name);
    expect(scan.decoySelected).toBe(false);

    // The three engine fill paths in sequence, each leaving the decoy
    // empty: the hint token never turns the offscreen field into a
    // fill target for the real fields.
    await firefoxHeuristicFill(page);
    expect(await page.locator(`input[name="${name}"]`).inputValue()).toBe('');
    await page.evaluate(() => {
      for (const n of ['email', 'username', 'password']) {
        document.querySelector(`input[name="${n}"]`).value = '';
      }
    });
    await webkitAssistantFill(page);
    expect(await page.locator(`input[name="${name}"]`).inputValue()).toBe('');
    await page.evaluate(() => {
      for (const n of ['email', 'username', 'password']) {
        document.querySelector(`input[name="${n}"]`).value = '';
      }
    });
    await chromiumPreviewFill(page);
    expect(await page.locator(`input[name="${name}"]`).inputValue()).toBe('');

    const serialized = await serializedForm(page);
    expect(serialized[name], 'FormData carries the decoy only as its own empty key').toBe('');
    expect(['email', 'username', 'password', 'kiwi__token'], 'the decoy never collides with a real field name').not.toContain(name);

    const token = await page.locator('[data-kiwi-token]').inputValue();
    const clean = await honeypotCheck(page, origin, {
      kiwi__token: token,
      email: 'user@example.com',
      username: 'user',
      password: 's3cret',
    });
    expect(clean.body.ok, 'the proof verifies').toBe(true);
    expect(clean.body.honeypot_hit).toBe(false);

    const name2 = await resetForFreshSolve(page);
    await simulateAutofill(page, `input[name="${name2}"]`, 'bot@example.com');
    await additiveEvidence(page, origin, name2, 'bot@example.com');
  });

  test('deferred strategy: the post-solve decoy stays off the candidate surface under engine fills', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await serveFormPage(page, '/challenge?decoy=pool&strategy=5');
    await solve(page);
    const origin = await fixtureOrigin(page);
    const name = await nameP;
    await expect(page.locator(`input[name="${name}"]`)).toHaveCount(1);

    // The deferred variant is the hidden bare look (display none,
    // autocomplete off) created only after the first solve completes.
    const surface = await page.evaluate((n) => {
      const el = document.querySelector(`input[name="${n}"]`);
      return {
        autocomplete: el.getAttribute('autocomplete'),
        display: getComputedStyle(el).display,
        ariaHidden: el.getAttribute('aria-hidden'),
      };
    }, name);
    expect(surface.autocomplete, 'the deferred variant stays off the autofill candidate surface').toBe('off');
    expect(surface.display).toBe('none');
    expect(surface.ariaHidden).toBe('true');

    const scan = await candidateScan(page, name);
    expect(scan.decoySelected).toBe(false);

    await firefoxHeuristicFill(page);
    expect(await page.locator(`input[name="${name}"]`).inputValue(), 'the deferred decoy stays empty after engine fills').toBe('');
    await webkitAssistantFill(page);
    expect(await page.locator(`input[name="${name}"]`).inputValue()).toBe('');
    await chromiumPreviewFill(page);
    expect(await page.locator(`input[name="${name}"]`).inputValue()).toBe('');

    await simulateAutofill(page, `input[name="${name}"]`, 'bot@example.com');
    await additiveEvidence(page, origin, name, 'bot@example.com');
  });

  test('accessibility tooling: the aria-hidden decoy is absent from the AT snapshot under every strategy', async ({ page }) => {
    for (let strategy = 0; strategy <= 5; strategy++) {
      const nameP = challengeDecoyName(page);
      await serveFormPage(page, `/challenge?decoy=pool&strategy=${strategy}`);
      await solve(page);
      const name = await nameP;

      const snapshot = await page.locator('form').ariaSnapshot();
      expect(snapshot, `strategy ${strategy}: the AT tree must expose the real fields`).toContain('Email');
      expect(snapshot).toContain('Username');
      expect(snapshot).toContain('Password');
      expect(snapshot, `strategy ${strategy}: the decoy is never exposed to assistive tech`).not.toContain(name);
      expect(snapshot, `strategy ${strategy}: even the offscreen auxiliary label never leaks`).not.toContain('off-screen field');

      const dom = await page.evaluate((n) => {
        const el = document.querySelector(`input[name="${n}"]`);
        return el ? { ariaHidden: el.getAttribute('aria-hidden'), tabindex: el.getAttribute('tabindex') } : null;
      }, name);
      expect(dom).not.toBeNull();
      expect(dom.ariaHidden, `strategy ${strategy}: the decoy stays excluded from assistive tech`).toBe('true');
      expect(dom.tabindex).toBe('-1');
    }
  });
});
