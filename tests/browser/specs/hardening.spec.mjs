import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

// Lifecycle and channel hardening of the widget runtime: worker
// termination on the cancel/reset/destroy paths, the bounded solve
// (the wall-clock deadline when the response carries no ttlSecs), the
// validated response-field alias and the strand-free expiry, execute()
// settlement after destruction, registry hygiene under destroy() and
// re-init, the SRI preflight's digest algorithms, the execution
// interpreter's sender gate, the canonical nonce shape, the compat
// loader's embedded worker glue (no second /api.js request), and the
// worker glue handshake's fail-closed re-handshake.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..', '..');
const ASSETS = path.join(REPO, 'packages', 'kiwicaptcha-wasm', 'assets');

function assetText(name) {
  return fs.readFileSync(path.join(ASSETS, name), 'utf8');
}

function sha256Hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

async function solve(page, timeout = 90_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

async function verifyToken(page, token, scope = 'login') {
  const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token, scope } });
  return { status: resp.status(), body: await resp.json() };
}

// Wrap the Worker constructor and record per-instance terminations, so
// a spec can prove a cancelled generation really terminated the live
// worker (a no-op handle would leave the flag unset).
async function captureTerminations(page) {
  await page.addInitScript(() => {
    window.__kiwiWorkers = [];
    const NativeWorker = window.Worker;
    if (NativeWorker) {
      window.Worker = function (...args) {
        const w = new NativeWorker(...args);
        const nativeTerminate = w.terminate.bind(w);
        w.__kiwiTerminated = false;
        w.terminate = function () {
          w.__kiwiTerminated = true;
          return nativeTerminate();
        };
        window.__kiwiWorkers.push(w);
        return w;
      };
      window.Worker.prototype = NativeWorker.prototype;
    }
  });
}

// A self-served widget page over the canonical assets (the container
// and widget attributes are the spec's to choose).
async function serveWidgetPage(page, url, containerAttrs, widgetAttrs = '') {
  const driver = assetText('widget-driver.js');
  const risk = assetText('widget-risk.js');
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<div class="kiwi-container" id="kiwicaptcha-root"${containerAttrs}>
  <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
  <div class="kiwi-widget" data-kiwi-widget${widgetAttrs} data-state="idle" role="status" aria-live="polite">
    <div class="kiwi-icon-wrapper"><svg></svg><div class="kiwi-glow"></div></div>
    <div class="kiwi-main">
      <div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>
      <div class="kiwi-track"><div class="kiwi-bar" data-kiwi-bar></div></div>
      <div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected</p><span class="kiwi-timer" data-kiwi-timer></span></div>
    </div>
  </div>
</div>
<script>${driver}</script><script>${risk}</script></body></html>`;
  await page.route(url, (route) => route.fulfill({ contentType: 'text/html', body: html }));
}

// The glue-less files-style container attributes (the versioned asset
// URLs and their SRI digests), with the digests rewritable per test.
function filesAttrs(kind) {
  const runtimeHash = sha256Hex(assetText('kiwicaptcha-wasm.js'));
  const workerHash = sha256Hex(assetText('kiwi-worker.js'));
  const runtimeSri = 'sha256-' + createHash('sha256').update(assetText('kiwicaptcha-wasm.js'), 'utf8').digest('base64');
  const workerSri = 'sha256-' + createHash('sha256').update(assetText('kiwi-worker.js'), 'utf8').digest('base64');
  const runtimeIntegrity = kind === 'sha384'
    ? 'sha384-' + createHash('sha384').update(assetText('kiwicaptcha-wasm.js'), 'utf8').digest('base64')
    : (kind === 'none' ? '' : runtimeSri);
  const workerIntegrity = kind === 'sha384'
    ? 'sha384-' + createHash('sha384').update(assetText('kiwi-worker.js'), 'utf8').digest('base64')
    : (kind === 'none' ? '' : workerSri);
  return ' data-kiwi-endpoint="/challenge?algorithm=argon2id&argon_bits=4"'
    + ` data-kiwi-runtime-src="/kiwi-captcha/assets/runtime.${runtimeHash}.js"`
    + (runtimeIntegrity ? ` data-kiwi-runtime-integrity="${runtimeIntegrity}"` : '')
    + ` data-kiwi-worker-src="/kiwi-captcha/assets/worker.${workerHash}.js"`
    + (workerIntegrity ? ` data-kiwi-worker-integrity="${workerIntegrity}"` : '');
}

// The slow Argon profile gives the spec a stable mid-solve window: the
// memory-hard search outlives the kill by seconds.
const SLOW_ARGON = '/?algorithm=argon2id&argon_bits=10&m_kib=65536';

test.describe('worker termination on cancelled generations', () => {
  for (const [label, kill] of [
    ['reset()', (page) => page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      window.KiwiCaptcha.reset(w.dataset.kiwiInstance);
    })],
    ['destroy()', (page) => page.evaluate(() => {
      window.KiwiCaptcha.destroy(document.querySelector('[data-kiwi-widget]'));
    })],
    ['remove()', (page) => page.evaluate(() => {
      window.KiwiCaptcha.remove(document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    })],
  ]) {
    test(`a mid-solve ${label} terminates the live argon worker`, async ({ page }) => {
      await captureTerminations(page);
      await page.goto(SLOW_ARGON);
      await page.waitForFunction(
        () => window.__kiwiWorkers.length >= 1,
        null,
        { timeout: 30_000 }
      );
      await kill(page);
      await page.waitForFunction(
        () => window.__kiwiWorkers[0].__kiwiTerminated === true,
        null,
        { timeout: 10_000 }
      );
      // The killed generation never writes a token — remove() also takes
      // the markup with it, so the read is optional-chained.
      await page.waitForTimeout(300);
      expect(await page.evaluate(() => (document.querySelector('[data-kiwi-token]') || {}).value ?? '')).toBe('');
    });
  }
});

test.describe('bounded solves', () => {
  test('a response without ttlSecs still solves and verifies (the wall-clock ceiling bounds it)', async ({ page }) => {
    const challengeP = page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'));
    await page.goto('/?ttl=none&bits=20');
    const resp = await challengeP;
    const data = await resp.json();
    expect(data.ttlSecs, 'the ttl=none fixture strips ttlSecs from the issuance').toBeUndefined();
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, token);
    expect(result.body.ok, 'the bounded solve must still verify').toBe(true);
  });

  test('the wasm branch enforces the hash cap and every solve carries a deadline (static source assertion)', () => {
    const src = assetText('widget-driver.js');
    // The wasm chunk window is bounded by the remaining hash budget and
    // the cap is re-checked right after the counter advance.
    expect(src).toMatch(/var want = Math\.min\(CHUNK, MAX_SHA_HASHES - counter\);/);
    // Every terminal path (including the cap) funnels through finish(),
    // which releases the WASM buffers and settles exactly once.
    expect(src).toMatch(/counter \+= res === -1 \? want : -res - 1;\s*\n\s*if \(counter >= MAX_SHA_HASHES\) \{ finish\(null\); return; \}/);
    expect(src).toMatch(/function finish\(result\)/);
    // The fallback deadline: a missing ttlSecs arms the wall-clock
    // ceiling, and the ceiling caps any longer estimate.
    expect(src).toMatch(/var KIWI_SOLVE_DEADLINE_CEILING_MS = 120000;/);
    expect(src).toMatch(/: KIWI_SOLVE_DEADLINE_CEILING_MS;/);
    expect(src).toMatch(/if \(solveDeadlineEstimate > KIWI_SOLVE_DEADLINE_CEILING_MS\) solveDeadlineEstimate = KIWI_SOLVE_DEADLINE_CEILING_MS;/);
  });
});

test.describe('response-field alias and expiry', () => {
  test('a selector-bearing response-field-name is rejected: no alias input, a warn, the token field keeps working', async ({ page }) => {
    const warnings = [];
    page.on('console', (msg) => {
      if (msg.type() === 'warning') warnings.push(msg.text());
    });
    // The incumbent container carries a response-field-name containing
    // a quote and a bracket — a value that would break out of a naive
    // selector interpolation.
    await page.route('**/migration/turnstile.html', async (route) => {
      const html = await (await route.fetch()).text();
      await route.fulfill({
        contentType: 'text/html',
        body: html.replace(
          '<div class="cf-turnstile"',
          `<div class="cf-turnstile" data-response-field-name='x"]<img src=x>'`
        ),
      });
    });
    await page.goto('/migration/turnstile.html');
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(10);
    const result = await verifyToken(page, token);
    expect(result.body.ok).toBe(true);
    // No input carries the hostile name and no img was injected.
    const names = await page.evaluate(() => Array.from(document.querySelectorAll('input')).map((i) => i.name));
    expect(names.some((n) => n.includes('"') || n.includes('<') || n.includes(']')), 'no alias input may carry the hostile name').toBe(false);
    expect(await page.locator('img').count()).toBe(0);
    expect(
      warnings.some((w) => w.includes('response-field-name rejected')),
      'the invalid option must be surfaced'
    ).toBe(true);
  });

  test('an expiry whose alias write throws still clears the lifecycle: started flag gone, expired callback fired', async ({ page }) => {
    // The alias input's value setter throws only on the empty-string
    // writes to the provider-named alias (reset/expiry), so the
    // successful token write passes and the expiry write is the
    // failing step.
    await page.addInitScript(() => {
      const desc = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
      Object.defineProperty(window.HTMLInputElement.prototype, 'value', {
        set: function (v) {
          if (v === '' && this.name === 'cf-turnstile-response') throw new Error('alias write failed');
          desc.set.call(this, v);
        },
        get: desc.get,
        configurable: true,
      });
    });
    await page.route('**/migration/turnstile.html', async (route) => {
      const html = await (await route.fetch()).text();
      await route.fulfill({
        contentType: 'text/html',
        body: html.replace(
          '<div class="cf-turnstile"',
          '<div class="cf-turnstile" data-kiwi-endpoint="/kiwi-captcha/challenge?ttl=2"'
        ),
      });
    });
    await page.goto('/migration/turnstile.html');
    await solve(page);
    const widget = page.locator('[data-kiwi-widget]');
    // The 2-second lifetime passes; the expiry must survive its failing
    // alias write.
    await expect(widget).toHaveAttribute('data-state', 'expired', { timeout: 20_000 });
    // The started flag lives on the compat W (the incumbent container).
    expect(
      await page.evaluate(() => document.querySelector('.cf-turnstile').dataset.kiwiStarted === undefined),
      'the started flag must be cleared so Retry can reacquire'
    ).toBe(true);
    await expect(page.locator('#out')).toHaveText('expired-cb', { timeout: 10_000 });
  });
});

test.describe('execute() settlement', () => {
  test('an execute() awaiting a destroyed widget rejects instead of pending forever', async ({ page }) => {
    await serveWidgetPage(page, '**/execute-test', ' data-kiwi-endpoint="/challenge?algorithm=argon2id&argon_bits=10&m_kib=65536"', ' data-execution="execute"');
    await page.goto('/execute-test');
    const outcome = await page.evaluate(async () => {
      const w = document.querySelector('[data-kiwi-widget]');
      const id = w.dataset.kiwiInstance;
      const p = window.KiwiCaptcha.execute(id);
      window.KiwiCaptcha.destroy(w);
      let settled = 'pending';
      await Promise.race([
        p.then(() => { settled = 'fulfilled'; }, (e) => { settled = 'rejected:' + e.message; }),
        new Promise((r) => setTimeout(() => r(), 8000)),
      ]);
      return settled;
    });
    expect(outcome).toMatch(/^rejected:/);
    expect(outcome).toContain('cancelled');
  });

  test('aborted v3 executes leave no holder divs behind', async ({ page }) => {
    let release;
    const gate = new Promise((r) => { release = r; });
    let started = 0;
    await page.route('**/kiwi-captcha/challenge', async (route) => {
      started++;
      await gate;
      try { await route.abort('failed'); } catch (e) { /* already aborted by the cancel */ }
    });
    await page.goto('/migration/recaptcha-v3.html');
    const outcome = await page.evaluate(async () => {
      const tries = [1, 2, 3].map(() => window.grecaptcha.execute('6Lc_v3_sitekey_a', { action: 'checkout' }).catch(() => 'rejected'));
      // Wait for the three in-flight challenges, then destroy the
      // hidden holders' widgets mid-solve.
      await new Promise((r) => setTimeout(r, 1500));
      window.KiwiCaptcha.destroy('.kiwi-container');
      const results = await Promise.all(tries);
      return {
        results,
        holders: document.querySelectorAll('body > div[style="display: none"]').length,
        widgets: window.__kiwiCaptchaCore.core.counts().widgets,
      };
    });
    release();
    expect(started).toBeGreaterThanOrEqual(3);
    expect(outcome.results.every((r) => r === 'rejected'), 'every aborted execute must settle rejected').toBe(true);
    expect(outcome.holders, 'the hidden holders must be removed on both settlement arms').toBe(0);
    expect(outcome.widgets, 'no widget records may survive the destroy').toBe(0);
  });
});

test.describe('registry hygiene', () => {
  test('destroy() removes the widget records; a re-init loop keeps the BFCache hook array bounded', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const outcome = await page.evaluate(() => {
      const core = window.__kiwiCaptchaCore.core;
      const original = document.querySelector('[data-kiwi-widget]');
      const container = original.closest('.kiwi-container');
      const created = [];
      const host = container.parentNode;
      for (let i = 0; i < 3; i++) {
        const clone = container.cloneNode(true);
        const cloneWidget = clone.querySelector('[data-kiwi-widget]');
        delete cloneWidget.dataset.kiwiStarted;
        delete cloneWidget.dataset.kiwiInstance;
        host.appendChild(clone);
        created.push(clone);
        window.KiwiCaptcha.render(cloneWidget);
      }
      const afterRender = core.counts();
      for (const clone of created) window.KiwiCaptcha.destroy(clone.querySelector('[data-kiwi-widget]'));
      const afterDestroy = core.counts();
      // The re-init loop: five resets of the surviving original widget.
      const id = original.dataset.kiwiInstance;
      for (let i = 0; i < 5; i++) window.KiwiCaptcha.reset(id);
      const afterResets = core.counts();
      return { afterRender, afterDestroy, afterResets };
    });
    expect(outcome.afterRender.widgets).toBe(4);
    expect(outcome.afterRender.resetHooks).toBe(4);
    expect(outcome.afterDestroy.widgets, 'destroy() must delete the widget records').toBe(1);
    expect(outcome.afterDestroy.resetHooks).toBe(1);
    expect(outcome.afterResets.resetHooks, 'a re-init loop must not grow the hook array').toBe(1);
    expect(outcome.afterResets.widgets).toBe(1);
  });
});

test.describe('SRI preflight digest algorithms', () => {
  test('a sha384 integrity attribute verifies and the solve completes', async ({ page }) => {
    await serveWidgetPage(page, '**/files-sri384', filesAttrs('sha384'));
    await page.goto('/files-sri384');
    await solve(page);
    expect(await page.evaluate(() => window.__kiwiWorkerUsed === true)).toBe(true);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, token);
    expect(result.body.ok).toBe(true);
  });

  test('asset URLs without integrity attributes keep working and warn exactly once', async ({ page }) => {
    const warnings = [];
    page.on('console', (msg) => {
      if (msg.type() === 'warning') warnings.push(msg.text());
    });
    await serveWidgetPage(page, '**/files-nosri', filesAttrs('none'));
    await page.goto('/files-nosri');
    await solve(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, token);
    expect(result.body.ok, 'the legacy unverified path must keep working').toBe(true);
    const noIntegrity = warnings.filter((w) => w.includes('no integrity digest'));
    expect(noIntegrity.length, 'the unverified state is surfaced exactly once per page').toBe(1);
  });
});

test.describe('execution interpreter sender gate', () => {
  test('a sibling frame posting forged run traffic is ignored while the parent channel works', async ({ page }) => {
    await page.goto('/');
    const outcome = await page.evaluate(async () => {
      const src = document.querySelector('.kiwi-container').getAttribute('data-kiwi-execution-src');
      const received = [];
      window.addEventListener('message', (ev) => {
        if (ev.data && ev.data.protocol === 'kiwi-execution-v1') received.push(ev.data);
      });
      // The interpreter iframe (the same construction the driver uses).
      const interp = document.createElement('iframe');
      interp.setAttribute('sandbox', 'allow-scripts allow-same-origin');
      interp.style.cssText = 'position:absolute;width:0;height:0;border:0;visibility:hidden;';
      interp.srcdoc = '<!doctype html><html><head><meta charset="utf-8"></head><body><script src="' + src + '"><\/script></body></html>';
      document.body.appendChild(interp);
      // A sibling frame that holds the interpreter's window reference.
      const sib = document.createElement('iframe');
      document.body.appendChild(sib);
      await new Promise((r) => { sib.onload = r; setTimeout(r, 2000); });
      // Wait for the interpreter's own ready handshake, so the probes
      // hit a live listener (not a pending script load).
      const readyBy = Date.now() + 5000;
      while (!received.some((m) => m.type === 'kiwi-execution-ready') && Date.now() < readyBy) {
        await new Promise((r) => setTimeout(r, 50));
      }
      sib.contentWindow.__target = interp.contentWindow;
      sib.contentWindow.eval([
        '__target.postMessage({ protocol: "kiwi-execution-v1", type: "kiwi-execution-run",',
        '  id: "forged-sibling-run-0001", program: "AAAAAAAAAAA=", nonce: "n" }, "*");',
      ].join(''));
      // Positive control: the real parent channel answers.
      interp.contentWindow.postMessage({ protocol: 'kiwi-execution-v1', type: 'kiwi-execution-run', id: 'parent-probe-run-0001', program: 'AAAAAAAAAAA=', nonce: 'n' }, window.location.origin);
      await new Promise((r) => setTimeout(r, 1500));
      const idOf = (m) => (m.payload && m.payload.id) || m.id || '';
      return {
        forged: received.filter((m) => idOf(m).indexOf('forged-sibling') !== -1),
        parentAnswered: received.some((m) => m.type === 'kiwi-execution-error' && idOf(m) === 'parent-probe-run-0001'),
      };
    });
    expect(outcome.parentAnswered, 'the parent channel must answer (the listener is live)').toBe(true);
    expect(outcome.forged, 'a sibling frame must never execute a run').toHaveLength(0);
  });
});

test.describe('canonical nonce shape', () => {
  test('a challenge with a non-Latin1 nonce fails validation up front — never a post-solve btoa exception', async ({ page }) => {
    const errors = [];
    page.on('pageerror', (err) => errors.push(String(err)));
    await page.route('**/challenge', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      data.nonce = 'é'.repeat(43) + '=';
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(data) });
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 60_000 });
    expect(await page.locator('[data-kiwi-token]').inputValue()).toBe('');
    // The failure is the validation message, never a btoa
    // InvalidCharacterError from the token write.
    const hint = await page.locator('[data-kiwi-info]').textContent();
    // The visible hint is the translated user-facing text; the raw parser
    // detail ("Challenge malformed") stays console/event-side.
    expect(hint).toContain('unexpected response');
    expect(hint).not.toContain('InvalidCharacterError');
    expect(hint).not.toContain('Latin1');
    expect(errors).toHaveLength(0);
  });
});

test.describe('compat worker glue (embedded, not re-fetched)', () => {
  test('the compat argon solve issues exactly one /api.js request and verifies', async ({ page }) => {
    const apiJsRequests = [];
    page.on('request', (req) => {
      if (req.url().includes('/api.js')) apiJsRequests.push(req.url());
    });
    await page.goto('/migration/recaptcha-v2-argon.html');
    await solve(page);
    expect(await page.evaluate(() => window.__kiwiWorkerUsed === true)).toBe(true);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    // The fixture's sitekey doubles as the challenge scope (no allowlist
    // mapping for this key).
    const result = await verifyToken(page, token, '6Lc_checkout_login');
    expect(result.body.ok).toBe(true);
    expect(apiJsRequests, 'the loader is downloaded exactly once — no self re-fetch').toHaveLength(1);
  });

  test('hostile values in the compat locales marker fall back to the no-locale attributes', async ({ page }) => {
    await page.route('**/api.js*', async (route) => {
      const resp = await route.fetch();
      const body = await resp.text();
      await route.fulfill({
        contentType: 'application/javascript',
        body: body.replace(
          /window\.__kiwiCaptchaCompatLocales=\{name:"locales",hash:"[^"]*",sri:"[^"]*"\};/,
          'window.__kiwiCaptchaCompatLocales={name:"locales",hash:"><img src=x>",sri:"sha256-"};'
        ),
      });
    });
    await page.goto('/migration/turnstile.html');
    await solve(page);
    const container = page.locator('.kiwi-container');
    await expect(container).toHaveCount(1);
    expect(await container.getAttribute('data-kiwi-locales-src')).toBeNull();
    expect(await page.locator('img').count()).toBe(0);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const result = await verifyToken(page, token);
    expect(result.body.ok).toBe(true);
  });
});

test.describe('worker glue handshake', () => {
  test('a re-directed runtime that fails to import fails the handshake closed (no stale boot loader)', async ({ page }) => {
    await captureTerminations(page);
    await page.goto('/?algorithm=argon2id');
    await page.waitForFunction(
      () => window.__kiwiWorkers.length >= 1,
      null,
      { timeout: 30_000 }
    );
    const outcome = await page.evaluate(async () => {
      const worker = window.__kiwiWorkers[0];
      const replies = [];
      worker.onmessage = (ev) => replies.push(ev.data);
      // First handshake: the real glue asset at an absolute same-origin
      // URL (the boot state stays intact), then a re-handshake to a URL
      // that fails to import.
      worker.postMessage({ v: 1, type: 'glue', runtimeSrc: window.location.origin + '/kiwicaptcha-wasm.js' });
      await new Promise((r) => setTimeout(r, 500));
      worker.postMessage({ v: 1, type: 'glue', runtimeSrc: window.location.origin + '/no-such-runtime.js' });
      await new Promise((r) => setTimeout(r, 500));
      return replies;
    });
    const readyCount = outcome.filter((m) => m.type === 'ready').length;
    const failure = outcome.find((m) => m.type === 'failed');
    expect(readyCount).toBeGreaterThanOrEqual(1);
    expect(failure, 'the failed re-handshake must fail closed').toBeTruthy();
    expect(failure.reason).toBe('no_wasm');
  });
});
