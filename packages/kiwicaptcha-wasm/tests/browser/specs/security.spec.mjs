import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Round-8 security audits #25, #27, #28.
//
// This file is canonical at packages/kiwicaptcha-wasm/tests/browser/specs/
// and MUST be copied into the public repo's tests/browser/specs/ during
// sync. The asset paths below resolve in BOTH layouts (public repo:
// tests/browser/specs -> ../../../packages/kiwicaptcha-wasm/assets;
// wasm package: tests/browser/specs -> ../../../assets).

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

function driverSource() {
  return fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
}

function workerSource() {
  return fs.readFileSync(assetPath('kiwi-worker.js'), 'utf8');
}

/// A widget page served from the test origin (127.0.0.1:8085) so
/// window.location.origin resolves — the driver refuses cross-origin
/// challenge endpoints BEFORE any fetch, so a page on another origin could
/// never exercise that check.
async function serveWidgetPage(page, attrs) {
  const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
  const driver = driverSource();
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

test.describe('KiwiCaptcha postMessage boundary (audit #28)', () => {
  test('driver has NO parent-page postMessage and NO unguarded message listeners (static source assertion)', () => {
    const src = driverSource();
    const worker = workerSource();

    for (const [name, source] of [['widget-driver.js', src], ['kiwi-worker.js', worker]]) {
      // The driver must never post to the parent page at all — and never
      // with a wildcard target origin.
      expect(
        source.match(/parent\.postMessage\s*\(/g) ?? [],
        `${name}: parent.postMessage must not exist (audit #28)`
      ).toEqual([]);
      expect(
        source.match(/postMessage\([^)]*["']\*["']/g) ?? [],
        `${name}: no postMessage may use the "*" wildcard target origin`
      ).toEqual([]);
      // Every window/document-level "message" listener must be paired with
      // an event.origin check (there are none today; this fails closed if
      // one is ever added unguarded).
      const listeners = source.match(/addEventListener\(\s*["']message["']/g) ?? [];
      if (listeners.length > 0) {
        expect(
          source.match(/\.origin\b/g),
          `${name}: every addEventListener("message") must be paired with an event.origin check`
        ).not.toBeNull();
      }
    }

    // The only postMessage traffic is worker-internal: the driver posts the
    // solve request to its own worker, the worker posts progress/done/failed
    // back, and the MessageChannel yield is fully internal.
    expect(src).toMatch(/worker\.postMessage\(/);
    expect(src).toMatch(/worker\.onmessage\s*=/);
  });

  test('worker message handlers are schema-guarded (versioned, unknown shapes ignored) (static source assertion)', () => {
    const src = driverSource();
    const worker = workerSource();

    // Driver side: the worker reply listener validates a version field and
    // the payload schema before acting; anything else is ignored.
    expect(src).toMatch(/msg\.v !== 1/);
    expect(src).toMatch(/typeof msg\.counter !== "number"/);
    expect(src).toMatch(/typeof msg\.reason !== "string"/);
    // Worker side (embedded KIWI_WORKER_SRC + standalone asset): the solve
    // request must be a v1 object with the full numeric/string field set.
    expect(src).toMatch(/m\.v !== 1 \|\| m\.type !== "solve"/);
    expect(worker).toMatch(/m\.v !== 1 \|\| m\.type !== "solve"/);
    // The solve request the driver sends carries the version field.
    expect(src).toMatch(/v: 1,\n\s*type: "solve"/);
  });

  test('the worker ignores versionless or unknown messages (runtime)', async ({ page }) => {
    await page.goto('/');
    // The worker is created by the driver from the standalone asset; run the
    // SAME worker source in isolation and verify the onmessage schema guard:
    // messages without the version field or with an unknown type must never
    // produce a reply (the pre-guard code would have replied "failed").
    const guardResult = await page.evaluate(async (workerSrc) => {
      const replies = [];
      const worker = new Worker(
        URL.createObjectURL(new Blob([workerSrc], { type: 'application/javascript' }))
      );
      worker.onmessage = (ev) => replies.push(ev.data);
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

      // Versionless solve request (the pre-hardening shape): must be ignored.
      worker.postMessage({ type: 'solve', algorithm: 'sha256', prefix: 'p', prefixLen: 1, salt: 's', saltLen: 1, targetBits: 0, mKib: 0, t: 1, p: 1, startCounter: 0, maxHashes: 1000 });
      await sleep(150);
      // Wrong protocol version: must be ignored.
      worker.postMessage({ v: 2, type: 'solve', algorithm: 'sha256', prefix: 'p', prefixLen: 1, salt: 's', saltLen: 1, targetBits: 0, mKib: 0, t: 1, p: 1, startCounter: 0, maxHashes: 1000 });
      await sleep(150);
      // Unknown type with the right version: must be ignored.
      worker.postMessage({ v: 1, type: 'kiwi:worker:something-else', payload: {} });
      await sleep(150);
      // Non-object data: must be ignored.
      worker.postMessage('not-an-object');
      await sleep(150);
      // Malformed payload (missing numeric fields): must be ignored.
      worker.postMessage({ v: 1, type: 'solve', prefix: 'p' });
      await sleep(150);

      const repliesAtGuard = replies.length;
      worker.terminate();
      return repliesAtGuard;
    }, workerSource());
    expect(guardResult, 'no rogue message may produce a worker reply').toBe(0);
  });
});

test.describe('KiwiCaptcha origin validation (audit #27)', () => {
  test('challenge fetch uses redirect:"error" and a redirecting endpoint fails closed (static + runtime)', async ({ page }) => {
    const src = driverSource();
    expect(src).toMatch(/credentials\s*:\s*["']same-origin["']/);
    expect(src).toMatch(/redirect\s*:\s*["']error["']/);

    // redirect:"error" rejects ANY redirect — even a same-origin one. The
    // widget must fail closed (no token, failed state) instead of following
    // the redirect.
    const challenged = [];
    await page.route('**/challenge', async (route) => {
      challenged.push(route.request().url());
      await route.fulfill({
        status: 302,
        headers: { location: 'http://127.0.0.1:8085/challenge' },
      });
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', {
      timeout: 30_000,
    });
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    expect(challenged).toHaveLength(1);
  });

  test('a cross-origin redirect target is never contacted', async ({ page }) => {
    const foreign = [];
    page.on('request', (req) => {
      if (req.url().startsWith('http://127.0.0.1:9999')) foreign.push(req.url());
    });
    await page.route('**/challenge', async (route) => {
      await route.fulfill({
        status: 302,
        headers: { location: 'http://127.0.0.1:9999/evil' },
      });
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', {
      timeout: 30_000,
    });
    expect(foreign, 'redirect:"error" must never leak the request to the cross-origin target').toEqual([]);
  });

  test('a cross-origin challenge endpoint is refused before any fetch', async ({ page }) => {
    const foreign = [];
    page.on('request', (req) => {
      if (req.url().startsWith('http://127.0.0.1:9999')) foreign.push(req.url());
    });
    await serveWidgetPage(page, {
      'data-kiwi-endpoint': 'http://127.0.0.1:9999/challenge',
      'data-kiwi-scope': 'login',
    });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', {
      timeout: 30_000,
    });
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    expect(foreign, 'the cross-origin endpoint must be refused before any request').toEqual([]);
    const badge = await page.locator('[data-kiwi-badge]').textContent();
    expect(badge).toMatch(/Error/i);
  });
});

test.describe('KiwiCaptcha calibration floor (audit #25)', () => {
  const FORBIDDEN = ['mKib', 'targetBits', 'capability', 'benchmark', 'benchmarkMs', 'maxHashes'];

  test('challenge request body carries only scope (SHA-256) and never difficulty-suggesting parameters (static + runtime)', async ({ page }) => {
    const src = driverSource();
    // Static: the request body construction must not reference any
    // difficulty/capability field.
    for (const field of FORBIDDEN) {
      expect(src, `reqBody must never contain ${field}`).not.toMatch(
        new RegExp(`reqBody\\.${field}|"${field}"\\s*:`)
      );
    }

    // Runtime: capture the actual challenge request.
    const bodies = [];
    await page.route('**/challenge', async (route) => {
      bodies.push(route.request().postDataJSON() ?? {});
      await route.continue();
    });
    await page.goto('/?algorithm=sha256');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
      timeout: 60_000,
    });
    expect(bodies).toHaveLength(1);
    const body = bodies[0];
    expect(Object.keys(body).sort()).toEqual(['scope']);
    for (const field of FORBIDDEN) {
      expect(body, `the challenge request must not suggest ${field}`).not.toHaveProperty(field);
    }
  });

  test('Argon2id requests add only the algorithm choice, never difficulty (runtime)', async ({ page }) => {
    const bodies = [];
    // The challenge request is issued during page load, so capture via the
    // route handler (registered before goto) instead of waitForRequest.
    await page.route('**/challenge', async (route) => {
      bodies.push(route.request().postDataJSON() ?? {});
      await route.continue();
    });
    await page.goto('/?algorithm=argon2id');
    await expect.poll(() => bodies.length).toBeGreaterThanOrEqual(1);
    const body = bodies[0];
    expect(Object.keys(body).sort()).toEqual(['algorithm', 'scope']);
    expect(body.algorithm).toBe('argon2id');
    for (const field of FORBIDDEN) {
      expect(body, `the argon2id request must not suggest ${field}`).not.toHaveProperty(field);
    }
  });
});
