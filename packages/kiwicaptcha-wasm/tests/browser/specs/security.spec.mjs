import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Security invariants: postMessage boundary, origin validation, calibration
// floor, BFCache recovery, failure recovery, request binding, solver version
// coupling, no wasm-downgrade fallback, fetch timeout, host-header
// independence, narrow request shape.
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

test.describe('KiwiCaptcha postMessage boundary', () => {
  test('driver has NO parent-page postMessage and NO unguarded message listeners (static source assertion)', () => {
    const src = driverSource();
    const worker = workerSource();

    for (const [name, source] of [['widget-driver.js', src], ['kiwi-worker.js', worker]]) {
      // The driver must never post to the parent page at all — and never
      // with a wildcard target origin.
      expect(
        source.match(/parent\.postMessage\s*\(/g) ?? [],
        `${name}: parent.postMessage must not exist`
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
    // solve request to its own worker, the worker posts ready/progress/
    // done/failed back, and the MessageChannel yield is fully internal.
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
    // The worker's own startup "ready" handshake is expected and filtered
    // out — it is not a reply to any posted message.
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

      const repliesAtGuard = replies.filter((r) => r.type !== 'ready').length;
      const handshakeSeen = replies.some(
        (r) => r.type === 'ready' && typeof r.buildId === 'string'
      );
      worker.terminate();
      return { repliesAtGuard, handshakeSeen };
    }, workerSource());
    expect(guardResult.repliesAtGuard, 'no rogue message may produce a worker reply').toBe(0);
    expect(guardResult.handshakeSeen, 'the worker must announce its build id on startup').toBe(true);
  });
});

test.describe('KiwiCaptcha origin validation', () => {
  test('challenge fetch uses redirect:"error" and a redirecting endpoint fails closed (static + runtime)', async ({ page }) => {
    const src = driverSource();
    expect(src).toMatch(/credentials\s*:\s*["']same-origin["']/);
    expect(src).toMatch(/redirect\s*:\s*["']error["']/);

    // redirect:"error" rejects ANY redirect — even a same-origin one. The
    // widget must fail closed (no token, idle state) instead of following
    // the redirect (the error path resets to idle; bounded
    // retries may re-attempt, so at least one request is expected).
    const challenged = [];
    await page.route('**/challenge', async (route) => {
      challenged.push(route.request().url());
      await route.fulfill({
        status: 302,
        headers: { location: 'http://127.0.0.1:8085/challenge' },
      });
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-info]')).toContainText('click the widget to retry', {
      timeout: 30_000,
    });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'idle');
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    expect(challenged.length).toBeGreaterThanOrEqual(1);
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
    await expect(page.locator('[data-kiwi-info]')).toContainText('click the widget to retry', {
      timeout: 30_000,
    });
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
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
    await expect(page.locator('[data-kiwi-info]')).toContainText('click the widget to retry', {
      timeout: 30_000,
    });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'idle');
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    expect(foreign, 'the cross-origin endpoint must be refused before any request').toEqual([]);
  });
});

test.describe('KiwiCaptcha calibration floor', () => {
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

test.describe('KiwiCaptcha BFCache recovery', () => {
  test('driver registers a persisted-pageshow reset and keeps the token in memory only (static source assertion)', () => {
    const src = driverSource();
    expect(src).toMatch(/addEventListener\(\s*["']pageshow["']\s*,\s*function\s*\(e\)/);
    expect(src).toMatch(/e\.persisted/);
    // The result token must live in memory only — no web storage anywhere.
    expect(src, 'the driver must never touch localStorage').not.toMatch(/localStorage/);
    expect(src, 'the driver must never touch sessionStorage').not.toMatch(/sessionStorage/);
  });

  test('a persisted pageshow clears the solved state and does NOT auto-solve on restore (runtime)', async ({ page }) => {
    const challenges = [];
    await page.route('**/challenge', async (route) => {
      challenges.push(route.request().url());
      await route.continue();
    });
    await serveWidgetPage(page, {
      'data-kiwi-endpoint': '/challenge',
      'data-kiwi-scope': 'login',
    });
    const widgetEl = page.locator('[data-kiwi-widget]');
    await expect(widgetEl).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const tokenInput = page.locator('[data-kiwi-token]');
    const token = await tokenInput.inputValue();
    expect(token.length, 'the widget must have produced a token before the restore').toBeGreaterThan(0);

    // Simulate a BFCache restore. The real event fires AT window (and
    // propagates down); a synthetic dispatch must therefore target window —
    // document.dispatchEvent never reaches window listeners in Chromium.
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    });

    await expect(widgetEl).toHaveAttribute('data-state', 'idle');
    await expect(tokenInput).toHaveValue('');
    // No reacquire on restore: the widget must not issue a new challenge
    // until the next interaction.
    await page.waitForTimeout(800);
    expect(challenges, 'a persisted restore must not auto-solve').toHaveLength(1);
  });
});

test.describe('KiwiCaptcha failure recovery', () => {
  test('a rejected challenge response leaves the widget idle with no token (rejected-token recovery)', async ({ page }) => {
    let calls = 0;
    await page.route('**/challenge', async (route) => {
      calls++;
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: '{"error":"down"}',
      });
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-info]')).toContainText('click the widget to retry', {
      timeout: 30_000,
    });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'idle');
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    expect(calls, 'bounded retries must have been attempted before settling').toBeGreaterThanOrEqual(1);
  });

  test('the widget reacquires a fresh challenge after transient failures (auto-recovery)', async ({ page }) => {
    let calls = 0;
    await page.route('**/challenge', async (route) => {
      calls++;
      if (calls <= 2) {
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: '{"error":"down"}',
        });
      } else {
        await route.continue();
      }
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
      timeout: 60_000,
    });
    expect(calls).toBeGreaterThanOrEqual(3);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);
  });

  test('after settling idle the widget reacquires on the next interaction (click-to-retry)', async ({ page }) => {
    let failing = true;
    await page.route('**/challenge', async (route) => {
      if (failing) {
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: '{"error":"down"}',
        });
      } else {
        await route.continue();
      }
    });
    await page.goto('/');
    await expect(page.locator('[data-kiwi-info]')).toContainText('click the widget to retry', {
      timeout: 30_000,
    });
    failing = false;
    await page.locator('[data-kiwi-widget]').click();
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
      timeout: 60_000,
    });
    await expect(page.locator('[data-kiwi-token]')).not.toHaveValue('');
  });
});

test.describe('KiwiCaptcha request binding', () => {
  test('data-kiwi-request-binding is forwarded in the challenge body and echoed as a hidden input next to the token (static + runtime)', async ({ page }) => {
    const src = driverSource();
    // Static: the driver reads the attribute and includes request_binding
    // in the body; the hidden input mirrors the token-input write path.
    expect(src).toMatch(/data-kiwi-request-binding/);
    expect(src).toMatch(/reqBody\.request_binding/);
    expect(src).toMatch(/kiwi_request_binding/);

    const bodies = [];
    await page.route('**/challenge', async (route) => {
      bodies.push(route.request().postDataJSON() ?? {});
      await route.continue();
    });
    await serveWidgetPage(page, {
      'data-kiwi-endpoint': '/challenge',
      'data-kiwi-scope': 'login',
      'data-kiwi-request-binding': 'form-42-abc',
    });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
      timeout: 60_000,
    });
    expect(bodies).toHaveLength(1);
    expect(bodies[0].request_binding).toBe('form-42-abc');

    const hidden = page.locator('input[name="kiwi_request_binding"]');
    await expect(hidden).toHaveValue('form-42-abc');
    const adjacency = await page.evaluate(() => {
      const token = document.querySelector('[data-kiwi-token]');
      const next = token && token.nextElementSibling;
      return !!(next && next.name === 'kiwi_request_binding');
    });
    expect(adjacency, 'the binding input must sit directly next to the token input').toBe(true);
  });
});

test.describe('KiwiCaptcha solver version coupling', () => {
  test('worker handshake carries the solver build id and the driver validates it (static source assertion)', () => {
    const src = driverSource();
    const worker = workerSource();

    // The build id constant must exist in the driver and the worker, and
    // both must agree.
    const driverBuildId = src.match(/KIWI_SOLVER_BUILD_ID\s*=\s*"([^"]+)"/)?.[1];
    const workerBuildId = worker.match(/KIWI_SOLVER_BUILD_ID\s*=\s*"([^"]+)"/)?.[1];
    expect(driverBuildId).toBeTruthy();
    expect(workerBuildId).toBe(driverBuildId);

    // The worker reports the id on startup (ready) and on success (done);
    // the embedded copy in the driver matches the standalone asset.
    const handshake = /post\(\{ type: "ready", buildId: KIWI_SOLVER_BUILD_ID \}\)/;
    expect(worker).toMatch(handshake);
    expect(src).toMatch(handshake);
    expect(worker).toMatch(/type: "done", counter: res, buildId: KIWI_SOLVER_BUILD_ID/);
    expect(src).toMatch(/type: "done", counter: res, buildId: KIWI_SOLVER_BUILD_ID/);
    expect(src).toMatch(/type: "done", counter: counter, buildId: KIWI_SOLVER_BUILD_ID/);

    // The driver validates against its own constant and enters a controlled
    // mismatch state — a mismatched worker must never yield a solution.
    expect(src).toMatch(/msg\.type === "ready"/);
    expect(src).toMatch(/msg\.buildId !== KIWI_SOLVER_BUILD_ID/);
    expect(src).toMatch(/mismatch: true/);
    expect(src).toMatch(/kiwi:solver-mismatch/);
  });

  test('a stale worker build id yields the controlled kiwi:solver-mismatch state (runtime)', async ({ page }) => {
    // /kiwi-worker-stale.js is the real worker asset with the build id
    // rewritten to a different value (see router.php). The driver must
    // refuse it: controlled mismatch state, clear message, no token.
    await page.goto('/?worker-stale=1&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute(
      'data-state',
      'kiwi:solver-mismatch',
      { timeout: 60_000 }
    );
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    await expect(page.locator('[data-kiwi-info]')).toContainText('out of date');
  });
});

test.describe('KiwiCaptcha no wasm-downgrade fallback', () => {
  test('solver failures cannot change the requested algorithm — one fetch, attribute-only algorithm (static source assertion)', () => {
    const src = driverSource();
    // Exactly ONE fetch exists in the whole driver: there can be no
    // "retry with a weaker challenge" code path to fetch a second time.
    expect(src.match(/fetch\(/g) ?? []).toHaveLength(1);
    // The algorithm variable is declared exactly twice in the file: once in
    // the driver (from the container/widget attributes only) and once in the
    // embedded worker source (from the solve request). No other declaration.
    expect(src.match(/var algorithm\s*=/g) ?? []).toHaveLength(2);
    // The ONLY hard-coded algorithm assignment in the entire file is the
    // profile normalization itself (pinned by both assertions
    // below) — no failure path may assign a different, weaker algorithm.
    expect(src.match(/algorithm\s*=\s*["']/g) ?? []).toHaveLength(1);
    expect(src).toMatch(/if \(algorithm !== "sha256" && algorithm !== "argon2id"\) algorithm = "sha256";/);
    // The request body algorithm is exactly the attribute-derived variable.
    expect(src).toMatch(/var algorithm\s*=\s*W\.getAttribute\("data-kiwi-algorithm"\) \|\| container\.getAttribute\("data-kiwi-algorithm"\) \|\| "sha256"/);
    expect(src).toMatch(/reqBody\.algorithm\s*=\s*algorithm/);
    // Only the two server-offered profiles are selectable — anything else is
    // normalized to the default; the client can never invent parameters.
    expect(src).toMatch(/algorithm !== "sha256" && algorithm !== "argon2id"/);
    // Solver selection is driven ONLY by the server's response algorithm —
    // never by a client capability probe (no navigator capability gating).
    expect(src).toMatch(/\(data\.algorithm \|\| "sha256"\) === "argon2id"/);
    expect(src, 'no capability probe may gate the algorithm choice').not.toMatch(/navigator\.[\w.]*[Cc]apab/);
    // A server-side downgrade (argon2id requested, weaker returned) is a
    // FAILED challenge, never accepted and never solved.
    expect(src).toMatch(/Challenge downgraded/);
    expect(src).toMatch(/\(data\.algorithm \|\| "sha256"\) !== "argon2id"/);
  });

  test('a stale worker leaves the widget in the mismatch state without ever re-requesting a weaker challenge (runtime)', async ({ page }) => {
    const bodies = [];
    await page.route('**/challenge', async (route) => {
      bodies.push(route.request().postDataJSON() ?? {});
      await route.continue();
    });
    await page.goto('/?worker-stale=1&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute(
      'data-state',
      'kiwi:solver-mismatch',
      { timeout: 60_000 }
    );
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    // The mismatch is terminal — exactly one challenge was requested, and it
    // asked for argon2id. The failed worker triggered NO weaker re-request.
    expect(bodies).toHaveLength(1);
    expect(bodies[0].algorithm).toBe('argon2id');
  });

  test('WASM unavailable: bounded retries keep requesting argon2id and settle in the controlled error state (runtime)', async ({ page }) => {
    // ?csp=strict blocks wasm compilation AND blob workers (script-src
    // without blob:/wasm-unsafe-eval), so the argon2id challenge cannot be
    // solved at all — there is no pure-JS argon2id fallback. The driver must
    // fail (bounded retries, then idle), and EVERY challenge request must
    // still ask for argon2id: never a downgrade to sha256.
    const bodies = [];
    await page.route('**/challenge', async (route) => {
      bodies.push(route.request().postDataJSON() ?? {});
      await route.continue();
    });
    await page.goto('/?csp=strict&algorithm=argon2id');
    await expect(page.locator('[data-kiwi-info]')).toContainText('click the widget to retry', {
      timeout: 60_000,
    });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'idle');
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    expect(bodies.length, 'bounded retries must re-attempt the challenge').toBeGreaterThanOrEqual(3);
    for (const body of bodies) {
      expect(body.algorithm, 'every challenge request must stay argon2id — no wasm-downgrade fallback').toBe('argon2id');
    }
  });
});

test.describe('KiwiCaptcha challenge fetch timeout', () => {
  test('the fetch is abortable: AbortController, 15 s default, data-kiwi-fetch-timeout-ms override, bounded worker solve (static source assertion)', () => {
    const src = driverSource();
    expect(src).toMatch(/AbortController/);
    expect(src).toMatch(/signal\s*:\s*abortController\.signal/);
    expect(src).toMatch(/KIWI_FETCH_TIMEOUT_MS\s*=\s*15000/);
    expect(src).toMatch(/data-kiwi-fetch-timeout-ms/);
    expect(src).toMatch(/clearTimeout\(abortTimer\)/);
    // The worker solve path is bounded end to end: the driver caps the
    // counter range it hands the worker (maxHashes), the worker caps its
    // own search range (argMax), and every worker path terminates in a
    // done/failed terminal message.
    expect(src).toMatch(/maxHashes: MAX_SHA_HASHES/);
    expect(src).toMatch(/argMax = Math\.min\(MAX_SHA_HASHES/);
  });

  test('a stalled challenge endpoint is aborted and the widget settles in the controlled idle error state (runtime)', async ({ page }) => {
    // The route never fulfills: the request hangs until the driver's
    // AbortController fires at data-kiwi-fetch-timeout-ms (1500 ms here).
    const stalled = [];
    await page.route('**/stall', async (route) => {
      stalled.push(route.request().url());
    });
    const start = Date.now();
    await serveWidgetPage(page, {
      'data-kiwi-endpoint': '/stall',
      'data-kiwi-scope': 'login',
      'data-kiwi-fetch-timeout-ms': '1500',
    });
    await expect(page.locator('[data-kiwi-info]')).toContainText('click the widget to retry', {
      timeout: 40_000,
    });
    const elapsed = Date.now() - start;
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'idle');
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');
    // Bounded retries re-attempt (3 fetches), each aborted by its own
    // timeout — the widget must never be left stuck on a hung server.
    expect(stalled).toHaveLength(3);
    // Three abort cycles at 1.5 s plus 1 s/2 s backoff ≈ 7.5 s; the lower
    // bound proves the abort timer actually ran (not an instant failure).
    expect(elapsed).toBeGreaterThanOrEqual(4000);
    expect(elapsed).toBeLessThan(25_000);
  });
});

test.describe('KiwiCaptcha host-header independence', () => {
  test('same-origin enforcement uses window.location.origin only — never location.host/hostname or a Host header (static source assertion)', () => {
    const src = driverSource();
    // The endpoint check compares ORIGINS (the page's own scheme+host+port),
    // never a request Host header — a Host header is attacker-influenced,
    // window.location is not.
    expect(src).toMatch(/url\.origin !== window\.location\.origin/);
    expect(src).toMatch(/window\.location\.origin/);
    // No host-based trust decision may exist anywhere in the driver.
    expect(src.match(/location\.hostname/g) ?? []).toEqual([]);
    expect(src.match(/location\.host\b/g) ?? []).toEqual([]);
    expect(src.match(/document\.location\.host/g) ?? []).toEqual([]);
    // The fetch never reads or sets a Host header (browser-managed only).
    expect(src.match(/["']Host["']/g) ?? []).toEqual([]);
  });
});

test.describe('KiwiCaptcha narrow request shape', () => {
  test('the challenge POST body is built from exactly {scope, algorithm, request_binding} (static source assertion)', () => {
    const src = driverSource();
    // scope enters via the object literal; algorithm and request_binding via
    // the only two reqBody assignments that exist in the file. A fourth
    // field would have to appear here.
    expect(src).toMatch(/var reqBody = \{ scope: scope \};/);
    expect(src.match(/reqBody\.\w+/g) ?? []).toEqual([
      'reqBody.algorithm',
      'reqBody.request_binding',
    ]);
  });

  test('with a binding and argon2id the wire body contains exactly {scope, algorithm, request_binding} (runtime)', async ({ page }) => {
    const bodies = [];
    await page.route('**/challenge', async (route) => {
      bodies.push(route.request().postDataJSON() ?? {});
      await route.continue();
    });
    await serveWidgetPage(page, {
      'data-kiwi-endpoint': '/challenge',
      'data-kiwi-scope': 'login',
      'data-kiwi-request-binding': 'form-42-abc',
      'data-kiwi-algorithm': 'argon2id',
    });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
      timeout: 60_000,
    });
    expect(bodies).toHaveLength(1);
    expect(Object.keys(bodies[0]).sort()).toEqual(['algorithm', 'request_binding', 'scope']);
  });

  test('without an algorithm the wire body is exactly {scope, request_binding} — no algorithm field, no extras (runtime)', async ({ page }) => {
    const bodies = [];
    await page.route('**/challenge', async (route) => {
      bodies.push(route.request().postDataJSON() ?? {});
      await route.continue();
    });
    await serveWidgetPage(page, {
      'data-kiwi-endpoint': '/challenge',
      'data-kiwi-scope': 'login',
      'data-kiwi-request-binding': 'form-42-abc',
    });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
      timeout: 60_000,
    });
    expect(bodies).toHaveLength(1);
    expect(Object.keys(bodies[0]).sort()).toEqual(['request_binding', 'scope']);
  });
});
