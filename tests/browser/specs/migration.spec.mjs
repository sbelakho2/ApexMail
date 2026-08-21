import { test, expect } from '@playwright/test';

// Incumbent migration is a CI contract. These fixtures are
// structurally copied from standard `reCAPTCHA` v2 / invisible / hCaptcha /
// Turnstile integrations — the only difference is the provider script URL
// (kiwi /kiwi-captcha/api.js?compat=...). The migration-diff budget: a
// standard incumbent page migrates with no more than a handful of changed
// lines; if a fixture requires more edits to keep working, that is a
// migration regression.

async function waitVerified(page, field = 'g-recaptcha-response') {
  const token = page.locator(`input[name="${field}"]`);
  await expect(token).not.toHaveValue('', { timeout: 60_000 });
  const value = await token.inputValue();
  expect(value.length).toBeGreaterThan(10);
  return value;
}

test.describe('KiwiCaptcha migration compatibility', () => {
  test('reCAPTCHA v2: implicit render, data-callback, g-recaptcha-response alias', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toBeVisible();
    const token = await waitVerified(page);
    // The success callback receives the same token.
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('reCAPTCHA v2: widget ids + getResponse resolve to a real widget', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    const token = await waitVerified(page);
    const id = await page.evaluate(() => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      return { wid, response: window.grecaptcha.getResponse(wid) };
    });
    expect(typeof id.wid).toBe('string');
    expect(id.wid.length).toBeGreaterThan(0);
    expect(id.response).toBe(token);
  });

  test('reCAPTCHA v2: omitted widget id defaults to the first created widget', async ({ page }) => {
    // The omitted id targets the first created widget (the incumbent
    // providers' documented default): reset()/getResponse()/execute()
    // with no argument operate on that widget, and reset() reacquires a
    // fresh response.
    await page.goto('/migration/recaptcha-v2.html');
    const token = await waitVerified(page);
    const result = await page.evaluate(async () => {
      const first = document.querySelector('.g-recaptcha').dataset.kiwiInstance;
      const noArgResponse = window.grecaptcha.getResponse();
      const noArgExecute = await window.grecaptcha.execute();
      window.grecaptcha.reset();
      await new Promise((r) => setTimeout(r, 6000));
      return { first, noArgResponse, noArgExecute, responseAfterReset: window.grecaptcha.getResponse() };
    });
    expect(result.noArgResponse).toBe(token);
    expect(result.noArgExecute).toBe(token);
    expect(result.responseAfterReset).toBeTruthy();
    expect(result.responseAfterReset).not.toBe(token);
  });

  test('reCAPTCHA v2 explicit loading: render=explicit suppresses auto-render and onload renders', async ({ page }) => {
    // The fixture is the documented integration pattern (onload +
    // render=explicit) with only the provider URL changed. The invariant:
    // render=explicit suppresses auto-render (exactly ONE widget) and the
    // onload callback runs.
    await page.goto('/migration/recaptcha-v2-explicit.html');
    await expect(page.locator('#out')).toHaveText(/^cb:/, { timeout: 60_000 });
    const state = await page.evaluate(() => ({
      onloadRan: window.kiwiExplicitRendered === true,
      containerCount: document.querySelectorAll('.kiwi-container').length,
      response: window.grecaptcha.getResponse(),
    }));
    expect(state.onloadRan).toBe(true);
    // Exactly ONE widget: the explicit render, not an auto-rendered
    // duplicate of the same container.
    expect(state.containerCount).toBe(1);
    expect(state.response.length).toBeGreaterThan(10);
  });

  test('Turnstile: action/cData bound at issuance, returned from verified server state, request forging ignored', async ({ page, request }) => {
    // The full trust chain: data-action/data-cdata on the container ->
    // the driver sends them in the challenge request -> the server binds
    // them to the nonce -> Siteverify returns the server-stored values.
    // A backend request that tries action=admin gets the real action.
    await page.goto('/migration/turnstile-meta.html');
    await expect(page.locator('#out')).toHaveText(/^cb:/, { timeout: 60_000 });
    const token = await page.evaluate(() => {
      const w = document.querySelector('.cf-turnstile [data-kiwi-widget]');
      return window.turnstile.getResponse(w.dataset.kiwiInstance);
    });
    expect(token.length).toBeGreaterThan(10);

    const verified = await request.post('/siteverify', {
      data: { secret: 'compat-secret-42', response: token, remoteip: '127.0.0.1', action: 'admin', cdata: 'forged' },
    });
    const body = await verified.json();
    expect(body.success).toBe(true);
    expect(body.action, 'the response action must come from SERVER state, never the request').toBe('checkout');
    expect(body.cdata, 'the response cdata must come from SERVER state, never the request').toBe('order_19382');

    // Ordinary replay (no idempotency): the token is single-use.
    const replay = await request.post('/siteverify', {
      data: { secret: 'compat-secret-42', response: token, remoteip: '127.0.0.1' },
    });
    const replayBody = await replay.json();
    expect(replayBody.success).toBe(false);
    expect(replayBody['error-codes']).toContain('timeout-or-duplicate');
  });

  test('reCAPTCHA v3: execute(sitekey, {action}) transmits the REAL pair and the server-owned policy resolves the scope', async ({ page, request }) => {
    // The invariant: the challenge request must carry sitekey AND action
    // independently, the server must resolve (sitekey, action) ->
    // commerce_high_value, and an unknown action must be refused.
    const bodies = [];
    const statuses = [];
    await page.route('**/challenge', async (route) => {
      bodies.push(route.request().postDataJSON() ?? {});
      const response = await route.fetch();
      statuses.push({ action: bodies[bodies.length - 1].action ?? null, status: response.status() });
      await route.fulfill({ response });
    });
    await page.goto('/migration/recaptcha-v3.html');
    // Capture the token from the execute promise (the hidden holder is
    // torn down on completion by design, so getResponse() afterwards is
    // empty).
    const token = await page.evaluate(async () => {
      const t = await window.grecaptcha.execute('6Lc_v3_sitekey_a', { action: 'checkout' });
      return t;
    });
    expect(token.length).toBeGreaterThan(10);

    const v3 = bodies.find((b) => b.sitekey === '6Lc_v3_sitekey_a');
    expect(v3, 'the challenge body must carry the real sitekey').toBeTruthy();
    expect(v3.action, 'the challenge body must carry the requested action independently').toBe('checkout');
    // The client scope is the public sitekey (the design): the server maps
    // (sitekey, action) to the protected scope.
    expect(v3.scope).toBe('6Lc_v3_sitekey_a');
    const verified = await request.post('/verify', { data: { token, scope: 'commerce_high_value' } });
    const body = await verified.json();
    expect(body.ok, 'the server-resolved scope must be what verifies').toBe(true);

    // Unknown action -> refused by the server policy (the 422 must reach
    // the client; the raw body is intentionally not leaked into the
    // widget's error message).
    const refused = await page.evaluate(async () => {
      try {
        await window.grecaptcha.execute('6Lc_v3_sitekey_a', { action: 'admin' });
        return 'resolved';
      } catch (e) {
        return String(e && e.message);
      }
    });
    const adminRefusals = statuses.filter((s2) => s2.action === 'admin');
    expect(adminRefusals.length).toBeGreaterThan(0);
    expect(adminRefusals.every((s2) => s2.status >= 400), 'the unknown action must be refused server-side').toBe(true);
    expect(refused).not.toBe('resolved');
  });

  test('reCAPTCHA v2: Retry after terminal failure preserves the FULL security configuration', async ({ page }) => {
    // A mapped sitekey -> sensitive scope must survive the Retry path:
    // reacquisition reinitializes from the preserved options, never a
    // blank initWidget(W) that falls back to the default scope.
    let failing = true;
    const scopes = [];
    await page.route('**/challenge', async (route) => {
      const body = route.request().postDataJSON() ?? {};
      if (failing) {
        await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
      } else {
        scopes.push(body.scope);
        await route.continue();
      }
    });
    await page.goto('/migration/recaptcha-v2.html');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 60_000 });
    // The initial render's scope identity (the container's data-kiwi-scope,
    // which is the mapped sitekey — the fixture allowlist maps it to
    // 'login' server-side; a downgrade would show a different scope here).
    const containerScope = await page.evaluate(() => document.querySelector('.g-recaptcha').dataset.sitekey || document.querySelector('.g-recaptcha').dataset.kiwiScope);
    failing = false;
    await page.locator('.g-recaptcha [data-kiwi-retry]').click();
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    // The retry's challenge MUST carry the same scope identity as the
    // initial render — a blank re-init would fall back to "login".
    expect(scopes.length).toBeGreaterThan(0);
    for (const scope of scopes) {
      expect(scope).toBe(containerScope);
    }
  });

  test('reCAPTCHA v2: expiry -> Retry keyboard reacquisition preserves host form fields', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2-ttl.html');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    // Fill unrelated host-form data before expiry.
    await page.fill('input[name="email"]', 'user@example.com');
    await expect(page.locator('input[name="g-recaptcha-response"]')).toHaveValue('', { timeout: 30_000 });
    // The expired state exposes the Retry button.
    await expect(page.locator('.g-recaptcha [data-kiwi-retry]')).toBeVisible();
    await page.locator('.g-recaptcha [data-kiwi-retry]').focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('input[name="g-recaptcha-response"]')).not.toHaveValue('', { timeout: 60_000 });
    // Host form state untouched by the reacquisition.
    expect(await page.inputValue('input[name="email"]')).toBe('user@example.com');
  });

  test('reCAPTCHA v2 explicit mode: dynamically inserted containers NEVER auto-render until an explicit render()', async ({ page }) => {
    // render=explicit means the application controls rendering — the
    // MutationObserver must not auto-render a later .g-recaptcha node.
    await page.goto('/migration/recaptcha-v2-explicit.html');
    await expect(page.locator('#out')).toHaveText(/^cb:/, { timeout: 60_000 });
    const dynamic = await page.evaluate(async () => {
      const el = document.createElement('div');
      el.className = 'g-recaptcha';
      el.dataset.sitekey = '6Lc_dynamic_explicit';
      document.body.appendChild(el);
      await new Promise((r) => setTimeout(r, 600));
      const before = { autoRendered: !!el.querySelector('[data-kiwi-widget]'), containers: document.querySelectorAll('.kiwi-container').length };
      const id = window.grecaptcha.render(el, { sitekey: '6Lc_dynamic_explicit' });
      await new Promise((r) => setTimeout(r, 8000));
      return { before, id, containers: document.querySelectorAll('.kiwi-container').length, response: window.grecaptcha.getResponse(id) };
    });
    expect(dynamic.before.autoRendered, 'explicit mode must NOT auto-render dynamic containers').toBe(false);
    expect(dynamic.before.containers).toBe(1);
    expect(typeof dynamic.id).toBe('string');
    expect(dynamic.containers).toBe(2);
    expect(dynamic.response.length).toBeGreaterThan(10);
  });

  test('reCAPTCHA v2 implicit mode: dynamically inserted containers still auto-render', async ({ page }) => {
    // The implicit-mode dynamic convenience is retained and proven.
    await page.goto('/migration/recaptcha-v2.html');
    await waitVerified(page);
    const dynamic = await page.evaluate(async () => {
      const el = document.createElement('div');
      el.className = 'g-recaptcha';
      el.dataset.sitekey = '6Lc_dynamic_implicit';
      document.body.appendChild(el);
      // Wait for the auto-rendered widget to solve (bounded poll — CI
      // machines are slower than the local run).
      const deadline = Date.now() + 30_000;
      let response = '';
      while (Date.now() < deadline) {
        // The instance id lives on the rendered container (compat mode),
        // not on the inner widget element.
        const id = el.dataset.kiwiInstance;
        response = id ? window.grecaptcha.getResponse(id) : '';
        if (response.length > 10) break;
        await new Promise((r) => setTimeout(r, 500));
      }
      return { autoRendered: !!el.querySelector('[data-kiwi-widget]'), response };
    });
    expect(dynamic.autoRendered).toBe(true);
    expect(dynamic.response.length).toBeGreaterThan(10);
  });

  test('reCAPTCHA v2: grecaptcha.render("id", params) and render(element, params) actually render', async ({ page }) => {
    // The invariant: the explicit render path must actually call
    // grecaptcha.render() — string ids/selectors resolve through the same
    // target resolver as the native API and return a working widget id.
    await page.goto('/migration/recaptcha-v2.html');
    await waitVerified(page);
    const result = await page.evaluate(async () => {
      const out = {};
      const targetA = document.createElement('div');
      targetA.id = 'explicit-a';
      document.body.appendChild(targetA);
      const idA = window.grecaptcha.render('explicit-a', { sitekey: '6Lc_explicit_login' });
      out.idA = idA;
      const targetB = document.createElement('div');
      targetB.className = 'explicit-b';
      document.body.appendChild(targetB);
      const idB = window.grecaptcha.render(targetB, { sitekey: '6Lc_explicit_login' });
      out.idB = idB;
      out.selectorId = window.grecaptcha.render('.explicit-b', { sitekey: '6Lc_explicit_login' });
      out.unknownId = window.grecaptcha.render('no-such-element', { sitekey: 'x' });
      out.containers = document.querySelectorAll('.kiwi-container').length;
      await new Promise((r) => setTimeout(r, 6000));
      out.responseA = window.grecaptcha.getResponse(idA);
      out.responseB = window.grecaptcha.getResponse(idB);
      return out;
    });
    expect(typeof result.idA).toBe('string');
    expect(result.idA.length).toBeGreaterThan(0);
    expect(typeof result.idB).toBe('string');
    expect(result.idB.length).toBeGreaterThan(0);
    expect(result.selectorId).toBe(result.idB);
    expect(result.unknownId).toBe(0);
    expect(result.containers).toBe(3);
    expect(result.responseA.length).toBeGreaterThan(10);
    expect(result.responseB.length).toBeGreaterThan(10);
  });

  test('reCAPTCHA v2: provider errorCallback fires exactly once on terminal failure', async ({ page }) => {
    // The invariant: the provider error callback fires exactly once on
    // terminal failure. fail(), workerUnavailable() and solverMismatch()
    // all invoke it.
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
    });
    await page.goto('/migration/recaptcha-v2.html');
    await expect(page.locator('#out')).toHaveText('err-cb', { timeout: 30_000 });
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'failed');
    await expect(page.locator('.g-recaptcha [data-kiwi-retry]')).toBeVisible();
    // Exactly once: no further callback invocation after the terminal state.
    await page.waitForTimeout(4000);
    await expect(page.locator('#out')).toHaveText('err-cb');
  });

  test('reCAPTCHA v2: reset during an in-flight challenge cancels generation 1', async ({ page }) => {
    // reset() must abort the in-flight generation's fetch and the
    // delayed response must never write a token or invoke a callback.
    let calls = 0;
    await page.route('**/challenge', async (route) => {
      calls++;
      if (calls === 1) {
        await new Promise((r) => setTimeout(r, 3000));
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          nonce: 'cancel-nonce-' + calls, salt: btoa(String(calls).padStart(16, '0')), prefix: 'x',
          targetBits: 6, algorithm: 'sha256', mKib: 0, t: 1, p: 1, ttlSecs: 120, minDurationMs: 0,
        }),
      });
    });
    await page.goto('/migration/recaptcha-v2.html');
    const result = await page.evaluate(async () => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      // Count the widget's own lifecycle events (the fixture's global
      // callback was captured at render time, so reassigning it here would
      // not observe the generations).
      let verified = 0;
      // kiwi:verified dispatches on the rendered container (W) and bubbles.
      el.addEventListener('kiwi:verified', () => { verified++; });
      await new Promise((r) => setTimeout(r, 600));
      window.grecaptcha.reset(wid);
      await new Promise((r) => setTimeout(r, 8000));
      return { verified, response: window.grecaptcha.getResponse(wid) };
    });
    expect(calls).toBeGreaterThanOrEqual(2);
    // Exactly ONE verified event (generation 2 only — generation 1 was
    // cancelled mid-fetch and can never complete) + a valid gen-2 token.
    expect(result.verified).toBe(1);
    expect(result.response.length).toBeGreaterThan(10);
  });

  test('reCAPTCHA v2: reset clears and reacquires', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    const token = await waitVerified(page);
    const result = await page.evaluate(async () => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      window.grecaptcha.reset(wid);
      await new Promise((r) => setTimeout(r, 4000));
      const responseAfter = window.grecaptcha.getResponse(wid);
      return { responseAfter };
    });
    // After reset the widget reacquires (the response is fresh again).
    expect(result.responseAfter).toBeTruthy();
    expect(result.responseAfter).not.toBe(token);
  });

  test('reCAPTCHA v2: execute(id) resolves with the token', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    const token = await waitVerified(page);
    const viaExecute = await page.evaluate(async () => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      return window.grecaptcha.execute(wid);
    });
    expect(viaExecute).toBe(token);
  });

  test('reCAPTCHA v2 Argon: grecaptcha.ready() queues behind glue readiness for explicit render', async ({ page }) => {
    // ready() must not race the loader-glue self-fetch — an
    // explicit render() inside ready() immediately starts an Argon worker
    // that needs the glue (no inline script exists on the external-loader
    // page). The api.js response is deliberately delayed so the race is
    // observable.
    await page.route('**/api.js?*', async (route) => {
      await new Promise((r) => setTimeout(r, 1500));
      await route.continue();
    });
    await page.goto('/migration/recaptcha-v2-argon.html');
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        window.grecaptcha.ready(() => {
          const holder = document.createElement('div');
          document.body.appendChild(holder);
          const id = window.grecaptcha.render(holder, { sitekey: '6Lc_ready_explicit' });
          resolve({ id, phase: 'rendered' });
        });
        setTimeout(() => resolve({ id: null, phase: 'timeout' }), 20_000);
      });
    });
    expect(result.phase).toBe('rendered');
    expect(typeof result.id).toBe('string');
    await expect(page.locator('input[name="g-recaptcha-response"]').nth(1)).not.toHaveValue('', { timeout: 90_000 });
    const response = await page.evaluate((id) => window.grecaptcha.getResponse(id), result.id);
    expect(response.length).toBeGreaterThan(10);
  });

  test('reCAPTCHA v2: v3-style execute(sitekey) tears down the hidden widget', async ({ page }) => {
    // Repeated execute(sitekey, {action}) calls must not
    // accumulate hidden DOM, registry entries or reset hooks.
    await page.goto('/migration/recaptcha-v2.html');
    await waitVerified(page);
    const result = await page.evaluate(async () => {
      const baseline = document.querySelectorAll('.kiwi-container').length;
      await window.grecaptcha.execute('6Lc_v3_checkout', { action: 'checkout' });
      const afterOne = document.querySelectorAll('.kiwi-container').length;
      await window.grecaptcha.execute('6Lc_v3_checkout', { action: 'checkout' });
      await window.grecaptcha.execute('6Lc_v3_checkout', { action: 'checkout' });
      await new Promise((r) => setTimeout(r, 500));
      return {
        baseline,
        afterOne,
        afterThree: document.querySelectorAll('.kiwi-container').length,
        hiddenHolders: Array.from(document.querySelectorAll('div')).filter((d) => d.style.display === 'none').length,
      };
    });
    // Every execute() cleans up its holder: no accumulation whatsoever.
    expect(result.afterOne).toBe(result.baseline);
    expect(result.afterThree).toBe(result.baseline);
    expect(result.hiddenHolders).toBe(0);
  });

  test('reCAPTCHA v2: execute() rejects with the ACTUAL failure reason', async ({ page }) => {
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
    });
    await page.goto('/migration/recaptcha-v2.html');
    const message = await page.evaluate(async () => {
      try {
        await window.grecaptcha.execute('6Lc_fail_reason', { action: 'checkout' });
        return 'resolved';
      } catch (err) {
        return String(err && err.message);
      }
    });
    // fail() dispatches {error: msg} — the promise must surface the real
    // reason ("Challenge failed"), not the generic fallback.
    expect(message).toContain('Challenge failed');
    expect(message).not.toContain('solve failed');
  });

  test('reCAPTCHA v2: expiry clears the token + field + fires the expired callback', async ({ page }) => {
    // ttl=2 -> the challenge expires 2s after the solve; the client expiry
    // lifecycle mirrors the incumbent providers (the server remains the
    // authoritative check).
    await page.goto('/migration/recaptcha-v2-ttl.html');
    const token = await waitVerified(page);
    await expect(page.locator('input[name="g-recaptcha-response"]')).toHaveValue(token);
    await expect(page.locator('#out')).toHaveText('expired-cb', { timeout: 15_000 });
    await expect(page.locator('input[name="g-recaptcha-response"]')).toHaveValue('', { timeout: 15_000 });
    const state = await page.evaluate(() => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      return {
        expired: window.grecaptcha.isExpired ? window.grecaptcha.isExpired(wid) : 'n/a',
        response: window.grecaptcha.getResponse(wid),
      };
    });
    expect(state.response).toBe('');
  });

  test('reCAPTCHA v2: remove(id) destroys the widget', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    await waitVerified(page);
    const gone = await page.evaluate(() => {
      const el = document.querySelector('.g-recaptcha');
      const wid = el.dataset.kiwiInstance;
      window.grecaptcha.remove(wid);
      // Provider parity with Turnstile's remove(): the widget markup leaves the
      // page entirely.
      return document.querySelector('.g-recaptcha') === null
        && document.querySelectorAll('[data-kiwi-widget]').length === 0;
    });
    expect(gone).toBe(true);
  });

  test('invisible reCAPTCHA: the control click triggers execute + data-callback', async ({ page }) => {
    await page.goto('/migration/recaptcha-invisible.html');
    const button = page.locator('button.g-recaptcha');
    await expect(button.locator('[data-kiwi-widget]')).toBeVisible();
    await button.click();
    const token = await waitVerified(page);
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('hCaptcha: implicit render + h-captcha-response alias + callbacks', async ({ page }) => {
    await page.goto('/migration/hcaptcha.html');
    await expect(page.locator('.h-captcha [data-kiwi-widget]')).toBeVisible();
    const token = await waitVerified(page, 'h-captcha-response');
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('Turnstile: implicit render + cf-turnstile-response alias + callbacks', async ({ page }) => {
    await page.goto('/migration/turnstile.html');
    await expect(page.locator('.cf-turnstile [data-kiwi-widget]')).toBeVisible();
    const token = await waitVerified(page, 'cf-turnstile-response');
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('Argon2id solves through the external compatibility loader (worker glue path)', async ({ page }) => {
    // With the driver loaded as the external /api.js, the
    // Blob worker has no inline glue element to copy — the loader's own
    // fetched source supplies it. Argon2id must therefore solve
    // end-to-end through the one-script migration path (SHA-256-only
    // fixtures would mask a broken glue handoff).
    await page.goto('/migration/recaptcha-v2-argon.html');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toBeVisible();
    const token = await waitVerified(page);
    expect(token.length).toBeGreaterThan(10);
  });

  test('the visible .kiwi-widget carries the done state', async ({ page }) => {
    // The state attribute must live on the inner
    // .kiwi-widget — the stylesheet keys the pulse/success/failure styling
    // and Retry visibility on .kiwi-widget[data-state=...].
    await page.goto('/migration/recaptcha-v2.html');
    await waitVerified(page);
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'done');
  });

  test('a failed compat widget shows the failed state and the Retry button', async ({ page }) => {
    // The endpoint 404s -> the challenge fails -> the inner widget enters
    // the failed state and the Retry button becomes visible (the state
    // lands on .kiwi-widget).
    await page.goto('/migration/recaptcha-v2.html');
    await page.evaluate(() => {
      document.querySelector('.g-recaptcha').setAttribute('data-kiwi-endpoint', '/definitely-missing-endpoint');
    });
    // The page already rendered with the default endpoint before the
    // attribute was set — force a fresh widget by navigating with the
    // broken endpoint baked in via the compat passthrough (reload with a
    // query the fixture passes through).
    await page.goto('/migration/recaptcha-v2.html');
    await page.evaluate(() => {
      const el = document.querySelector('.g-recaptcha');
      el.setAttribute('data-kiwi-endpoint', '/definitely-missing-endpoint');
      // Re-init by resetting through the provider API (the attribute is
      // read at init).
      const wid = el.dataset.kiwiInstance;
      if (wid) window.grecaptcha.reset(wid);
    });
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'failed', { timeout: 30_000 });
    await expect(page.locator('.g-recaptcha [data-kiwi-retry]')).toBeVisible({ timeout: 15_000 });
  });

  test('the provider alias and the native token carry the SAME credential', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    const native = await waitVerified(page, 'kiwi__token');
    const alias = await page.locator('input[name="g-recaptcha-response"]').inputValue();
    expect(alias).toBe(native);
  });

  test('Turnstile execution=execute: render registers a pending widget, zero challenge hits until execute(id), getResponse works', async ({ page }) => {
    // Cloudflare's explicit-execution model: with execution "execute" the
    // widget renders and registers but does NOT start a challenge — the
    // widget carries data-state "pending" (distinct from "idle") and no
    // **/challenge request may fire until turnstile.execute().
    let challengeHits = 0;
    await page.route('**/challenge', async (route) => {
      challengeHits++;
      await route.continue();
    });
    await page.goto('/migration/turnstile.html');
    await expect(page.locator('input[name="cf-turnstile-response"]')).not.toHaveValue('', { timeout: 60_000 });
    const baseline = challengeHits;
    expect(baseline).toBeGreaterThan(0);
    const id = await page.evaluate(() => {
      const el = document.createElement('div');
      el.id = 'ts-exec';
      el.className = 'cf-turnstile';
      el.setAttribute('data-sitekey', '0x4AAAAAAABC');
      document.body.appendChild(el);
      return window.turnstile.render(el, { sitekey: '0x4AAAAAAABC', execution: 'execute' });
    });
    expect(typeof id).toBe('string');
    await expect(page.locator('#ts-exec [data-kiwi-widget]')).toHaveAttribute('data-state', 'pending');
    await page.waitForTimeout(2500);
    expect(challengeHits, 'a pending execution=execute widget must issue ZERO challenge requests').toBe(baseline);
    const token = await page.evaluate(async (wid) => window.turnstile.execute(wid), id);
    expect(token.length).toBeGreaterThan(10);
    expect(challengeHits).toBeGreaterThan(baseline);
    const response = await page.evaluate((wid) => window.turnstile.getResponse(wid), id);
    expect(response).toBe(token);
  });

  test('Turnstile execution=execute: execute(container-id) and execute(selector) resolve and fire', async ({ page }) => {
    // String arguments resolve as a widget id first, then an element id,
    // then a selector matching an existing .cf-turnstile container.
    await page.goto('/migration/turnstile.html');
    await expect(page.locator('input[name="cf-turnstile-response"]')).not.toHaveValue('', { timeout: 60_000 });
    const setup = await page.evaluate(() => {
      // Drop the implicit widget so '.cf-turnstile' matches only ours.
      window.turnstile.remove();
      const el = document.createElement('div');
      el.id = 'ts-sel';
      el.className = 'cf-turnstile';
      el.setAttribute('data-sitekey', '0x4AAAAAAABC');
      document.body.appendChild(el);
      const id = window.turnstile.render(el, { sitekey: '0x4AAAAAAABC', execution: 'execute' });
      return id;
    });
    await expect(page.locator('#ts-sel [data-kiwi-widget]')).toHaveAttribute('data-state', 'pending');
    const viaSelector = await page.evaluate(async () => window.turnstile.execute('.cf-turnstile'));
    expect(viaSelector.length).toBeGreaterThan(10);
    expect(await page.evaluate((wid) => window.turnstile.getResponse(wid), setup)).toBe(viaSelector);

    const setup2 = await page.evaluate(() => {
      const el = document.createElement('div');
      el.id = 'ts-el';
      el.className = 'cf-turnstile';
      el.setAttribute('data-sitekey', '0x4AAAAAAABC');
      document.body.appendChild(el);
      return window.turnstile.render(el, { sitekey: '0x4AAAAAAABC', execution: 'execute' });
    });
    await expect(page.locator('#ts-el [data-kiwi-widget]')).toHaveAttribute('data-state', 'pending');
    const viaId = await page.evaluate(async () => window.turnstile.execute('ts-el'));
    expect(viaId.length).toBeGreaterThan(10);
    expect(await page.evaluate((wid) => window.turnstile.getResponse(wid), setup2)).toBe(viaId);
  });

  test('Turnstile execution=auto (default) still auto-solves without execute()', async ({ page }) => {
    // execution "auto" (and the absent option) keeps the incumbent
    // auto-solving behavior — the challenge starts at render.
    await page.goto('/migration/turnstile.html');
    await expect(page.locator('input[name="cf-turnstile-response"]')).not.toHaveValue('', { timeout: 60_000 });
    const id = await page.evaluate(() => {
      const el = document.createElement('div');
      el.id = 'ts-auto';
      el.className = 'cf-turnstile';
      el.setAttribute('data-sitekey', '0x4AAAAAAABC');
      document.body.appendChild(el);
      return window.turnstile.render(el, { sitekey: '0x4AAAAAAABC', execution: 'auto' });
    });
    await page.waitForFunction((wid) => window.turnstile.getResponse(wid).length > 10, id, { timeout: 60_000 });
    await expect(page.locator('#ts-auto [data-kiwi-widget]')).toHaveAttribute('data-state', 'done');
  });

  test('hCaptcha: getRespKey returns a distinct, stable, non-empty per-widget key, never the token', async ({ page }) => {
    await page.goto('/migration/hcaptcha.html');
    const token = await waitVerified(page, 'h-captcha-response');
    const result = await page.evaluate(() => {
      const first = document.querySelector('.h-captcha').dataset.kiwiInstance;
      const keyNoArg = window.hcaptcha.getRespKey();
      const keyById = window.hcaptcha.getRespKey(first);
      const el = document.createElement('div');
      el.id = 'hcap-2';
      document.body.appendChild(el);
      const id2 = window.hcaptcha.render(el, { sitekey: '10000000-aaaa-bbbb-cccc-000000000001' });
      const key2 = window.hcaptcha.getRespKey(id2);
      const token1 = window.hcaptcha.getResponse(first);
      return { first, keyNoArg, keyById, id2, key2, token1 };
    });
    expect(result.keyNoArg).toBeTruthy();
    expect(result.keyNoArg).toMatch(/^hkey-/);
    expect(result.keyNoArg).toBe(result.keyById);
    expect(result.keyNoArg).not.toBe(result.token1);
    expect(result.key2).toBeTruthy();
    expect(result.key2).not.toBe(result.keyNoArg);
    expect(token).toBe(result.token1);
  });

  test('hCaptcha async execute resolves {response, key} with key === getRespKey(id)', async ({ page }) => {
    await page.goto('/migration/hcaptcha.html');
    await waitVerified(page, 'h-captcha-response');
    const result = await page.evaluate(async () => {
      const first = document.querySelector('.h-captcha').dataset.kiwiInstance;
      const token = window.hcaptcha.getResponse(first);
      const asyncRes = await window.hcaptcha.execute(first, { async: true });
      const bare = await window.hcaptcha.execute(first);
      return { token, asyncRes, bare, key: window.hcaptcha.getRespKey(first) };
    });
    expect(result.asyncRes).toEqual({ response: result.token, key: result.key });
    expect(result.asyncRes.key).toBe(result.key);
    expect(result.asyncRes.response).toBe(result.token);
    expect(result.asyncRes.response).not.toBe(result.key);
    expect(result.bare).toBe(result.token);
  });

  test('hCaptcha async execute(undefined) resolves {response, key} against the FIRST created widget', async ({ page }) => {
    // widgetID is optional in the incumbent API: with no argument the
    // async form targets the first created widget and resolves the
    // {response, key} pair — key === getRespKey() on the same default.
    await page.goto('/migration/hcaptcha.html');
    await waitVerified(page, 'h-captcha-response');
    const result = await page.evaluate(async () => {
      const token = window.hcaptcha.getResponse();
      const asyncRes = await window.hcaptcha.execute(undefined, { async: true });
      return { token, asyncRes, key: window.hcaptcha.getRespKey() };
    });
    expect(result.asyncRes).toEqual({ response: result.token, key: result.key });
    expect(result.asyncRes.key).toBe(result.key);
    expect(result.asyncRes.response).toBe(result.token);
    expect(result.asyncRes.response).not.toBe(result.key);
  });

  test('hCaptcha async execute(undefined) rejects with the STRING "missing-captcha" when no widget exists', async ({ page }) => {
    // A page that loads the hCaptcha compat API but never renders a
    // widget: the fixture's .h-captcha container is removed before the
    // driver's implicit render runs, so no first widget exists and the
    // async form rejects with the incumbent's "missing-captcha" string —
    // never an Error object.
    await page.addInitScript(() => {
      document.addEventListener('DOMContentLoaded', () => {
        const el = document.querySelector('.h-captcha');
        if (el) el.remove();
      });
    });
    await page.goto('/migration/hcaptcha.html');
    const result = await page.evaluate(async () => {
      try {
        await window.hcaptcha.execute(undefined, { async: true });
        return { rejected: false, code: null };
      } catch (code) {
        return { rejected: true, code };
      }
    });
    expect(result.rejected).toBe(true);
    expect(typeof result.code).toBe('string');
    expect(result.code).toBe('missing-captcha');
  });

  test('hCaptcha async execute(non-resolving target) rejects with the STRING "invalid-captcha-id"', async ({ page }) => {
    // A string that is not a widget id, element id or container selector
    // rejects with the incumbent's "invalid-captcha-id" string — never
    // an Error object — even while a widget exists.
    await page.goto('/migration/hcaptcha.html');
    await waitVerified(page, 'h-captcha-response');
    const result = await page.evaluate(async () => {
      try {
        await window.hcaptcha.execute('definitely-not-a-widget', { async: true });
        return { rejected: false, code: null };
      } catch (code) {
        return { rejected: true, code };
      }
    });
    expect(result.rejected).toBe(true);
    expect(typeof result.code).toBe('string');
    expect(result.code).toBe('invalid-captcha-id');
  });

  test('hCaptcha async execute rejects with the STRING "network-error" when the challenge endpoint fails', async ({ page }) => {
    // Mapping: a non-2xx challenge response (status >= 400), an aborted
    // fetch (AbortError) and a fetch transport TypeError all reject with
    // the incumbent's "network-error" string — an Error object is never
    // surfaced through the async form.
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
    });
    await page.goto('/migration/hcaptcha.html');
    const result = await page.evaluate(async () => {
      const first = document.querySelector('.h-captcha').dataset.kiwiInstance;
      try {
        await window.hcaptcha.execute(first, { async: true });
        return { rejected: false, code: null };
      } catch (code) {
        return { rejected: true, code };
      }
    });
    expect(result.rejected).toBe(true);
    expect(typeof result.code).toBe('string');
    expect(result.code).toBe('network-error');
  });

  test('hCaptcha async execute rejects with the STRING "challenge-error" on a malformed challenge payload', async ({ page }) => {
    // Mapping: a 200 response whose body is not parseable JSON is a
    // challenge-content failure (the payload never yields a challenge) ->
    // "challenge-error"; downgraded challenges and exhausted solves map
    // the same way.
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{not-json' });
    });
    await page.goto('/migration/hcaptcha.html');
    const result = await page.evaluate(async () => {
      const first = document.querySelector('.h-captcha').dataset.kiwiInstance;
      try {
        await window.hcaptcha.execute(first, { async: true });
        return { rejected: false, code: null };
      } catch (code) {
        return { rejected: true, code };
      }
    });
    expect(result.rejected).toBe(true);
    expect(typeof result.code).toBe('string');
    expect(result.code).toBe('challenge-error');
  });

  test('hCaptcha BARE execute still rejects with an Error object on failure', async ({ page }) => {
    // The error-code normalization applies only to the async form — the
    // bare (non-async) execute keeps the native Error-object rejection.
    await page.route('**/challenge', async (route) => {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
    });
    await page.goto('/migration/hcaptcha.html');
    const result = await page.evaluate(async () => {
      const first = document.querySelector('.h-captcha').dataset.kiwiInstance;
      try {
        await window.hcaptcha.execute(first);
        return { rejected: false, isError: false, message: '' };
      } catch (err) {
        return { rejected: true, isError: err instanceof Error, message: String(err && err.message) };
      }
    });
    expect(result.rejected).toBe(true);
    expect(result.isError).toBe(true);
    expect(result.message).toContain('Challenge failed');
  });
});
