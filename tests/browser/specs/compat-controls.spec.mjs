import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

// The provider-control compatibility architecture.
//
// Invisible-class controls (a button, an input, or
// data-size="invisible") default to deferred execution: the challenge
// starts only when the control is activated, exactly like the
// incumbent invisible reCAPTCHA, and never at page render. The Kiwi
// tree renders into a Kiwi-owned holder adjacent to the control, so a
// void input or an interactive button (the host of Kiwi's native Retry
// control) never contains nested interactive content. The owned
// bindings resolve render/reset/execute/remove, and dynamic insertion
// renders and binds every nested container.
//
// Runs in Chromium, Firefox and WebKit via playwright.a11y.config.mjs
// (and in the default Chromium config too).

const AXE_RULES = [
  'color-contrast', 'aria-allowed-attr', 'aria-hidden-body', 'aria-hidden-focus',
  'aria-progressbar-name', 'button-name', 'focus-order-semantics', 'html-has-lang',
  'label', 'link-in-text-block', 'select-name', 'valid-lang', 'document-title',
];

function collectChallenges(page) {
  const urls = [];
  page.on('request', (req) => {
    if (req.url().includes('/kiwi-captcha/challenge')) urls.push(req.url());
  });
  return urls;
}

async function compatReady(page) {
  await page.waitForFunction(() => window.grecaptcha && typeof window.grecaptcha.execute === 'function');
}

test.describe('KiwiCaptcha provider-control compatibility', () => {
  test('invisible button: the challenge waits for the click, then runs exactly once', async ({ page }) => {
    const challenges = collectChallenges(page);
    await page.goto('/migration/recaptcha-invisible.html');
    const button = page.locator('button.g-recaptcha');
    const widget = page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });

    // Well beyond any normal SHA-256 solve time: nothing may have
    // started, no token may exist, no callback may have fired.
    await page.waitForTimeout(3000);
    expect(challenges.length, 'no challenge may be requested before activation').toBe(0);
    await expect(page.locator('input[name="g-recaptcha-response"]')).toHaveValue('');
    await expect(page.locator('#out')).toHaveText('');

    await button.click();
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    expect(challenges.length, 'exactly one challenge after activation').toBe(1);
    const token = await page.locator('input[name="g-recaptcha-response"]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('button control: the widget lives in an adjacent holder and the full provider surface works', async ({ page }) => {
    const challenges = collectChallenges(page);
    await page.goto('/migration/recaptcha-button.html');
    const control = page.locator('button.g-recaptcha');
    const widget = page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });

    // The control is never a Kiwi container: no widget and, above all,
    // no interactive content (Kiwi's Retry button) nested inside it.
    expect(await control.locator('[data-kiwi-widget]').count()).toBe(0);
    expect(await control.locator('button').count()).toBe(0);
    expect((await control.textContent()).trim()).toBe('Sign in');

    // render() on the already-rendered control returns the same id.
    const ids = await page.evaluate(() => {
      const el = document.querySelector('button.g-recaptcha');
      return { first: window.grecaptcha.render(el), again: window.grecaptcha.render(el) };
    });
    expect(ids.again).toBe(ids.first);
    const id = ids.first;

    await page.evaluate((widgetId) => window.grecaptcha.reset(widgetId), id);
    await expect(widget).toHaveAttribute('data-state', 'pending');
    await page.evaluate((widgetId) => window.grecaptcha.execute(widgetId), id);
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    expect(challenges.length).toBe(1);

    await page.evaluate((widgetId) => window.grecaptcha.remove(widgetId), id);
    await expect(page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]')).toHaveCount(0);
    expect(await control.count(), 'the provider control survives remove()').toBe(1);
    expect((await control.textContent()).trim()).toBe('Sign in');

    // The owned activation listener left with the widget: clicking the
    // control after remove() starts nothing.
    await control.click();
    await page.waitForTimeout(500);
    expect(challenges.length, 'a removed widget must not answer clicks').toBe(1);

    // Re-render through the provider API after remove(): a fresh widget.
    const reRendered = await page.evaluate(() => window.grecaptcha.render(document.querySelector('button.g-recaptcha')));
    expect(reRendered).not.toBe(0);
    await expect(page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]')).toHaveAttribute('data-state', 'pending');
  });

  test('submit input: the control keeps its semantics and the holder carries the widget', async ({ page }) => {
    await page.goto('/migration/recaptcha-input.html');
    const control = page.locator('input.g-recaptcha');
    const widget = page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });

    expect(await control.getAttribute('type')).toBe('submit');
    expect(await control.getAttribute('value')).toBe('Sign in');
    // The input is void: it cannot contain the widget at all.
    expect(await control.locator('[data-kiwi-widget]').count()).toBe(0);

    await control.click();
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await page.locator('input[name="g-recaptcha-response"]').inputValue();
    expect(token.length).toBeGreaterThan(0);
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));
  });

  test('dynamic insertion: nested subtrees, multiple widgets, reinsertion and a late invisible control', async ({ page }) => {
    const challenges = collectChallenges(page);
    await page.goto('/migration/recaptcha-v2.html');
    await compatReady(page);
    const initial = await page.locator('[data-kiwi-widget]').count();

    // A framework inserting a subtree: the observer must find the
    // containers nested inside the added top-level node, and render
    // several of them from one insertion.
    await page.evaluate(() => {
      const section = document.createElement('section');
      section.id = 'dynamic-subtree';
      section.innerHTML = '<div><div class="g-recaptcha" data-sitekey="6Lc_dyn_one"></div>'
        + '<div class="g-recaptcha" data-sitekey="6Lc_dyn_two"></div></div>';
      document.body.appendChild(section);
    });
    await expect(page.locator('#dynamic-subtree .g-recaptcha [data-kiwi-widget]')).toHaveCount(2, { timeout: 30_000 });

    // Removal and reinsertion of the same subtree keeps the rendered
    // widget (idempotent render, no duplicate).
    await page.evaluate(() => {
      const section = document.getElementById('dynamic-subtree');
      section.remove();
      document.body.appendChild(section);
    });
    await expect(page.locator('#dynamic-subtree .g-recaptcha [data-kiwi-widget]')).toHaveCount(2);

    // A dynamically added invisible button gets the same deferred
    // render and the same owned activation listener as a static one.
    await page.evaluate(() => {
      const button = document.createElement('button');
      button.className = 'g-recaptcha';
      button.type = 'button';
      button.textContent = 'Dynamic sign in';
      button.setAttribute('data-sitekey', '6Lc_dyn_three');
      button.id = 'dynamic-invisible';
      document.body.appendChild(button);
    });
    const dynamicWidget = page.locator('#dynamic-invisible + [data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(dynamicWidget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });
    const before = challenges.length;
    await page.locator('#dynamic-invisible').click();
    await expect(dynamicWidget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    expect(challenges.length, 'the dynamically bound control starts exactly one challenge').toBe(before + 1);

    expect(await page.locator('[data-kiwi-widget]').count()).toBe(initial + 3);
  });

  test('axe: the control migration pages pass the widget-scope rules', async ({ page }) => {
    for (const path of ['/migration/recaptcha-button.html', '/migration/recaptcha-input.html', '/migration/recaptcha-invisible.html']) {
      await page.goto(path);
      await expect(page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]')).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });
      const results = await new AxeBuilder({ page })
        .include('[data-kiwi-compat-holder]')
        .withRules(AXE_RULES)
        .analyze();
      expect(results.violations, `${path}: ${JSON.stringify(results.violations.map((v) => v.id))}`).toEqual([]);
    }
  });

  test('settled execute() promises retire their cancellation hooks', async ({ page }) => {
    await page.goto('/migration/recaptcha-button.html');
    const widget = page.locator('[data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });
    const id = await page.locator('[data-kiwi-compat-holder]').first().evaluate((el) => el.dataset.kiwiInstance);
    expect(typeof id).toBe('string');

    // One deferred solve fanned out into hundreds of execute() callers:
    // every settled promise must remove its own cancellation hook, so
    // the record retains none after completion.
    const result = await page.evaluate(async (widgetId) => {
      const promises = [];
      for (let i = 0; i < 300; i++) promises.push(window.grecaptcha.execute(widgetId));
      const tokens = await Promise.all(promises);
      const record = window.__kiwiCaptchaCore.core.record(widgetId);
      return {
        unique: new Set(tokens).size,
        first: tokens[0],
        pending: record ? record.pendingExecute : 'no-record',
      };
    }, id);
    expect(result.unique, 'all callers must observe the same solution token').toBe(1);
    expect(result.first.length).toBeGreaterThan(0);
    expect(result.pending === null || (Array.isArray(result.pending) && result.pending.length === 0)).toBe(true);
  });
});

// The standalone provider shims (widget-shims.js over a plain driver
// bootstrap, no compat loader): the incumbent globals exist for
// application code, the Altcha and Friendly Captcha element conventions
// keep working, and every shim token redeems on the real verify
// endpoint.
//
// Runs in Chromium, Firefox and WebKit via playwright.a11y.config.mjs
// (and in the default Chromium config too).

function collectShimChallenges(page) {
  const bodies = [];
  page.on('request', (req) => {
    if (req.url().includes('/challenge') && req.method() === 'POST') {
      try { bodies.push(req.postDataJSON() ?? {}); } catch { bodies.push({}); }
    }
  });
  return bodies;
}

async function shimsReady(page) {
  await page.waitForFunction(
    () => window.grecaptcha && window.hcaptcha && window.turnstile
      && typeof window.grecaptcha.render === 'function',
    undefined,
    { timeout: 30_000 },
  );
}

test.describe('KiwiCaptcha standalone provider shims', () => {
  test('grecaptcha: render auto-solves, the response field and the token field agree, getResponse and reset round-trip', async ({ page, request }) => {
    await page.goto('/migration/shims-recaptcha.html');
    await shimsReady(page);
    await page.evaluate(() => {
      window.shimId = window.grecaptcha.render(document.getElementById('shim-box'), {
        sitekey: '6Lc_shim_v2',
        callback: 'onShimToken',
        'expired-callback': 'onShimExpired',
      });
    });
    const widget = page.locator('#shim-box [data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });

    const token = await page.locator('textarea#g-recaptcha-response').inputValue();
    expect(token.length).toBeGreaterThan(10);
    // The kiwi token field carries the same solution, so a backend
    // reading either field sees one proof.
    await expect(page.locator('input[name="kiwi__token"]')).toHaveValue(token);
    await expect(page.locator('#out')).toHaveText('cb:' + token.slice(0, 8));

    // getResponse by id, by creation-order number and by the omitted
    // default all answer the same widget.
    const responses = await page.evaluate((id) => ({
      byId: window.grecaptcha.getResponse(id),
      byIndex: window.grecaptcha.getResponse(0),
      noArg: window.grecaptcha.getResponse(),
    }), await page.evaluate(() => window.shimId));
    expect(responses.byId).toBe(token);
    expect(responses.byIndex).toBe(token);
    expect(responses.noArg).toBe(token);

    // The challenge carried the mapped scope and the verbatim sitekey.
    const verified = await request.post('/verify', { data: { token, scope: 'login' } });
    expect((await verified.json()).ok, 'the shim token must redeem on the real endpoint').toBe(true);

    // Capture the cleared fields in the reset call: this visible widget
    // auto-solves again, so a later locator poll can see the fresh token.
    const cleared = await page.evaluate((id) => {
      window.grecaptcha.reset(id);
      return {
        response: document.getElementById('g-recaptcha-response').value,
        token: document.querySelector('#shim-box input[name="kiwi__token"]').value,
        api: window.grecaptcha.getResponse(id),
      };
    }, await page.evaluate(() => window.shimId));
    expect(cleared).toEqual({ response: '', token: '', api: '' });
    const second = await page.evaluate(async (id) => {
      const next = await window.grecaptcha.execute(id);
      return { next, after: window.grecaptcha.getResponse(id) };
    }, await page.evaluate(() => window.shimId));
    expect(second.next.length).toBeGreaterThan(10);
    expect(second.next).not.toBe(token);
    expect(second.after).toBe(second.next);
    const reverified = await request.post('/verify', { data: { token: second.next, scope: 'login' } });
    expect((await reverified.json()).ok).toBe(true);
  });

  test('grecaptcha: the sitekey table knob resolves the scope and an invisible control defers to execute', async ({ page, request }) => {
    const bodies = collectShimChallenges(page);
    await page.goto('/migration/shims-recaptcha.html');
    await shimsReady(page);

    // The page table maps this sitekey to the signup scope; the request
    // must present that scope, not the verbatim key. The map box carries
    // no explicit scope knob, so the table decides.
    await page.evaluate(() => {
      window.mappedId = window.grecaptcha.render(document.getElementById('map-box'), { sitekey: '6Lc_shim_map' });
    });
    await expect(page.locator('#map-box [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const mappedToken = await page.locator('textarea#g-recaptcha-response').inputValue();
    const mapped = await request.post('/verify', { data: { token: mappedToken, scope: 'signup' } });
    expect((await mapped.json()).ok, 'the mapped scope must be the minted scope').toBe(true);
    expect(bodies[0].scope).toBe('signup');

    // A button control renders into an adjacent holder and waits for
    // execute(), exactly like the incumbent invisible control.
    const before = bodies.length;
    await page.evaluate(() => {
      window.controlId = window.grecaptcha.render(document.getElementById('invisible-go'));
    });
    const controlWidget = page.locator('#invisible-go + [data-kiwi-compat-holder] [data-kiwi-widget]');
    await expect(controlWidget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });
    await page.waitForTimeout(1500);
    expect(bodies.length, 'a control widget defers its challenge until execute').toBe(before);
    const controlToken = await page.evaluate(async (id) => {
      const value = await window.grecaptcha.execute(id);
      return { value, response: window.grecaptcha.getResponse(id) };
    }, await page.evaluate(() => window.controlId));
    await expect(controlWidget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    expect(controlToken.value.length).toBeGreaterThan(10);
    expect(controlToken.response).toBe(controlToken.value);
    expect(await page.locator('#invisible-go [data-kiwi-widget]').count(), 'no interactive content nests in the control').toBe(0);
  });

  test('grecaptcha v3: execute(sitekey, action) solves a hidden widget and cleans it up', async ({ page, request }) => {
    const bodies = collectShimChallenges(page);
    await page.goto('/migration/shims-recaptcha.html');
    await shimsReady(page);
    const token = await page.evaluate(() => window.grecaptcha.execute('6Lc_shim_v3', { action: 'checkout' }));
    expect(token.length).toBeGreaterThan(10);
    expect(bodies.length).toBe(1);
    expect(bodies[0].action).toBe('checkout');
    expect(bodies[0].sitekey).toBe('6Lc_shim_v3');
    // The hidden helper leaves no widget behind.
    expect(await page.locator('[data-kiwi-widget]').count()).toBe(0);
    const verified = await request.post('/verify', { data: { token, scope: 'login' } });
    expect((await verified.json()).ok).toBe(true);
  });

  test('hcaptcha: both provider response fields carry the token and the async form answers the pair', async ({ page, request }) => {
    await page.goto('/migration/shims-hcaptcha.html');
    await shimsReady(page);
    await page.evaluate(() => {
      window.hId = window.hcaptcha.render(document.getElementById('shim-box'), { sitekey: '10000000-aaaa-bbbb-cccc-000000000002' });
    });
    await expect(page.locator('#shim-box [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const hToken = await page.locator('textarea#h-captcha-response').inputValue();
    const gToken = await page.locator('textarea#g-recaptcha-response').inputValue();
    expect(hToken.length).toBeGreaterThan(10);
    expect(gToken, 'an integration reading only the reCAPTCHA field keeps working').toBe(hToken);
    const result = await page.evaluate(async (id) => {
      const pair = await window.hcaptcha.execute(id, { async: true });
      return { pair, key: window.hcaptcha.getRespKey(id), response: window.hcaptcha.getResponse(id) };
    }, await page.evaluate(() => window.hId));
    expect(result.pair.response).toBe(hToken);
    expect(result.pair.key).toBe(result.key);
    expect(result.key.length).toBeGreaterThan(0);
    expect(result.response).toBe(hToken);
    const verified = await request.post('/verify', { data: { token: hToken, scope: 'login' } });
    expect((await verified.json()).ok).toBe(true);
  });

  test('turnstile: render starts the implicit challenge, reset re-runs and remove tears down', async ({ page, request }) => {
    const bodies = collectShimChallenges(page);
    await page.goto('/migration/shims-turnstile.html');
    await shimsReady(page);
    await page.evaluate(() => {
      window.tId = window.turnstile.render(document.getElementById('shim-box'), { sitekey: '0x4AAAAAASHIM' });
    });
    const widget = page.locator('#shim-box [data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    expect(bodies.length, 'the implicit challenge runs without execute').toBe(1);
    const token = await page.evaluate((id) => ({
      response: window.turnstile.getResponse(id),
      expired: window.turnstile.isExpired(id),
    }), await page.evaluate(() => window.tId));
    expect(token.response.length).toBeGreaterThan(10);
    expect(token.expired).toBe(false);
    const fieldToken = await page.locator('textarea#cf-turnstile-response').inputValue();
    expect(fieldToken).toBe(token.response);
    const verified = await request.post('/verify', { data: { token: token.response, scope: 'login' } });
    expect((await verified.json()).ok).toBe(true);

    // reset re-runs the implicit challenge; remove tears the widget out.
    await page.evaluate((id) => window.turnstile.reset(id), await page.evaluate(() => window.tId));
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    expect(bodies.length).toBe(2);
    await page.evaluate((id) => window.turnstile.remove(id), await page.evaluate(() => window.tId));
    await expect(page.locator('#shim-box .kiwi-container')).toHaveCount(0);
    await expect(page.locator('#shim-box [data-kiwi-widget]')).toHaveCount(0);
  });

  test('altcha markup: the altcha-widget element auto-solves into its named field', async ({ page, request }) => {
    await page.goto('/migration/shims-altcha.html');
    await expect(page.locator('altcha-widget [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await page.locator('textarea#altcha').inputValue();
    expect(token.length).toBeGreaterThan(10);
    const verified = await request.post('/verify', { data: { token, scope: 'login' } });
    expect((await verified.json()).ok, 'the Altcha convention token must redeem').toBe(true);
  });

  test('friendly markup: the frc-captcha element auto-solves into its solution field', async ({ page, request }) => {
    await page.goto('/migration/shims-friendly.html');
    await expect(page.locator('.frc-captcha [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await page.locator('textarea[name="frc-captcha-solution"]').inputValue();
    expect(token.length).toBeGreaterThan(10);
    const verified = await request.post('/verify', { data: { token, scope: 'login' } });
    expect((await verified.json()).ok, 'the Friendly Captcha convention token must redeem').toBe(true);
  });

  test('axe: the shims pages pass the widget-scope rules', async ({ page }) => {
    for (const path of ['/migration/shims-recaptcha.html', '/migration/shims-altcha.html', '/migration/shims-friendly.html']) {
      await page.goto(path);
      if (path.endsWith('shims-recaptcha.html')) {
        await shimsReady(page);
        await page.evaluate(() => window.grecaptcha.render(document.getElementById('shim-box'), { sitekey: '6Lc_shim_v2' }));
      }
      const scope = path.endsWith('shims-recaptcha.html') ? '#shim-box' : (path.endsWith('shims-altcha.html') ? 'altcha-widget' : '.frc-captcha');
      await expect(page.locator(`${scope} [data-kiwi-widget]`)).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
      const results = await new AxeBuilder({ page })
        .include(scope)
        .withRules(AXE_RULES)
        .analyze();
      expect(results.violations, `${path}: ${JSON.stringify(results.violations.map((v) => v.id))}`).toEqual([]);
    }
  });
});
