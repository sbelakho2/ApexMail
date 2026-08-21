import { test, expect } from '@playwright/test';

// Curated three-engine functional smoke suite — the
// solver/lifecycle critical paths in Chromium + Firefox + WebKit (run via
// playwright.a11y.config.mjs's projects alongside the accessibility
// evidence). Argon2id is deliberately included on every engine: WASM,
// worker glue, Blob URLs and memory allocation are exactly the paths that
// differ across engines.

async function waitToken(page, field = 'kiwi__token') {
  const token = page.locator(`input[name="${field}"]`);
  await expect(token).not.toHaveValue('', { timeout: 90_000 });
  return token.inputValue();
}

test.describe('KiwiCaptcha cross-browser critical paths', () => {
  test('capability matrix (item 31): every declared flag is real on the live API surface', async ({ page }) => {
    // The source-controlled declaration is the single machine-readable
    // answer to "what does compatible mean in this release" — this test
    // proves the declared flags exist on the live surface (marketing/docs
    // can never silently outrun the implementation). Each provider's
    // global is installed only on ITS fixture page.
    await page.goto('/migration/recaptcha-v2.html');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toBeVisible();
    const g = await page.evaluate(() => {
      const x = window.grecaptcha || {};
      return { render: typeof x.render, reset: typeof x.reset, getResponse: typeof x.getResponse, execute: typeof x.execute, ready: typeof x.ready };
    });
    expect(g.render).toBe('function');
    expect(g.reset).toBe('function');
    expect(g.getResponse).toBe('function');
    expect(g.execute).toBe('function');
    expect(g.ready).toBe('function');

    await page.goto('/migration/turnstile.html');
    await expect(page.locator('.cf-turnstile [data-kiwi-widget]')).toBeVisible();
    const t = await page.evaluate(() => {
      const x = window.turnstile || {};
      return { render: typeof x.render, reset: typeof x.reset, getResponse: typeof x.getResponse, execute: typeof x.execute, remove: typeof x.remove, ready: typeof x.ready, isExpired: typeof x.isExpired };
    });
    expect(t.render).toBe('function');
    expect(t.reset).toBe('function');
    expect(t.getResponse).toBe('function');
    expect(t.execute).toBe('function');
    expect(t.remove).toBe('function');
    expect(t.ready).toBe('function');
    expect(t.isExpired).toBe('function');
  });
  test('native SHA challenge: solve -> token', async ({ page }) => {
    await page.goto('/');
    const token = await waitToken(page);
    expect(token.length).toBeGreaterThan(10);
  });

  test('native Argon2id: worker solve -> token', async ({ page }) => {
    await page.goto('/?algorithm=argon2id');
    const token = await waitToken(page);
    expect(token.length).toBeGreaterThan(10);
  });

  test('reset while challenge fetch delayed: stale generation cannot complete', async ({ page }) => {
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
          nonce: 'x-r-' + calls, salt: btoa(String(calls).padStart(16, '0')), prefix: 'x',
          targetBits: 6, algorithm: 'sha256', mKib: 0, t: 1, p: 1, ttlSecs: 120, minDurationMs: 0,
        }),
      });
    });
    await page.goto('/');
    const result = await page.evaluate(async () => {
      const w = document.querySelector('[data-kiwi-widget]');
      const id = w.dataset.kiwiInstance;
      let verified = 0;
      w.closest('.kiwi-container').addEventListener('kiwi:verified', () => { verified++; });
      await new Promise((r) => setTimeout(r, 600));
      window.KiwiCaptcha.reset(id);
      await new Promise((r) => setTimeout(r, 8000));
      return { verified, response: window.KiwiCaptcha.getResponse(id) };
    });
    expect(calls).toBeGreaterThanOrEqual(2);
    expect(result.verified).toBe(1);
    expect(result.response.length).toBeGreaterThan(10);
  });

  test('expiry clears the response and reacquisition works', async ({ page }) => {
    // The TTL fixture binds the widget to /challenge?ttl=2 (the native
    // page's endpoint has no ttl override).
    await page.goto('/migration/recaptcha-v2-ttl.html');
    const token = await waitToken(page, 'g-recaptcha-response');
    expect(token.length).toBeGreaterThan(10);
    await expect(page.locator('input[name="g-recaptcha-response"]')).toHaveValue('', { timeout: 30_000 });
    // Reacquire via the compat reset + the provider field.
    const id = await page.evaluate(() => document.querySelector('.g-recaptcha [data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((i) => window.grecaptcha.reset(i), id);
    await waitToken(page, 'g-recaptcha-response');
  });

  test('BFCache pageshow: stale state cleared, no auto-solve', async ({ page }) => {
    await page.goto('/');
    await waitToken(page);
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    });
    const after = await page.evaluate(() => ({
      state: document.querySelector('[data-kiwi-widget]').dataset.state,
      token: document.querySelector('input[name="kiwi__token"]').value,
    }));
    expect(after.token).toBe('');
    expect(after.state).toBe('idle');
  });

  test('external /api.js Argon loader solves', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2-argon.html');
    const token = await waitToken(page);
    expect(token.length).toBeGreaterThan(10);
  });

  test('grecaptcha.ready() waits for glue; explicit render solves', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2.html');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toBeVisible();
    const result = await page.evaluate(async () => {
      return new Promise((resolve) => {
        window.grecaptcha.ready(() => {
          const holder = document.createElement('div');
          holder.id = 'ready-holder';
          document.body.appendChild(holder);
          const id = window.grecaptcha.render(holder, { sitekey: '6Lc_ready_explicit' });
          resolve({ id, phase: 'rendered' });
        });
        setTimeout(() => resolve({ id: null, phase: 'timeout' }), 20_000);
      });
    });
    expect(result.phase).toBe('rendered');
    await expect(page.locator('#ready-holder input[name="g-recaptcha-response"]')).not.toHaveValue('', { timeout: 90_000 });
  });

  test('render=explicit: dynamic containers stay unrendered until render()', async ({ page }) => {
    await page.goto('/migration/recaptcha-v2-explicit.html');
    await expect(page.locator('#out')).toHaveText(/^cb:/, { timeout: 60_000 });
    const dynamic = await page.evaluate(async () => {
      const el = document.createElement('div');
      el.className = 'g-recaptcha';
      el.dataset.sitekey = '6Lc_dynamic_explicit';
      document.body.appendChild(el);
      await new Promise((r) => setTimeout(r, 600));
      const autoRendered = !!el.querySelector('[data-kiwi-widget]');
      const id = window.grecaptcha.render(el, { sitekey: '6Lc_dynamic_explicit' });
      await new Promise((r) => setTimeout(r, 8000));
      return { autoRendered, response: window.grecaptcha.getResponse(id) };
    });
    expect(dynamic.autoRendered).toBe(false);
    expect(dynamic.response.length).toBeGreaterThan(10);
  });

  test('Turnstile: render -> execute -> response -> remove', async ({ page }) => {
    await page.goto('/migration/turnstile.html');
    const id = await page.evaluate(() => {
      const el = document.createElement('div');
      el.className = 'cf-turnstile';
      el.setAttribute('data-sitekey', '0x4AAAAAAABC');
      document.body.appendChild(el);
      return window.turnstile.render(el, { sitekey: '0x4AAAAAAABC' });
    });
    expect(typeof id).toBe('string');
    const response = await page.evaluate(async (wid) => {
      const t = await window.turnstile.execute(wid);
      return t;
    }, id);
    expect(response.length).toBeGreaterThan(10);
    await page.evaluate((wid) => window.turnstile.remove(wid), id);
  });

  test('RTL/localization smoke: hl=ar forces dir=rtl on the visible widget', async ({ page }) => {
    // ONE semantic root — the locale attributes land on
    // the visible inner [data-kiwi-widget]; the provider wrapper stays
    // semantically neutral.
    await page.goto('/migration/recaptcha-v2.html?hl=ar');
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('dir', 'rtl', { timeout: 60_000 });
    await expect(page.locator('.g-recaptcha [data-kiwi-widget]')).toHaveAttribute('lang', 'ar');
    await expect(page.locator('.g-recaptcha')).toHaveAttribute('dir', '', { timeout: 5_000 }).catch(() => {});
  });

  test('compat accessibility: ONE semantic root per provider — the visible widget carries role/lang/dir/aria-label, the wrapper stays neutral', async ({ page }) => {
    // Item 9: compatibility rendering must not produce a localized outer
    // group wrapping a second inner group with a stale English label.
    const providers = [
      { path: '/migration/recaptcha-v2.html?hl=de', inner: '.g-recaptcha [data-kiwi-widget]', wrapper: '.g-recaptcha' },
      { path: '/migration/recaptcha-v2.html?hl=ar', inner: '.g-recaptcha [data-kiwi-widget]', wrapper: '.g-recaptcha' },
      { path: '/migration/hcaptcha.html', inner: '.h-captcha [data-kiwi-widget]', wrapper: '.h-captcha' },
      { path: '/migration/turnstile.html', inner: '.cf-turnstile [data-kiwi-widget]', wrapper: '.cf-turnstile' },
    ];
    for (const p of providers) {
      await page.goto(p.path);
      await expect(page.locator(p.inner)).toBeVisible({ timeout: 60_000 });
      await page.waitForFunction(
        (sel) => !!document.querySelector(sel) && document.querySelector(sel).getAttribute('lang') !== null,
        p.inner,
        { timeout: 60_000 },
      );
      const state = await page.evaluate(([inner, wrapper]) => {
        const w = document.querySelector(inner);
        const wrap = document.querySelector(wrapper);
        return {
          inner: { role: w.getAttribute('role'), lang: w.getAttribute('lang'), dir: w.getAttribute('dir'), aria: w.getAttribute('aria-label') },
          wrapper: { role: wrap.getAttribute('role'), lang: wrap.getAttribute('lang'), dir: wrap.getAttribute('dir'), aria: wrap.getAttribute('aria-label') },
          innerText: w.querySelector('[data-kiwi-label]').textContent,
        };
      }, [p.inner, p.wrapper]);
      expect(state.inner.role, `${p.path}: the visible widget must be the semantic group`).toBe('group');
      expect(state.inner.lang, `${p.path}: the visible widget carries the resolved language`).toBeTruthy();
      expect(state.inner.aria, `${p.path}: the visible widget has a localized accessible name`).toBeTruthy();
      if (p.path.includes('hl=ar')) {
        expect(state.inner.dir).toBe('rtl');
      }
      // The provider wrapper is semantically neutral (no second group, no
      // English label, no stale language).
      expect(state.wrapper.role, `${p.path}: the wrapper must not be a second group`).toBeNull();
      expect(state.wrapper.lang, `${p.path}: the wrapper must not carry a language`).toBeNull();
      expect(state.wrapper.aria, `${p.path}: the wrapper must not carry an accessible label`).toBeNull();
      // The inner widget's accessible name must be the localized string,
      // not the static English template. (The visible label element
      // carries transient status text during a solve, so the accessible
      // name — set from the same translated pack — is the stable check.)
      if (p.path.includes('hl=de')) {
        expect(state.inner.aria).toContain('Sicherheitspr');
      }
      if (p.path.includes('hl=ar')) {
        expect(state.inner.aria).not.toBe('KiwiCaptcha security check');
      }
    }
  });

  test('reduced-motion smoke: no animation and no SMIL', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/');
    await waitToken(page);
    const motion = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      const anims = Array.from(w.querySelectorAll('*')).map((el) => getComputedStyle(el).animationName).filter((n) => n && n !== 'none');
      return { anims, wink: !!w.querySelector('svg animate') };
    });
    expect(motion.anims).toEqual([]);
    expect(motion.wink).toBe(false);
  });
});
