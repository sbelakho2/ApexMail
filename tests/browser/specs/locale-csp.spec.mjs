import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Direct coverage of the lazy widget-locales.js path (the non-default
// locale packs loaded on demand through a same-origin SRI-pinned script
// injection) under a real Content-Security-Policy response header. The
// fixture emits the genuine header (?csp=strict with ?assets=files):
// the documented production profile, same-origin sources only
// (script-src, style-src, connect-src and worker-src 'self'), the
// fixture inline stylesheet hash-pinned, no unsafe-inline, object-src
// 'none' and base-uri 'none'. That restrictive policy still permits
// the lazy module load: the injected script src stays same-origin and
// its SRI pin matches the bytes of the immutable content-addressed
// route. The ?csp=execution-blocked variant (hash-only script-src)
// would refuse the module; every case here drives the strict profile,
// and each page asserts which policy actually arrived.
//
// The delivery contract under test: the fixture emits
// data-kiwi-locales-src plus data-kiwi-locales-integrity on every
// widget container in both asset tiers (widget-locales.js is never
// embedded inline), and the widget core (widget-driver.js) resolves
// the widget language (options.lang, then data-kiwi-lang, then
// navigator.language), paints the English fallback while the pack is
// pending, injects the pinned same-origin script once per page (the
// per-kind module loader dedups), and re-paints the settled language
// when the module registers its packs on the internal bridge
// (window.__kiwiCaptchaCore). A failed load keeps the English
// fallback, the browser's native SRI check refuses tampered bytes,
// and the per-widget generation guards stop a settlement that lands
// after destroy or reset from touching the current widget.

const LOCALES_URL_MARKER = '/assets/locales.';

// The exact pack strings of widget-locales.js (the \u escapes are the
// pack's own encoding, kept here so the spec source stays ASCII).
const FR = {
  label: 'Contr\u00f4le de s\u00e9curit\u00e9',
  badgeDone: 'R\u00e9ussi',
  hintDone: 'Preuve de travail v\u00e9rifi\u00e9e localement.',
};
const AR = {
  label: '\u0641\u062d\u0635 \u0627\u0644\u0623\u0645\u0627\u0646',
  badgeDone: '\u0646\u0627\u062c\u062d',
};
const DE = {
  label: 'Sicherheitspr\u00fcfung',
  badgeDone: 'Erfolgreich',
};
const EN = {
  label: 'Security Check',
  badgeDone: 'Success',
};

const specDir = path.dirname(fileURLToPath(import.meta.url));

function localeAssetPath() {
  const candidates = [
    path.resolve(specDir, '../../../packages/kiwicaptcha-wasm/assets/widget-locales.js'),
    path.resolve(specDir, '../../../assets/widget-locales.js'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error('cannot locate widget-locales.js; tried ' + candidates.join(', '));
}

// The fixture origin is read from the live page, so the same spec
// serves the default chromium lane (8085) and the three-engine lane
// (8087) without a hard-coded port. Call it after a navigation.
async function fixtureOrigin(page) {
  return page.evaluate(() => window.location.origin);
}

async function verifyToken(page, origin, token) {
  const resp = await page.request.post(`${origin}/verify`, {
    data: { token, scope: 'login' },
  });
  return { status: resp.status(), body: await resp.json() };
}

// Request accounting: every widget-locales.js request of the page
// lands in the returned array. Register before the navigation.
function localeRequests(page) {
  const requests = [];
  page.on('request', (request) => {
    if (request.url().includes(LOCALES_URL_MARKER)) requests.push(request);
  });
  return requests;
}

function collectPageErrors(page) {
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  return errors;
}

test.describe('Lazy locale packs under real CSP headers (files tier)', () => {
  test('files mode, strict CSP, French: the locale asset is requested exactly once, the pack paints, the challenge solves', async ({ page }) => {
    const requests = localeRequests(page);

    const response = await page.goto('/?assets=files&csp=strict&lang=fr');
    const policy = response.headers()['content-security-policy'] || '';
    expect(policy, 'the fixture must send the strict files-tier policy').toContain("script-src 'self'");
    expect(policy, 'the strict profile must allow the same-origin challenge POST').toContain("connect-src 'self'");
    expect(policy, 'the strict files profile carries no inline allowance').not.toContain('unsafe-inline');

    // The module delivery surface: content-addressed URL plus SRI pin
    // on the container, the attributes the core reads to inject.
    const emitted = await page.evaluate(() => {
      const container = document.querySelector('.kiwi-container');
      return {
        src: container.getAttribute('data-kiwi-locales-src'),
        integrity: container.getAttribute('data-kiwi-locales-integrity'),
      };
    });
    expect(emitted.src, 'the container must emit the content-addressed locale URL').toMatch(/\/kiwi-captcha\/assets\/locales\.[0-9a-f]{64}\.js$/);
    expect(emitted.integrity, 'the container must emit the locale SRI pin').toMatch(/^sha256-[A-Za-z0-9+/]{43}=$/);

    // The French pack paints: subtree language, accessible name and
    // the visible label all carry the pack strings.
    const widget = page.locator('[data-kiwi-widget]');
    await expect(widget).toHaveAttribute('lang', 'fr');
    await expect(widget).toHaveAttribute('aria-label', FR.label);
    await expect(page.locator('[data-kiwi-label]')).toHaveText(FR.label);

    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(page.locator('[data-kiwi-label]')).toHaveText(FR.label);
    await expect(page.locator('[data-kiwi-badge]')).toHaveText(FR.badgeDone);
    await expect(page.locator('[data-kiwi-info]')).toHaveText(FR.hintDone);

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the solved widget must mint a token').toBeGreaterThan(0);
    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, `the French solve must verify (got ${result.body.code})`).toBe(true);

    expect(requests, 'one French widget must fetch the locale module exactly once').toHaveLength(1);
    expect(requests[0].resourceType(), 'the locale module must ride a script element load').toBe('script');
  });

  test('files mode, strict CSP, Arabic: the pack paints rtl under lang=ar and the challenge solves', async ({ page }) => {
    const requests = localeRequests(page);

    const response = await page.goto('/?assets=files&csp=strict&lang=ar');
    const policy = response.headers()['content-security-policy'] || '';
    expect(policy, 'the fixture must send the strict files-tier policy').toContain("script-src 'self'");

    const widget = page.locator('[data-kiwi-widget]');
    await expect(widget).toHaveAttribute('lang', 'ar');
    await expect(widget).toHaveAttribute('dir', 'rtl');
    await expect(widget).toHaveAttribute('aria-label', AR.label);
    await expect(page.locator('[data-kiwi-label]')).toHaveText(AR.label);

    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(page.locator('[data-kiwi-label]')).toHaveText(AR.label);
    await expect(page.locator('[data-kiwi-badge]')).toHaveText(AR.badgeDone);

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the solved widget must mint a token').toBeGreaterThan(0);
    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, `the Arabic solve must verify (got ${result.body.code})`).toBe(true);

    expect(requests, 'one Arabic widget must fetch the locale module exactly once').toHaveLength(1);
  });

  test('two French widgets on one page share exactly one widget-locales.js request', async ({ page }) => {
    const requests = localeRequests(page);

    await page.goto('/?assets=files&csp=strict&lang=fr&widgets=2');
    const widgets = page.locator('[data-kiwi-widget]');
    await expect(widgets.nth(0)).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(widgets.nth(1)).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(widgets.nth(0)).toHaveAttribute('lang', 'fr');
    await expect(widgets.nth(1)).toHaveAttribute('lang', 'fr');
    await expect(page.locator('[data-kiwi-label]').first()).toHaveText(FR.label);
    await expect(page.locator('[data-kiwi-label]').nth(1)).toHaveText(FR.label);

    expect(requests, 'the per-kind module dedup must hold across widgets on one page').toHaveLength(1);

    const tokens = [];
    for (const el of await page.locator('[data-kiwi-token]').all()) {
      tokens.push(await el.inputValue());
    }
    expect(new Set(tokens).size, 'each widget must mint its own token').toBe(2);
    const origin = await fixtureOrigin(page);
    for (const token of tokens) {
      const result = await verifyToken(page, origin, token);
      expect(result.body.ok, `each French solve must verify (got ${result.body.code})`).toBe(true);
    }
  });

  test('a 404 on the locale asset keeps the English fallback (lang=en) and the challenge still solves', async ({ page }) => {
    let hits = 0;
    await page.route('**/assets/locales*.js', async (route) => {
      hits++;
      await route.fulfill({
        status: 404,
        contentType: 'application/javascript',
        headers: { 'Cache-Control': 'no-store' },
        body: 'not found',
      });
    });

    await page.goto('/?assets=files&csp=strict&lang=fr');
    const widget = page.locator('[data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    // The bounded loader: the initial attempt plus two retries, then
    // the degrade-to-English path, never a translation gate. The
    // retries outlive the (ungated) solve: the flow never waits for the
    // module's bounded attempts to exhaust, so the count settles shortly
    // after the solve.
    await expect.poll(() => hits, 'the missing module must repeat through the bounded retries').toBe(3);
    await expect(widget).toHaveAttribute('lang', 'en');
    await expect(widget).toHaveAttribute('aria-label', EN.label);
    await expect(page.locator('[data-kiwi-label]')).toHaveText(EN.label);
    await expect(page.locator('[data-kiwi-badge]')).toHaveText(EN.badgeDone);
    const text = await widget.evaluate((el) => el.textContent);
    expect(text, 'no French bytes may ever paint').not.toContain('Contr\u00f4le');

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the English fallback must still solve').toBeGreaterThan(0);
    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, `the fallback solve must verify (got ${result.body.code})`).toBe(true);
  });

  test('tampered locale bytes fail the native SRI check: the pack never executes and English stays', async ({ page }) => {
    // The served body is the real module plus an appended comment: a
    // digest mismatch against the page-issued pin, yet still parseable
    // JavaScript. Only the browser's native SRI refusal stands between
    // those bytes and the DOM, so an execution would paint French and
    // fail this test loudly.
    const realBytes = fs.readFileSync(localeAssetPath(), 'utf8');
    const tampered = realBytes + '\n/* tampered suffix */\n';
    let hits = 0;
    await page.route('**/assets/locales*.js', async (route) => {
      hits++;
      await route.fulfill({
        status: 200,
        contentType: 'application/javascript',
        headers: { 'Cache-Control': 'no-store' },
        body: tampered,
      });
    });

    await page.goto('/?assets=files&csp=strict&lang=fr');
    const widget = page.locator('[data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 120_000 });

    // The bounded loader: the initial attempt plus two retries, then
    // the degrade-to-English path, never a translation gate. The
    // retries outlive the (ungated) solve: the flow never waits for the
    // module's bounded attempts to exhaust, so the count settles shortly
    // after the solve.
    await expect.poll(() => hits, 'each SRI refusal must repeat through the bounded retries').toBe(3);
    await expect(widget).toHaveAttribute('lang', 'en');
    await expect(widget).toHaveAttribute('aria-label', EN.label);
    await expect(page.locator('[data-kiwi-label]')).toHaveText(EN.label);
    const text = await widget.evaluate((el) => el.textContent);
    expect(text, 'the tampered module bytes must never execute').not.toContain('Contr\u00f4le');
    expect(text, 'the tampered module bytes must never execute').not.toContain('R\u00e9ussi');

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the English fallback must still solve').toBeGreaterThan(0);
    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, `the fallback solve must verify (got ${result.body.code})`).toBe(true);
  });

  test('destroy while the locale fetch is pending: the settlement cannot mutate the destroyed widget', async ({ page }) => {
    const pageErrors = collectPageErrors(page);
    const consoleErrors = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    // Hold the locale module request so the destroy lands while the
    // settlement is provably in flight. The page load event would wait
    // for the held script, so the navigation resolves at
    // domcontentloaded (the driver inits and injects the module there).
    const held = [];
    await page.route('**/assets/locales*.js', async (route) => {
      held.push(route);
    });
    await page.goto('/?assets=files&csp=strict&lang=fr', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held.length, 'the locale fetch must be in flight').toBe(1);

    await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      window.KiwiCaptcha.destroy(w);
      // The observer starts after the destroy teardown, so every record
      // from here on would be a stale settlement mutation.
      window.__kiwiPostDestroyMutations = [];
      const observer = new MutationObserver((records) => {
        for (const r of records) {
          window.__kiwiPostDestroyMutations.push({ type: r.type, attr: r.attributeName });
        }
      });
      observer.observe(w, { attributes: true, childList: true, characterData: true, subtree: true });
    });

    const destroyed = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      return {
        marked: w.dataset.kiwiDestroyed === '1',
        state: w.getAttribute('data-state'),
        lang: w.getAttribute('lang'),
        label: w.querySelector('[data-kiwi-label]').textContent,
        token: document.querySelector('[data-kiwi-token]').value,
      };
    });
    expect(destroyed.marked, 'destroy must mark the widget destroyed').toBe(true);
    expect(destroyed.state, 'destroy must clear the widget state').toBeNull();
    expect(destroyed.label, 'the destroyed widget carries the English fallback text').toBe(EN.label);
    expect(destroyed.token, 'destroy must clear the token field').toBe('');

    // Release the module: it loads, registers its packs on the bridge,
    // and the pending settlement runs against the stale generation.
    for (const route of held.splice(0)) {
      await route.continue().catch(() => {});
    }
    await page.waitForTimeout(2000);

    const injected = await page.evaluate(() => {
      const script = document.querySelector('script[data-kiwi-module="locales"]');
      return script ? script.getAttribute('src') : null;
    });
    expect(injected, 'the released module script must exist in the page').toBeTruthy();
    expect(injected, 'the released module script must be the locale asset').toContain('/assets/locales.');
    const mutations = await page.evaluate(() => window.__kiwiPostDestroyMutations);
    expect(mutations, 'the pending settlement must never mutate the destroyed widget DOM').toEqual([]);
    const settled = await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      return {
        state: w.getAttribute('data-state'),
        lang: w.getAttribute('lang'),
        label: w.querySelector('[data-kiwi-label]').textContent,
        badge: w.querySelector('[data-kiwi-badge]').textContent,
      };
    });
    expect(settled.state, 'the destroyed widget must stay stateless after the settlement').toBeNull();
    expect(settled.lang, 'the destroyed widget must stay lang=en after the settlement').toBe('en');
    expect(settled.label, 'the destroyed widget must keep the English fallback label').toBe(EN.label);
    expect(settled.badge, 'the destroyed widget must keep the English fallback badge').toBe('Idle');
    expect(pageErrors, 'the destroy race must raise no page error').toEqual([]);
    expect(consoleErrors, 'the destroy race must raise no console error').toEqual([]);
  });

  test('reset while the locale fetch is pending: the replacement generation settles, the stale one never paints', async ({ page }) => {
    // The stale generation resolved French before the reset; the
    // replacement generation re-inits with data-kiwi-lang switched to
    // German. Both wait on the same in-flight module (the per-kind
    // dedup), and its arrival runs both settlements in order. Only the
    // current generation may paint, so the subtree must go straight
    // from the English fallback to German, with no French in between.
    const held = [];
    await page.route('**/assets/locales*.js', async (route) => {
      held.push(route);
    });
    await page.goto('/?assets=files&csp=strict&lang=fr', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held.length, 'the locale fetch must be in flight').toBe(1);

    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate(() => {
      const w = document.querySelector('[data-kiwi-widget]');
      w.setAttribute('data-kiwi-lang', 'de');
      window.__kiwiLangHistory = [];
      const observer = new MutationObserver((records) => {
        for (const r of records) {
          window.__kiwiLangHistory.push({ from: r.oldValue, to: w.getAttribute('lang') });
        }
      });
      observer.observe(w, { attributes: true, attributeFilter: ['lang'], attributeOldValue: true });
    });
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);

    for (const route of held.splice(0)) {
      await route.continue().catch(() => {});
    }

    const widget = page.locator('[data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(widget).toHaveAttribute('lang', 'de');
    await expect(widget).toHaveAttribute('aria-label', DE.label);
    await expect(page.locator('[data-kiwi-label]')).toHaveText(DE.label);
    await expect(page.locator('[data-kiwi-badge]')).toHaveText(DE.badgeDone);

    // The stale French settlement would have repainted lang to fr
    // before the replacement generation settled German; the guard must
    // keep the real transitions to the single en-to-de change. (The
    // reset's own re-init re-writes lang=en over the same value, which
    // some engines record as a same-value attribute mutation; those
    // no-op records are filtered out, never a language paint.)
    const history = await page.evaluate(() => window.__kiwiLangHistory);
    const transitions = history.filter((h) => h.from !== h.to);
    expect(transitions, 'only the current generation may settle the language').toEqual([{ from: 'en', to: 'de' }]);
    expect(history.flatMap((h) => [h.from, h.to]), 'the stale French settlement must never paint').not.toContain('fr');

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the German re-solve must mint a token').toBeGreaterThan(0);
    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, `the German re-solve must verify (got ${result.body.code})`).toBe(true);
  });

  // ── The challenge flow is never gated on the pack ──
  // The locale settlement is a pure language swap that repaints the
  // current view. The first run() proceeds immediately with the English
  // fallback; a late pack (the held route below) must switch the text
  // language without regressing the data-state the widget is in. Every
  // case drives the fixture in the strict files tier, holding the
  // content-addressed widget-locales.js request and releasing it at a
  // chosen point of the lifecycle.
  const FR_EXTRA = {
    verifying: 'V\u00e9rification\u2026',
    badgeWorking: 'Traitement',
  };

  test('locale pack: the challenge POST fires while the locale request is held (issuance never waits for the pack)', async ({ page }) => {
    const held = [];
    await page.route('**/assets/locales*.js', async (route) => {
      held.push(route);
    });
    const challengeSeen = page.waitForRequest(
      (r) => r.method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'),
      { timeout: 30_000 }
    );
    await page.goto('/?assets=files&csp=strict&lang=fr', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held.length, 'the locale fetch must be in flight').toBe(1);

    // The flow must run to a started state while the pack is still held
    // — the settle gate is gone, so the widget leaves idle on its own.
    await challengeSeen;
    await expect
      .poll(() => page.evaluate(() => document.querySelector('[data-kiwi-widget]').getAttribute('data-state')))
      .not.toBe('idle');

    // Release the module: the settlement repaints the current state.
    for (const route of held.splice(0)) {
      await route.continue().catch(() => {});
    }
    const widget = page.locator('[data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(widget).toHaveAttribute('lang', 'fr');
    await expect(widget).toHaveAttribute('aria-label', FR.label);
    await expect(page.locator('[data-kiwi-label]')).toHaveText(FR.label);
    await expect(page.locator('[data-kiwi-badge]')).toHaveText(FR.badgeDone);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the French solve must mint a token').toBeGreaterThan(0);
    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, `the French solve must verify (got ${result.body.code})`).toBe(true);
  });

  test('locale pack: released while solving, the pack switches the text language and data-state stays solving', async ({ page }) => {
    // A files-mode argon2id challenge needs the lazy widget-risk.js
    // module for its worker solve tier; holding the risk asset parks
    // the widget in the solving state for a deterministic window (the
    // module watchdog bounds it), which is when the released locale
    // pack must repaint the current view.
    const heldLocale = [];
    await page.route('**/assets/locales*.js', async (route) => {
      heldLocale.push(route);
    });
    const heldRisk = [];
    await page.route('**/assets/risk*.js', async (route) => {
      heldRisk.push(route);
    });
    await page.goto('/?assets=files&lang=fr&algorithm=argon2id', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => heldLocale.length, 'the locale fetch must be in flight').toBe(1);
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'solving', { timeout: 30_000 });
    await expect.poll(() => heldRisk.length, 'the required risk fetch must be in flight').toBe(1);

    for (const route of heldLocale.splice(0)) {
      await route.continue().catch(() => {});
    }

    // The settle must repaint the solving view in French: the label is
    // the verifying key, the badge the working key, and the data-state
    // attribute must remain solving at the very instant the language
    // switched — a settlement that regressed to idle would never show
    // this combination. (The hint element is not part of the
    // connecting/solving views — those transitions never rewrite it —
    // so only the label, badge and retry text switch language here.)
    await expect
      .poll(async () => {
        const snap = await page.evaluate(() => {
          const w = document.querySelector('[data-kiwi-widget]');
          return {
            label: w.querySelector('[data-kiwi-label]').textContent,
            badge: w.querySelector('[data-kiwi-badge]').textContent,
            state: w.getAttribute('data-state'),
          };
        });
        return snap;
      }, { timeout: 20_000, intervals: [50, 100, 200] })
      .toEqual({ label: FR_EXTRA.verifying, badge: FR_EXTRA.badgeWorking, state: 'solving' });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('lang', 'fr');

    // Release the required risk module: the awaited worker tier loads
    // and the solve completes in the now-French widget.
    for (const route of heldRisk.splice(0)) {
      await route.continue().catch(() => {});
    }
    const widget = page.locator('[data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(widget).toHaveAttribute('lang', 'fr');
    await expect(page.locator('[data-kiwi-label]')).toHaveText(FR.label);
    await expect(page.locator('[data-kiwi-badge]')).toHaveText(FR.badgeDone);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the delayed-French argon solve must still mint a token').toBeGreaterThan(0);
    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, `the delayed-French argon solve must verify (got ${result.body.code})`).toBe(true);
  });

  test('locale pack: released after verified, the pack localizes the success strings and the token stays byte-identical', async ({ page }) => {
    const held = [];
    await page.route('**/assets/locales*.js', async (route) => {
      held.push(route);
    });
    await page.goto('/?assets=files&csp=strict&lang=fr', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held.length, 'the locale fetch must be in flight').toBe(1);

    const widget = page.locator('[data-kiwi-widget]');
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const widgetId = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    const tokenBefore = await page.locator('[data-kiwi-token]').inputValue();
    expect(tokenBefore.length, 'the English solve must mint a token').toBeGreaterThan(0);
    const before = await page.evaluate((id) => window.KiwiCaptcha.getResponse(id), widgetId);
    expect(before, 'getResponse must return the English-minted token').toBe(tokenBefore);

    for (const route of held.splice(0)) {
      await route.continue().catch(() => {});
    }

    // The settlement repaints the done view in French: state remains
    // done, the strings localize, and the credential is untouched.
    await expect(widget).toHaveAttribute('lang', 'fr');
    await expect(widget).toHaveAttribute('aria-label', FR.label);
    await expect(page.locator('[data-kiwi-label]')).toHaveText(FR.label);
    await expect(page.locator('[data-kiwi-badge]')).toHaveText(FR.badgeDone);
    await expect(page.locator('[data-kiwi-info]')).toHaveText(FR.hintDone);
    await expect(widget).toHaveAttribute('data-state', 'done');
    const tokenAfter = await page.locator('[data-kiwi-token]').inputValue();
    expect(tokenAfter, 'the released pack must never rewrite the token').toBe(tokenBefore);
    const after = await page.evaluate((id) => window.KiwiCaptcha.getResponse(id), widgetId);
    expect(after, 'getResponse must stay byte-identical after the settlement').toBe(tokenBefore);
  });

  test('locale pack: released after terminal failure, the pack localizes the error text and the Retry button still re-solves', async ({ page }) => {
    const held = [];
    await page.route('**/assets/locales*.js', async (route) => {
      held.push(route);
    });
    let failing = true;
    await page.route('**/challenge', async (route) => {
      if (failing) {
        await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
      } else {
        await route.continue();
      }
    });
    await page.goto('/?assets=files&csp=strict&lang=fr', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held.length, 'the locale fetch must be in flight').toBe(1);

    const widget = page.locator('[data-kiwi-widget]');
    await expect(page.locator('[data-kiwi-info]')).toContainText('press the Retry button to try again', { timeout: 30_000 });
    await expect(widget).toHaveAttribute('data-state', 'failed');
    await expect(page.locator('[data-kiwi-token]')).toHaveValue('');

    for (const route of held.splice(0)) {
      await route.continue().catch(() => {});
    }

    // The failed view repaints in French: the state stays failed and
    // the error/retry hint carries the pack's text.
    await expect(widget).toHaveAttribute('lang', 'fr');
    await expect(page.locator('[data-kiwi-label]')).toHaveText(FR.label);
    await expect(page.locator('[data-kiwi-badge]')).toHaveText('\u00c9chec');
    await expect(page.locator('[data-kiwi-info]')).toContainText('appuyez sur le bouton R\u00e9essayer');
    await expect(widget).toHaveAttribute('data-state', 'failed');

    // The Retry button stays usable: it re-inits and re-solves against
    // the recovered endpoint, ending in the localized done view.
    failing = false;
    await page.locator('[data-kiwi-retry]').click();
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    await expect(page.locator('[data-kiwi-label]')).toHaveText(FR.label);
    await expect(page.locator('[data-kiwi-badge]')).toHaveText(FR.badgeDone);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'the French retry must mint a token').toBeGreaterThan(0);
    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, `the French retry solve must verify (got ${result.body.code})`).toBe(true);
  });
});

test.describe('Locale registry coherence and regional resolution', () => {
  test('every shipped locale row has an eager placeholder in the driver table', () => {
    const locales = fs.readFileSync(localeAssetPath(), 'utf8');
    const driverPath = path.resolve(specDir, '../../../packages/kiwicaptcha-wasm/assets/widget-driver.js');
    const driver = fs.readFileSync(driverPath, 'utf8');
    const langs = [...locales.matchAll(/^    "([a-z-]+)": \[/gm)].map((m) => m[1]);
    expect(langs.length, 'the locales asset must ship at least one pack').toBeGreaterThan(0);
    const start = driver.indexOf('de: null');
    expect(start, 'the placeholder table must exist in the driver').toBeGreaterThan(-1);
    const table = driver.slice(start, driver.indexOf('};', start));
    for (const lang of langs) {
      const covered = table.includes(`"${lang}": null`) || table.includes(`${lang}: null`);
      expect(covered, `the eager placeholder table must carry ${lang} so resolution cannot downgrade before the module lands`).toBe(true);
    }
  });

  test('pt-br resolves regionally and paints the Brazilian forms after the module lands', async ({ page }) => {
    const held = [];
    await page.route('**/assets/locales*.js', (route) => {
      held.push(route);
    });
    await page.goto('/?assets=files&lang=pt-br&bits=4', { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held.length, 'the pt-br module load must start').toBe(1);
    const widget = page.locator('[data-kiwi-widget]');
    // While the pack is pending the subtree mirrors the English fallback
    // that is actually on screen; the resolved language, however, must be
    // pt-br, not the base language pt (the placeholder table must carry
    // "pt-br"), or the late pack would paint European Portuguese.
    await expect(widget).toHaveAttribute('lang', 'en');
    await held.shift().continue().catch(() => {});
    await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    await expect(widget).toHaveAttribute('lang', 'pt-br');
    await expect(page.locator('[data-kiwi-label]')).toHaveText('Verificação de segurança');
    await expect(page.locator('[data-kiwi-badge]')).toHaveText('Concluído');

    // A widget created after the module registered must resolve the same
    // language: the earlier table returned "pt" before the module landed, so
    // two widgets on one page could disagree. The second widget proves
    // both generations agree on pt-br and its Brazilian text.
    await page.evaluate(() => {
      const origin = document.querySelector('.kiwi-container');
      const clone = origin.cloneNode(true);
      clone.id = 'kiwicaptcha-ptbr-second';
      clone.querySelectorAll('[data-kiwi-instance]').forEach((el) => el.removeAttribute('data-kiwi-instance'));
      const w = clone.querySelector('[data-kiwi-widget]');
      w.removeAttribute('data-kiwi-started');
      w.removeAttribute('data-state');
      for (const input of clone.querySelectorAll('[data-kiwi-token]')) input.value = '';
      document.body.appendChild(clone);
      window.__kiwiCaptchaCore.core.scan(document);
    });
    const second = page.locator('#kiwicaptcha-ptbr-second [data-kiwi-widget]');
    await expect(second).toHaveAttribute('lang', 'pt-br');
    await expect(second).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    await expect(page.locator('#kiwicaptcha-ptbr-second [data-kiwi-label]')).toHaveText('Verificação de segurança');
  });
});
