import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The compat observer and pre-loader contract.
//
// Dynamic implicit rendering traverses every added subtree for all three
// providers, so a late h-captcha or cf-turnstile container renders like a
// reCAPTCHA one. A same-task move keeps the rendered widget and its
// solved state; a control that stays detached tears its widget down.
//
// The reCAPTCHA pre-loader shim parks ready callbacks as arrays on the
// global configuration object before the loader runs. Those callbacks
// drain exactly once, in order, after the Kiwi glue is ready, and the
// configuration object keeps its unknown fields.
//
// Runs on Chromium, Firefox and WebKit through playwright.a11y.config.mjs.

const specDir = path.dirname(fileURLToPath(import.meta.url));
const pentestDir = path.resolve(specDir, '../pentest');

const PROVIDERS = [
  {
    compat: 'recaptcha',
    api: 'grecaptcha',
    selector: '.g-recaptcha',
    field: 'g-recaptcha-response',
    deferred: 'control',
  },
  {
    compat: 'hcaptcha',
    api: 'hcaptcha',
    selector: '.h-captcha',
    field: 'h-captcha-response',
    deferred: 'control',
  },
  {
    compat: 'turnstile',
    api: 'turnstile',
    selector: '.cf-turnstile',
    field: 'cf-turnstile-response',
    deferred: 'execution',
  },
];

// A schema-valid issuance the challenge route returns for fast solves.
function canned(overrides = {}) {
  return {
    nonce: Buffer.from(Uint8Array.from({ length: 32 }, (_, i) => (i * 13 + 7) & 0xff)).toString('base64'),
    challenge: 'canned',
    salt: Buffer.from('compat-observer-salt').toString('base64'),
    algorithm: 'sha256',
    mKib: 0,
    t: 1,
    p: 1,
    targetBits: 4,
    ttlSecs: 120,
    minDurationMs: 0,
    prefix: 'compat-observer-prefix',
    ...overrides,
  };
}

// Serve a fixture from disk with placeholder substitution.
async function serveFixture(page, file, patch = {}) {
  let html = fs.readFileSync(path.join(pentestDir, file), 'utf8');
  for (const [key, value] of Object.entries(patch)) html = html.split(key).join(value);
  await page.route(`**/pentest/${file}*`, (route) =>
    route.fulfill({ contentType: 'text/html; charset=utf-8', body: html })
  );
}

// Count every challenge request and answer it with the canned issuance.
async function routeCanned(page) {
  const challenges = [];
  await page.route(/\/challenge(\?.*)?$/, (route) => {
    challenges.push(route.request().url());
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(canned()) });
  });
  return challenges;
}

async function openCompat(page, provider) {
  await serveFixture(page, 'compat-observer.html', { __COMPAT__: provider.compat });
  const challenges = await routeCanned(page);
  await page.goto('/pentest/compat-observer.html');
  await page.waitForFunction((name) => window[name] && typeof window[name].render === 'function', provider.api);
  return challenges;
}

function addContainer({ cls, id, sitekey, execution }) {
  const el = document.createElement('div');
  el.className = cls;
  el.id = id;
  el.dataset.sitekey = sitekey;
  if (execution) el.setAttribute('data-execution', execution);
  document.body.appendChild(el);
}

for (const provider of PROVIDERS) {
  const cls = provider.selector.slice(1);

  test.describe(`compat observer: ${provider.compat}`, () => {
    test('direct insertion renders one solving widget', async ({ page }) => {
      const challenges = await openCompat(page, provider);
      await page.evaluate(addContainer, { cls, id: 'obs-direct', sitekey: '6Lc_obs_direct' });
      const widget = page.locator('#obs-direct [data-kiwi-widget]');
      await expect(widget).toHaveCount(1, { timeout: 30_000 });
      await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 30_000 });
      expect(challenges.length).toBe(1);
    });

    test('insertion as a descendant of a new subtree renders the nested widget', async ({ page }) => {
      await openCompat(page, provider);
      await page.evaluate((selectorClass) => {
        const section = document.createElement('section');
        section.id = 'obs-subtree';
        const outer = document.createElement('div');
        const inner = document.createElement('div');
        inner.className = selectorClass;
        inner.dataset.sitekey = '6Lc_obs_nested';
        outer.appendChild(inner);
        section.appendChild(outer);
        document.body.appendChild(section);
      }, cls);
      await expect(page.locator('#obs-subtree [data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 30_000 });
    });

    test('multiple widgets in one subtree render with distinct ids', async ({ page }) => {
      const challenges = await openCompat(page, provider);
      await page.evaluate((selectorClass) => {
        const section = document.createElement('section');
        section.id = 'obs-multi';
        const first = document.createElement('div');
        first.className = selectorClass;
        first.dataset.sitekey = '6Lc_obs_m1';
        const second = document.createElement('div');
        second.className = selectorClass;
        second.dataset.sitekey = '6Lc_obs_m2';
        section.appendChild(first);
        section.appendChild(second);
        document.body.appendChild(section);
      }, cls);
      const widgets = page.locator('#obs-multi [data-kiwi-widget]');
      await expect(widgets).toHaveCount(2, { timeout: 30_000 });
      await expect(page.locator('#obs-multi [data-kiwi-widget][data-state="done"]')).toHaveCount(2, { timeout: 30_000 });
      const ids = await widgets.evaluateAll((els) => els.map((el) => (el.closest('[data-kiwi-instance]') || el).dataset.kiwiInstance));
      expect(new Set(ids).size).toBe(2);
      expect(challenges.length).toBe(2);
    });

    test('same-task move keeps the widget, its id, its state and its token', async ({ page }) => {
      const challenges = await openCompat(page, provider);
      await page.evaluate(addContainer, { cls, id: 'obs-move', sitekey: '6Lc_obs_move' });
      const widget = page.locator('#obs-move [data-kiwi-widget]');
      await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 30_000 });
      const before = await page.evaluate((field) => {
        const el = document.getElementById('obs-move');
        const w = el.querySelector('[data-kiwi-widget]');
        return { id: (w.closest('[data-kiwi-instance]') || w).dataset.kiwiInstance, token: el.querySelector(`input[name="${field}"]`).value };
      }, provider.field);
      expect(before.token.length).toBeGreaterThan(0);
      const challengeCount = challenges.length;
      await page.evaluate(() => {
        const home = document.createElement('div');
        home.id = 'obs-move-home';
        document.body.appendChild(home);
        const el = document.getElementById('obs-move');
        el.remove();
        home.appendChild(el);
      });
      await page.waitForTimeout(300);
      const after = await page.evaluate((field) => {
        const el = document.getElementById('obs-move');
        const w = el.querySelector('[data-kiwi-widget]');
        return {
          local: el.querySelectorAll('[data-kiwi-widget]').length,
          global: document.querySelectorAll('[data-kiwi-widget]').length,
          id: (w.closest('[data-kiwi-instance]') || w).dataset.kiwiInstance,
          state: w.getAttribute('data-state'),
          token: el.querySelector(`input[name="${field}"]`).value,
        };
      }, provider.field);
      expect(after.local).toBe(1);
      expect(after.global).toBe(1);
      expect(after.id).toBe(before.id);
      expect(after.state).toBe('done');
      expect(after.token).toBe(before.token);
      expect(challenges.length, 'a move must not re-solve').toBe(challengeCount);
    });

    test('detach and reinsert keeps exactly one working widget', async ({ page }) => {
      const challenges = await openCompat(page, provider);
      await page.evaluate(addContainer, { cls, id: 'obs-detach', sitekey: '6Lc_obs_detach' });
      const widget = page.locator('#obs-detach [data-kiwi-widget]');
      await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 30_000 });
      const before = await page.evaluate((field) => {
        const el = document.getElementById('obs-detach');
        const w = el.querySelector('[data-kiwi-widget]');
        return { id: (w.closest('[data-kiwi-instance]') || w).dataset.kiwiInstance, token: el.querySelector(`input[name="${field}"]`).value };
      }, provider.field);
      const challengeCount = challenges.length;
      await page.evaluate(() => {
        window.__obsDetached = document.getElementById('obs-detach');
        window.__obsDetached.remove();
      });
      await page.waitForTimeout(100);
      await page.evaluate(() => {
        const home = document.createElement('div');
        home.id = 'obs-detach-home';
        document.body.appendChild(home);
        home.appendChild(window.__obsDetached);
      });
      await page.waitForTimeout(500);
      const after = await page.evaluate((field) => {
        const el = document.getElementById('obs-detach');
        const w = el.querySelector('[data-kiwi-widget]');
        return {
          count: el.querySelectorAll('[data-kiwi-widget]').length,
          global: document.querySelectorAll('[data-kiwi-widget]').length,
          id: (w.closest('[data-kiwi-instance]') || w).dataset.kiwiInstance,
          state: w.getAttribute('data-state'),
          token: el.querySelector(`input[name="${field}"]`).value,
        };
      }, provider.field);
      expect(after.count).toBe(1);
      expect(after.global).toBe(1);
      expect(after.id).toBe(before.id);
      expect(after.state).toBe('done');
      expect(after.token).toBe(before.token);
      expect(challenges.length, 'a reinsert must not re-solve').toBe(challengeCount);
    });

    test('the deferred variant waits for activation and starts one challenge', async ({ page }) => {
      const challenges = await openCompat(page, provider);
      if (provider.deferred === 'control') {
        await page.evaluate((selectorClass) => {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = selectorClass;
          button.id = 'obs-deferred';
          button.textContent = 'Sign in';
          button.dataset.sitekey = '6Lc_obs_deferred';
          document.body.appendChild(button);
        }, cls);
        const widget = page.locator('#obs-deferred + [data-kiwi-compat-holder] [data-kiwi-widget]');
        await expect(widget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });
        await page.waitForTimeout(2000);
        expect(challenges.length, 'no challenge may start before activation').toBe(0);
        await page.locator('#obs-deferred').click();
        await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 30_000 });
        expect(challenges.length, 'exactly one challenge after activation').toBe(1);
      } else {
        await page.evaluate(addContainer, { cls, id: 'obs-deferred', sitekey: '6Lc_obs_deferred', execution: 'execute' });
        const widget = page.locator('#obs-deferred [data-kiwi-widget]');
        await expect(widget).toHaveAttribute('data-state', 'pending', { timeout: 30_000 });
        await page.waitForTimeout(2000);
        expect(challenges.length, 'no challenge may start before execute()').toBe(0);
        await page.evaluate(() => {
          const button = document.createElement('button');
          button.id = 'obs-go';
          button.textContent = 'Run';
          button.addEventListener('click', () => {
            const w = document.querySelector('#obs-deferred [data-kiwi-widget]');
            window.turnstile.execute((w.closest('[data-kiwi-instance]') || w).dataset.kiwiInstance);
          });
          document.body.appendChild(button);
        });
        await page.locator('#obs-go').click();
        await expect(widget).toHaveAttribute('data-state', 'done', { timeout: 30_000 });
        expect(challenges.length, 'exactly one challenge after execute()').toBe(1);
      }
    });
  });
}

test.describe('compat pre-loader shim', () => {
  test('callbacks queued before and during loading drain once, in order, after readiness', async ({ page }) => {
    await serveFixture(page, 'compat-preload.html');
    const challenges = await routeCanned(page);
    // Hold the loader response until the in-flight inline script has
    // queued its callbacks and the stub global is still in place.
    await page.route('**/kiwi-captcha/api.js*', async (route) => {
      await page.waitForFunction(
        () => window.__loadingQueued === true && typeof (window.grecaptcha || {}).execute !== 'function'
      );
      await route.continue();
    });
    await page.goto('/pentest/compat-preload.html');
    await page.waitForFunction(() => window.grecaptcha && typeof window.grecaptcha.execute === 'function');

    await expect
      .poll(() => page.evaluate(() => window.__events.slice()), { timeout: 15_000 })
      .toEqual(['before', 'before-global', 'loading', 'loading-global', 'nested']);

    const audit = await page.evaluate(() => ({
      isArray: Array.isArray(window.___grecaptcha_cfg.ready),
      length: window.___grecaptcha_cfg.ready.length,
      custom: window.___grecaptcha_cfg.customField,
      events: window.__events.slice(),
    }));
    expect(audit.isArray).toBe(true);
    expect(audit.length, 'the queue drains exactly once').toBe(0);
    expect(audit.custom, 'unknown configuration fields survive').toEqual({ keep: 1 });
    for (const name of ['before', 'before-global', 'loading', 'loading-global', 'nested']) {
      expect(audit.events.filter((event) => event === name).length, `${name} fires once`).toBe(1);
    }

    // The drain ran after the glue was ready: the explicit render inside
    // a drained callback produced a working widget, and it solves.
    const nestedId = await page.evaluate(() => window.__nestedId);
    expect(typeof nestedId).toBe('string');
    expect(nestedId.length).toBeGreaterThan(0);
    await expect.poll(() => page.locator('.kiwi-widget').count(), { timeout: 15_000 }).toBe(2);
    await expect(page.locator('.kiwi-widget[data-state="done"]')).toHaveCount(2, { timeout: 30_000 });
    expect(challenges.length).toBe(2);

    // After readiness the provider API answers ready() directly.
    const fired = await page.evaluate(() => new Promise((resolve) => window.grecaptcha.ready(() => resolve('after'))));
    expect(fired).toBe('after');

    // A late push into the drained array is not consumed: the drain ran once.
    await page.evaluate(() => {
      window.___grecaptcha_cfg.ready.push(() => window.__events.push('late'));
    });
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => window.__events.indexOf('late'))).toBe(-1);
  });

  test('a nested clients.af.ready queue is recognized and drained once', async ({ page }) => {
    await serveFixture(page, 'compat-preload-af.html');
    await routeCanned(page);
    await page.goto('/pentest/compat-preload-af.html');
    await page.waitForFunction(() => window.grecaptcha && typeof window.grecaptcha.execute === 'function');
    await expect.poll(() => page.evaluate(() => window.__events.slice()), { timeout: 15_000 }).toEqual(['af']);
    const audit = await page.evaluate(() => ({
      length: window.___grecaptcha_cfg.clients.af.ready.length,
      marker: window.___grecaptcha_cfg.marker,
    }));
    expect(audit.length).toBe(0);
    expect(audit.marker, 'the configuration object keeps its fields').toBe('keep');
  });

  test('an object-local ready queue shape still drains after readiness', async ({ page }) => {
    await serveFixture(page, 'compat-preload-local.html');
    await routeCanned(page);
    await page.goto('/pentest/compat-preload-local.html');
    await page.waitForFunction(() => window.grecaptcha && typeof window.grecaptcha.execute === 'function');
    await expect.poll(() => page.evaluate(() => window.__localFired), { timeout: 15_000 }).toBe(1);
    const audit = await page.evaluate(() => ({
      identity: window.__localRef === window.grecaptcha,
      length: window.grecaptcha._.length,
    }));
    expect(audit.identity, 'the pre-seeded object is merged in place').toBe(true);
    expect(audit.length).toBe(0);
  });
});
