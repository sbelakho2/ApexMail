import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Polymorphic decoy rendering: the driver renders the
// authenticated server-issued decoy (honeypot) name with one of six
// bounded rendering strategies chosen per challenge independently of the
// name — each challenge draws its strategy from the client-side `CSPRNG`,
// and the fixture's /challenge response may carry an optional
// non-authenticated `strategy` hint (0-5) that the driver honors when
// present (production responses omit it). This spec drives every
// strategy deterministically through the fixture's
// ?decoy=1&decoyname=<name>&strategy=<id> knob and asserts the
// invariants that hold for ALL of them:
//  - exactly ONE decoy input carrying the authenticated name
//  - invisible to humans (display:none, hidden attribute, or offscreen)
//  - non-interactive: tabindex=-1, aria-hidden, never in the tab order
//  - autofill-safe: never a labelled visible field, autocomplete off or
//    new-password
//  - axe-clean (no WCAG violations) per strategy
//  - lifecycle: reset removes the decoy, reissue replaces it with
//    exactly one fresh decoy, unarmed issuance renders no decoy at all
// The evidence semantics (filled exact name rides the next challenge
// request as honeypot markers) are covered by risk-v2.spec.mjs.
//
// This spec is portable: it runs in Chromium, Firefox and WebKit via
// playwright.a11y.config.mjs with no engine-specific APIs, so variants 3
// (offscreen) and 5 (deferred) are proven on all three engines.

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

// The fixture emits one strategy per test via the ?strategy=<id> knob;
// the driver honors the hint when present. The wrapper class of the
// wrapped variants is a separate client-side choice per challenge from a
// small bounded set — the assertions below only pin membership in that
// set, never a specific class.
const STRATEGIES = [
  { id: 0 },
  { id: 1 },
  { id: 2 },
  { id: 3 },
  { id: 4 },
  { id: 5 },
];

const WRAP_CLASSES = ['kiwi-form-aux', 'kiwi-form-aux-alt', 'kiwi-field-aux', 'kiwi-aux-group'];

const AXE_RULES = [
  'color-contrast', 'aria-allowed-attr', 'aria-hidden-body', 'aria-hidden-focus',
  'aria-progressbar-name', 'button-name', 'focus-order-semantics', 'html-has-lang',
  'label', 'link-in-text-block', 'select-name', 'valid-lang', 'document-title',
];

async function solve(page, timeout = 60_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

// The decoy element facts a strategy must satisfy, read in one browser
// round trip so the assertions below are race-free.
async function decoyFacts(page, name) {
  return page.evaluate(([n, wrapClasses]) => {
    const token = document.querySelector('[data-kiwi-token]');
    const input = document.querySelector(`input[name="${n}"]`);
    if (!input) return { present: false };
    const cs = getComputedStyle(input);
    const host = token ? token.parentNode : null;
    const wrap = input.parentNode;
    return {
      present: true,
      type: input.getAttribute('type'),
      tabIndex: input.tabIndex,
      ariaHidden: input.getAttribute('aria-hidden'),
      autocomplete: input.getAttribute('autocomplete'),
      value: input.value,
      display: cs.display,
      position: cs.position,
      left: cs.left,
      hiddenAttr: input.hasAttribute('hidden'),
      wrapped: !!(host && wrap !== host && wrapClasses.indexOf(wrap.className) !== -1),
      inHost: !!(host && host.contains(input)),
      // beforeToken: true when the decoy (or its wrapper) precedes the
      // token input among the host's element children.
      beforeToken: (() => {
        if (!host) return false;
        const els = Array.prototype.slice.call(host.children);
        return els.indexOf(input.parentNode === host ? input : wrap) < els.indexOf(token);
      })(),
      tokenParentChildren: token ? token.parentNode.children.length : 0,
    };
  }, [name, WRAP_CLASSES]);
}

test.describe('KiwiCaptcha polymorphic decoy rendering', () => {
  for (const strategy of STRATEGIES) {
    test(`strategy ${strategy.id}: one authenticated decoy input, invisible, non-interactive, axe-clean`, async ({ page }) => {
      // The fixture's ?strategy= knob is the deterministic driver: the
      // hint rides the challenge response and the driver honors it. The
      // authenticated name comes from the challenge response (the
      // fixture knows what it issued); the DOM never exposes it.
      const respP = page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'));
      await page.goto(`/?decoy=1&strategy=${strategy.id}`);
      await solve(page);
      const data = await (await respP).json();
      expect(data.decoy_field, 'the response must carry the authenticated decoy name').toBeTruthy();
      const name = data.decoy_field;
      await expect(page.locator(`input[name="${name}"]`)).toHaveCount(1);

      const facts = await decoyFacts(page, name);
      expect(facts.present).toBe(true);
      expect(facts.type).toBe('text');
      expect(facts.tabIndex).toBe(-1);
      expect(facts.ariaHidden).toBe('true');
      expect(facts.value).toBe('');
      expect(facts.inHost, 'the decoy must live inside the token form host').toBe(true);

      // Invisible to humans under every strategy.
      const invisible = facts.display === 'none' || facts.hiddenAttr || facts.position === 'absolute';
      expect(invisible, `the decoy must be invisible (display=${facts.display}, hidden=${facts.hiddenAttr}, position=${facts.position})`).toBe(true);

      // Strategy-specific shape.
      if (strategy.id === 0) {
        expect(facts.display).toBe('none');
        expect(facts.autocomplete).toBe('off');
        expect(facts.wrapped).toBe(false);
        expect(facts.beforeToken).toBe(false);
      } else if (strategy.id === 1) {
        expect(facts.display).toBe('none');
        expect(facts.autocomplete).toBe('off');
        expect(facts.wrapped).toBe(true);
        expect(facts.beforeToken).toBe(false);
      } else if (strategy.id === 2) {
        expect(facts.hiddenAttr).toBe(true);
        expect(facts.autocomplete).toBe('off');
        expect(facts.wrapped).toBe(false);
        expect(facts.beforeToken).toBe(true);
      } else if (strategy.id === 3) {
        expect(facts.position).toBe('absolute');
        expect(facts.left).toBe('-9999px');
        expect(facts.autocomplete).toBe('new-password');
        expect(facts.wrapped).toBe(false);
      } else if (strategy.id === 4) {
        expect(facts.hiddenAttr).toBe(true);
        expect(facts.autocomplete).toBe('off');
        expect(facts.wrapped).toBe(true);
        expect(facts.beforeToken).toBe(true);
      }

      // Axe-clean: no WCAG violations from the rendered strategy.
      const results = await new AxeBuilder({ page }).withRules(AXE_RULES).analyze();
      expect(results.violations, `strategy ${strategy.id}: ${JSON.stringify(results.violations, null, 2)}`).toEqual([]);
    });
  }

  test('strategy 5 (deferred): the decoy input appears only after the first solve completes', async ({ page }) => {
    // The deferred strategy records the name at issuance but creates the
    // input only when the solve completes. The proof is deterministic
    // and timing-free: the challenge response is held by a route gate,
    // a MutationObserver watches the form host, and the gate is then
    // released. If the strategy were NOT deferred, the input would be
    // inserted while the token is still empty (at response processing)
    // and the observer would catch it; with the deferred strategy the
    // input exists only after the solve, when the token is already
    // written. The assertion holds on every engine regardless of solve
    // speed.
    const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
    const driver = fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<form id="f" action="/form-submit" method="post">
<div class="kiwi-container" id="kiwicaptcha-root" data-kiwi-endpoint="/challenge?decoy=1&strategy=5" data-kiwi-scope="login" data-kiwi-algorithm="argon2id">
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
</form>
<script>${glue}</script><script>${driver}</script></body></html>`;
    await page.route('**/argon-form', (route) =>
      route.fulfill({ contentType: 'text/html', body: html })
    );
    // The route gate holds the challenge response until the observer is
    // installed, so no response processing can race the instrumentation.
    let releaseGate;
    const gate = new Promise((resolve) => {
      releaseGate = resolve;
    });
    let challengeData = null;
    await page.route('**/challenge?*', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      challengeData = data;
      await gate;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
    });
    await page.goto('/argon-form');
    await page.waitForFunction(() => document.querySelector('[data-kiwi-widget]').getAttribute('data-state') === 'connecting', null, { timeout: 30_000 });
    // The route handler holds the response; poll until it has captured it
    // (the connecting state precedes the fetch dispatch, so the capture
    // may lag the state by a moment).
    await expect.poll(() => challengeData, { timeout: 30_000 }).toBeTruthy();
    const name = challengeData.decoy_field;
    expect(name, 'the held response must carry the authenticated decoy name').toBeTruthy();

    // The observer resolves with the violation flag: true when the decoy
    // input appears while the token is still empty (a non-deferred
    // insert at response processing), false when the token write comes
    // first (the deferred flush runs synchronously with it).
    const observed = page.evaluate((n) => new Promise((resolve) => {
      const token = document.querySelector('[data-kiwi-token]');
      const host = token.parentNode;
      let insertedBeforeTokenWrite = false;
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        observer.disconnect();
        clearInterval(timer);
        clearTimeout(deadline);
        resolve(value);
      };
      const check = () => {
        if (token.value !== '') {
          finish({ insertedBeforeTokenWrite });
          return;
        }
        if (host.querySelector(`input[name="${n}"]`)) {
          insertedBeforeTokenWrite = true;
          finish({ insertedBeforeTokenWrite });
        }
      };
      const observer = new MutationObserver(check);
      observer.observe(host, { childList: true, subtree: true });
      // The token write is a property set (no mutation record), so the
      // fallback poll covers a solve that completes without any DOM
      // mutation before it. The deadline turns a failed solve into a
      // visible test failure instead of a hang.
      const timer = setInterval(check, 5);
      const deadline = setTimeout(() => finish({ insertedBeforeTokenWrite, timedOut: true }), 30_000);
    }), name);
    releaseGate();
    const result = await observed;
    expect(result.timedOut, 'the solve must complete so the deferred flush is observable').not.toBe(true);
    expect(result.insertedBeforeTokenWrite, 'the deferred decoy must not exist before the first solve completes').toBe(false);

    // After the solve the deferred input exists, exactly once, with the
    // invariant surface of the strategy-0 look.
    await solve(page);
    await expect(page.locator(`input[name="${name}"]`), 'the deferred decoy appears after the solve').toHaveCount(1);
    await expect(page.locator(`input[name="${name}"]`)).toHaveAttribute('tabindex', '-1');
    await expect(page.locator(`input[name="${name}"]`)).toHaveAttribute('aria-hidden', 'true');
  });

  test('unarmed issuance renders no decoy input and carries no name', async ({ page }) => {
    await page.goto('/');
    await solve(page);
    const state = await page.evaluate(() => {
      // A decoy is the input the accessibility union selects inside the
      // token host: aria-hidden with tabindex -1. The kiwi_* inputs
      // (token, request binding) are driver-owned fields, never decoys.
      const host = document.querySelector('[data-kiwi-token]').parentNode;
      return {
        owned: host.querySelectorAll('input[aria-hidden="true"][tabindex="-1"]').length,
        decoys: Array.from(document.querySelectorAll('input')).filter((el) => el.getAttribute('aria-hidden') === 'true' && el.getAttribute('tabindex') === '-1').length,
      };
    });
    expect(state.owned).toBe(0);
    expect(state.decoys).toBe(0);
  });

  test('reset removes the rendered decoy; reissue replaces it with exactly one fresh decoy', async ({ page }) => {
    // The reissue flow is driven by the fixture route override: the
    // first challenge response carries names[0] with strategy 2, the
    // re-solve after the reset carries names[1] with strategy 4, so the
    // replacement is proven across strategies, not just within one.
    const names = ['secondary_contact_name', 'secondary_contact_url'];
    let issued = 0;
    await page.route('**/challenge*', async (route) => {
      const resp = await route.fetch();
      const data = await resp.json();
      data.decoy_field = names[issued % names.length];
      data.strategy = issued % 2 === 0 ? 2 : 4;
      issued++;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
    });

    await page.goto('/?decoy=1');
    await solve(page);
    const oldName = names[0];
    const stale = page.locator(`input[name="${oldName}"]`);
    await expect(stale).toHaveCount(1);
    await stale.evaluate((el) => {
      el.value = 'bot@example.com';
    });

    // Reset: the rendered decoy input leaves the form synchronously.
    const wid = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((id) => window.KiwiCaptcha.reset(id), wid);
    await expect(stale, 'the reset must remove the rendered decoy input').toHaveCount(0);

    // The reset-triggered re-solve auto-runs against the fixture: the
    // fresh challenge carries names[1] and renders exactly one decoy
    // input — never a stale echo of the prior one.
    await solve(page);
    const freshName = names[1];
    await expect(page.locator(`input[name="${freshName}"]`)).toHaveCount(1);
    await expect(page.locator(`input[name="${oldName}"]`), 'the stale decoy must never linger').toHaveCount(0);
    const totalDecoys = await page.evaluate(() => {
      const host = document.querySelector('[data-kiwi-token]').parentNode;
      return host.querySelectorAll('input[aria-hidden="true"][tabindex="-1"]').length;
    });
    expect(totalDecoys, 'exactly one decoy input after the reissue').toBe(1);
  });
});
