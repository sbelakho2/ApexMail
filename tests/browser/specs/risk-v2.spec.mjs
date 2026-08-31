import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Risk-v2 driver evidence: the challenge request carries the coarse
// client_context capability descriptor only when the widget container or
// widget element carries the explicit data-kiwi-risk-context="coarse"
// opt-in attribute (the default is off); a decoy_field issuance response
// renders a hidden honeypot input next to the token input whose fill rides
// both the protected form submission and a later challenge request; and
// data-kiwi-chain-ticket presents the one-shot chain ticket exactly once,
// then clears it so a re-solve never re-sends a consumed ticket.

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

async function solve(page, timeout = 60_000) {
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout });
}

// The next challenge response's authenticated decoy name (the decoy name
// is response-known; the DOM never carries a tracking attribute). The
// promise must be registered before the navigation that triggers the
// challenge fetch.
function challengeDecoyName(page) {
  return page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/challenge') && !r.url().includes('/cancel'))
    .then((resp) => resp.json())
    .then((data) => data.decoy_field ?? null);
}

async function readCapture(page, name) {
  const resp = await page.request.get(`http://127.0.0.1:8085/capture/${name}`);
  const data = await resp.json();
  return data && typeof data.body === 'string' ? data.body : null;
}

test.describe('KiwiCaptcha risk-v2 driver evidence', () => {
  test('the challenge request carries the coarse client_context descriptor under the explicit opt-in', async ({ page }) => {
    await page.goto('/?capture=cc1&risk-context=coarse');
    await solve(page);

    const body = JSON.parse(await readCapture(page, 'cc1'));
    expect(body, 'the challenge request must be captured').toBeTruthy();
    expect(typeof body.client_context).toBe('string');
    // The server's accepted bounded pattern.
    expect(body.client_context).toMatch(/^[a-z0-9+_,=:-]{1,64}$/);
    // The coarse capabilities: viewport class, touch class, language
    // family and timezone class.
    expect(body.client_context).toMatch(/v[123]/);
    expect(body.client_context).toMatch(/t[01]/);
    expect(body.client_context).toMatch(/l[a-z]{2,3}/);
    expect(body.client_context).toMatch(/z[0-4]/);
    // No decoy markers when no decoy was rendered.
    expect(body.decoy_field).toBeUndefined();
    expect(body.honeypot).toBeUndefined();
  });

  test('without the opt-in attribute no client_context is ever sent', async ({ page }) => {
    await page.goto('/?capture=cc2');
    await solve(page);

    const body = JSON.parse(await readCapture(page, 'cc2'));
    expect(body, 'the challenge request must be captured').toBeTruthy();
    // The default is OFF: a container without
    // data-kiwi-risk-context="coarse" must not send any device-capability
    // or screen-size signal with the challenge request.
    expect(body.client_context).toBeUndefined();
    // No decoy markers when no decoy was rendered.
    expect(body.decoy_field).toBeUndefined();
    expect(body.honeypot).toBeUndefined();
  });

  test('a decoy_field response renders one hidden non-interactive decoy input inside the token form host', async ({ page }) => {
    const nameP = challengeDecoyName(page);
    await page.goto('/?decoy=1');
    await solve(page);

    const name = await nameP;
    expect(name, 'the decoy name must be the server-issued name').toBeTruthy();
    const decoy = page.locator(`input[name="${name}"]`);
    await expect(decoy).toHaveCount(1);
    // The honeypot input is hidden from humans AND assistive tech: never
    // auto-filled, never tabbed into, whatever the rendering strategy.
    await expect(decoy).toHaveAttribute('tabindex', '-1');
    await expect(decoy).toHaveAttribute('aria-hidden', 'true');
    const attrs = await decoy.evaluate((el) => ({
      display: getComputedStyle(el).display,
      hidden: el.hasAttribute('hidden'),
      offscreen: getComputedStyle(el).position === 'absolute',
    }));
    expect(
      attrs.display === 'none' || attrs.hidden || attrs.offscreen,
      `the decoy must be invisible to humans (display=${attrs.display}, hidden=${attrs.hidden}, offscreen=${attrs.offscreen})`
    ).toBe(true);
    // inside the same form/host as the token input (the app's form).
    const sameHost = await page.evaluate((n) => {
      const token = document.querySelector('[data-kiwi-token]');
      const d = document.querySelector(`input[name="${n}"]`);
      return !!(token && d && token.parentNode === d.parentNode || (token && d && token.parentNode && token.parentNode.contains(d)));
    }, name);
    expect(sameHost).toBe(true);
    // Never auto-filled: the rendered value stays empty.
    expect(await decoy.inputValue()).toBe('');
  });

  test('filling the decoy input then submitting sends the decoy markers', async ({ page }) => {
    const glue = fs.readFileSync(assetPath('kiwicaptcha-wasm.js'), 'utf8');
    const driver = fs.readFileSync(assetPath('widget-driver.js'), 'utf8');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<form id="f" action="/form-submit" method="post">
<div class="kiwi-container" id="kiwicaptcha-root" data-kiwi-endpoint="/challenge?decoy=1&capture=d1" data-kiwi-scope="login">
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
    await page.route('**/decoy-form', (route) =>
      route.fulfill({ contentType: 'text/html', body: html })
    );
    const nameP = challengeDecoyName(page);
    await page.goto('/decoy-form');
    await solve(page);

    const name = await nameP;
    const decoy = page.locator(`input[name="${name}"]`);
    await expect(decoy).toHaveCount(1);
    // A bot's filler — the driver never auto-fills; the value the form
    // carries is exactly the evidence.
    await decoy.evaluate((el) => {
      el.value = 'bot@example.com';
    });
    await page.evaluate(() => document.getElementById('f').submit());
    await page.waitForURL('**/form-submit');

    const posted = await readCapture(page, 'form');
    expect(posted, 'the form submission must be captured').toBeTruthy();
    expect(posted).toContain(`${name}=bot%40example.com`);
    expect(posted).toContain('kiwi__token=');
  });

  test('a filled decoy input rides the NEXT challenge request (expiry re-solve)', async ({ page }) => {
    // ttl=3: the solved credential expires 3s after the solve; the
    // expiry-driven re-solve presents a NEW challenge request that must
    // carry the still-filled decoy as honeypot evidence.
    const nameP = challengeDecoyName(page);
    await page.goto('/?decoy=1&ttl=3&capture=res');
    await solve(page);

    const name = await nameP;
    const decoy = page.locator(`input[name="${name}"]`);
    await expect(decoy).toHaveCount(1);
    await decoy.evaluate((el) => {
      el.value = 'bot@example.com';
    });

    const widgetId = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.waitForTimeout(3500);
    const expired = await page.evaluate((wid) => window.KiwiCaptcha.isExpired(wid), widgetId);
    expect(expired).toBe(true);
    // The fresh decoy name is captured from the re-solve's challenge
    // response (registered before the re-solve fetch fires).
    const freshNameP = challengeDecoyName(page);
    await page.evaluate((wid) => window.KiwiCaptcha.execute(wid), widgetId);
    await solve(page);

    const body = JSON.parse(await readCapture(page, 'res'));
    expect(body, 'the re-solve challenge request must be captured').toBeTruthy();
    expect(body.decoy_field).toBe(name);
    expect(body.honeypot).toBe('bot@example.com');
    // The re-issuance rendered its OWN per-issuance decoy: the stale
    // input was replaced, exactly one decoy input remains.
    const freshName = await freshNameP;
    await expect(page.locator(`input[name="${freshName}"]`)).toHaveCount(1);
    await expect(page.locator(`input[name="${name}"]`)).toHaveCount(0);
  });

  test('data-kiwi-chain-ticket presents chain_ticket once and clears it', async ({ page }) => {
    await page.goto('/?chain=ticket-abc-123&capture=ch1');
    await solve(page);

    const body = JSON.parse(await readCapture(page, 'ch1'));
    expect(body, 'the first challenge request must be captured').toBeTruthy();
    expect(body.chain_ticket).toBe('ticket-abc-123');

    // After the solve the attribute is cleared — a re-solve must not
    // re-present the consumed one-shot ticket.
    const attr = await page.locator('#kiwicaptcha-root').getAttribute('data-kiwi-chain-ticket');
    expect(attr).toBeNull();

    const widgetId = await page.evaluate(() => document.querySelector('[data-kiwi-widget]').dataset.kiwiInstance);
    await page.evaluate((wid) => window.KiwiCaptcha.reset(wid), widgetId);
    await solve(page);

    const second = JSON.parse(await readCapture(page, 'ch1'));
    expect(second.chain_ticket).toBeUndefined();
  });

  test('a malformed chain ticket is never sent', async ({ page }) => {
    await page.goto('/?chain=bad%20ticket%21%21&capture=chbad');
    await solve(page);

    const body = JSON.parse(await readCapture(page, 'chbad'));
    expect(body, 'the challenge request must be captured').toBeTruthy();
    expect(body.chain_ticket).toBeUndefined();
  });
});
