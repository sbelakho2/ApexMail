import { test, expect } from '@playwright/test';

// The form-level collection contract (change.md 3.2.3): the telemetry
// listeners attach at the form containing the widget, in the capture
// phase, so interaction anywhere in the host form is observed. A widget
// without a form ancestor degrades to widget-only attachment. The
// payload is the published telemetry-v1 aggregate contract
// (protocol/telemetry-v1/payload.json): event-class counts, one 4-bit
// quantized inter-event entropy value, a focus-transition count, a
// paste-versus-type ratio and the sample count. No raw coordinates, no
// key values, no timing series ever leave the page.

const SCHEMA_KEYS = ['v', 'ec', 'qe', 'ft', 'pt', 'n'];
const EC_KEYS = ['fo', 'ke', 'pa', 'po', 'fm'];

function tokenTelemetry(token) {
  const parts = atob(token).split('.');
  expect(parts.length, 'the token must carry the telemetry segment').toBeGreaterThanOrEqual(4);
  return JSON.parse(parts[3]);
}

function assertSchemaShape(payload) {
  expect(Object.keys(payload).sort(), 'the payload carries exactly the published schema keys')
    .toEqual([...SCHEMA_KEYS].sort());
  expect(Object.keys(payload.ec).sort(), 'the event-class counts carry exactly the published classes')
    .toEqual([...EC_KEYS].sort());
  expect(payload.v).toBe(1);
  expect(payload.qe, 'the quantized entropy is a 4-bit value').toBeGreaterThanOrEqual(0);
  expect(payload.qe).toBeLessThanOrEqual(15);
  expect(payload.pt, 'the paste ratio is a per-mille').toBeGreaterThanOrEqual(0);
  expect(payload.pt).toBeLessThanOrEqual(1000);
  expect(payload.n, 'the sample count stays at the payload cap').toBeLessThanOrEqual(32);
  const sum = EC_KEYS.reduce((acc, k) => acc + payload.ec[k], 0);
  expect(sum, 'the collector invariant: the class counts sum to the sample count').toBe(payload.n);
  // The privacy canary: a schema-shaped aggregate payload is small. A
  // coordinate, key value or timing series would need far more bytes.
  expect(JSON.stringify(payload).length, 'the payload stays a compact aggregate').toBeLessThan(200);
}

test.describe('Form-level telemetry collection', () => {
  test('interaction OUTSIDE the widget subtree is observed: the form attachment sees the whole form', async ({ page }) => {
    // Hold the challenge POST so the session is still open while the
    // human input happens, then release and let the solve finish.
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    await page.route('**/challenge**', async (route) => {
      if (route.request().method() === 'POST' && !route.request().url().includes('/cancel')) {
        await held;
      }
      await route.continue().catch(() => {});
    });

    await page.goto('/?assets=files&telemetry=full&form=1', { waitUntil: 'domcontentloaded' });
    expect(await page.locator('#host-form').count(), 'the form fixture variant is armed').toBe(1);

    // Real input events on the form fields, away from the widget: a
    // widget-only listener would count none of this.
    await page.locator('#form-email').click();
    await page.locator('#form-email').pressSequentially('kiwi@kiwi.dev');
    await page.locator('#form-name').click();
    await page.locator('#form-name').pressSequentially('Kiwi');

    release();
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const payload = tokenTelemetry(await page.locator('[data-kiwi-token]').inputValue());
    assertSchemaShape(payload);

    expect(payload.ec.ke, 'the form-level keydowns outside the widget are counted').toBeGreaterThanOrEqual(8);
    expect(payload.ec.fm, 'the value mutations are counted as form-class events').toBeGreaterThanOrEqual(8);
    expect(payload.ft, 'the field-to-field focus moves are counted as focus transitions').toBeGreaterThanOrEqual(2);
    expect(payload.ec.po, 'the pointer interaction outside the widget is counted').toBeGreaterThanOrEqual(2);
    expect(payload.n, 'the cap bounds the sample count').toBeLessThanOrEqual(32);
  });

  test('a widget without a form ancestor degrades to widget-only attachment', async ({ page }) => {
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    await page.route('**/challenge**', async (route) => {
      if (route.request().method() === 'POST' && !route.request().url().includes('/cancel')) {
        await held;
      }
      await route.continue().catch(() => {});
    });

    // The default fixture page hosts the container bare (no form).
    await page.goto('/?assets=files&telemetry=full', { waitUntil: 'domcontentloaded' });

    // Interaction inside the widget subtree is observed; a form field
    // would not exist here.
    await page.locator('[data-kiwi-widget]').click();

    release();
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const payload = tokenTelemetry(await page.locator('[data-kiwi-token]').inputValue());
    assertSchemaShape(payload);
    expect(payload.ec.po + payload.n, 'the widget-only session counted the widget interaction')
      .toBeGreaterThanOrEqual(1);
  });

  test('the default page (telemetry off) carries the empty stub and no module fetch', async ({ page }) => {
    const requests = [];
    page.on('request', (r) => {
      if (r.url().includes('/assets/telemetry.')) requests.push(r.url());
    });
    await page.goto('/?assets=files', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(tokenTelemetry(token), 'an off widget posts the empty stub').toEqual({});
    expect(requests, 'a default page never fetches the telemetry module').toEqual([]);
  });
});
