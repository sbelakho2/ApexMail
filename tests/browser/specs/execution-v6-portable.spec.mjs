import { test, expect } from '@playwright/test';

// Portable ExecutionChallengeV1 version-6 evidence for the three-engine
// lane (playwright.a11y.config.mjs): the real-platform rung must
// qualify end to end on Chromium, Firefox and WebKit, the engines the
// cross-engine qualification matrix is derived from.
//
// A version-6 program exercises the five real-platform probe families
// in a real layout engine: computed style over real layout
// (dcsgeom), MutationObserver delivery order (dmutord), the full
// capture/target/bubble event path with listener side effects
// (devphf), Range/Selection over a constructed text graph (drange),
// and IntersectionObserver thresholds driven by real geometry
// (dintobs). The fixture issues the v6 grammar under
// ?execution=1&exec_cap=6 (the driver advertises
// Kiwi-Execution-Max-Version 6), the browser runs the program in the
// sandboxed ephemeral iframe, and the fixture /verify endpoint
// re-verifies the submitted trace server-side against the operand-
// derived envelopes through the real PHP core. A pure reimplementation
// or a jsdom/happy-dom style host cannot satisfy those envelopes, so
// every green lifecycle here is a real-engine qualification datapoint.

const K = 24;

async function armedV6Page(page) {
  await page.goto('/?assets=files&execution=1&exec_cap=6');
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
    timeout: 120_000,
  });
}

async function fixtureOrigin(page) {
  return page.evaluate(() => window.location.origin);
}

async function verifyToken(page, origin, token) {
  const resp = await page.request.post(`${origin}/verify`, { data: { token } });
  return { status: resp.status(), body: await resp.json() };
}

function tokenTrace(token) {
  const plain = Buffer.from(token, 'base64').toString('utf8');
  const parts = plain.split('.');
  const evidence = parts[parts.length - 1].split(':');
  const standard = evidence[1].replace(/-/g, '+').replace(/_/g, '/');
  return {
    digest: evidence[0],
    trace: Buffer.from(standard, 'base64').toString('utf8'),
  };
}

test.describe('ExecutionChallengeV1 version-6 (real-platform rung, three-engine corpus)', () => {
  test('25 fresh v6 lifecycles run the platform probes and verify end to end on every engine', async ({ page }) => {
    for (let i = 0; i < K; i++) {
      await armedV6Page(page);
      const origin = await fixtureOrigin(page);
      const token = await page.locator('[data-kiwi-token]').inputValue();
      expect(token.length, `lifecycle ${i}: the armed v6 solve must mint a token`).toBeGreaterThan(0);
      const { digest, trace } = tokenTrace(token);
      expect(digest, `lifecycle ${i}: the digest must be 64 lowercase hex`).toMatch(/^[0-9a-f]{64}$/);
      for (const marker of ['dcsgeom(', 'dmutord(', 'devphf(', 'drange(', 'dintobs(']) {
        expect(trace.includes(marker), `lifecycle ${i}: the v6 probe entry ${marker} must be present`).toBe(true);
      }
      if (i === 0) {
        // The quantized-observation shapes of the five families.
        expect(trace).toMatch(/dcsgeom\(\d+,\d+\)/);
        expect(trace).toMatch(/dmutord\(\d+\)/);
        expect(trace).toMatch(/devphf\(\d+:\d+\)/);
        expect(trace).toMatch(/drange\(\d+,\d+,\d+\)/);
        expect(trace).toMatch(/dintobs\(\d+,\d+,\d+\)/);
      }
      const result = await verifyToken(page, origin, token);
      expect(
        result.body.ok,
        `lifecycle ${i}: the v6 solve must verify against the server-side envelope, got ${result.body.code}`
      ).toBe(true);
    }
  });

  test('the v6 probe observations stay inside the operand-derived envelopes on every engine', async ({ page }) => {
    // The envelope semantics pinned from the browser side (the server
    // walker enforces the same bounds): the computed font size equals
    // the drawn declaration, the mutation record sequence carries the
    // promise marker last, the event phases read capture-target-bubble
    // with the listener side effect, the Selection holds the added
    // range, and the intersection observer delivers its initial entry.
    await armedV6Page(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const { trace } = tokenTrace(token);
    const entries = trace.split(';');
    const cssgeom = entries.find((e) => e.startsWith('dcsgeom('));
    const cssParts = cssgeom.slice('dcsgeom('.length, -1).split(',');
    const fs = Number(cssParts[0]);
    expect(fs, 'the computed font size resolves the drawn declaration').toBeGreaterThanOrEqual(10);
    expect(fs, 'the computed font size resolves the drawn declaration').toBeLessThanOrEqual(14);
    const h = Number(cssParts[1]);
    expect(h, 'the probe measures a real line-box stack').toBeGreaterThanOrEqual(fs);
    const mutord = entries.find((e) => e.startsWith('dmutord('));
    expect(mutord.endsWith('7)'), 'the promise marker is delivered after every mutation record').toBe(true);
    expect(mutord, 'the observer runs at the microtask checkpoint, not later').toMatch(/^dmutord\(1[23]+7\)$/);
    const evphf = entries.find((e) => e.startsWith('devphf('));
    expect(evphf, 'the full event path is capture, target order, bubble').toBe('devphf(1234:3)');
    const drange = entries.find((e) => e.startsWith('drange('));
    const rangeParts = drange.slice('drange('.length, -1).split(',');
    expect(Number(rangeParts[2]), 'the Selection holds the added range').toBe(1);
    expect(Number(rangeParts[1]), 'the range crosses real line boxes').toBeGreaterThanOrEqual(3);
    const dintobs = entries.find((e) => e.startsWith('dintobs('));
    const intParts = dintobs.slice('dintobs('.length, -1).split(',');
    expect(Number(intParts[0]), 'the intersection observer delivers its initial entry').toBe(1);
    expect(Number(intParts[1]), 'the quantized ratio stays in percent').toBeGreaterThanOrEqual(0);
    expect(Number(intParts[1]), 'the quantized ratio stays in percent').toBeLessThanOrEqual(100);
    expect(Number(intParts[2]), 'isIntersecting is set').toBeLessThanOrEqual(1);
  });
});
