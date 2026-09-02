import { test, expect } from '@playwright/test';

// Portable ExecutionChallengeV1 evidence for the three-engine lane
// (playwright.a11y.config.mjs): the armed challenge lifecycle must
// prove end to end on Chromium, Firefox and WebKit, not only on the
// chromium-only default lane.
//
// The chromium-only execution.spec.mjs keeps the tamper outcomes, the
// digest-crossing case, the exact request accounting, the interpreter
// source grep and the kiwi:execution-unavailable state. This spec pins
// the lifecycle every engine must honor: issue a real armed challenge,
// run its program in the sandboxed ephemeral iframe, mint the token
// and verify the solve against the fixture. The fixture knobs and the
// token attributes are the same ones the full suite uses.
//
// The sandbox wording stays precise here: the srcdoc sandbox with
// allow-scripts allow-same-origin is DOM and execution isolation for
// the first-party content-addressed interpreter the browser pins via
// SRI, never a hostile-code security boundary.

const K = 6;

async function armedPage(page) {
  // One fresh armed lifecycle per page load: the files-tier page with
  // the execution fixture knob (?execution=1), solved by the driver to
  // the done state.
  await page.goto('/?assets=files&execution=1');
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
    timeout: 120_000,
  });
}

// The fixture origin is read from the live page, so the same spec
// serves the default chromium lane (8085) and the three-engine lane
// (8087) without a hard-coded port. Call it after a navigation.
async function fixtureOrigin(page) {
  return page.evaluate(() => window.location.origin);
}

async function verifyToken(page, origin, token) {
  const resp = await page.request.post(`${origin}/verify`, { data: { token } });
  return { status: resp.status(), body: await resp.json() };
}

test.describe('ExecutionChallengeV1 (portable three-engine corpus)', () => {
  test('six fresh armed lifecycles issue, mint and verify end to end on every engine', async ({ page }) => {
    // K fresh armed lifecycles, one per page load. Every issued
    // program carries the guaranteed construction-to-probe structure
    // (a DOM construction block, then real probes of the constructed
    // node), so each solve genuinely runs the interpreter. The
    // fixture /verify recomputes the expected digest from the stored
    // program and validates the trace entry by entry.
    for (let i = 0; i < K; i++) {
      await armedPage(page);
      const origin = await fixtureOrigin(page);
      const token = await page.locator('[data-kiwi-token]').inputValue();
      expect(token.length, `lifecycle ${i}: the armed solve must mint a token`).toBeGreaterThan(0);
      if (i === 0) {
        const plain = Buffer.from(token, 'base64').toString('utf8');
        const evidence = plain.split('.').at(-1).split(':');
        const standard = evidence[1].replace(/-/g, '+').replace(/_/g, '/');
        const trace = Buffer.from(standard, 'base64').toString('utf8');
        expect(trace.includes('obs('), 'the causal observe entry must be present').toBe(true);
      }
      const result = await verifyToken(page, origin, token);
      expect(
        result.body.ok,
        `lifecycle ${i}: the armed solve must verify end to end (got ${result.body.code})`
      ).toBe(true);

      if (i === 0) {
        // The first lifecycle also pins the token shape: the execution
        // evidence is the final segment, the 64-lowercase-hex digest
        // plus the base64url trace after the colon.
        const plain = Buffer.from(token, 'base64').toString('utf8');
        const parts = plain.split('.');
        expect(parts.length, 'an armed token must carry the execution evidence as the final segment').toBe(5);
        const evidence = parts[4].split(':');
        expect(evidence[0], 'the digest must be 64 lowercase hex').toMatch(/^[0-9a-f]{64}$/);
        expect(evidence.length, 'the trace evidence must be present after the digest').toBe(2);
        expect(evidence[1].length, 'the base64url trace must be non-empty').toBeGreaterThan(0);
        // The interpreter iframe is ephemeral: it must be gone after
        // the run.
        const iframes = await page.evaluate(
          () => Array.from(document.querySelectorAll('iframe[sandbox*="allow-scripts"]')).length
        );
        expect(iframes, 'the sandboxed execution iframe must be removed after the run').toBe(0);
      }
    }
  });
});
