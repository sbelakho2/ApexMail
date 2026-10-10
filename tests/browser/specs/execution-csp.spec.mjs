import { test, expect } from '@playwright/test';

// ExecutionChallengeV1 under real Content-Security-Policy response
// headers (playwright.a11y.config.mjs three-engine lane and the default
// chromium lane): the fixture router emits genuine policy headers on
// the widget page (?csp=strict, ?csp=execution-blocked), never a <meta>
// approximation, so these tests qualify what a real deployment header
// allows and blocks for the execution lifecycle.
//
// The files tier page under ?csp=strict carries the documented
// production profile: same-origin assets only (script-src, style-src,
// connect-src and worker-src 'self'), the fixture's inline stylesheet
// hash-pinned, no wasm-unsafe-eval (the SHA-256 page solves in pure
// JS), object-src 'none', base-uri 'none', form-action 'self',
// frame-src 'none' and frame-ancestors 'none'. The policy stays
// functional for execution: the driver script and the challenge POST
// are same-origin, and the sandboxed srcdoc iframe inherits the policy
// for its own same-origin interpreter <script src> (about:srcdoc is
// not governed by frame-src in any of the three engines, which is what
// makes frame-src 'none' compatible with the ephemeral execution
// iframe).
//
// The ?csp=execution-blocked policy removes the 'self' source from
// script-src and lists content hashes instead; the interpreter asset's
// hash is absent, so its fetch inside the srcdoc iframe is refused
// while the page's own driver script still runs through its hash.
// The armed lifecycle must then fail closed in the controlled
// kiwi:execution-unavailable state with no token, never a version-1
// downgrade and never an unarmed solve.

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

test.describe('ExecutionChallengeV1 under real CSP headers', () => {
  test('the documented strict CSP permits the execution challenge end to end', async ({ page }) => {
    const execResponses = [];
    page.on('response', (response) => {
      if (response.url().includes('/assets/execution.')) execResponses.push(response);
    });

    const response = await page.goto('/?assets=files&execution=1&csp=strict');
    const policy = response.headers()['content-security-policy'] || '';
    expect(policy, 'the fixture must send a real Content-Security-Policy header').toContain("script-src 'self'");
    expect(policy, 'the documented profile keeps frame-src none').toContain("frame-src 'none'");
    expect(policy, 'the documented profile never needs unsafe-inline in the files tier').not.toContain('unsafe-inline');

    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
      timeout: 120_000,
    });

    // The strict policy must not block the lazy interpreter load: the
    // srcdoc iframe's same-origin script fetch rides the inherited
    // script-src 'self'.
    expect(execResponses, 'the strict policy must permit the one interpreter fetch').toHaveLength(1);
    expect(execResponses[0].status(), 'the interpreter asset must be served').toBe(200);

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'an armed solve under the strict policy must mint a token').toBeGreaterThan(0);

    // The token shape is the armed shape: the final segment is the
    // 64-lowercase-hex digest plus the base64url trace after the colon.
    const plain = Buffer.from(token, 'base64').toString('utf8');
    const parts = plain.split('.');
    expect(parts.length, 'an armed token must carry the execution evidence as the final segment').toBe(5);
    const evidence = parts[4].split(':');
    expect(evidence[0], 'the digest must be 64 lowercase hex').toMatch(/^[0-9a-f]{64}$/);
    expect(evidence.length, 'the trace evidence must be present after the digest').toBe(2);

    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, `the armed solve must verify (got ${result.body.code})`).toBe(true);

    // The interpreter iframe is ephemeral: it must be gone after the run.
    const iframes = await page.evaluate(
      () => Array.from(document.querySelectorAll('iframe[sandbox*="allow-scripts"]')).length
    );
    expect(iframes, 'the sandboxed execution iframe must be removed after the run').toBe(0);
  });

  test('the documented strict CSP permits a version-5 armed execution challenge end to end', async ({ page }) => {
    // The version-5 causal grammar under the real strict header: the
    // fixture cap knob (?exec_cap=5) makes the driver's
    // Kiwi-Execution-Max-Version 5 advertisement issue the v5 program,
    // and the interpreter executes its object-graph ops inside the
    // same policy-inheriting srcdoc iframe. The durlc entry reads the
    // iframe's about:srcdoc URL, which is not governed by frame-src in
    // any engine — the same property that keeps frame-src 'none'
    // compatible with the ephemeral execution iframe.
    const execResponses = [];
    page.on('response', (response) => {
      if (response.url().includes('/assets/execution.')) execResponses.push(response);
    });

    const response = await page.goto('/?assets=files&execution=1&exec_cap=5&csp=strict');
    const policy = response.headers()['content-security-policy'] || '';
    expect(policy, 'the fixture must send a real Content-Security-Policy header').toContain("script-src 'self'");

    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
      timeout: 120_000,
    });

    expect(execResponses, 'the strict policy must permit the one interpreter fetch').toHaveLength(1);
    expect(execResponses[0].status(), 'the interpreter asset must be served').toBe(200);

    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length, 'an armed v5 solve under the strict policy must mint a token').toBeGreaterThan(0);
    const plain = Buffer.from(token, 'base64').toString('utf8');
    const parts = plain.split('.');
    expect(parts.length, 'an armed token must carry the execution evidence as the final segment').toBe(5);
    const evidence = parts[4].split(':');
    expect(evidence[0], 'the digest must be 64 lowercase hex').toMatch(/^[0-9a-f]{64}$/);
    expect(evidence.length, 'the trace evidence must be present after the digest').toBe(2);
    const standard = evidence[1].replace(/-/g, '+').replace(/_/g, '/');
    const trace = Buffer.from(standard, 'base64').toString('utf8');
    for (const marker of ['dclone(', 'drepar(', 'durlc(', 'dmutate(']) {
      expect(trace.includes(marker), `the v5 spine entry ${marker} must be present under the strict policy`).toBe(true);
    }

    const result = await verifyToken(page, await fixtureOrigin(page), token);
    expect(result.body.ok, `the v5 armed solve must verify (got ${result.body.code})`).toBe(true);
  });

  test('blocking the execution asset fails closed: no token, no unarmed fallback, no version downgrade', async ({ page }) => {
    // The challenge requests of this lifecycle: the count must stay at
    // one (no retry storm) and the issuance must be execution-armed, so
    // a failure can never fall back to a non-execution solve.
    const challengeRequests = [];
    const challengeResponses = [];
    const execResponses = [];
    page.on('request', (request) => {
      if (request.url().includes('/challenge')) challengeRequests.push(request);
    });
    page.on('response', async (response) => {
      if (response.url().includes('/challenge')) challengeResponses.push(response);
      if (response.url().includes('/assets/execution.')) execResponses.push(response);
    });

    const response = await page.goto('/?assets=files&execution=1&csp=execution-blocked');
    const policy = response.headers()['content-security-policy'] || '';
    expect(policy, 'the fixture must send the interpreter-blocking policy header').toContain("script-src 'sha256-");
    expect(policy, 'the interpreter-blocking policy must not carry a same-origin script source').not.toContain("script-src 'self'");

    // The controlled failure: the interpreter fetch is refused by the
    // inherited script-src hash allowlist, no ready handshake arrives,
    // and the driver times out into kiwi:execution-unavailable.
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:execution-unavailable', {
      timeout: 60_000,
    });

    // Never a silent success, never a weaker-profile fallback: the
    // token stays empty.
    expect(await page.locator('[data-kiwi-token]').inputValue(), 'no token may be minted without its execution digest').toBe('');

    // The program issued to the page was execution-armed: the challenge
    // response carried the execution_program, so the widget was never
    // downgraded to an unarmed or version-1-only issuance.
    expect(challengeRequests, 'exactly one challenge request, no retry storm').toHaveLength(1);
    expect(challengeRequests[0].headers()['kiwi-execution-max-version'], 'the driver must advertise its execution capability').toBe('6');
    expect(challengeResponses, 'the armed challenge response must have arrived').toHaveLength(1);
    const issuance = await challengeResponses[0].json();
    expect(typeof issuance.execution_program, 'the issuance must be execution-armed').toBe('string');
    expect(issuance.execution_program.length, 'the armed program must be non-empty').toBeGreaterThan(0);

    // The blocked interpreter never produced a response: the refusal
    // happens inside the srcdoc iframe before any network request.
    expect(execResponses, 'the blocked interpreter asset must never be served').toHaveLength(0);
  });
});
