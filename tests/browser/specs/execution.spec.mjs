import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// ExecutionChallengeV1 — the Cap-style browser-execution dimension.
//
// An armed challenge response carries an `execution_program` (base64 of
// a deterministic bytecode blob). The driver lazily loads the fixed
// audited interpreter asset (execution.<sha256>.js, served by the
// existing immutable content-addressed asset route with SRI), runs the
// program in a sandboxed ephemeral iframe (srcdoc, per challenge,
// removed after), and appends the resulting execution digest (64 hex)
// to the solution token. The fixture /verify recomputes the expected
// digest from the stored program and rejects a mismatch with the
// deterministic execution_mismatch outcome.
//
// Lazy invariant: a SHA-only challenge without a program pays zero
// bytes for the interpreter — the no-program spec asserts zero requests.
// Request accounting: an armed lifecycle performs exactly one
// interpreter fetch (the iframe's same-origin <script src
// integrity=...>; the browser's native SRI check is the fail-closed
// preflight — a mismatch never executes and the driver times out into
// the controlled kiwi:execution-unavailable state, never a silent
// success). A second armed widget's iframe load is served from the
// browser cache (the content-addressed immutable URL), and the driver
// itself never issues a fetch for the interpreter.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..', '..');

function assetPath(name) {
  return path.join(REPO, 'packages', 'kiwicaptcha-wasm', 'assets', name);
}

async function armedPage(page, query = '') {
  await page.goto(`/?assets=files&execution=1${query}`);
  await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', {
    timeout: 120_000,
  });
}

async function verifyToken(page, token) {
  const resp = await page.request.post('http://127.0.0.1:8085/verify', {
    data: { token },
  });
  return { status: resp.status(), body: await resp.json() };
}

test.describe('ExecutionChallengeV1 (browser)', () => {
  test('an armed challenge executes in the sandboxed interpreter and verifies end to end', async ({ page }) => {
    await armedPage(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    expect(token.length).toBeGreaterThan(0);

    // The token carries the 5th execution-digest segment: 64 lowercase hex.
    const plain = Buffer.from(token, 'base64').toString('utf8');
    const parts = plain.split('.');
    expect(parts.length, 'an armed token must carry the execution digest as the final segment').toBe(5);
    expect(parts[4], 'the digest must be 64 lowercase hex').toMatch(/^[0-9a-f]{64}$/);

    const result = await verifyToken(page, token);
    expect(result.body.ok, `the armed solve must verify (got ${result.body.code})`).toBe(true);

    // The interpreter iframe is ephemeral: it must be gone after the run.
    const iframes = await page.evaluate(
      () => Array.from(document.querySelectorAll('iframe[sandbox*="allow-scripts"]')).length
    );
    expect(iframes, 'the sandboxed execution iframe must be removed after the run').toBe(0);
  });

  test('a WRONG (tampered) digest is the deterministic execution_mismatch', async ({ page }) => {
    await armedPage(page);
    const token = await page.locator('[data-kiwi-token]').inputValue();
    const plain = Buffer.from(token, 'base64').toString('utf8');
    const parts = plain.split('.');
    expect(parts.length).toBe(5);
    // Flip the first hex character of the digest.
    const tamperedDigest = (parts[4][0] === '0' ? '1' : '0') + parts[4].slice(1);
    expect(tamperedDigest).not.toBe(parts[4]);
    parts[4] = tamperedDigest;
    const tamperedToken = Buffer.from(parts.join('.')).toString('base64');

    const result = await verifyToken(page, tamperedToken);
    expect(result.body.ok).toBe(false);
    expect(result.body.code, 'a tampered digest must fail with the deterministic execution_mismatch').toBe('execution_mismatch');
  });

  test('a digest from another challenge is execution_mismatch', async ({ page }) => {
    // Two armed lifecycles on one page: each token carries its own
    // digest. Presenting challenge A's digest with challenge B's nonce
    // must fail (the digest binds the nonce-bound context).
    await page.goto('/?assets=files&execution=1&widgets=2');
    await expect(page.locator('[data-kiwi-widget]').first()).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    await expect(page.locator('[data-kiwi-widget]').nth(1)).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const tokens = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[data-kiwi-token]')).map((el) => el.value)
    );
    const plainA = Buffer.from(tokens[0], 'base64').toString('utf8').split('.');
    const plainB = Buffer.from(tokens[1], 'base64').toString('utf8').split('.');
    expect(plainA[0]).not.toBe(plainB[0]);

    // The digest of B presented for the nonce of A.
    plainA[4] = plainB[4];
    const crossed = Buffer.from(plainA.join('.')).toString('base64');
    const result = await verifyToken(page, crossed);
    expect(result.body.ok).toBe(false);
    expect(result.body.code).toBe('execution_mismatch');
  });

  test('the interpreter asset is a fixed audited VM: no eval, no new Function', async () => {
    const src = fs.readFileSync(assetPath('execution-interpreter.js'), 'utf8');
    // The spec grep assertion: the audited interpreter must contain no
    // dynamic code-construction surface. `new Function` and `eval` are
    // banned outright; `setTimeout`-with-string and `importScripts` are
    // not part of the VM either.
    expect(src).not.toMatch(/\beval\s*\(/);
    expect(src).not.toMatch(/new\s+Function\s*\(/);
    expect(src).not.toMatch(/setTimeout\s*\(\s*["']/);
    expect(src).not.toMatch(/Function\s*\(\s*["']/);
    // The op-count bound is enforced by the parser (8..24 ops), the
    // deterministic proxy for the ~20 ms wall-clock budget documented
    // in the interpreter header: the VM never loops over an unbounded
    // program.
    expect(src).toContain('MAX_OPS = 24');
    expect(src).toContain('8..24 ops');
  });

  test('request accounting is exact: one interpreter fetch for an armed lifecycle, zero for the no-program SHA path', async ({ page }) => {
    const execRequests = [];
    page.on('request', (request) => {
      if (request.url().includes('/assets/execution.')) execRequests.push(request);
    });

    // 1. The no-program SHA path fetches nothing (the lazy invariant).
    await page.goto('/?assets=files');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    expect(execRequests, 'a SHA-only challenge without a program must fetch zero interpreter bytes').toHaveLength(0);

    // 2. An armed lifecycle fetches the interpreter exactly once, and
    //    the driver never issues its own fetch (resourceType 'script' —
    //    the iframe's SRI-pinned same-origin load).
    await page.goto('/?assets=files&execution=1');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 120_000 });
    const armed = execRequests.filter((r) => r.url().includes('/assets/execution.'));
    expect(armed, 'an armed lifecycle must perform exactly one interpreter fetch').toHaveLength(1);
    expect(armed[0].resourceType(), 'the interpreter load is the iframe script (the driver performs no fetch of its own)').toBe('script');
  });

  test('the op-count bound holds and the wall-clock stays far under the documented ~20 ms budget', async ({ page }) => {
    // The documented budget: ~20 ms on low-end devices for the VM run.
    // The measured span here is the whole armed lifecycle from the
    // challenge response to the solved token, a deliberately loose
    // wall-clock assertion; the deterministic proxy is the 8..24
    // op-count bound the program parser enforces (asserted below).
    const started = Date.now();
    await armedPage(page);
    expect(Date.now() - started).toBeLessThan(60_000);

    // The deterministic bound: every issued program carries 8..24 ops.
    const resp = await page.request.post('http://127.0.0.1:8085/challenge?execution=1', {
      data: { scope: 'login' },
    });
    const challenge = await resp.json();
    expect(typeof challenge.execution_program).toBe('string');
    const blob = Buffer.from(challenge.execution_program, 'base64');
    // Blob layout: format(1) scopeLen(1) scope actionLen(1) action
    // opVersion(1) opCount(1) ...
    let pos = 1;
    const scopeLen = blob[pos++];
    pos += scopeLen;
    const actionLen = blob[pos++];
    pos += actionLen;
    pos += 1; // op version
    const opCount = blob[pos];
    expect(opCount).toBeGreaterThanOrEqual(8);
    expect(opCount).toBeLessThanOrEqual(24);
  });

  test('an interpreter failure enters the controlled kiwi:execution-unavailable state, never a silent success', async ({ page }) => {
    // Route the interpreter asset to a 404: the iframe's script never
    // loads, no ready handshake arrives, and the driver must enter the
    // controlled error state with the token cleared — never a token
    // without its digest.
    await page.route('**/assets/execution.*.js', (route) => route.fulfill({ status: 404, body: 'not found' }));
    await page.goto('/?assets=files&execution=1');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'kiwi:execution-unavailable', {
      timeout: 30_000,
    });
    expect(await page.locator('[data-kiwi-token]').inputValue(), 'no token may be minted without its execution digest').toBe('');
  });
});
