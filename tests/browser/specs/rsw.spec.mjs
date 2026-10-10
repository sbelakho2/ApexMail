import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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

function workerSource() {
  return fs.readFileSync(assetPath('kiwi-worker.js'), 'utf8');
}

// The fixture's fixed 2048-bit rsw modulus (tests/browser/router.php is
// the single source of the fixture key pair): a canonical modulus is
// exactly 256 bytes with the top bit set and the last byte odd.
function fixtureModulus() {
  const router = fs.readFileSync(
    path.resolve(specDir, '../router.php'),
    'utf8',
  );
  const match = router.match(/\$GLOBALS\['kiwi_rsw_modulus_n'\] = '([^']+)'/);
  if (!match) throw new Error('fixture rsw modulus not found in router.php');
  return match[1];
}

// The optional rsw time-lock rung end to end: the fixture issues an rsw
// challenge (algorithm rsw, sequential cost T from ?rsw_t=), the widget
// driver dispatches it to the worker asset, the worker performs the T
// sequential modular squarings in pure JS BigInt and reports the final
// value, and the driver mints the rsw token shape: counter 0 plus the
// final 512-hex proof segment. The fixture's /verify endpoint checks the
// proof against the trapdoor expectation and accepts it.
test.describe('KiwiCaptcha rsw sequential time-lock', () => {
  async function solveRsw(page, t, query) {
    await page.goto(`/?algorithm=rsw&rsw_t=${t}${query || ''}`);
    const tokenInput = page.locator('[data-kiwi-token]');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 60_000 });
    const token = await tokenInput.inputValue();
    expect(token.length).toBeGreaterThan(0);
    // The rsw token shape: base64(nonce.0.duration.telemetry.512hex).
    const parts = atob(token).split('.');
    expect(parts.length).toBe(5);
    expect(parts[1]).toBe('0'); // no search counter exists for a time lock
    expect(parts[4]).toMatch(/^[0-9a-f]{512}$/);
    return token;
  }

  test('the worker solves the sequential time lock and the fixture verifies the proof', async ({ page }) => {
    // The legacy static-worker path (?worker=1) loads the fresh worker
    // asset from disk and derives the runtime URL, so the spec exercises
    // the real asset bytes without depending on the glue copy.
    const token = await solveRsw(page, 10000, '&worker=1');
    const workerUsed = await page.evaluate(() => window.__kiwiWorkerUsed === true);
    expect(workerUsed, 'the rsw solve must run in the same-origin worker').toBe(true);
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    const body = await resp.json();
    expect(body.ok, `verify must accept the worker-solved rsw token (${body.code})`).toBe(true);
  });

  test('files mode solves an rsw challenge with the versioned worker asset', async ({ page }) => {
    // Files mode fetches the content-addressed worker and runtime assets
    // with their SRI pins and constructs a same-origin Worker from the
    // verified bytes; the rsw solver in the asset must solve it.
    const token = await solveRsw(page, 10000, '&assets=files');
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    const body = await resp.json();
    expect(body.ok, `files-mode rsw verify must accept the token (${body.code})`).toBe(true);
  });

  test('a tampered rsw proof never verifies', async ({ page }) => {
    // Mint a real rsw token through the widget, then flip one hex digit
    // of the proof: the fixture verifier recomputes the trapdoor
    // expectation and must reject the mismatch.
    const token = await solveRsw(page, 10000, '&worker=1');
    const parts = atob(token).split('.');
    let proof = parts[4];
    proof = (proof[0] === '0' ? '1' : '0') + proof.slice(1);
    parts[4] = proof;
    const tampered = btoa(parts.join('.'));
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token: tampered } });
    const body = await resp.json();
    expect(body.ok).toBe(false);
    expect(body.code).toBe('insufficient_work');
  });

  test('an execution-armed rsw challenge solves with the digest:trace evidence and the final value on one token', async ({ page }) => {
    // The rsw + execution composition end to end: the fixture issues an
    // execution-armed rsw challenge (algorithm rsw, T=10000, armed
    // ExecutionChallengeV1 program), the driver runs the worker's
    // sequential squarer AND the interpreter, and mints the composed
    // token shape — nonce.0.duration.telemetry.digest:trace.512hex —
    // whose server-side decode must now accept the composed token.
    await page.goto('/?algorithm=rsw&rsw_t=10000&execution=1&assets=files');
    const tokenInput = page.locator('[data-kiwi-token]');
    await expect(page.locator('[data-kiwi-widget]')).toHaveAttribute('data-state', 'done', { timeout: 90_000 });
    const token = await tokenInput.inputValue();
    expect(token.length).toBeGreaterThan(0);
    const parts = atob(token).split('.');
    expect(parts.length).toBe(6, 'the composed token is nonce.0.duration.telemetry.digest:trace.proof');
    expect(parts[1]).toBe('0'); // no search counter exists for a time lock
    expect(parts[4]).toMatch(/^[0-9a-f]{64}:[A-Za-z0-9_-]+$/); // the digest:trace evidence
    expect(parts[5]).toMatch(/^[0-9a-f]{512}$/); // the rsw final value
    const resp = await page.request.post('http://127.0.0.1:8085/verify', { data: { token } });
    const body = await resp.json();
    expect(body.ok, `verify must accept the composed rsw + execution token (${body.code})`).toBe(true);
  });
});

test.describe('KiwiCaptcha rsw worker parameter rejection', () => {
  // The worker must reject an unsupported rsw ladder at once, before
  // any work: T outside the protocol bounds 10,000..=300,000, a T that
  // is not an integer, or a modulus that is not a canonical 2048-bit odd
  // composite (not 256 bytes, top bit clear, or even) must produce the
  // shared unsupported_rsw_params failure with zero progress posts and
  // no done message. The driver contract already filters these, so the
  // worker is exercised directly here (the standalone asset in a Blob
  // worker, the same isolation pattern as the security spec).
  const GOOD_T = 10000;
  const NON_INTEGER_T = 75000.5;
  const BELOW_FLOOR_T = 9999;
  const ABOVE_CEILING_T = 300001;

  function solveMessage(t, modulusB64) {
    return {
      v: 1,
      type: 'solve',
      algorithm: 'rsw',
      prefix: 'kiwicaptcha-rsw-reject-test-prefix',
      prefixLen: 34,
      salt: 'a2l3aWNhcHRjaGE=',
      saltLen: 11,
      targetBits: 1,
      mKib: 0,
      t,
      p: 1,
      startCounter: 0,
      maxHashes: 5000000,
      nonce: 'reject-test-nonce',
      modulus: modulusB64,
    };
  }

  async function probeWorker(page, msg) {
    const workerSrc = workerSource();
    return page.evaluate(
      async ({ src, solve }) => {
        const replies = [];
        const worker = new Worker(
          URL.createObjectURL(new Blob([src], { type: 'application/javascript' }))
        );
        worker.onmessage = (ev) => replies.push(ev.data);
        worker.postMessage(solve);
        // A rejected solve must fail closed inside this window with no
        // progress and no done (a valid solve of T=10000 posts progress
        // and done well inside it too, so the window cannot skew the
        // control case).
        const deadline = Date.now() + 30000;
        while (Date.now() < deadline) {
          if (replies.some((r) => r.type === 'failed' || r.type === 'done')) break;
          await new Promise((r) => setTimeout(r, 10));
        }
        const terminal = replies.find((r) => r.type === 'failed' || r.type === 'done') || null;
        const progress = replies.filter((r) => r.type === 'progress').length;
        const failedReasons = replies.filter((r) => r.type === 'failed').map((r) => r.reason);
        worker.terminate();
        return {
          failedReasons,
          done: terminal && terminal.type === 'done' ? terminal : null,
          progress,
          elapsedMs: null,
        };
      },
      { src: workerSrc, solve: msg },
    );
  }

  test('an out-of-range T is rejected immediately with unsupported_rsw_params (runtime)', async ({ page }) => {
    await page.goto('/');
    const modulusB64 = fixtureModulus();
    for (const [label, t] of [
      ['below the 10,000 floor', BELOW_FLOOR_T],
      ['above the 300,000 ceiling', ABOVE_CEILING_T],
      ['a non-integer T', NON_INTEGER_T],
      ['a non-safe-integer T', 1e16],
    ]) {
      const result = await probeWorker(page, solveMessage(t, modulusB64));
      expect(result.failedReasons, `${label} (T=${t}) must fail with unsupported_rsw_params`).toEqual([
        'unsupported_rsw_params',
      ]);
      expect(result.done, `${label} (T=${t}) must never solve`).toBeNull();
      expect(result.progress, `${label} (T=${t}) must fail before any squaring starts`).toBe(0);
    }
  });

  test('a non-canonical modulus is rejected immediately with unsupported_rsw_params (runtime)', async ({ page }) => {
    await page.goto('/');
    const canonical = Buffer.from(fixtureModulus(), 'base64');
    const even = Buffer.from(canonical);
    even[255] &= 0xfe;
    const topBitClear = Buffer.from(canonical);
    topBitClear[0] &= 0x7f;
    const shortModulus = Buffer.from(canonical.subarray(0, 255));
    const invalidBase64 = 'not-valid-base64!!!';
    const cases = [
      ['an even modulus', even.toString('base64')],
      ['a modulus with the top bit clear', topBitClear.toString('base64')],
      ['a 255-byte modulus', shortModulus.toString('base64')],
      ['a modulus that is not base64', invalidBase64],
    ];
    for (const [label, modulusB64] of cases) {
      const result = await probeWorker(page, solveMessage(GOOD_T, modulusB64));
      expect(result.failedReasons, `${label} must fail with unsupported_rsw_params`).toEqual([
        'unsupported_rsw_params',
      ]);
      expect(result.done, `${label} must never solve`).toBeNull();
      expect(result.progress, `${label} must fail before any squaring starts`).toBe(0);
    }
  });

  test('a canonical rsw solve still completes in the same worker (control)', async ({ page }) => {
    await page.goto('/');
    const result = await probeWorker(page, solveMessage(GOOD_T, fixtureModulus()));
    expect(result.failedReasons).toEqual([]);
    expect(result.done).not.toBeNull();
    expect(result.done.proof).toMatch(/^[0-9a-f]{512}$/);
    expect(result.progress).toBeGreaterThan(0);
  });
});
