// The version-6 emulator leg of the fail harness: a best-effort
// emulation attempt that runs the real interpreter asset (the audited
// browser asset, unmodified) inside a jsdom or happy-dom window and
// submits whatever trace the emulation produces. A host without a real
// layout engine or real observers either crashes an attempt (recorded
// as a rejection with the failure reason, the verify leg judges a null
// trace rejected) or produces trace entries the envelope walker
// rejects server-side.
//
// The attempt mirrors the browser context: a fresh document per
// program (the browser runs every program in a fresh sandboxed
// iframe), the unmodified asset source evaluated in that document's
// realm, and runProgram entered exactly as the driver enters it (the
// exposed parseProgram + runProgram pair, the returned promise awaited
// so the asynchronous platform probes run to completion).
//
// Usage: php corpus.php <offset> <n> | node emulator-leg.mjs <jsdom|happy-dom>
// Prints one JSON object per line: {i, ok, trace, error, ms}.

import fs from 'node:fs';
import readline from 'node:readline';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const engine = process.argv[2] || 'jsdom';

const assetPath = path.resolve(
  fileURLToPath(new URL('../../../packages/kiwicaptcha-wasm/assets/execution-interpreter.js', import.meta.url))
);
const assetSource = fs.readFileSync(assetPath, 'utf8');

function decodeBase64(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

async function jsdomAttempt(programB64) {
  const { JSDOM } = await import('jsdom');
  const dom = new JSDOM('<!doctype html><html><head></head><body></body></html>', {
    runScripts: 'outside-only',
    pretendToBeVisual: true,
    url: 'about:srcdoc',
  });
  const t0 = performance.now();
  try {
    dom.window.eval(assetSource);
    const api = dom.window.KiwiCaptchaExecution;
    const program = api.parseProgram(decodeBase64(programB64));
    const trace = await api.runProgram(program, dom.window.document);
    return { trace, ms: performance.now() - t0 };
  } finally {
    dom.window.close();
  }
}

async function happyDomAttempt(programB64) {
  const { Window } = await import('happy-dom');
  const win = new Window({ url: 'about:srcdoc' });
  const t0 = performance.now();
  try {
    win.document.body.innerHTML = '';
    vm.runInContext(assetSource, win, { timeout: 5000 });
    const api = win.KiwiCaptchaExecution;
    const program = api.parseProgram(decodeBase64(programB64));
    const trace = await api.runProgram(program, win.document);
    return { trace, ms: performance.now() - t0 };
  } finally {
    await win.happyDOM.close();
  }
}

const attempt = engine === 'jsdom' ? jsdomAttempt : happyDomAttempt;

async function main() {
  const out = fs.createWriteStream(null, { fd: 1 });
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  let done = 0;
  for await (const line of rl) {
    if (!line.trim()) continue;
    const record = JSON.parse(line);
    let result;
    const t0 = performance.now();
    try {
      const { trace, ms } = await attempt(record.program);
      result = { i: record.i, ok: true, trace, error: null, ms: Math.round(ms * 100) / 100 };
    } catch (err) {
      result = {
        i: record.i,
        ok: false,
        trace: null,
        error: String(err && err.message ? err.message : err).slice(0, 200),
        ms: Math.round((performance.now() - t0) * 100) / 100,
      };
    }
    out.write(JSON.stringify(result) + '\n');
    done++;
    if (done % 1000 === 0) {
      fs.writeSync(2, `emulator-leg(${engine}): ${done} attempts\n`);
    }
  }
  out.end();
}

main().catch((err) => {
  console.error(String(err));
  process.exit(1);
});
