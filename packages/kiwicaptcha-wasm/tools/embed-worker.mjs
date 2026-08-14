#!/usr/bin/env node
// Generates the KIWI_WORKER_SRC template literal inside
// assets/widget-driver.js FROM the standalone assets/kiwi-worker.js
// (audit round 15): kiwi-worker.js is the source of truth; the driver's
// embedded copy is machine-generated so the two can never drift by hand.
//
//   node tools/embed-worker.mjs            # --sync: rewrite the driver
//   node tools/embed-worker.mjs --check    # exit 1 on drift (CI)
//
// The embedded literal is escaped for template-literal semantics:
// backticks and ${ sequences in the worker source (e.g. in comments)
// become \` and \${ — the executed bytes are identical to the standalone
// file. A closing-script-tag sequence is REJECTED: the driver is inlined
// into pages by the renderers, so "</script>" inside the literal would
// terminate the page's script element.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WORKER_PATH = join(ROOT, 'assets', 'kiwi-worker.js');
const DRIVER_PATH = join(ROOT, 'assets', 'widget-driver.js');

const OPEN = 'var KIWI_WORKER_SRC = `';
const CLOSE = '`;';

function generate(driver, workerSrc) {
  if (/<\/script/i.test(workerSrc)) {
    throw new Error('kiwi-worker.js must not contain a closing-script-tag sequence (the driver is inlined into pages)');
  }
  // Escape for a JS template literal: backslashes, backticks, ${ sequences.
  const escaped = workerSrc
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\$\{/g, '\\${');

  const startIdx = driver.indexOf(OPEN);
  if (startIdx < 0) {
    throw new Error('widget-driver.js: KIWI_WORKER_SRC opening marker not found');
  }
  const endIdx = driver.indexOf(CLOSE, startIdx + OPEN.length);
  if (endIdx < 0) {
    throw new Error('widget-driver.js: KIWI_WORKER_SRC closing marker not found');
  }

  return driver.slice(0, startIdx + OPEN.length) + escaped + driver.slice(endIdx);
}

const workerSrc = readFileSync(WORKER_PATH, 'utf8');
const driver = readFileSync(DRIVER_PATH, 'utf8');
const regenerated = generate(driver, workerSrc);

const check = process.argv.includes('--check');
if (check) {
  if (regenerated !== driver) {
    console.error('DRIFT: assets/widget-driver.js embeds a stale copy of assets/kiwi-worker.js');
    console.error('run: node tools/embed-worker.mjs  (or packages/kiwicaptcha-wasm/build.sh)');
    process.exit(1);
  }
  console.log('worker source in sync (widget-driver.js <-> kiwi-worker.js)');
} else {
  writeFileSync(DRIVER_PATH, regenerated);
  console.log('widget-driver.js updated from assets/kiwi-worker.js');
}
