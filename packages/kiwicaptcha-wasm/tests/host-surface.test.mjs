// Host-side checks for the two public JS surfaces the browser specs only
// exercise end to end:
//
//   - window.KiwiCaptchaExecution: the execution interpreter's exposed
//     protocol string and computeDigest (the digest the server mirror
//     must reproduce). The asset is a classic IIFE, so it runs in a
//     node:vm context with a window object and no DOM.
//   - window.__kiwiCaptchaWasm.initSync: the wasm-bindgen synchronous
//     initializer the glue exposes beside load(). It is a real public
//     surface (the worker/compat path calls it), so it is pinned here
//     against the embedded wasm bytes.
//
// Run with: node --test tests/host-surface.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const assets = path.resolve(here, '../assets');

function loadExecutionInterpreter() {
  const source = fs.readFileSync(path.join(assets, 'execution-interpreter.js'), 'utf8');
  const window = {};
  const context = vm.createContext({
    window,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Int32Array,
    DataView,
    Math,
    JSON,
    console,
    atob: globalThis.atob,
    btoa: globalThis.btoa,
    setTimeout,
    clearTimeout,
  });
  vm.runInContext(source, context, { filename: 'execution-interpreter.js' });
  return window.KiwiCaptchaExecution;
}

function loadWasmGlue() {
  const source = fs.readFileSync(path.join(assets, 'kiwicaptcha-wasm.js'), 'utf8');
  const window = {};
  const context = vm.createContext({
    window,
    WebAssembly,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Int32Array,
    DataView,
    Math,
    JSON,
    console,
    atob: globalThis.atob,
    btoa: globalThis.btoa,
    Date,
    performance: { now: () => 0 },
  });
  vm.runInContext(source, context, { filename: 'kiwicaptcha-wasm.js' });
  return { glue: window.__kiwiCaptchaWasm, context };
}

const NONCE = 'A'.repeat(43) + '=';

test('KiwiCaptchaExecution.protocol is the shared execution protocol id', () => {
  const execution = loadExecutionInterpreter();
  assert.equal(execution.protocol, 'kiwi-execution-v1');
});

test('KiwiCaptchaExecution.computeDigest is HMAC-SHA256 over the canonical trace', () => {
  const execution = loadExecutionInterpreter();
  const programBytes = new Uint8Array(Array.from({ length: 48 }, (_, i) => (i * 7) & 0xff));
  const program = { scope: 'login', action: 'submit', opVersion: 4 };
  const trace = 'add(2);mul(3);obs(1,' + 'ab'.repeat(32) + ')';
  const expected = createHmac('sha256', programBytes)
    .update(
      'kiwi-execution-v1|' + NONCE + '|login|submit|4|' + trace,
      'utf8',
    )
    .digest('hex');
  const digest = execution.computeDigest(programBytes, program, NONCE, trace);
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.equal(digest, expected);

  // A different trace must produce a different digest (the trace is
  // inside the HMAC message, not just the key).
  assert.notEqual(
    execution.computeDigest(programBytes, program, NONCE, trace + ';add(1)'),
    digest,
  );
});

test('KiwiCaptchaExecution.parseProgram refuses malformed bytecode', () => {
  const execution = loadExecutionInterpreter();
  assert.equal(execution.parseProgram(new Uint8Array([])), null);
  // Format byte 1, then an out-of-range scope length.
  assert.equal(execution.parseProgram(new Uint8Array([1, 200])), null);
});

test('__kiwiCaptchaWasm.initSync instantiates the embedded wasm synchronously', () => {
  const { glue, context } = loadWasmGlue();
  assert.equal(typeof glue.initSync, 'function');
  const bytes = new Uint8Array(
    fs.readFileSync(path.resolve(here, '../pkg/kiwicaptcha_wasm_bg.wasm')),
  );
  // The module wrapper must be created in the glue's realm: wasm-bindgen
  // detects the { module } form with Object.getPrototypeOf() === the
  // realm's Object.prototype.
  context.__wasmBytes = bytes;
  const wasm = vm.runInContext(
    'window.__kiwiCaptchaWasm.initSync({ module: __wasmBytes })',
    context,
  );
  assert.equal(wasm.solver_protocol_version(), 2);

  // The allocator/deallocator pair the widget's raw-pointer ABI uses is
  // live after a synchronous init.
  const ptr = wasm.alloc(8);
  assert.notEqual(ptr, 0);
  wasm.dealloc(ptr, 8);
});
