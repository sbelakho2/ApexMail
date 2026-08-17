(function() {
  var encoder = new TextEncoder();

  // ── Solver PROTOCOL id (audit #53 / round 23) ───────────────────────
  // A protocol/ABI generation label, bumped manually when the solver
  // protocol or the worker contract changes. The worker reports the SAME
  // id in its `ready`/`done` handshake messages AND verifies the wasm
  // glue's exported solver_protocol_id() before ready; the driver refuses
  // any worker whose id differs (a stale cached worker must never
  // contribute a solution). This establishes driver+worker+wasm protocol
  // compatibility ONLY — exact-artifact identity is guaranteed by the
  // release tag + SHA256SUMS + SRI + attestation, never by this string.
  // Integrators must serve the driver, worker and wasm from the SAME
  // release (see SECURITY.md — versioned-resource expectation).
  var KIWI_SOLVER_PROTOCOL_ID = "2026-08-r1";

  // ── Challenge fetch timeout (audit #66) ─────────────────────────────
  // A hung challenge endpoint must never leave the widget stuck: the fetch
  // carries an AbortController whose timer aborts it after this many ms,
  // routing the widget into the controlled error state (idle-resettable).
  // data-kiwi-fetch-timeout-ms overrides the default per container/widget
  // (test-injectable; integrators may tune their own latency budget).
  var KIWI_FETCH_TIMEOUT_MS = 15000;

  // ── Argon2id worker source (embedded) ───────────────────────────────
  // Same-origin Web Worker for the memory-hard Argon2id solver. The worker
  // must run off the main thread (each 64 MiB hash blocks the UI for tens of
  // ms). The worker source is embedded here as a string constant so the
  // driver can create the worker from a Blob URL (no network, same-origin by
  // construction); when the wasm glue is present as an inline script element in
  // the page its source is prepended to the Blob, and the worker also tries
  // importScripts("kiwicaptcha-wasm.js") for file-based deployments
  // (data-kiwi-worker-src). This literal is GENERATED from
  // assets/kiwi-worker.js by the kiwicaptcha-embed-worker Rust tool
  // (tools/embed-worker, run by build.sh; CI --check fails on drift) —
  // the standalone file is the source of truth; backticks and ${ are
  // escaped for template-literal semantics. The worker must not contain a
  // closing-script-tag sequence (the driver is inlined into pages by the
  // renderers); the generator rejects one.
// KIWI_WORKER_SRC_BEGIN — generated section (tools/embed-worker): the whole span
// from this marker to the KIWI_WORKER_SRC_END marker is machine-written.
  var KIWI_WORKER_SRC = `/* KiwiCaptcha worker solver — standalone same-origin asset.
 *
 * Served next to kiwicaptcha-wasm.js and imported via importScripts, OR
 * embedded: the widget driver (widget-driver.js) embeds the identical
 * worker logic as the KIWI_WORKER_SRC string constant and builds a Blob URL
 * worker from it (prepending the wasm glue source), so no network request
 * is ever made for the worker or the wasm module.
 *
 * Message protocol (worker <-> driver):
 *   in : { type: "solve", algorithm, prefix, prefixLen, salt, saltLen,
 *          targetBits, mKib, t, p, startCounter, maxHashes }
 *        prefix/salt are base64 strings (the driver passes the decoded byte
 *        lengths alongside); the worker decodes them itself.
 *   out: { type: "ready", buildId } on startup (build-id handshake, audit #53)
 *        { type: "progress", counter } every 1000 hashes
 *        { type: "done", counter, buildId }  |  { type: "failed", reason }
 *
 * SHA-256 is solved via the wasm exports (solve_sha256_chunk) with a
 * pure-JS SHA-256 fallback; Argon2id is solved via solve_argon2_chunk (the
 * same wasm the main thread uses — no pure-JS Argon2 exists).
 */
(function () {
  "use strict";

  // Solver PROTOCOL id (audit round 23 — renamed from the misleading
  // "build id" semantics): a compatibility/ABI generation LABEL reported
  // in the handshake for debugging. MUST equal the widget driver's
  // KIWI_SOLVER_PROTOCOL_ID constant. The ENFORCED check is the numeric
  // protocol version against the wasm glue's exported
  // solver_protocol_version() (verified below BEFORE ready). Together
  // they prove driver+worker+wasm speak the same protocol generation —
  // exact artifact identity is guaranteed by the release tag +
  // SHA256SUMS + SRI + attestation, not by these values.
  var KIWI_SOLVER_PROTOCOL_ID = "2026-08-r1";
  var KIWI_SOLVER_PROTOCOL_VERSION = 1;

  // The wasm glue exposes itself as \`window.__kiwiCaptchaWasm\`, so the
  // worker establishes the \`window\` alias (same prelude the widget driver
  // prepends for its Blob worker) BEFORE importing the glue. Without it a
  // standalone same-origin worker (data-kiwi-worker-src) could not load
  // the glue and silently lost its off-main-thread Argon2 solver.
  if (typeof self !== "undefined" && typeof window === "undefined") {
    self.window = self;
  }

  var loader = null;
  try { importScripts("kiwicaptcha-wasm.js"); } catch (e) {}
  if (typeof self !== "undefined" && self.__kiwiCaptchaWasm) {
    loader = self.__kiwiCaptchaWasm;
  }

  var wasm = null;
  var wasmDisabled = false;

  function initWasm() {
    if (wasmDisabled) return Promise.resolve(null);
    if (wasm) return Promise.resolve(wasm);
    if (!loader) return Promise.resolve(null);
    return loader
      .load()
      .then(function (w) {
        wasm = w;
        if (w && w.init_panic_hook) {
          try { w.init_panic_hook(); } catch (e) {}
        }
        return w;
      })
      .catch(function () {
        wasmDisabled = true;
        return null;
      });
  }

  function alloc(w, bytes) {
    var ptr = 0;
    if (w.alloc) {
      ptr = w.alloc(bytes.length);
    } else if (w.__wbindgen_malloc) {
      ptr = w.__wbindgen_malloc(bytes.length, 1);
    } else {
      return 0;
    }
    if (ptr === 0 || ptr === null) return 0;
    new Uint8Array(w.memory.buffer).set(bytes, ptr);
    return ptr;
  }

  function free(w, ptr, len) {
    if (!ptr) return;
    if (w.dealloc) {
      try { w.dealloc(ptr, len); } catch (e) {}
    } else if (w.__wbindgen_free) {
      w.__wbindgen_free(ptr, len, 1);
    }
  }

  function allocatorPresent(w) {
    return !!(w && (w.alloc || w.__wbindgen_malloc) && (w.dealloc || w.__wbindgen_free));
  }

  function b64decode(str) {
    str = String(str).replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    var bin = atob(str);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function leadingZeros(bytes) {
    var n = 0;
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) { n += 8; }
      else { var b = bytes[i]; while ((b & 128) === 0) { n++; b <<= 1; } break; }
    }
    return n;
  }

  // Pure-JS SHA-256 (recycled buffers) — identical to the driver's
  // implementation, used when the wasm module is unavailable.
  var _h = new Uint32Array(8), _w = new Uint32Array(64);
  var _k = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function sha256sync(data, result) {
    _h[0] = 0x6a09e667; _h[1] = 0xbb67ae85; _h[2] = 0x3c6ef372; _h[3] = 0xa54ff53a;
    _h[4] = 0x510e527f; _h[5] = 0x9b05688c; _h[6] = 0x1f83d9ab; _h[7] = 0x5be0cd19;
    var l = data.length * 8;
    var padLen = (data.length % 64 < 56) ? (56 - data.length % 64) : (120 - data.length % 64);
    var msg = new Uint8Array(data.length + padLen + 8);
    msg.set(data); msg[data.length] = 0x80;
    var view = new DataView(msg.buffer);
    view.setUint32(msg.length - 4, l, false);
    var a, b, c, d, e, f, g, hh, s0, s1, ch, maj, t1, t2;
    for (var i = 0; i < msg.length; i += 64) {
      for (var j = 0; j < 16; j++) _w[j] = view.getUint32(i + j * 4, false);
      for (j = 16; j < 64; j++) {
        var x = _w[j - 15]; s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var y = _w[j - 2]; s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        _w[j] = (_w[j - 16] + s0 + _w[j - 7] + s1) | 0;
      }
      a = _h[0]; b = _h[1]; c = _h[2]; d = _h[3]; e = _h[4]; f = _h[5]; g = _h[6]; hh = _h[7];
      for (j = 0; j < 64; j++) {
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ch = (e & f) ^ (~e & g); t1 = (hh + s1 + ch + _k[j] + _w[j]) | 0;
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        maj = (a & b) ^ (a & c) ^ (b & c); t2 = (s0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      _h[0] = (_h[0] + a) | 0; _h[1] = (_h[1] + b) | 0; _h[2] = (_h[2] + c) | 0; _h[3] = (_h[3] + d) | 0;
      _h[4] = (_h[4] + e) | 0; _h[5] = (_h[5] + f) | 0; _h[6] = (_h[6] + g) | 0; _h[7] = (_h[7] + hh) | 0;
    }
    for (i = 0; i < 8; i++) {
      result[i * 4] = (_h[i] >>> 24) & 0xff; result[i * 4 + 1] = (_h[i] >>> 16) & 0xff;
      result[i * 4 + 2] = (_h[i] >>> 8) & 0xff; result[i * 4 + 3] = _h[i] & 0xff;
    }
  }
  var _hashBuf = new Uint8Array(32), _inputBuf = null;
  function deriveHash(prefixBytes, counter, saltBytes) {
    var cStr = counter.toString(), cLen = cStr.length, totalLen = prefixBytes.length + cLen + saltBytes.length;
    if (!_inputBuf || _inputBuf.length !== totalLen) _inputBuf = new Uint8Array(totalLen);
    _inputBuf.set(prefixBytes, 0);
    for (var i = 0; i < cLen; i++) _inputBuf[prefixBytes.length + i] = cStr.charCodeAt(i);
    _inputBuf.set(saltBytes, prefixBytes.length + cLen);
    sha256sync(_inputBuf, _hashBuf);
    return _hashBuf;
  }

  function post(m) {
    m.v = 1;
    self.postMessage(m);
  }

  function solveMessage(m) {
    var algorithm = m.algorithm === "argon2id" ? "argon2id" : "sha256";
    var prefix = new TextEncoder().encode(String(m.prefix));
    var salt = b64decode(m.salt);
    if (prefix.length !== (m.prefixLen | 0) || salt.length !== (m.saltLen | 0)) {
      post({ type: "failed", reason: "length_mismatch" });
      return;
    }
    var targetBits = m.targetBits | 0;
    var mKib = m.mKib | 0;
    var t = m.t | 0;
    var p = m.p | 0;
    var counter = m.startCounter | 0;
    var maxHashes = (m.maxHashes | 0) > 0 ? (m.maxHashes | 0) : 5000000;

    initWasm().then(function (w) {
      if (algorithm === "argon2id") {
        solveArgon(w, prefix, salt, targetBits, mKib, t, p, counter, maxHashes);
        return;
      }
      solveSha(w, prefix, salt, targetBits, counter, maxHashes);
    }).catch(function () {
      post({ type: "failed", reason: "error" });
    });
  }

  function solveArgon(w, prefix, salt, targetBits, mKib, t, p, start, maxHashes) {
    if (!w || !w.solve_argon2_chunk || !allocatorPresent(w) || mKib < 8 * p) {
      post({ type: "failed", reason: "no_wasm" });
      return;
    }
    // Same search cap as the main-thread solver: bound the counter range so a
    // memory-hard challenge can never run away.
    var expected = Math.pow(2, targetBits);
    var argMax = Math.min(maxHashes, Math.max(1024, expected * 8));
    var pp = alloc(w, prefix);
    if (!pp) { post({ type: "failed", reason: "alloc" }); return; }
    var sp = alloc(w, salt);
    if (!sp) { free(w, pp, prefix.length); post({ type: "failed", reason: "alloc" }); return; }
    try {
      var counter = start;
      while (counter < argMax) {
        var res = w.solve_argon2_chunk(pp, prefix.length, sp, salt.length, targetBits, mKib, t, p, counter, 1);
        if (res !== -1) {
          free(w, pp, prefix.length); free(w, sp, salt.length);
          post({ type: "done", counter: res, buildId: KIWI_SOLVER_PROTOCOL_ID });
          return;
        }
        counter += 1;
        if (counter % 1000 === 0) post({ type: "progress", counter: counter });
      }
    } catch (e) {
      free(w, pp, prefix.length); free(w, sp, salt.length);
      post({ type: "failed", reason: "solve_error" });
      return;
    }
    free(w, pp, prefix.length); free(w, sp, salt.length);
    post({ type: "failed", reason: "exhausted" });
  }

  function solveSha(w, prefix, salt, targetBits, start, maxHashes) {
    var pp = 0, sp = 0;
    var useWasm = !!(w && w.solve_sha256_chunk && allocatorPresent(w));
    function buffers() {
      if (pp === 0) {
        pp = alloc(w, prefix);
        if (pp === 0) { useWasm = false; return; }
      }
      if (sp === 0) {
        sp = alloc(w, salt);
        if (sp === 0) { useWasm = false; return; }
      }
    }
    var counter = start;
    while (counter < maxHashes) {
      if (useWasm) {
        try {
          buffers();
          if (!useWasm) continue;
          var res = w.solve_sha256_chunk(pp, prefix.length, sp, salt.length, targetBits, counter, 1000);
          if (res !== -1) {
            free(w, pp, prefix.length); free(w, sp, salt.length);
            post({ type: "done", counter: res, buildId: KIWI_SOLVER_PROTOCOL_ID });
            return;
          }
          counter += 1000;
        } catch (e) {
          free(w, pp, prefix.length); free(w, sp, salt.length);
          pp = 0; sp = 0;
          useWasm = false;
        }
      } else {
        var end = Math.min(counter + 1000, maxHashes);
        for (; counter < end; counter++) {
          if (leadingZeros(deriveHash(prefix, counter, salt)) >= targetBits) {
            free(w, pp, prefix.length); free(w, sp, salt.length);
            post({ type: "done", counter: counter, buildId: KIWI_SOLVER_PROTOCOL_ID });
            return;
          }
        }
      }
      if (counter % 1000 === 0) post({ type: "progress", counter: counter });
    }
    free(w, pp, prefix.length); free(w, sp, salt.length);
    post({ type: "failed", reason: "exhausted" });
  }

  // Messages arrive ONLY from the driver that created this worker (a Blob
  // URL built from local code, or the configured same-origin asset URL) —
  // no cross-origin listener exists, so no rate-limit window is needed.
  // The guard is defense-in-depth: ignore anything that is not a versioned
  // v1 solve request carrying the full field set.
  self.onmessage = function (ev) {
    var m = ev.data;
    if (!m || typeof m !== "object" || m.v !== 1 || m.type !== "solve") return;
    if (typeof m.prefix !== "string" || typeof m.salt !== "string") return;
    if (typeof m.prefixLen !== "number" || typeof m.saltLen !== "number") return;
    if (typeof m.targetBits !== "number" || typeof m.mKib !== "number") return;
    if (typeof m.t !== "number" || typeof m.p !== "number") return;
    if (typeof m.startCounter !== "number" || typeof m.maxHashes !== "number") return;
    try {
      solveMessage(m);
    } catch (e) {
      post({ type: "failed", reason: "error: " + (e && e.message) });
    }
  };

  // Read the wasm glue's exported solver protocol VERSION. The glue's
  // load() resolves to the RAW wasm exports, where an integer export is a
  // plain number (audit round 24: the earlier String export surfaced as a
  // [ptr, len] tuple and had to be decoded — an integer needs no decode).
  // Any failure returns null (fail closed).
  function wasmProtocolVersion(w) {
    if (!w || typeof w.solver_protocol_version !== "function") return null;
    try {
      var v = w.solver_protocol_version();
      return typeof v === "number" ? v : null;
    } catch (e) {
      return null;
    }
  }

  // Startup handshake (audit #53 / round 23-24): BEFORE any solve work,
  // verify the loaded wasm's exported solver_protocol_version() against
  // this constant (driver + worker + wasm must speak the same protocol
  // generation) and only then announce ready — a mismatched pair fails
  // closed instead of solving.
  initWasm().then(function (w) {
    var wasmProtocol = wasmProtocolVersion(w);
    if (typeof wasmProtocol !== "number" || wasmProtocol !== KIWI_SOLVER_PROTOCOL_VERSION) {
      post({ type: "failed", reason: "protocol-mismatch" });
      return;
    }
    post({ type: "ready", buildId: KIWI_SOLVER_PROTOCOL_ID });
  });
})();
`;
// KIWI_WORKER_SRC_END — generated section (tools/embed-worker): the whole span
// from the KIWI_WORKER_SRC_BEGIN marker to this marker is machine-written.

  // ── Optimized yielding ──────────────────────────────────────────────
  var channel = new MessageChannel();
  var yieldQueue = [];
  channel.port1.onmessage = function() { if (yieldQueue.length) yieldQueue.shift()(); };
  function fastYield(fn) { yieldQueue.push(fn); channel.port2.postMessage(0); }

  // ── WASM solver ──────────────────────────────────────────────────────
  var wasm = null;
  var wasmDisabled = false; // set permanently when WASM memory allocation fails
  var wasmLoader = (typeof window !== "undefined" && window.__kiwiCaptchaWasm) ? window.__kiwiCaptchaWasm : null;
  async function initWasm() {
    if (wasmDisabled) return null;
    if (wasm) return wasm;
    if (!wasmLoader) return null;
    try { wasm = await wasmLoader.load(); if (wasm.init_panic_hook) wasm.init_panic_hook(); return wasm; }
    catch (e) { console.warn("KiwiCaptcha: WASM init failed", e); return null; }
  }
  // Copy bytes into wasm memory (explicit alloc/free — the raw-pointer ABI
  // avoids wasm-bindgen's Vec/slice glue entirely). Uses the crate's own
  // `alloc`/`dealloc` exports (stable names, never DCE'd by wasm-opt) and
  // falls back to wasm-bindgen's generated symbols when present. The Rust
  // `alloc` returns null (0) on allocation failure — callers MUST check for
  // it and fall back to the pure-JS solver path.
  function wasmAlloc(w, bytes) {
    var ptr = 0;
    if (w.alloc) {
      ptr = w.alloc(bytes.length);
    } else if (w.__wbindgen_malloc) {
      ptr = w.__wbindgen_malloc(bytes.length, 1);
    } else {
      return 0;
    }
    if (ptr === 0 || ptr === null) return 0; // allocation failed
    new Uint8Array(w.memory.buffer).set(bytes, ptr);
    return ptr;
  }
  function wasmFree(w, ptr, len) {
    if (!ptr) return;
    if (w.dealloc) {
      try { w.dealloc(ptr, len); } catch (_) {}
    } else if (w.__wbindgen_free) {
      w.__wbindgen_free(ptr, len, 1);
    }
  }

  // ── Optimized synchronous SHA-256 (pure JS, recycled buffers) ───────
  var _h = new Uint32Array(8), _w = new Uint32Array(64);
  var _k = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function sha256sync(data, result) {
    _h[0] = 0x6a09e667; _h[1] = 0xbb67ae85; _h[2] = 0x3c6ef372; _h[3] = 0xa54ff53a;
    _h[4] = 0x510e527f; _h[5] = 0x9b05688c; _h[6] = 0x1f83d9ab; _h[7] = 0x5be0cd19;
    var l = data.length * 8;
    var padLen = (data.length % 64 < 56) ? (56 - data.length % 64) : (120 - data.length % 64);
    var msg = new Uint8Array(data.length + padLen + 8);
    msg.set(data); msg[data.length] = 0x80;
    var view = new DataView(msg.buffer);
    view.setUint32(msg.length - 4, l, false);
    var a, b, c, d, e, f, g, hh, s0, s1, ch, maj, t1, t2;
    for (var i = 0; i < msg.length; i += 64) {
      for (var j = 0; j < 16; j++) _w[j] = view.getUint32(i + j * 4, false);
      for (j = 16; j < 64; j++) {
        var x = _w[j - 15]; s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var y = _w[j - 2]; s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        _w[j] = (_w[j - 16] + s0 + _w[j - 7] + s1) | 0;
      }
      a = _h[0]; b = _h[1]; c = _h[2]; d = _h[3]; e = _h[4]; f = _h[5]; g = _h[6]; hh = _h[7];
      for (j = 0; j < 64; j++) {
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ch = (e & f) ^ (~e & g); t1 = (hh + s1 + ch + _k[j] + _w[j]) | 0;
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        maj = (a & b) ^ (a & c) ^ (b & c); t2 = (s0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      _h[0] = (_h[0] + a) | 0; _h[1] = (_h[1] + b) | 0; _h[2] = (_h[2] + c) | 0; _h[3] = (_h[3] + d) | 0;
      _h[4] = (_h[4] + e) | 0; _h[5] = (_h[5] + f) | 0; _h[6] = (_h[6] + g) | 0; _h[7] = (_h[7] + hh) | 0;
    }
    for (i = 0; i < 8; i++) {
      result[i * 4] = (_h[i] >>> 24) & 0xff; result[i * 4 + 1] = (_h[i] >>> 16) & 0xff;
      result[i * 4 + 2] = (_h[i] >>> 8) & 0xff; result[i * 4 + 3] = _h[i] & 0xff;
    }
  }
  function b64decode(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    return Uint8Array.from(atob(str), function(c) { return c.charCodeAt(0); });
  }
  function leadingZeros(bytes) {
    var n = 0;
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) { n += 8; }
      else { var b = bytes[i]; while ((b & 128) === 0) { n++; b <<= 1; } break; }
    }
    return n;
  }
  var _hashBuf = new Uint8Array(32), _inputBuf = null;
  function deriveHash(prefixBytes, counter, saltBytes) {
    var cStr = counter.toString(), cLen = cStr.length, totalLen = prefixBytes.length + cLen + saltBytes.length;
    if (!_inputBuf || _inputBuf.length !== totalLen) _inputBuf = new Uint8Array(totalLen);
    _inputBuf.set(prefixBytes, 0);
    for (var i = 0; i < cLen; i++) _inputBuf[prefixBytes.length + i] = cStr.charCodeAt(i);
    _inputBuf.set(saltBytes, prefixBytes.length + cLen);
    sha256sync(_inputBuf, _hashBuf);
    return _hashBuf;
  }

  var MAX_SHA_HASHES = 5000000;
  function solve(prefix, saltBytes, targetBits, algorithm, m_kib, t, p, onProgress) {
    return new Promise(async function(resolve) {
      var prefixBytes = encoder.encode(prefix), expectedHashes = Math.pow(2, targetBits), solveStart = performance.now(), counter = 0;
      var w = await initWasm();
      // Persistent WASM-side buffers: allocated once and reused across all
      // chunks, eliminating malloc/free churn on every 50k-hash iteration
      // (the hottest loop in the SHA-256 solver).
      var pp = 0, sp = 0;
      // wasm is usable when the solver AND an allocator export exist. The
      // wasm-opt pipeline exports alloc/dealloc (stable names); wasm-bindgen's
      // generated __wbindgen_malloc may be dead-code-eliminated, so it is not
      // a reliable capability signal.
      function wasmUsable() {
        return !wasmDisabled && !!(w && w.solve_sha256_chunk && (w.alloc || w.__wbindgen_malloc));
      }
      function wasmAllocatorPresent() {
        return !!(w && (w.alloc || w.__wbindgen_malloc) && (w.dealloc || w.__wbindgen_free));
      }
      // An allocation failure (Rust `alloc` returns null) disables WASM
      // PERMANENTLY: a memory-exhausted wasm module can never be trusted to
      // allocate again, so every later solve must use the pure-JS fallback.
      function disableWasm() {
        wasmDisabled = true;
        wasm = null;
        wasmFree(w, pp, prefixBytes.length);
        wasmFree(w, sp, saltBytes.length);
        pp = 0;
        sp = 0;
      }
      function ensureBuffers() {
        if (pp === 0) {
          pp = wasmAlloc(w, prefixBytes);
          if (pp === 0) { disableWasm(); return false; }
        }
        if (sp === 0) {
          sp = wasmAlloc(w, saltBytes);
          if (sp === 0) { disableWasm(); return false; }
        }
        return true;
      }
      // Round-13 invariant: this function ONLY ever solves SHA-256. Argon2id
      // is memory-hard and must run in the same-origin worker; the main
      // thread NEVER runs an Argon2 hash. The argon2id path in run() routes
      // a missing/failed worker to the controlled kiwi:worker-unavailable
      // state instead of ever calling solve() for a memory-hard challenge.
      var useWasm = wasmUsable();
      var CHUNK = useWasm ? 50000 : 8000;
      function chunk() {
        if (useWasm) {
          try {
            if (ensureBuffers()) {
              var res = w.solve_sha256_chunk(pp, prefixBytes.length, sp, saltBytes.length, targetBits, counter, CHUNK);
              if (res !== -1) { wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); resolve({ counter: res, duration: Math.round(performance.now() - solveStart) }); return; }
              counter += CHUNK;
            } else {
              // Allocation failed: wasm is disabled permanently — fall back to JS.
              console.warn("KiwiCaptcha: WASM allocation failed, disabling WASM and falling back to JS");
              useWasm = false;
            }
          } catch (e) { wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); console.error("KiwiCaptcha: WASM solve failed, falling back to JS", e); useWasm = false; }
        }
        if (!useWasm) {
          var end = Math.min(counter + CHUNK, MAX_SHA_HASHES);
          for (; counter < end; counter++) if (leadingZeros(deriveHash(prefixBytes, counter, saltBytes)) >= targetBits) {
            resolve({ counter: counter, duration: Math.round(performance.now() - solveStart) }); return;
          }
        }
        if (counter >= MAX_SHA_HASHES) { resolve(null); return; }
        onProgress(Math.min(92, (counter * 100) / expectedHashes));
        fastYield(chunk);
      }
      fastYield(chunk);
    });
  }

  // ── Same-origin Argon2id Web Worker ─────────────────────────────────
  // postMessage BOUNDARY: this driver NEVER posts to the parent page — all
  // postMessage usage is worker-internal (driver <-> worker solve traffic
  // and the internal MessageChannel yield). There is no
  // window.addEventListener("message") / parent.postMessage anywhere in
  // this file, so no cross-origin target exists and no origin check or
  // rate-limit window is required on a page-level listener (the browser
  // test suite asserts this statically — see tests/browser/specs).
  // The memory-hard solver ALWAYS runs off the main thread: the worker is
  // constructed from a Blob URL built from local code (the embedded
  // KIWI_WORKER_SRC plus the inline wasm glue source), or from the asset
  // URL when data-kiwi-worker-src is set — never from a network URL.
  // Round-13 invariant: if the worker cannot be created (no Worker
  // support, CSP blocks Blob workers) or the solve fails inside it, the
  // widget enters the controlled kiwi:worker-unavailable state. There is
  // NO main-thread Argon2 fallback and no weaker-profile retry — the main
  // thread never runs an Argon2 hash. A subsequent attempt (Retry button,
  // click, re-init) retries the worker from scratch.
  var kiwiActiveBlobUrl = null; // shared so reset/unavailable paths can revoke
  var kiwiInstanceCounter = 0;
  function kiwiFindGlueSource() {
    // The renderers embed the wasm glue inline as a script element before this
    // driver; its source contains KIWI_WASM_B64 (unique marker). The glue is
    // a self-contained IIFE, so its text can run inside the worker with a
    // `var window = self` prelude to expose self.__kiwiCaptchaWasm.
    try {
      var scripts = document.scripts || [];
      for (var i = 0; i < scripts.length; i++) {
        var text = scripts[i].textContent || "";
        if (text.indexOf("KIWI_WASM_B64") !== -1 && text.indexOf("__kiwiCaptchaWasm") !== -1) {
          return text;
        }
      }
    } catch (e) {}
    return null;
  }
  function solveWithWorker(data, onProgress, container) {
    var terminateHandle = function () {};
    var promise = new Promise(function(resolve) {
      if (typeof Worker === "undefined") { resolve({ unavailable: true, reason: "no-worker-support" }); return; }
      var worker = null;
      var blobUrl = null;
      try {
        var workerSrc = container.getAttribute("data-kiwi-worker-src");
        if (workerSrc) {
          worker = new Worker(workerSrc);
        } else {
          // Round 26: the compat loader's fetched glue covers the external
          // /api.js case (no inline script element on the page).
          var glue = kiwiFindGlueSource() || kiwiCompatGlue;
          var blobSrc = (glue ? "var window = self;" + glue + "\n" : "") + KIWI_WORKER_SRC;
          blobUrl = URL.createObjectURL(new Blob([blobSrc], { type: "application/javascript" }));
          worker = new Worker(blobUrl);
        }
      } catch (e) { if (blobUrl) URL.revokeObjectURL(blobUrl); resolve({ unavailable: true, reason: "worker-creation-failed" }); return; }
      if (!worker) { if (blobUrl) URL.revokeObjectURL(blobUrl); resolve({ unavailable: true, reason: "worker-creation-failed" }); return; }
      if (kiwiActiveBlobUrl) { URL.revokeObjectURL(kiwiActiveBlobUrl); kiwiActiveBlobUrl = null; }
      kiwiActiveBlobUrl = blobUrl;
      // Round 28 (P2): explicit termination handle — a cancelled
      // generation terminates the worker outright (revoking the blob URL
      // alone would NOT stop it).
      terminateHandle = function () {
        try { worker.terminate(); } catch (e) {}
        teardown();
      };
      window.__kiwiWorkerUsed = true;
      var workerStart = performance.now();
      var expectedHashes = Math.pow(2, data.targetBits);
      var settled = false;
      // Blob-URL cleanup (round-13): the object URL is revoked exactly once
      // on EVERY terminal path — done, failed, build-id mismatch, worker
      // error, and postMessage failure. Revoking never kills the worker
      // itself (terminate() does that); it only releases the URL, so a
      // stale blob URL can never leak for the page's lifetime.
      function teardown() {
        if (blobUrl) {
          URL.revokeObjectURL(blobUrl);
          if (kiwiActiveBlobUrl === blobUrl) kiwiActiveBlobUrl = null;
          blobUrl = null;
        }
      }
      // The worker is CREATED BY THIS DRIVER (a Blob URL built from local
      // code, or the explicitly configured same-origin asset URL), so no
      // cross-origin postMessage target exists and no rate-limit window is
      // needed here — admission rate limiting lives on the challenge
      // endpoint, server-side. The shape guard below is defense-in-depth
      // for the worker port: any message that is not a versioned
      // progress/done/failed solution message with the expected payload is
      // ignored outright, never acted on.
      worker.onmessage = function(ev) {
        var msg = ev.data;
        if (!msg || typeof msg !== "object" || msg.v !== 1) return;
        if (msg.type === "ready") {
          // Startup handshake (audit #53): the worker must report the SAME
          // solver build id as this driver. A stale cached worker is
          // refused — it never contributes a solution and there is no
          // fallback.
          if (typeof msg.buildId !== "string" || msg.buildId !== KIWI_SOLVER_PROTOCOL_ID) {
            if (!settled) {
              console.error("KiwiCaptcha worker protocol mismatch: ready buildId", msg.buildId);
              settled = true; worker.terminate(); teardown(); resolve({ mismatch: true });
            }
          }
          return;
        }
        if (msg.type === "progress") {
          if (typeof msg.counter !== "number" || !isFinite(msg.counter)) return;
          onProgress(Math.min(95, (msg.counter * 100) / expectedHashes));
        } else if (msg.type === "done") {
          if (typeof msg.counter !== "number" || !isFinite(msg.counter)) return;
          if (typeof msg.buildId !== "string" || msg.buildId !== KIWI_SOLVER_PROTOCOL_ID) {
            if (!settled) { settled = true; worker.terminate(); teardown(); resolve({ mismatch: true }); }
            return;
          }
          settled = true;
          worker.terminate();
          teardown();
          resolve({ counter: msg.counter, duration: Math.round(performance.now() - workerStart) });
        } else if (msg.type === "failed") {
          if (typeof msg.reason !== "string") return;
          // Round 23: the worker verifies the wasm glue's exported
          // solver_protocol_id() BEFORE ready and reports
          // protocol-mismatch when the wasm/worker generations differ —
          // surface it as the controlled solver-mismatch state (a stale
          // worker or a mixed-generation deployment; same UX as a worker
          // reporting the wrong protocol id in its ready handshake).
          if (msg.reason === "protocol-mismatch") {
            if (!settled) {
              console.error("KiwiCaptcha worker protocol mismatch: wasm/worker generation differ");
              settled = true; worker.terminate(); teardown(); resolve({ mismatch: true });
            }
            return;
          }
          settled = true;
          worker.terminate();
          teardown();
          console.error("KiwiCaptcha worker failed:", msg.reason);
          resolve({ unavailable: true, reason: "worker-failed-" + msg.reason });
        }
      };
      worker.onerror = function(ev) {
        if (settled) return;
        settled = true;
        worker.terminate();
        teardown();
        console.error("KiwiCaptcha worker error:", ev && ev.message, ev && ev.filename, ev && ev.lineno);
        resolve({ unavailable: true, reason: "worker-error" });
      };
      var prefixBytes = encoder.encode(data.prefix);
      var saltBytes = b64decode(data.salt);
      try {
        worker.postMessage({
          v: 1,
          type: "solve",
          algorithm: "argon2id",
          prefix: data.prefix,
          prefixLen: prefixBytes.length,
          salt: data.salt,
          saltLen: saltBytes.length,
          targetBits: data.targetBits,
          mKib: data.mKib || 0,
          t: data.t || 1,
          p: data.p || 1,
          startCounter: 0,
          maxHashes: MAX_SHA_HASHES,
        });
      } catch (e) {
        if (!settled) { settled = true; worker.terminate(); teardown(); resolve({ unavailable: true, reason: "post-failed" }); }
      }
    });
    return { promise: promise, terminate: terminateHandle };
  }

  // ── Privacy-aware telemetry (widget-local, mode-gated) ──────────────
  // data-kiwi-telemetry on the container OR the widget: "off" (default) |
  // "minimal" | "full". Listeners are attached to the widget element ONLY
  // (never document-wide) and are removed when the solve finishes or fails.
  // No device-capability or screen-size signals are ever collected, and
  // scrolling/touch interactions are not tracked; navigator.webdriver is only
  // reported in "full" mode. Event timings are only recorded in "full" mode,
  // capped at 20 entries and quantized to 250 ms buckets.
  function telemetrySession(container, W) {
    var mode = "off";
    if (W) mode = W.getAttribute("data-kiwi-telemetry") || mode;
    if (container && container !== W) mode = container.getAttribute("data-kiwi-telemetry") || mode;
    if (mode !== "minimal" && mode !== "full") mode = "off";
    var mouseEvents = 0, keyEvents = 0, eventTimings = [];
    function onEvent(e) {
      if (e.type === "keydown") {
        if (e.repeat) return;
        keyEvents++;
      } else {
        mouseEvents++;
      }
      if (mode === "full" && eventTimings.length < 20) {
        eventTimings.push(Math.round(performance.now() / 250) * 250);
      }
    }
    function attach() {
      if (mode === "off") return;
      W.addEventListener("pointerdown", onEvent, {passive:true});
      W.addEventListener("keydown", onEvent, {passive:true});
      W.addEventListener("click", onEvent, {passive:true});
    }
    function stop() {
      if (mode === "off") return;
      W.removeEventListener("pointerdown", onEvent);
      W.removeEventListener("keydown", onEvent);
      W.removeEventListener("click", onEvent);
    }
    function build() {
      if (mode === "off") return {};
      var t = { v: 2, mode: mode, me: mouseEvents, ke: keyEvents };
      if (mode === "full") {
        t.wd = navigator.webdriver === true;
        t.et = eventTimings;
      }
      return t;
    }
    attach();
    return { build: build, stop: stop };
  }

  // ── Same-origin enforcement ─────────────────────────────────────────
  // The challenge endpoint must resolve to the page's own origin — a
  // cross-origin endpoint would leak the scope and the solve behavior to a
  // third party, so it is refused outright.
  function kiwiEndpoint(raw) {
    var url = new URL(raw, window.location.href);
    if (url.origin !== window.location.origin) {
      throw new Error("KiwiCaptcha refuses cross-origin challenge endpoints");
    }
    return url.href;
  }

  // ── Round-13 a11y helpers ───────────────────────────────────────────
  // The dedicated role="status" announcer (data-kiwi-status) is the ONLY
  // aria-live traffic: the changing widget itself carries no aria-live and
  // no checkbox semantics — an auto-solving proof-of-work is not a
  // checkbox. The announcer reports ONLY meaningful transitions
  // (Checking…, Verification complete, Verification failed, Worker
  // unavailable); countdown/progress stay strictly visual.
  function createAnnouncer(W) {
    var s = document.createElement("span");
    s.className = "kiwi-status";
    s.setAttribute("data-kiwi-status", "");
    s.setAttribute("role", "status");
    s.setAttribute("aria-live", "polite");
    var main = W.querySelector(".kiwi-main");
    if (main) main.appendChild(s); else W.appendChild(s);
    return s;
  }
  // ── Round 29: localization (WCAG 3.1.2) ─────────────────────────────
  // A reusable security component for European deployment needs a real
  // locale contract: `lang` is a first-class widget option
  // (options.lang / data-kiwi-lang / navigator.language in that order),
  // the resolved language is written to the widget subtree's lang
  // attribute (dir for RTL packs), and an untranslated fallback stays
  // English and is explicitly marked lang="en" so the passage language is
  // always programmatically determinable.
  var kiwiLocalePacks = {
    en: { dir: "ltr",
      label: "Security Check", badgeIdle: "Idle", badgeWait: "Wait",
      badgeWorking: "Working", badgeSuccess: "Success", badgeFailed: "Failed",
      badgeVersionError: "Version Error", badgeUnavailable: "Unavailable",
      statusConnecting: "Connecting\u2026", statusVerifying: "Verifying\u2026",
      statusVerified: "Verification complete", statusFailed: "Verification failed",
      statusExpired: "Verification expired", statusWorkerUnavailable: "Worker unavailable",
      statusSolverMismatch: "Solver version mismatch",
      hintProtected: "Protected", hintRetrying: "Challenge failed ({msg}) \u2014 retrying\u2026",
      hintClickRetry: "Challenge failed ({msg}) \u2014 press the Retry button to try again.",
      hintVerified: "Proof-of-work verified locally.",
      hintWorker: "Worker unavailable \u2014 Argon2id needs a Web Worker that this page's CSP blocks; retry, or configure data-kiwi-worker-src.",
      hintSolver: "The solver worker is out of date \u2014 reload the page to load the current version.",
      expired: "expired", retryButton: "Retry", checking: "Checking\u2026" },
    de: { dir: "ltr",
      label: "Sicherheitspr\u00fcfung", badgeIdle: "Bereit", badgeWait: "Warten",
      badgeWorking: "Arbeitet", badgeSuccess: "Erfolgreich", badgeFailed: "Fehlgeschlagen",
      badgeVersionError: "Versionsfehler", badgeUnavailable: "Nicht verf\u00fcgbar",
      statusConnecting: "Verbinde\u2026", statusVerifying: "Pr\u00fcfe\u2026",
      statusVerified: "Pr\u00fcfung abgeschlossen", statusFailed: "Pr\u00fcfung fehlgeschlagen",
      statusExpired: "Pr\u00fcfung abgelaufen", statusWorkerUnavailable: "Worker nicht verf\u00fcgbar",
      statusSolverMismatch: "Solver-Version stimmt nicht",
      hintProtected: "Gesch\u00fctzt", hintRetrying: "Pr\u00fcfung fehlgeschlagen ({msg}) \u2014 neuer Versuch\u2026",
      hintClickRetry: "Pr\u00fcfung fehlgeschlagen ({msg}) \u2014 dr\u00fccken Sie die Schaltfl\u00e4che Erneut.",
      hintVerified: "Proof-of-Work lokal verifiziert.",
      hintWorker: "Worker nicht verf\u00fcgbar \u2014 Argon2id ben\u00f6tigt einen Web Worker, den das CSP dieser Seite blockiert; erneut versuchen oder data-kiwi-worker-src konfigurieren.",
      hintSolver: "Der Solver-Worker ist veraltet \u2014 laden Sie die Seite neu, um die aktuelle Version zu laden.",
      expired: "abgelaufen", retryButton: "Erneut", checking: "Pr\u00fcfe\u2026" },
    fr: { dir: "ltr",
      label: "Contr\u00f4le de s\u00e9curit\u00e9", badgeIdle: "Inactif", badgeWait: "Attente",
      badgeWorking: "Traitement", badgeSuccess: "R\u00e9ussi", badgeFailed: "\u00c9chec",
      badgeVersionError: "Erreur de version", badgeUnavailable: "Indisponible",
      statusConnecting: "Connexion\u2026", statusVerifying: "V\u00e9rification\u2026",
      statusVerified: "V\u00e9rification termin\u00e9e", statusFailed: "V\u00e9rification \u00e9chou\u00e9e",
      statusExpired: "V\u00e9rification expir\u00e9e", statusWorkerUnavailable: "Worker indisponible",
      statusSolverMismatch: "Version du solveur incompatible",
      hintProtected: "Prot\u00e9g\u00e9", hintRetrying: "V\u00e9rification \u00e9chou\u00e9e ({msg}) \u2014 nouvelle tentative\u2026",
      hintClickRetry: "V\u00e9rification \u00e9chou\u00e9e ({msg}) \u2014 appuyez sur le bouton R\u00e9essayer.",
      hintVerified: "Preuve de travail v\u00e9rifi\u00e9e localement.",
      hintWorker: "Worker indisponible \u2014 Argon2id n\u00e9cessite un Web Worker que le CSP de cette page bloque; r\u00e9essayez ou configurez data-kiwi-worker-src.",
      hintSolver: "Le solveur est obsol\u00e8te \u2014 rechargez la page pour charger la version actuelle.",
      expired: "expir\u00e9", retryButton: "R\u00e9essayer", checking: "V\u00e9rification\u2026" },
    es: { dir: "ltr",
      label: "Comprobaci\u00f3n de seguridad", badgeIdle: "Inactivo", badgeWait: "Espera",
      badgeWorking: "Trabajando", badgeSuccess: "Correcto", badgeFailed: "Fall\u00f3",
      badgeVersionError: "Error de versi\u00f3n", badgeUnavailable: "No disponible",
      statusConnecting: "Conectando\u2026", statusVerifying: "Verificando\u2026",
      statusVerified: "Verificaci\u00f3n completada", statusFailed: "Verificaci\u00f3n fallida",
      statusExpired: "Verificaci\u00f3n caducada", statusWorkerUnavailable: "Worker no disponible",
      statusSolverMismatch: "Versi\u00f3n del solver no coincide",
      hintProtected: "Protegido", hintRetrying: "Verificaci\u00f3n fallida ({msg}) \u2014 reintentando\u2026",
      hintClickRetry: "Verificaci\u00f3n fallida ({msg}) \u2014 pulse el bot\u00f3n Reintentar.",
      hintVerified: "Prueba de trabajo verificada localmente.",
      hintWorker: "Worker no disponible \u2014 Argon2id necesita un Web Worker que el CSP de esta p\u00e1gina bloquea; reintente o configure data-kiwi-worker-src.",
      hintSolver: "El worker del solver est\u00e1 desactualizado \u2014 recargue la p\u00e1gina para cargar la versi\u00f3n actual.",
      expired: "caducado", retryButton: "Reintentar", checking: "Verificando\u2026" },
    it: { dir: "ltr",
      label: "Controllo di sicurezza", badgeIdle: "Inattivo", badgeWait: "Attesa",
      badgeWorking: "In corso", badgeSuccess: "Riuscito", badgeFailed: "Non riuscito",
      badgeVersionError: "Errore di versione", badgeUnavailable: "Non disponibile",
      statusConnecting: "Connessione\u2026", statusVerifying: "Verifica\u2026",
      statusVerified: "Verifica completata", statusFailed: "Verifica non riuscita",
      statusExpired: "Verifica scaduta", statusWorkerUnavailable: "Worker non disponibile",
      statusSolverMismatch: "Versione del solver non corrispondente",
      hintProtected: "Protetto", hintRetrying: "Verifica non riuscita ({msg}) \u2014 nuovo tentativo\u2026",
      hintClickRetry: "Verifica non riuscita ({msg}) \u2014 premere il pulsante Riprova.",
      hintVerified: "Prova di lavoro verificata localmente.",
      hintWorker: "Worker non disponibile \u2014 Argon2id richiede un Web Worker bloccato dal CSP di questa pagina; riprovare o configurare data-kiwi-worker-src.",
      hintSolver: "Il worker del solver \u00e8 obsoleto \u2014 ricaricare la pagina per caricare la versione corrente.",
      expired: "scaduto", retryButton: "Riprova", checking: "Verifica\u2026" },
    nl: { dir: "ltr",
      label: "Beveiligingscontrole", badgeIdle: "Inactief", badgeWait: "Wachten",
      badgeWorking: "Bezig", badgeSuccess: "Geslaagd", badgeFailed: "Mislukt",
      badgeVersionError: "Versiefout", badgeUnavailable: "Niet beschikbaar",
      statusConnecting: "Verbinden\u2026", statusVerifying: "Controleren\u2026",
      statusVerified: "Controle voltooid", statusFailed: "Controle mislukt",
      statusExpired: "Controle verlopen", statusWorkerUnavailable: "Worker niet beschikbaar",
      statusSolverMismatch: "Solver-versie komt niet overeen",
      hintProtected: "Beschermd", hintRetrying: "Controle mislukt ({msg}) \u2014 opnieuw proberen\u2026",
      hintClickRetry: "Controle mislukt ({msg}) \u2014 druk op de knop Opnieuw.",
      hintVerified: "Proof of work lokaal geverifieerd.",
      hintWorker: "Worker niet beschikbaar \u2014 Argon2id vereist een Web Worker die door het CSP van deze pagina wordt geblokkeerd; probeer opnieuw of configureer data-kiwi-worker-src.",
      hintSolver: "De solver-worker is verouderd \u2014 herlaad de pagina om de huidige versie te laden.",
      expired: "verlopen", retryButton: "Opnieuw", checking: "Controleren\u2026" },
    pl: { dir: "ltr",
      label: "Kontrola bezpiecze\u0144stwa", badgeIdle: "Bezczynny", badgeWait: "Oczekiwanie",
      badgeWorking: "Pracuje", badgeSuccess: "Powodzenie", badgeFailed: "Niepowodzenie",
      badgeVersionError: "B\u0142\u0105d wersji", badgeUnavailable: "Niedost\u0119pny",
      statusConnecting: "\u0141\u0105czenie\u2026", statusVerifying: "Weryfikacja\u2026",
      statusVerified: "Weryfikacja zako\u0144czona", statusFailed: "Weryfikacja nieudana",
      statusExpired: "Weryfikacja wygas\u0142a", statusWorkerUnavailable: "Worker niedost\u0119pny",
      statusSolverMismatch: "Niezgodna wersja solwera",
      hintProtected: "Chronione", hintRetrying: "Weryfikacja nieudana ({msg}) \u2014 ponawianie\u2026",
      hintClickRetry: "Weryfikacja nieudana ({msg}) \u2014 naci\u015bnij przycisk Pon\u00f3w.",
      hintVerified: "Dow\u00f3d pracy zweryfikowany lokalnie.",
      hintWorker: "Worker niedost\u0119pny \u2014 Argon2id wymaga Web Workera blokowanego przez CSP tej strony; spr\u00f3buj ponownie lub skonfiguruj data-kiwi-worker-src.",
      hintSolver: "Worker solwera jest nieaktualny \u2014 prze\u0142aduj stron\u0119, aby za\u0142adowa\u0107 bie\u017c\u0105c\u0105 wersj\u0119.",
      expired: "wygas\u0142", retryButton: "Pon\u00f3w", checking: "Weryfikacja\u2026" },
    pt: { dir: "ltr",
      label: "Verifica\u00e7\u00e3o de seguran\u00e7a", badgeIdle: "Inativo", badgeWait: "Aguardar",
      badgeWorking: "A trabalhar", badgeSuccess: "Conclu\u00eddo", badgeFailed: "Falhou",
      badgeVersionError: "Erro de vers\u00e3o", badgeUnavailable: "Indispon\u00edvel",
      statusConnecting: "A ligar\u2026", statusVerifying: "A verificar\u2026",
      statusVerified: "Verifica\u00e7\u00e3o conclu\u00edda", statusFailed: "Verifica\u00e7\u00e3o falhada",
      statusExpired: "Verifica\u00e7\u00e3o expirada", statusWorkerUnavailable: "Worker indispon\u00edvel",
      statusSolverMismatch: "Vers\u00e3o do solver incompat\u00edvel",
      hintProtected: "Protegido", hintRetrying: "Verifica\u00e7\u00e3o falhada ({msg}) \u2014 a tentar novamente\u2026",
      hintClickRetry: "Verifica\u00e7\u00e3o falhada ({msg}) \u2014 prima o bot\u00e3o Repetir.",
      hintVerified: "Prova de trabalho verificada localmente.",
      hintWorker: "Worker indispon\u00edvel \u2014 Argon2id precisa de um Web Worker que o CSP desta p\u00e1gina bloqueia; tente novamente ou configure data-kiwi-worker-src.",
      hintSolver: "O worker do solver est\u00e1 desatualizado \u2014 recarregue a p\u00e1gina para carregar a vers\u00e3o atual.",
      expired: "expirado", retryButton: "Repetir", checking: "A verificar\u2026" },
    ar: { dir: "rtl",
      label: "\u0641\u062d\u0635 \u0627\u0644\u0623\u0645\u0627\u0646", badgeIdle: "\u062e\u0627\u0645\u062f", badgeWait: "\u0627\u0646\u062a\u0638\u0627\u0631",
      badgeWorking: "\u064a\u0639\u0645\u0644", badgeSuccess: "\u0646\u0627\u062c\u062d", badgeFailed: "\u0641\u0634\u0644",
      badgeVersionError: "\u062e\u0637\u0623 \u0641\u064a \u0627\u0644\u0625\u0635\u062f\u0627\u0631", badgeUnavailable: "\u063a\u064a\u0631 \u0645\u062a\u0648\u0641\u0631",
      statusConnecting: "\u062c\u0627\u0631\u064d \u0627\u0644\u0627\u062a\u0635\u0627\u0644\u2026", statusVerifying: "\u062c\u0627\u0631\u064d \u0627\u0644\u062a\u062d\u0642\u0642\u2026",
      statusVerified: "\u0627\u0643\u062a\u0645\u0644 \u0627\u0644\u062a\u062d\u0642\u0642", statusFailed: "\u0641\u0634\u0644 \u0627\u0644\u062a\u062d\u0642\u0642",
      statusExpired: "\u0627\u0646\u062a\u0647\u062a \u0645\u0647\u0644\u0629 \u0627\u0644\u062a\u062d\u0642\u0642", statusWorkerUnavailable: "\u0627\u0644\u0639\u0627\u0645\u0644 \u063a\u064a\u0631 \u0645\u062a\u0648\u0641\u0631",
      statusSolverMismatch: "\u0625\u0635\u062f\u0627\u0631 \u0627\u0644\u062d\u0644 \u063a\u064a\u0631 \u0645\u062a\u0637\u0627\u0628\u0642",
      hintProtected: "\u0645\u062d\u0645\u064a", hintRetrying: "\u0641\u0634\u0644 \u0627\u0644\u062a\u062d\u0642\u0642 ({msg}) \u2014 \u0625\u0639\u0627\u062f\u0629 \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629\u2026",
      hintClickRetry: "\u0641\u0634\u0644 \u0627\u0644\u062a\u062d\u0642\u0642 ({msg}) \u2014 \u0627\u0636\u063a\u0637 \u0639\u0644\u0649 \u0632\u0631 \u0625\u0639\u0627\u062f\u0629 \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629.",
      hintVerified: "\u062a\u0645 \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u062f\u0644\u064a\u0644 \u0627\u0644\u0639\u0645\u0644 \u0645\u062d\u0644\u064a\u064b\u0627.",
      hintWorker: "\u0627\u0644\u0639\u0627\u0645\u0644 \u063a\u064a\u0631 \u0645\u062a\u0648\u0641\u0631 \u2014 \u064a\u062a\u0637\u0644\u0628 Argon2id \u0639\u0627\u0645\u0644 \u0648\u064a\u0628 \u062a\u062d\u062c\u0628\u0647 \u0633\u064a\u0627\u0633\u0629 CSP \u0647\u0630\u0647 \u0627\u0644\u0635\u0641\u062d\u0629\u061b \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629 \u0623\u0648 \u0642\u0645 \u0628\u062a\u0643\u0648\u064a\u0646 data-kiwi-worker-src.",
      hintSolver: "\u0639\u0627\u0645\u0644 \u0627\u0644\u062d\u0644 \u0642\u062f\u064a\u0645 \u2014 \u0623\u0639\u062f \u062a\u062d\u0645\u064a\u0644 \u0627\u0644\u0635\u0641\u062d\u0629 \u0644\u062a\u062d\u0645\u064a\u0644 \u0627\u0644\u0625\u0635\u062f\u0627\u0631 \u0627\u0644\u062d\u0627\u0644\u064a.",
      expired: "\u0627\u0646\u062a\u0647\u062a \u0627\u0644\u0645\u0647\u0644\u0629", retryButton: "\u0625\u0639\u0627\u062f\u0629 \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629", checking: "\u062c\u0627\u0631\u064d \u0627\u0644\u062a\u062d\u0642\u0642\u2026" }
  };
  var kiwiFallbackLang = "en";
  function kiwiNormalizeLang(pref) {
    if (typeof pref !== "string") return "";
    return pref.trim().toLowerCase().split(/[_-]/)[0] || "";
  }
  function kiwiResolveLang(options) {
    var prefs = [];
    if (options && typeof options.lang === "string" && options.lang) prefs.push(options.lang);
    if (!prefs.length && typeof document !== "undefined") {
      var attr = null;
      try {
        var cs = document.currentScript;
        attr = cs && cs.getAttribute ? cs.getAttribute("data-kiwi-lang") : null;
      } catch (e) {}
      if (attr) prefs.push(attr);
    }
    if (!prefs.length && navigator && navigator.language) prefs.push(navigator.language);
    for (var i = 0; i < prefs.length; i++) {
      var base = kiwiNormalizeLang(prefs[i]);
      if (kiwiLocalePacks[base]) return base;
    }
    return kiwiFallbackLang;
  }
  function kiwiPackFor(lang) { return kiwiLocalePacks[lang] || kiwiLocalePacks[kiwiFallbackLang]; }
  // Round 30 (item 29): integrator callbacks must be observable — an
  // exception is rethrown on a microtask (never corrupting Kiwi's own
  // lifecycle, never double-invoking) so migration failures are
  // diagnosable in the console.
  function kiwiSafeCallback(fn) {
    try {
      fn();
    } catch (err) {
      if (typeof queueMicrotask === "function") {
        queueMicrotask(function () { throw err; });
      } else {
        setTimeout(function () { throw err; }, 0);
      }
    }
  }
  // Manual retry is a genuine native <button> (focusable, Enter/Space
  // activation built in) rendered in the error/unavailable states. It
  // triggers the SAME re-init path as the click/tap reacquire.
  function createRetryButton(W, retryLabel) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "kiwi-retry";
    b.setAttribute("data-kiwi-retry", "");
    b.textContent = retryLabel || kiwiLocalePacks[kiwiFallbackLang].retryButton;
    var bottom = W.querySelector(".kiwi-bottom");
    if (bottom) bottom.appendChild(b);
    else { var main = W.querySelector(".kiwi-main"); if (main) main.appendChild(b); else W.appendChild(b); }
    return b;
  }

  // Round 28 (P2): per-widget generation + cancellation handles. Every
  // async continuation (fetch, worker, retry, expiry) captures the
  // generation it started under and refuses to touch state once the
  // generation is no longer current — reset()/remove()/destroy() bump the
  // generation and abort/terminate/clear the handles, so a stale
  // generation can never write a token, invoke a callback or flip state.
  // Handles: gen (generation counter), abortController/abortTimer (challenge
  // fetch), worker (active solver worker), retryTimer (backoff retry),
  // countdownTimer/expiryTimer (timers), errorFired (one error callback per
  // generation).
  var kiwiWidgets = {}; // widgetId -> {W, options, state, token, gen, abortController, abortTimer, worker, retryTimer, countdownTimer, expiryTimer, errorFired}
  function kiwiGenerationCurrent(id, gen) {
    var r = kiwiWidgets[id];
    return !!(r && r.gen === gen);
  }
  function kiwiCancelGeneration(id) {
    var r = kiwiWidgets[id];
    if (!r) return;
    r.gen++; // any in-flight generation is stale from here on
    r.errorFired = false;
    if (r.abortController) { try { r.abortController.abort(); } catch (e) {} r.abortController = null; }
    if (r.abortTimer) { clearTimeout(r.abortTimer); r.abortTimer = null; }
    if (r.worker) { try { r.worker.terminate(); } catch (e) {} r.worker = null; }
    if (r.retryTimer) { clearTimeout(r.retryTimer); r.retryTimer = null; }
    if (r.countdownTimer) { clearInterval(r.countdownTimer); r.countdownTimer = null; }
    if (r.expiryTimer) { clearTimeout(r.expiryTimer); r.expiryTimer = null; }
  }
  function initWidget(W, options) {
    if (!W || W.dataset.kiwiStarted || W.dataset.kiwiDestroyed) return null;
    options = options || {};
    W.dataset.kiwiStarted = "1";
    // Round-13: no fixed DOM id. The driver locates elements by local
    // traversal only (closest/querySelector), so the removed
    // id="kiwicaptcha-root" has no dependencies; data-kiwi-instance is a
    // unique per-widget debugging marker, not a hook.
    if (!W.dataset.kiwiInstance) {
      W.dataset.kiwiInstance = "kiwi-" + (++kiwiInstanceCounter) + "-" + Math.random().toString(36).slice(2, 8);
    }
    // Round 24: formal widget instances — widgetId == data-kiwi-instance.
    var widgetId = W.dataset.kiwiInstance;
    // Round 28 (P2): the generation COUNTER MUST CONTINUE across re-inits —
    // a re-init that restarts at 1 would let a stale in-flight run see
    // itself as current again after a reset cancelled it (the record is
    // replaced, so the old captured generation must never match).
    var prevRecord = kiwiWidgets[widgetId];
    var newGen = prevRecord ? prevRecord.gen + 1 : 1;
    kiwiWidgets[widgetId] = { W: W, options: options, state: "solving", token: "", gen: newGen, abortController: null, abortTimer: null, worker: null, retryTimer: null, countdownTimer: null, expiryTimer: null, errorFired: false };
    // Neutral role: the widget is a passive status/group, never a
    // checkbox, and it is NOT focusable — the retry button is.
    // Round 31 (P1): ONE semantic component root. In compatibility mode
    // initWidget's W is the incumbent PROVIDER WRAPPER — the role, lang,
    // dir and accessible name must land on the actual visible inner
    // [data-kiwi-widget] (the wrapper stays semantically neutral);
    // otherwise AT sees a localized outer group wrapping a second inner
    // group with a stale English label.
    var compatInnerWidget = W.querySelector && W !== (W.querySelector("[data-kiwi-widget]") || W) ? W.querySelector("[data-kiwi-widget]") : null;
    var a11yRoot = compatInnerWidget || W;
    if (!compatInnerWidget && !W.getAttribute("role")) W.setAttribute("role", "group");
    var container = W.closest(".kiwi-container") || W;
    // Round 30 (item 18): the accessible group name is the TRANSLATED
    // security-check string (the aria-label hard-coded "KiwiCaptcha
    // security check" in the static markup would stay English while the
    // visible UI localized — a lang/name divergence). The markup's
    // static aria-label is replaced at init with the resolved locale.
    var kiwiWidgetRoot = W;
    // Round 29 (WCAG 3.1.2): resolve the widget language and write it onto
    // the widget subtree (lang + dir for RTL packs). Preference order:
    // options.lang -> data-kiwi-lang on the widget/container ->
    // navigator.language. The untranslated fallback is explicitly
    // lang="en". (document.currentScript is NULL during the async init,
    // so the attribute is read from the subtree, not the script tag.)
    var kiwiLangAttr = (W.getAttribute ? W.getAttribute("data-kiwi-lang") : null)
      || (container && container.getAttribute ? container.getAttribute("data-kiwi-lang") : null);
    // Round 30 (item 13): the language precedence is instance-level
    // overrides (params.lang / data-kiwi-lang) -> provider language
    // (Turnstile language) -> loader hl= -> navigator.language -> English.
    var kiwiProviderLang = options && options.language ? String(options.language) : null;
    var kiwiWidgetLang = kiwiResolveLang({
      lang: (options && options.lang) || kiwiLangAttr || kiwiProviderLang || compatLoaderLang || undefined
    });
    var kiwiWidgetPack = kiwiPackFor(kiwiWidgetLang);
    a11yRoot.setAttribute("lang", kiwiWidgetLang);
    if (kiwiWidgetPack.dir) a11yRoot.setAttribute("dir", kiwiWidgetPack.dir);
    // Round 30 (item 18): accessible name == the translated label string.
    a11yRoot.setAttribute("aria-label", kiwiWidgetPack.label);
    function kiwiT(key) { return (kiwiWidgetPack[key] !== undefined) ? kiwiWidgetPack[key] : kiwiLocalePacks[kiwiFallbackLang][key] || key; }
    var labelEl = W.querySelector("[data-kiwi-label]"), pillEl = W.querySelector("[data-kiwi-badge]"), fillEl = W.querySelector("[data-kiwi-bar]"), hintEl = W.querySelector("[data-kiwi-info]"), countdownEl = W.querySelector("[data-kiwi-timer]"), tokenEl = W.querySelector("[data-kiwi-token]") || container.querySelector("[data-kiwi-token]"), trackEl = W.querySelector(".kiwi-track");
    var announcerEl = W.querySelector("[data-kiwi-status]") || createAnnouncer(W);
    // The mascot is decorative next to the already-labelled widget: hide it
    // from assistive technology (round-13). Set defensively so renderers
    // that omit the attributes are still covered.
    var iconSvg = W.querySelector(".kiwi-icon-wrapper svg");
    if (iconSvg) { iconSvg.setAttribute("aria-hidden", "true"); iconSvg.setAttribute("focusable", "false"); }
    // Audit round 15: the kiwi wink is an SVG SMIL <animate> element — CSS
    // animation:none cannot stop SMIL, so reduced-motion users get the
    // animate element REMOVED (not merely paused) on init. A matchMedia
    // change listener also removes it when the OS setting flips while the
    // page is open (the reverse transition is not applied: a removed wink
    // stays removed for the session).
    if (iconSvg && window.matchMedia) {
      var reducedMotionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
      function kiwiRemoveWink() {
        var smilWink = iconSvg.querySelector("animate");
        if (smilWink) smilWink.remove();
        if (reducedMotionQuery.removeEventListener) reducedMotionQuery.removeEventListener("change", kiwiRemoveWink);
      }
      if (reducedMotionQuery.matches) kiwiRemoveWink();
      else if (reducedMotionQuery.addEventListener) reducedMotionQuery.addEventListener("change", kiwiRemoveWink);
    }
    var retryEl = W.querySelector("[data-kiwi-retry]") || createRetryButton(W, kiwiWidgetPack.retryButton);
    var telemetry = telemetrySession(container, W);
    // Round 26 (P1): options.scope is AUTHORITATIVE — the incumbent
    // compatibility loader passes the data-sitekey as the scope, and the
    // server maps it through the sitekey allowlist to the intended policy
    // scope. Letting DOM/path heuristics override it would silently
    // downgrade admin_login/financial_action challenges to the login
    // policy. Explicit options.scope beats the container attribute beats
    // the path heuristics.
    var scope = (options && typeof options.scope === "string" && options.scope)
      || W.getAttribute("data-kiwi-scope")
      || container.getAttribute("data-kiwi-scope");
    if (!scope) {
      scope = "login";
      var p = window.location.pathname.toLowerCase();
      if (p.indexOf("signup")>=0||p.indexOf("register")>=0) scope="signup";
      else if (p.indexOf("forgot")>=0) scope="forgot-password";
    }
    // Lifecycle events (round-13): kiwi:ready | kiwi:verifying |
    // kiwi:verified | kiwi:error | kiwi:worker-unavailable, dispatched on
    // the widget element, bubbling, not cancelable, detail {scope, ...}.
    function dispatch(name, detail) {
      var ev = new CustomEvent("kiwi:" + name, {
        bubbles: true,
        cancelable: false,
        detail: Object.assign({ scope: scope }, detail || {})
      });
      W.dispatchEvent(ev);
    }
    function announce(text) { if (announcerEl) announcerEl.textContent = text; }
    // Round 27 (P2): the state attribute belongs on the VISIBLE
    // .kiwi-widget — the stylesheet keys the pulse/success/failure
    // styling and the Retry button visibility on
    // .kiwi-widget[data-state=...]. When initWidget's W is an incumbent
    // wrapper (.g-recaptcha/.h-captcha/.cf-turnstile), target the inner
    // widget element instead of leaving it frozen at "idle".
    var stateEl = (W.matches && W.matches(".kiwi-widget"))
      ? W
      : (W.querySelector ? W.querySelector("[data-kiwi-widget]") || W : W);
    function setStatus(label, pillText, state) {
      if (labelEl) labelEl.textContent = label;
      if (pillEl) pillEl.textContent = pillText;
      if (stateEl) stateEl.setAttribute("data-state", state);
    }
    function setHint(text) { if (hintEl) hintEl.textContent = text; }
    // Round 29: paint the resolved language immediately (the static
    // template is English until the driver runs; the widget subtree lang
    // attribute was set above, so the English fallback is programmatically
    // marked until localized).
    setStatus(kiwiT("label"), kiwiT("badgeIdle"), "idle");
    setHint(kiwiT("hintProtected"));
    function setProgress(pct) {
      var clamped = Math.max(0, Math.min(100, pct));
      if (fillEl) fillEl.setAttribute("data-progress", String(clamped));
    }
    
    var countdownTimer = null;
    var retryCount = 0;
    var RETRY_LIMIT = 2;
    // Round 24: widget-instance state helpers (provider-facing lifecycle).
    function kiwiRecordState(state, token) {
      var r = kiwiWidgets[widgetId];
      if (r) { r.state = state; r.token = token || ""; }
    }
    function writeResponseAlias(value) {
      if (!options.responseField) return;
      var host = tokenEl ? tokenEl.parentNode : null;
      var input = host ? host.querySelector('input[name="' + options.responseField + '"]') : null;
      if (!input && host) {
        input = document.createElement("input");
        input.type = "hidden";
        input.name = options.responseField;
        host.insertBefore(input, tokenEl.nextSibling);
      }
      if (input) input.value = value || "";
    }
    function clearExpiryTimer() {
      var r = kiwiWidgets[widgetId];
      if (r && r.expiryTimer) { clearTimeout(r.expiryTimer); r.expiryTimer = null; }
    }
    function expireWidget() {
      var r = kiwiWidgets[widgetId];
      if (!r || r.state !== "verified") return;
      r.state = "expired";
      r.token = "";
      if (tokenEl) tokenEl.value = "";
      setBinding("");
      writeResponseAlias("");
      if (stateEl) stateEl.setAttribute("data-state", "expired");
      if (countdownEl) countdownEl.textContent = kiwiT("expired");
      // Round 31 (P1): the credential is gone — the widget is NOT started
      // anymore, so the (now visible) Retry button can reacquire.
      delete W.dataset.kiwiStarted;
      dispatch("expired", {});
      announce(kiwiT("statusExpired"));
      if (options.expiredCallback) { try { options.expiredCallback(); } catch (e) {} }
    }
    function scheduleExpiry(ttlSecs) {
      clearExpiryTimer();
      if (!ttlSecs || ttlSecs <= 0) return;
      var r = kiwiWidgets[widgetId];
      if (!r) return;
      r.expiryTimer = setTimeout(expireWidget, ttlSecs * 1000);
    }
    function startCountdown(ttlSecs) {
      var remaining = ttlSecs;
      var tick = function() { if (countdownEl) countdownEl.textContent = remaining > 0 ? remaining + "s" : kiwiT("expired"); };
      tick(); clearInterval(countdownTimer);
      countdownTimer = setInterval(function() { remaining--; tick(); if (remaining <= 0) clearInterval(countdownTimer); }, 1000);
      var rc = kiwiWidgets[widgetId];
      if (rc) rc.countdownTimer = countdownTimer;
    }
    // Request binding (audit #41): a hidden input carrying the bound value,
    // placed next to the token input (mirroring how the token is written).
    function setBinding(value) {
      if (!tokenEl) return;
      var host = tokenEl.parentNode;
      var input = host ? host.querySelector('input[name="kiwi_request_binding"]') : null;
      if (!input) {
        input = document.createElement("input");
        input.type = "hidden";
        input.name = "kiwi_request_binding";
        if (host) host.insertBefore(input, tokenEl.nextSibling);
      }
      input.value = value || "";
    }
    function resetToIdle() {
      clearInterval(countdownTimer);
      var rc = kiwiWidgets[widgetId];
      if (rc) rc.countdownTimer = null;
      clearExpiryTimer();
      writeResponseAlias("");
      kiwiRecordState("idle", "");
      telemetry.stop();
      // Round-13 blob cleanup: a pending worker object URL is revoked on
      // every reset/re-init path, not just on worker completion.
      if (kiwiActiveBlobUrl) { URL.revokeObjectURL(kiwiActiveBlobUrl); kiwiActiveBlobUrl = null; }
      if (tokenEl) tokenEl.value = "";
      setBinding("");
      if (countdownEl) countdownEl.textContent = "";
      setStatus(kiwiT("label"), kiwiT("badgeIdle"), "idle");
      setHint(kiwiT("hintProtected"));
      setProgress(0);
    }
    // Failure recovery (audit #55): an error never leaves the widget stuck
    // in "failed" — it resets to idle, retries a bounded number of times
    // with backoff, then settles idle and reacquires on the next
    // interaction (click the widget, the Retry button, or a page re-init).
    function fireErrorCallback(msg) {
      var r = kiwiWidgets[widgetId];
      if (!r || r.errorFired || !options.errorCallback) return;
      r.errorFired = true;
      try { options.errorCallback(msg || "challenge-failed"); } catch (e) {}
    }
    function fail(msg) {
      resetToIdle();
      announce(kiwiT("statusFailed"));
      dispatch("error", { error: msg });
      if (retryCount < RETRY_LIMIT) {
        retryCount++;
        setHint(kiwiT("hintRetrying").replace("{msg}", msg));
        // Round 28 (P2): the retry is a cancellable handle — a reset that
        // lands during the backoff must never start a stale run().
        var r = kiwiWidgets[widgetId];
        if (r && r.retryTimer) clearTimeout(r.retryTimer);
        if (r) r.retryTimer = setTimeout(function () { if (r) r.retryTimer = null; run(); }, 1000 * retryCount);
      } else {
        setHint(kiwiT("hintClickRetry").replace("{msg}", msg));
        delete W.dataset.kiwiStarted;
        // Round 27 (P2): terminal failure must surface on the visible
        // widget — the Retry button's visibility is keyed on
        // .kiwi-widget[data-state="failed"] (it never appeared before,
        // because the state was never set on failure).
        setStatus(kiwiT("label"), kiwiT("badgeFailed"), "failed");
        if (retryEl) retryEl.style.display = "";
        // Round 28 (P2): the provider error callback fires exactly once
        // per generation, at automatic-retry exhaustion.
        fireErrorCallback(msg);
      }
    }
    // Build-id mismatch (audit #53): the worker reported a solver build id
    // different from this driver's constant. The stale worker must NEVER
    // contribute a solution, and there is no fallback (retrying cannot
    // change the cached worker the page was served).
    function solverMismatch() {
      clearInterval(countdownTimer);
      telemetry.stop();
      if (tokenEl) tokenEl.value = "";
      setBinding("");
      if (countdownEl) countdownEl.textContent = "";
      setStatus(kiwiT("statusSolverMismatch"), kiwiT("badgeVersionError"), "kiwi:solver-mismatch");
      setHint(kiwiT("hintSolver"));
      setProgress(0);
      fireErrorCallback("solver-mismatch");
    }
    // Round-13 invariant: worker creation failure or a worker solve failure
    // for a memory-hard challenge enters this controlled state. The token
    // is cleared, nothing is solved on the main thread, and the profile is
    // never downgraded. The widget stays reacquirable: a subsequent attempt
    // (Retry button, click, re-init) retries the worker from scratch — or
    // uses the explicitly configured data-kiwi-worker-src static worker.
    function workerUnavailable(reason) {
      clearInterval(countdownTimer);
      telemetry.stop();
      if (kiwiActiveBlobUrl) { URL.revokeObjectURL(kiwiActiveBlobUrl); kiwiActiveBlobUrl = null; }
      if (tokenEl) tokenEl.value = "";
      setBinding("");
      if (countdownEl) countdownEl.textContent = "";
      setStatus(kiwiT("statusWorkerUnavailable"), kiwiT("badgeUnavailable"), "kiwi:worker-unavailable");
      setHint(kiwiT("hintWorker"));
      setProgress(0);
      announce(kiwiT("statusWorkerUnavailable"));
      dispatch("worker-unavailable", { reason: reason || "worker-creation-failed" });
      delete W.dataset.kiwiStarted;
      // Round 28 (P2): worker conditions are non-retryable within the
      // flow — the provider error callback fires immediately.
      fireErrorCallback("worker-unavailable");
    }
    // BFCache restore (audit #54): a persisted pageshow must NOT auto-solve —
    // it clears the solved state and leaves the widget idle, ready to
    // reacquire on the next interaction or page re-init. Round 28 (P2): the
    // restore also CANCELS the in-flight generation (abort fetch, terminate
    // worker, clear retry/expiry timers) — a solve from before the restore
    // can never write a token afterwards.
    function reset() {
      kiwiCancelGeneration(widgetId);
      resetToIdle();
      delete W.dataset.kiwiStarted;
    }
    kiwiResetHooks.push({ el: W, reset: reset });
    // The Retry button re-inits exactly like the click/tap reacquire path.
    if (retryEl && !retryEl.dataset.kiwiRetryBound) {
      retryEl.dataset.kiwiRetryBound = "1";
      kiwiAddListener(retryEl, "click", function () {
        if (W.dataset.kiwiStarted || W.dataset.kiwiDestroyed) return;
        // Round 31 (P1): reacquisition MUST restore the FULL original
        // configuration — a blank initWidget(W) would fall back to DOM
        // attributes/URL heuristics/default "login", silently downgrading
        // a sitekey that maps server-side to a sensitive scope, and would
        // lose callbacks/response-field/language/action/cData. The widget
        // record always carries the options from the INITIAL render;
        // BFCache restore (reset) preserves them the same way.
        var preserved = (kiwiWidgets[widgetId] && kiwiWidgets[widgetId].options) || options;
        delete W.dataset.kiwiStarted;
        initWidget(W, preserved);
      });
    }
    // destroy() teardown: idle the runtime state (countdown, telemetry,
    // blob URL, token) exactly like resetToIdle does.
    kiwiCleanups.set(W, function () { resetToIdle(); });

    async function run() {
      // Round 28 (P2): every continuation is generation-guarded — a reset
      // that lands while this run is in flight bumps the generation and
      // aborts/terminates the handles; this run then bails without ever
      // touching state.
      var gen = (kiwiWidgets[widgetId] || {}).gen || 1;
      if (!kiwiGenerationCurrent(widgetId, gen)) return;
      try {
        setStatus(kiwiT("statusConnecting"), kiwiT("badgeWait"), "connecting");
        var endpoint = kiwiEndpoint(W.getAttribute("data-kiwi-endpoint") || container.getAttribute("data-kiwi-endpoint") || "/api/kcaptcha/challenge");
        // Algorithm selection (audit #62): the client may only select among
        // the solver profiles the server offers (sha256 / argon2id). Any
        // other attribute value is normalized back to the default — the
        // driver can never invent an algorithm, and a solver failure must
        // never downgrade a challenge request (there is no capability-based
        // fallback anywhere: a failed worker/WASM path retries with the SAME
        // profile, and difficulty parameters come from the server alone).
        var algorithm = W.getAttribute("data-kiwi-algorithm") || container.getAttribute("data-kiwi-algorithm") || "sha256";
        if (algorithm !== "sha256" && algorithm !== "argon2id") algorithm = "sha256";
        var requestBinding = W.getAttribute("data-kiwi-request-binding") || container.getAttribute("data-kiwi-request-binding");
        var reqBody = { scope: scope };
        if (algorithm !== "sha256") reqBody.algorithm = algorithm;
        if (requestBinding) reqBody.request_binding = requestBinding;
        // Round 30 (P1): provider-compatible challenge metadata is declared
        // by the WIDGET at issuance (data-action / data-cdata on the
        // container, or params.action/cData) — the server validates the
        // provider shapes and binds them to the nonce; a Siteverify
        // request can never supply them.
        var kiwiAction = (container.getAttribute ? container.getAttribute("data-action") : null)
          || (W.getAttribute ? W.getAttribute("data-action") : null)
          || (options && options.action ? String(options.action) : null);
        var kiwiCdata = (container.getAttribute ? container.getAttribute("data-cdata") : null)
          || (W.getAttribute ? W.getAttribute("data-cdata") : null)
          || (options && options.cData ? String(options.cData) : null);
        if (kiwiAction) reqBody.action = kiwiAction;
        if (kiwiCdata) reqBody.cdata = kiwiCdata;
        // Round 30 (item 14): the public sitekey travels with the request
        // so the server resolves (sitekey, action) -> security scope —
        // the client never chooses protected scope names.
        if (options && options.sitekey) reqBody.sitekey = String(options.sitekey);
        var timeoutAttr = W.getAttribute("data-kiwi-fetch-timeout-ms") || container.getAttribute("data-kiwi-fetch-timeout-ms") || "";
        var fetchTimeoutMs = parseInt(timeoutAttr, 10);
        if (!(fetchTimeoutMs > 0)) fetchTimeoutMs = KIWI_FETCH_TIMEOUT_MS;
        var abortController = new AbortController();
        var abortTimer = setTimeout(function () { abortController.abort(); }, fetchTimeoutMs);
        var rw = kiwiWidgets[widgetId];
        if (rw) { rw.abortController = abortController; rw.abortTimer = abortTimer; }
        var resp, data;
        try {
          resp = await fetch(endpoint, { method:"POST", credentials:"same-origin", cache:"no-store", redirect:"error", referrerPolicy:"no-referrer", headers:{"Accept":"application/json","Content-Type":"application/json"}, body: JSON.stringify(reqBody), signal: abortController.signal });
          if (!resp.ok) throw new Error("Challenge failed");
          data = await resp.json();
        } finally {
          clearTimeout(abortTimer);
          var rw2 = kiwiWidgets[widgetId];
          if (rw2 && rw2.abortTimer === abortTimer) rw2.abortTimer = null;
        }
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        // No weaker challenge (audit #62): the response algorithm may only
        // be equal or stronger than requested — a server downgrade (argon2id
        // requested, sha256 returned) is a FAILED challenge, never a weaker
        // solve. The client may only ever accept what it asked for or more.
        if (algorithm === "argon2id" && (data.algorithm || "sha256") !== "argon2id") throw new Error("Challenge downgraded");
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        if (data.ttlSecs) startCountdown(data.ttlSecs);
        setStatus(kiwiT("statusVerifying"), kiwiT("badgeWorking"), "solving");
        announce(kiwiT("checking"));
        dispatch("verifying");
        var result = null;
        if ((data.algorithm || "sha256") === "argon2id") {
          // Round-13 invariant: memory-hard challenges ALWAYS run in the
          // same-origin worker. There is no synchronous CHUNK=1 fallback
          // and no weaker-profile retry — a missing or failed worker enters
          // the controlled kiwi:worker-unavailable state.
          // Round 28 (P2): the worker handle is stored on the widget record
          // so a cancelled generation can terminate() it outright.
          var workerHandle = solveWithWorker(data, setProgress, container);
          var wr = kiwiWidgets[widgetId];
          if (wr) wr.worker = workerHandle.terminate;
          result = await workerHandle.promise;
          var wr2 = kiwiWidgets[widgetId];
          if (wr2 && wr2.worker === workerHandle.terminate) wr2.worker = null;
          if (!kiwiGenerationCurrent(widgetId, gen)) return;
          if (result && result.mismatch) { solverMismatch(); return; }
          if (!result || result.unavailable) { workerUnavailable(result ? result.reason : "solve-failed"); return; }
        } else {
          result = await solve(data.prefix, b64decode(data.salt), data.targetBits, "sha256", data.mKib||0, data.t||1, data.p||1, setProgress);
        }
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        if (!result) throw new Error("Exhausted");
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        tokenEl.value = btoa(data.nonce + "." + result.counter + "." + result.duration + "." + JSON.stringify(telemetry.build()));
        setBinding(requestBinding || "");
        retryCount = 0;
        setStatus(kiwiT("label"), kiwiT("badgeSuccess"), "done"); setHint(kiwiT("hintVerified")); setProgress(100); clearInterval(countdownTimer); if (countdownEl) countdownEl.textContent = "";
        announce(kiwiT("statusVerified"));
        var token = tokenEl.value;
        kiwiRecordState("verified", token);
        writeResponseAlias(token);
        dispatch("verified", { nonce: data.nonce, token: token });
        // Round 24: provider-style solved-token expiry lifecycle. The
        // server remains authoritative (an expired record is rejected);
        // this client timer is UX convenience only and mirrors the
        // incumbent providers' token lifetime.
        scheduleExpiry(data.ttlSecs || 0);
        if (options.callback) { try { options.callback(token); } catch (e) {} }
        telemetry.stop();
      } catch (e) {
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        fail(e.message);
      }
    }
    dispatch("ready");
    run();
    return widgetId;
  }

  // ── BFCache restore (audit #54) ─────────────────────────────────────
  // A persisted pageshow restores the page WITHOUT re-running the driver
  // init, so a previously solved widget would otherwise keep its stale
  // token. Reset every live widget: clear the solved state and reacquire
  // on the next interaction instead of auto-solving on restore.
  var kiwiResetHooks = [];

  // ── Per-widget lifecycle bookkeeping (round-14) ──────────────────────
  // destroy(element|selector) needs to reverse EVERYTHING initWidget
  // attached: listeners (registered in a per-element registry so they can
  // be removed by reference), the countdown/telemetry/blob-URL runtime
  // state (one cleanup closure per widget), and the BFCache hook. A
  // destroyed widget is marked data-kiwi-destroyed and initWidget refuses
  // to resurrect it — the SPA owns the DOM node from then on.
  var kiwiCleanups = new WeakMap();
  var kiwiListenerRegistry = new WeakMap();
  function kiwiAddListener(el, type, fn, opts) {
    var list = kiwiListenerRegistry.get(el) || [];
    list.push({ type: type, fn: fn, opts: opts });
    kiwiListenerRegistry.set(el, list);
    el.addEventListener(type, fn, opts);
  }
  function kiwiRemoveListeners(el) {
    var list = kiwiListenerRegistry.get(el) || [];
    for (var i = 0; i < list.length; i++) {
      try { el.removeEventListener(list[i].type, list[i].fn, list[i].opts); } catch (err) {}
    }
    kiwiListenerRegistry.set(el, []);
  }
  function kiwiDestroy(sel) {
    var els = typeof sel === "string" ? (document.querySelectorAll(sel) ? Array.prototype.slice.call(document.querySelectorAll(sel)) : []) : (sel ? [sel] : []);
    for (var i = 0; i < els.length; i++) {
      var W = els[i];
      if (!W || W.nodeType !== 1) continue;
      W.dataset.kiwiDestroyed = "1";
      kiwiResetHooks = kiwiResetHooks.filter(function (h) { return h.el !== W; });
      if (W.dataset.kiwiInstance && kiwiWidgets[W.dataset.kiwiInstance]) {
        kiwiCancelGeneration(W.dataset.kiwiInstance);
      }
      var cleanup = kiwiCleanups.get(W);
      if (cleanup) { try { cleanup(); } catch (err) {} kiwiCleanups.delete(W); }
      kiwiRemoveListeners(W);
      var retryEl = W.querySelector("[data-kiwi-retry]");
      if (retryEl) kiwiRemoveListeners(retryEl);
      delete W.dataset.kiwiStarted;
      var destroyStateEl = (W.matches && W.matches(".kiwi-widget")) ? W : (W.querySelector ? W.querySelector("[data-kiwi-widget]") || W : W);
      destroyStateEl.removeAttribute("data-state");
      var tokenEl = W.querySelector("[data-kiwi-token]");
      if (tokenEl) tokenEl.value = "";
    }
  }
  window.addEventListener("pageshow", function (e) {
    if (!e.persisted) return;
    for (var i = 0; i < kiwiResetHooks.length; i++) {
      try { kiwiResetHooks[i].reset(); } catch (err) {}
    }
  });

  // ── SPA lifecycle observer (round-13, OPT-IN) ───────────────────────
  // Single-page apps that insert widgets dynamically call
  // window.KiwiCaptcha.observe(document.body) (or any root) once; the
  // MutationObserver auto-inits every [data-kiwi-widget] that appears
  // later. Not started automatically — opt-in only, so a page that wants
  // strict control over init timing never gets surprise challenges.
  var kiwiObserver = null;
  function kiwiScanNode(node) {
    if (!node || node.nodeType !== 1) return;
    var widgets = [];
    if (node.matches && node.matches("[data-kiwi-widget]")) widgets.push(node);
    if (node.querySelectorAll) {
      var found = node.querySelectorAll("[data-kiwi-widget]");
      for (var i = 0; i < found.length; i++) widgets.push(found[i]);
    }
    for (var j = 0; j < widgets.length; j++) {
      if (!widgets[j].dataset.kiwiStarted) initWidget(widgets[j]);
    }
  }
  function kiwiObserve(root) {
    if (typeof MutationObserver === "undefined") return { disconnect: function() {} };
    if (!kiwiObserver) {
      kiwiObserver = new MutationObserver(function (mutations) {
        for (var i = 0; i < mutations.length; i++) {
          var added = mutations[i].addedNodes;
          for (var j = 0; j < added.length; j++) kiwiScanNode(added[j]);
        }
      });
    }
    kiwiObserver.observe(root || document.body, { childList: true, subtree: true });
    return { disconnect: function () { if (kiwiObserver) kiwiObserver.disconnect(); } };
  }

  // ── Round-24 provider-style public API ──────────────────────────────
  // Native KiwiCaptcha now exposes the incumbent lifecycle: render() ->
  // stable widget id, reset/getResponse/execute/remove/isExpired/ready.
  // The compatibility globals (grecaptcha/hcaptcha/turnstile) delegate to
  // the SAME instances — one widget, one token, one lifecycle.
  function kiwiResolveTarget(target) {
    if (!target) return null;
    if (typeof target === "string") {
      var el = document.getElementById(target);
      if (!el) {
        var list = document.querySelectorAll(target);
        return list.length ? list[0] : null;
      }
      return el;
    }
    return target.nodeType === 1 ? target : null;
  }
  function kiwiRender(target, options) {
    var el = kiwiResolveTarget(target);
    if (!el) return 0;
    return initWidget(el, options) || 0;
  }
  function kiwiReset(id) {
    var r = kiwiWidgets[id];
    if (!r) return;
    // Round 28 (P2): reset is cancellation — the old generation's fetch is
    // aborted, its worker terminated, its retry/expiry timers cleared; the
    // new initWidget starts generation +1.
    kiwiCancelGeneration(id);
    var W = r.W;
    if (W) {
      var t = W.querySelector("[data-kiwi-token]");
      if (t) t.value = "";
      if (r.options && r.options.responseField) {
        var host = t ? t.parentNode : null;
        var input = host ? host.querySelector('input[name="' + r.options.responseField + '"]') : null;
        if (input) input.value = "";
      }
      delete W.dataset.kiwiStarted;
      initWidget(W, r.options);
    }
  }
  function kiwiGetResponse(id) {
    var r = kiwiWidgets[id];
    return (r && r.state === "verified") ? (r.token || "") : "";
  }
  function kiwiIsExpired(id) {
    var r = kiwiWidgets[id];
    return !!(r && r.state === "expired");
  }
  function kiwiExecute(id) {
    var r = kiwiWidgets[id];
    if (!r) return Promise.reject(new Error("kiwicaptcha: unknown widget id " + id));
    if (r.state === "verified") return Promise.resolve(r.token || "");
    if (r.W && !r.W.dataset.kiwiStarted) {
      delete r.W.dataset.kiwiStarted;
      initWidget(r.W, r.options);
    }
    return new Promise(function (resolve, reject) {
      var W = r.W;
      var onVerified = function () {
        var cur = kiwiWidgets[id];
        resolve(cur ? (cur.token || "") : "");
      };
      var onError = function (ev) {
        // Round 28 (P3): fail() dispatches {error: msg} — the promise must
        // reject with the ACTUAL reason, not the generic fallback.
        var detail = (ev && ev.detail) || {};
        var reason = detail.error || detail.reason || "kiwicaptcha: solve failed";
        reject(new Error(String(reason)));
      };
      if (W) {
        W.addEventListener("kiwi:verified", onVerified, { once: true });
        W.addEventListener("kiwi:error", onError, { once: true });
      }
      var cur = kiwiWidgets[id];
      if (cur && cur.state === "verified") onVerified();
    });
  }
  function kiwiReady(id) {
    var r = kiwiWidgets[id];
    if (!r) return Promise.reject(new Error("kiwicaptcha: unknown widget id " + id));
    return Promise.resolve();
  }
  function kiwiRemove(id) {
    var r = kiwiWidgets[id];
    if (!r) return;
    kiwiCancelGeneration(id);
    if (r.W) {
      kiwiDestroy(r.W);
      // Provider parity (Turnstile remove()): the widget markup leaves the
      // page.
      var node = r.W;
      var container = (node.closest ? node.closest(".kiwi-container") : null) || node;
      var toRemove = container && container.parentNode ? container : node;
      if (toRemove && toRemove.parentNode) toRemove.parentNode.removeChild(toRemove);
    }
    delete kiwiWidgets[id];
  }
  window.KiwiCaptcha = {
    render: kiwiRender,
    reset: kiwiReset,
    getResponse: kiwiGetResponse,
    execute: kiwiExecute,
    remove: kiwiRemove,
    isExpired: kiwiIsExpired,
    ready: kiwiReady,
    init: initWidget,
    workerSource: KIWI_WORKER_SRC,
    protocolId: KIWI_SOLVER_PROTOCOL_ID,
    buildId: KIWI_SOLVER_PROTOCOL_ID,
    observe: kiwiObserve,
    destroy: kiwiDestroy
  };
  // ── Round-24 incumbent compatibility loader ─────────────────────────
  // The driver doubles as the first-party compatibility loader: when the
  // driver script itself is loaded as .../api.js?compat=recaptcha (or
  // hcaptcha/turnstile), it auto-renders the incumbent containers
  // (.g-recaptcha/.h-captcha/.cf-turnstile), installs the provider
  // global, and keeps the provider-named response field in sync with the
  // same underlying Kiwi solution token. An incumbent page changes only
  // its provider script URL.
  var compat = null;
  var compatScriptUrl = null;
  // Round 29 (P1): Google's API defaults reset()/getResponse() and
  // invisible execute() to the FIRST CREATED widget when the id is
  // omitted. Track the first successful compat render.
  var kiwiCompatFirstId = null;
  // Round 26 (P1): when the driver is loaded as the external
  // /kiwi-captcha/api.js (glue + driver concatenated, split by the
  // /*KIWI_COMPAT_SPLIT*/ marker), the worker cannot find the glue in an
  // inline script element. Fetch the loader's own source once and keep the
  // glue part for the Blob-worker prelude — Argon2id stays worker-only and
  // WORKING through the external loader.
  var kiwiCompatGlue = null;
  var kiwiCompatGlueReady = null;
  try {
    var currentScript = document.currentScript;
    if (!currentScript) {
      var scripts = document.getElementsByTagName("script");
      currentScript = scripts[scripts.length - 1];
    }
    compatScriptUrl = currentScript && currentScript.src ? currentScript.src : null;
    // Round 30 (items 13+28): ONE coherent loader parser — URLSearchParams
    // (no regexes): compat, render, onload, hl, with callback-identifier
    // validation and locale normalization.
    function parseCompatLoader(scriptUrl) {
      var out = { provider: null, renderMode: "auto", onloadName: null, language: null };
      if (!scriptUrl) return out;
      var url;
      try {
        url = new URL(scriptUrl, document.baseURI);
      } catch (e) {
        return out;
      }
      var compatParam = url.searchParams.get("compat");
      if (compatParam === "recaptcha" || compatParam === "hcaptcha" || compatParam === "turnstile") {
        out.provider = compatParam;
      }
      if (url.searchParams.get("render") === "explicit") out.renderMode = "explicit";
      var onloadParam = url.searchParams.get("onload");
      if (typeof onloadParam === "string" && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(onloadParam)) {
        out.onloadName = onloadParam;
      }
      var hl = url.searchParams.get("hl");
      if (typeof hl === "string" && hl !== "") out.language = kiwiNormalizeLang(hl) || null;
      return out;
    }
    var compatLoader = parseCompatLoader(compatScriptUrl);
    compat = compatLoader.provider;
    var compatRenderMode = compatLoader.renderMode;
    var compatOnloadName = compatLoader.onloadName;
    var compatLoaderLang = compatLoader.language;
    if (compat && compatScriptUrl) {
      // Round 27 (P2): revalidate — force-cache would let the browser
      // reuse a stale /api.js representation, defeating the server's ETag
      // policy and potentially pairing the current driver with an old
      // glue of the same protocol generation.
      kiwiCompatGlueReady = fetch(compatScriptUrl.split("?")[0], { cache: "no-cache", credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.text() : null; })
        .then(function (src) {
          if (!src) return;
          var idx = src.indexOf("/*KIWI_COMPAT_SPLIT*/");
          if (idx !== -1) kiwiCompatGlue = src.slice(0, idx);
        })
        .catch(function () {});
    }
  } catch (e) {}
  if (compat) {
    var COMPAT_FIELD = { recaptcha: "g-recaptcha-response", hcaptcha: "h-captcha-response", turnstile: "cf-turnstile-response" }[compat];
    var COMPAT_SELECTOR = { recaptcha: ".g-recaptcha", hcaptcha: ".h-captcha", turnstile: ".cf-turnstile" }[compat];
    var COMPAT_SVG = '<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M26 19c0 5.5-4 10-10 10S7 24.5 7 19c0-6 3-11 7-12 2-0.5 4-0.5 6 0 4 1 6 6 6 12z" fill="currentColor"/><path d="M12.5 8.5c-.8-1.5-1-3.5-.5-5.5.5-2 2-3.5 4-4 2-.5 4 .5 5 2.5.2 1 .5 2 .5 3.5" fill="currentColor"/><path d="M10 7c-4 1-8 3-8.5 3.5-.3.3-.3.8 0 1 1 0.5 8 2.5 9.5 2.5" fill="currentColor"/><path d="M14 29v2m6-2v2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/><circle cx="16.5" cy="4.5" r="1" fill="white"/><circle cx="17" cy="4" r="0.6" fill="currentColor"/><path d="M19 14c1.5 0 2.5 1 2.5 2s-1 2-2.5 2-2.5-1-2.5-2 1-2 2.5-2z" fill="white" opacity="0.2"/></svg>';
    function compatInjectCss() {
      if (!compatScriptUrl || document.querySelector('link[data-kiwi-css]')) return;
      var link = document.createElement("link");
      link.rel = "stylesheet";
      link.setAttribute("data-kiwi-css", "");
      var base = compatScriptUrl.split("?")[0];
      link.href = base.substring(0, base.lastIndexOf("/") + 1) + "widget.css";
      document.head.appendChild(link);
    }
    function compatMarkup() {
      return '<div class="kiwi-container"><input type="hidden" name="kiwi__token" data-kiwi-token value="">' +
        '<div class="kiwi-widget" data-kiwi-widget data-kiwi-started="1" data-state="idle" role="group" aria-label="KiwiCaptcha security check">' +
        '<div class="kiwi-icon-wrapper" aria-hidden="true">' + COMPAT_SVG + '<div class="kiwi-glow"></div></div>' +
        '<div class="kiwi-main"><div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>' +
        '<div class="kiwi-track" aria-hidden="true"><div class="kiwi-bar" data-kiwi-bar></div></div>' +
        '<div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected by KiwiCaptcha</p><span class="kiwi-timer" data-kiwi-timer></span></div></div>' +
        '<span class="kiwi-sr-only" data-kiwi-status role="status" aria-live="polite"></span></div></div>';
    }
    function compatReadCallbacks(el, params) {
      var cb = function (name) {
        var v = (params && (params[name] !== undefined)) ? params[name]
          : (el.getAttribute("data-" + name.replace(/([A-Z])/g, "-$1").toLowerCase()) || "");
        return typeof v === "function" ? v : (typeof v === "string" && v ? (window[v] || null) : null);
      };
      return {
        callback: cb("callback"),
        expiredCallback: cb("expired-callback"),
        errorCallback: cb("error-callback")
      };
    }
    function compatRender(target, params) {
      // Round 28 (P2): grecaptcha.render("id", ...) / render(selector, ...)
      // resolve through the same target resolver as the native API — an
      // explicit string id previously returned 0 silently.
      var el = kiwiResolveTarget(target);
      if (!el || el.nodeType !== 1) return 0;
      // Round 28 (P2): re-rendering an already-rendered container must be
      // idempotent — the existing widget instance is returned instead of
      // double-initializing the same container (a second solve on the same
      // element would race the first). initWidget keys the instance on the
      // CONTAINER (el.dataset.kiwiInstance); the inner [data-kiwi-widget]
      // markup carries no instance id of its own.
      if (el.dataset.kiwiInstance && kiwiWidgets[el.dataset.kiwiInstance]) {
        return el.dataset.kiwiInstance;
      }
      var existingWidget = el.querySelector ? el.querySelector("[data-kiwi-widget]") : null;
      if (existingWidget && existingWidget.dataset.kiwiInstance && kiwiWidgets[existingWidget.dataset.kiwiInstance]) {
        return existingWidget.dataset.kiwiInstance;
      }
      if (!el.querySelector("[data-kiwi-widget]")) {
        if (el.tagName === "BUTTON" || el.tagName === "INPUT") {
          // Invisible-style controls keep their label; the widget is
          // appended (reCAPTCHA renders inside the control the same way).
          el.insertAdjacentHTML("beforeend", compatMarkup());
        } else {
          el.innerHTML = compatMarkup();
        }
      }
      // Pass through explicit Kiwi overrides (e.g.
      // data-kiwi-endpoint="/challenge?ttl=2") from the incumbent
      // container onto the rendered widget container; the endpoint
      // defaults to the bundle's same-origin prefix so a migrated page
      // needs NO endpoint configuration.
      var inner = el.querySelector(".kiwi-container");
      if (inner) {
        ["data-kiwi-endpoint", "data-kiwi-scope", "data-kiwi-algorithm", "data-kiwi-worker-src"].forEach(function (attr) {
          if (el.hasAttribute(attr) && !inner.hasAttribute(attr)) inner.setAttribute(attr, el.getAttribute(attr));
        });
        if (!inner.hasAttribute("data-kiwi-endpoint")) inner.setAttribute("data-kiwi-endpoint", "/kiwi-captcha/challenge");
        // The driver reads the endpoint from the rendered container AND
        // from its own ancestor chain — mirror the default onto the
        // incumbent container so a page with NO explicit endpoint uses
        // the bundle's same-origin prefix (round 26: the one-line
        // migration contract relies on this default).
        if (!el.hasAttribute("data-kiwi-endpoint")) el.setAttribute("data-kiwi-endpoint", "/kiwi-captcha/challenge");
      }
      var sitekey = (params && (params.sitekey || params["sitekey"])) || el.getAttribute("data-sitekey") || "";
      var cbs = compatReadCallbacks(el, params);
      var id = kiwiRender(el, {
        scope: sitekey || "login",
        callback: cbs.callback,
        expiredCallback: cbs.expiredCallback,
        errorCallback: cbs.errorCallback,
        // Round 29 (P3): Turnstile's configurable response field
        // (response-field-name / params["response-field-name"]) — the
        // default stays the provider-named field.
        // Round 30 (item 12): Turnstile's response-field=false keeps the
        // internal Kiwi token field and SKIPS the provider alias input;
        // response-field-name overrides the alias name.
        responseField: (params && params["response-field"] === false)
          || el.getAttribute("data-response-field") === "false"
          ? false
          : ((params && typeof params["response-field-name"] === "string" && params["response-field-name"])
            || el.getAttribute("data-response-field-name") || COMPAT_FIELD),
        // Round 29 (WCAG 3.1.2): grecaptcha.render(el, {lang: "de"}) or
        // data-kiwi-lang on the incumbent container.
        lang: (params && typeof params.lang === "string" && params.lang)
          || el.getAttribute("data-kiwi-lang") || undefined,
        // Round 30 (P1): Turnstile action/cData — forwarded to the
        // challenge request at issuance (server-owned binding).
        action: (params && typeof params.action === "string" && params.action)
          || el.getAttribute("data-action") || undefined,
        cData: (params && typeof params.cData === "string" && params.cData)
          || el.getAttribute("data-cdata") || undefined,
        // Round 30 (items 12+14): Turnstile language + the public sitekey
        // (server-owned scope resolution).
        language: (params && typeof params.language === "string" && params.language)
          || el.getAttribute("data-language") || undefined,
        sitekey: sitekey || undefined
      });
      if (id && !kiwiCompatFirstId) kiwiCompatFirstId = id;
      return id || 0;
    }
    function compatExecute(arg, opts) {
      // Round 29 (P1): execute() with NO argument targets the first widget.
      if (arg === undefined || arg === null) {
        return kiwiCompatFirstId ? kiwiExecute(kiwiCompatFirstId) : Promise.reject(new Error("kiwicaptcha: no widget has been rendered"));
      }
      var id = (typeof arg === "string" && kiwiWidgets[arg]) ? arg : null;
      if (id) return kiwiExecute(id);
      // v3-style execute(sitekey, {action}): map action -> Kiwi scope on a
      // hidden widget. Honest v3 handling: no fabricated score is ever
      // produced — the application migrates to Kiwi verification plus the
      // optional adaptive-risk decision machinery.
      var sitekey = typeof arg === "string" ? arg : "";
      var action = (opts && opts.action) || sitekey || "login";
      var holder = document.createElement("div");
      holder.style.display = "none";
      var inner = document.createElement("div");
      inner.className = "kiwi-container";
      inner.setAttribute("data-kiwi-scope", action);
      holder.appendChild(inner);
      document.body.appendChild(holder);
      // Round 28 (P3): render through compatRender so the same endpoint/
      // scope/response-field defaults land on the holder (an explicit
      // native-default endpoint would 404 on a compat deployment).
      // Round 31 (P1): the REAL sitekey and the requested action are
      // transmitted INDEPENDENTLY — passing the action as the sitekey
      // disconnected the server-owned (sitekey, action) -> scope policy.
      var id2 = compatRender(inner, { sitekey: sitekey, action: action });
      if (!id2) {
        if (holder && holder.parentNode) holder.parentNode.removeChild(holder);
        return Promise.reject(new Error("kiwicaptcha: hidden render failed"));
      }
      var p = kiwiExecute(id2);
      // Round 28 (P3): a long-lived SPA repeatedly calling execute()
      // must not accumulate hidden DOM, registry entries or reset hooks —
      // the holder is removed and the widget destroyed on BOTH paths.
      if (p && typeof p.then === "function") {
        return p.then(function (tok) {
          if (id2 && kiwiWidgets[id2]) kiwiRemove(id2);
          if (holder && holder.parentNode) holder.parentNode.removeChild(holder);
          return tok;
        }, function (err) {
          if (id2 && kiwiWidgets[id2]) kiwiRemove(id2);
          if (holder && holder.parentNode) holder.parentNode.removeChild(holder);
          throw err;
        });
      }
      return p;
    }
    function compatResolveId(idOrEl) {
      // Round 29 (P1): an OMITTED id targets the first created widget
      // (the incumbent providers' documented default); an element resolves
      // to its rendered widget instance.
      if (idOrEl === undefined || idOrEl === null) return kiwiCompatFirstId;
      if (typeof idOrEl === "string" && kiwiWidgets[idOrEl]) return idOrEl;
      if (idOrEl && idOrEl.nodeType === 1 && idOrEl.querySelector) {
        return (idOrEl.querySelector("[data-kiwi-widget]") || {}).dataset.kiwiInstance || null;
      }
      return null;
    }
    var compatApi = {
      render: compatRender,
      reset: function (idOrEl) {
        var id = compatResolveId(idOrEl);
        if (id) kiwiReset(id);
      },
      getResponse: function (idOrEl) {
        var id = compatResolveId(idOrEl);
        return id ? kiwiGetResponse(id) : "";
      },
      execute: compatExecute,
      remove: function (idOrEl) {
        var id = compatResolveId(idOrEl);
        if (id) kiwiRemove(id);
      },
      // Round 29 (P3): Turnstile's ready() + isExpired() lifecycle surface.
      ready: function (fn) {
        if (typeof fn !== "function") return;
        (kiwiCompatGlueReady || Promise.resolve()).then(function () { try { fn(); } catch (e) {} });
      },
      isExpired: function (idOrEl) {
        var id = compatResolveId(idOrEl);
        return id ? kiwiIsExpired(id) : false;
      }
    };
    if (compat === "recaptcha") {
      window.grecaptcha = window.grecaptcha || Object.assign({}, compatApi, {
        // Round 28 (P2): ready() queues until the compat loader's glue
        // self-fetch resolves — an explicit render() inside ready() that
        // immediately starts an Argon challenge can no longer race the
        // glue bootstrap (implicit rendering already waited).
        ready: function (fn) {
          if (typeof fn !== "function") return;
          (kiwiCompatGlueReady || Promise.resolve()).then(function () { kiwiSafeCallback(fn); });
        },
        enterprise: undefined
      });
    } else if (compat === "hcaptcha") {
      window.hcaptcha = window.hcaptcha || Object.assign({}, compatApi, {
        getRespKey: function (idOrEl) {
          // Round 31 (item 10): the omitted argument must default to the
          // FIRST created widget exactly like the shared resolver.
          var id = compatResolveId(idOrEl);
          return id ? kiwiGetResponse(id) : "";
        }
      });
    } else {
      window.turnstile = window.turnstile || compatApi;
    }
    compatInjectCss();
    // Round 29 (P1): render=explicit suppresses automatic rendering — the
    // application calls render() itself (the documented explicit pattern);
    // onload=<fn> runs after the loader glue is ready so an immediate
    // explicit Argon render can never race the glue bootstrap.
    (kiwiCompatGlueReady || Promise.resolve()).then(function () {
      if (compatOnloadName) {
        var onloadFn = window[compatOnloadName];
        if (typeof onloadFn === "function") kiwiSafeCallback(onloadFn);
      }
      if (compatRenderMode === "explicit") return;
      // Implicit render: every incumbent container on the page. The initial
      // render waits for the loader-glue fetch so Argon2id solves work on
      // first paint through the external /api.js path (round 26).
      var compatContainers = document.querySelectorAll(COMPAT_SELECTOR);
      for (var ci = 0; ci < compatContainers.length; ci++) {
        var el = compatContainers[ci];
        var wid = compatRender(el);
        // Invisible-style controls (buttons / inputs / data-size="invisible"):
        // clicking the control triggers execute() — the incumbent pattern.
        if (wid && (el.tagName === "BUTTON" || el.tagName === "INPUT" || el.getAttribute("data-size") === "invisible")) {
          (function (id, node) {
            node.addEventListener("click", function (ev) {
              ev.preventDefault();
              kiwiExecute(id);
            });
          })(wid, el);
        }
      }
    });
    // Dynamic implicit-render convenience: a .g-recaptcha node inserted
    // later is auto-rendered. Round 30 (P1): NEVER in explicit mode —
    // render=explicit means the application controls rendering (Google's
    // documented contract), so a later container must stay untouched
    // until an explicit grecaptcha.render() call.
    if (compat === "recaptcha" && compatRenderMode !== "explicit" && typeof MutationObserver !== "undefined") {
      new MutationObserver(function (mutations) {
        for (var m = 0; m < mutations.length; m++) {
          var nodes = mutations[m].addedNodes;
          for (var n = 0; n < nodes.length; n++) {
            var node = nodes[n];
            if (node && node.nodeType === 1 && node.matches && node.matches(COMPAT_SELECTOR) && !node.querySelector("[data-kiwi-widget]")) {
              compatRender(node);
            }
          }
        }
      }).observe(document.body, { childList: true, subtree: true });
    }
  }

  var runInit = function() {
    document.querySelectorAll("[data-kiwi-widget]").forEach(function (W) {
      // Round 29 (WCAG 2.5.2): no pointerdown-only activation. After a
      // reset or a settled failure the widget is idle; the native Retry
      // button (visible in idle/failed/unavailable states via
      // data-state CSS) is the reacquire control for EVERY input method.
      initWidget(W);
    });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runInit); else runInit();
})();
