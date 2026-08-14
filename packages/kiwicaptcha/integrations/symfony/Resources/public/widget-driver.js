(function() {
  var encoder = new TextEncoder();

  // ── Solver build id (audit #53) ─────────────────────────────────────
  // Bumped manually at build time. The worker reports the SAME id in its
  // `ready`/`done` handshake messages; the driver refuses any worker whose
  // id differs (a stale cached worker must never contribute a solution).
  // Integrators must serve the driver, worker and wasm from the SAME build
  // (see SECURITY.md — versioned-resource expectation).
  var KIWI_SOLVER_BUILD_ID = "2026-08-r1";

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
  // assets/kiwi-worker.js by tools/embed-worker.mjs (audit round 15) — the
  // standalone file is the source of truth; backticks and ${ are escaped
  // for template-literal semantics. The worker must not contain a
  // closing-script-tag sequence (the driver is inlined into pages by the
  // renderers); the generator rejects one.
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

  // Solver build id (audit #53): MUST equal the widget driver's
  // KIWI_SOLVER_BUILD_ID constant. Reported in the ready/done handshake
  // messages so the driver can refuse a stale cached worker.
  var KIWI_SOLVER_BUILD_ID = "2026-08-r1";

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
          post({ type: "done", counter: res, buildId: KIWI_SOLVER_BUILD_ID });
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
            post({ type: "done", counter: res, buildId: KIWI_SOLVER_BUILD_ID });
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
            post({ type: "done", counter: counter, buildId: KIWI_SOLVER_BUILD_ID });
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

  // Startup handshake (audit #53): announce this worker's solver build id
  // BEFORE any solve work so the driver can refuse a stale worker outright.
  post({ type: "ready", buildId: KIWI_SOLVER_BUILD_ID });
})();
`;

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
    return new Promise(function(resolve) {
      if (typeof Worker === "undefined") { resolve({ unavailable: true, reason: "no-worker-support" }); return; }
      var worker = null;
      var blobUrl = null;
      try {
        var workerSrc = container.getAttribute("data-kiwi-worker-src");
        if (workerSrc) {
          worker = new Worker(workerSrc);
        } else {
          var glue = kiwiFindGlueSource();
          var blobSrc = (glue ? "var window = self;" + glue + "\n" : "") + KIWI_WORKER_SRC;
          blobUrl = URL.createObjectURL(new Blob([blobSrc], { type: "application/javascript" }));
          worker = new Worker(blobUrl);
        }
      } catch (e) { if (blobUrl) URL.revokeObjectURL(blobUrl); resolve({ unavailable: true, reason: "worker-creation-failed" }); return; }
      if (!worker) { if (blobUrl) URL.revokeObjectURL(blobUrl); resolve({ unavailable: true, reason: "worker-creation-failed" }); return; }
      if (kiwiActiveBlobUrl) { URL.revokeObjectURL(kiwiActiveBlobUrl); kiwiActiveBlobUrl = null; }
      kiwiActiveBlobUrl = blobUrl;
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
          if (typeof msg.buildId !== "string" || msg.buildId !== KIWI_SOLVER_BUILD_ID) {
            if (!settled) { settled = true; worker.terminate(); teardown(); resolve({ mismatch: true }); }
          }
          return;
        }
        if (msg.type === "progress") {
          if (typeof msg.counter !== "number" || !isFinite(msg.counter)) return;
          onProgress(Math.min(95, (msg.counter * 100) / expectedHashes));
        } else if (msg.type === "done") {
          if (typeof msg.counter !== "number" || !isFinite(msg.counter)) return;
          if (typeof msg.buildId !== "string" || msg.buildId !== KIWI_SOLVER_BUILD_ID) {
            if (!settled) { settled = true; worker.terminate(); teardown(); resolve({ mismatch: true }); }
            return;
          }
          settled = true;
          worker.terminate();
          teardown();
          resolve({ counter: msg.counter, duration: Math.round(performance.now() - workerStart) });
        } else if (msg.type === "failed") {
          if (typeof msg.reason !== "string") return;
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
  // Manual retry is a genuine native <button> (focusable, Enter/Space
  // activation built in) rendered in the error/unavailable states. It
  // triggers the SAME re-init path as the click/tap reacquire.
  function createRetryButton(W) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "kiwi-retry";
    b.setAttribute("data-kiwi-retry", "");
    b.textContent = "Retry";
    var bottom = W.querySelector(".kiwi-bottom");
    if (bottom) bottom.appendChild(b);
    else { var main = W.querySelector(".kiwi-main"); if (main) main.appendChild(b); else W.appendChild(b); }
    return b;
  }

  function initWidget(W) {
    if (!W || W.dataset.kiwiStarted || W.dataset.kiwiDestroyed) return;
    W.dataset.kiwiStarted = "1";
    // Round-13: no fixed DOM id. The driver locates elements by local
    // traversal only (closest/querySelector), so the removed
    // id="kiwicaptcha-root" has no dependencies; data-kiwi-instance is a
    // unique per-widget debugging marker, not a hook.
    if (!W.dataset.kiwiInstance) {
      W.dataset.kiwiInstance = "kiwi-" + (++kiwiInstanceCounter) + "-" + Math.random().toString(36).slice(2, 8);
    }
    // Neutral role: the widget is a passive status/group, never a
    // checkbox, and it is NOT focusable — the retry button is.
    if (!W.getAttribute("role")) W.setAttribute("role", "group");
    var container = W.closest(".kiwi-container") || W;
    var labelEl = W.querySelector("[data-kiwi-label]"), pillEl = W.querySelector("[data-kiwi-badge]"), fillEl = W.querySelector("[data-kiwi-bar]"), hintEl = W.querySelector("[data-kiwi-info]"), countdownEl = W.querySelector("[data-kiwi-timer]"), tokenEl = W.querySelector("[data-kiwi-token]") || container.querySelector("[data-kiwi-token]"), trackEl = W.querySelector(".kiwi-track");
    var announcerEl = W.querySelector("[data-kiwi-status]") || createAnnouncer(W);
    // The mascot is decorative next to the already-labelled widget: hide it
    // from assistive technology (round-13). Set defensively so renderers
    // that omit the attributes are still covered.
    var iconSvg = W.querySelector(".kiwi-icon-wrapper svg");
    if (iconSvg) { iconSvg.setAttribute("aria-hidden", "true"); iconSvg.setAttribute("focusable", "false"); }
    // Audit round 15: the kiwi wink is an SVG SMIL <animate> element — CSS
    // animation:none cannot stop SMIL, so reduced-motion users get the
    // animate element REMOVED (not merely paused) on init.
    if (iconSvg && window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      var smilWink = iconSvg.querySelector("animate");
      if (smilWink) smilWink.remove();
    }
    var retryEl = W.querySelector("[data-kiwi-retry]") || createRetryButton(W);
    var telemetry = telemetrySession(container, W);
    var scope = W.getAttribute("data-kiwi-scope") || container.getAttribute("data-kiwi-scope");
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
    function setStatus(label, pillText, state) {
      if (labelEl) labelEl.textContent = label;
      if (pillEl) pillEl.textContent = pillText;
      if (W) W.setAttribute("data-state", state);
    }
    function setHint(text) { if (hintEl) hintEl.textContent = text; }
    function setProgress(pct) {
      var clamped = Math.max(0, Math.min(100, pct));
      if (fillEl) fillEl.setAttribute("data-progress", String(clamped));
      /* Sync aria-valuenow on the progressbar role (WCAG 4.1.2). */
      if (trackEl) trackEl.setAttribute("aria-valuenow", String(clamped));
    }
    
    var countdownTimer = null;
    var retryCount = 0;
    var RETRY_LIMIT = 2;
    function startCountdown(ttlSecs) {
      var remaining = ttlSecs;
      var tick = function() { if (countdownEl) countdownEl.textContent = remaining > 0 ? remaining + "s" : "expired"; };
      tick(); clearInterval(countdownTimer);
      countdownTimer = setInterval(function() { remaining--; tick(); if (remaining <= 0) clearInterval(countdownTimer); }, 1000);
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
      telemetry.stop();
      // Round-13 blob cleanup: a pending worker object URL is revoked on
      // every reset/re-init path, not just on worker completion.
      if (kiwiActiveBlobUrl) { URL.revokeObjectURL(kiwiActiveBlobUrl); kiwiActiveBlobUrl = null; }
      if (tokenEl) tokenEl.value = "";
      setBinding("");
      if (countdownEl) countdownEl.textContent = "";
      setStatus("Security Check", "Idle", "idle");
      setHint("Protected");
      setProgress(0);
    }
    // Failure recovery (audit #55): an error never leaves the widget stuck
    // in "failed" — it resets to idle, retries a bounded number of times
    // with backoff, then settles idle and reacquires on the next
    // interaction (click the widget, the Retry button, or a page re-init).
    function fail(msg) {
      resetToIdle();
      announce("Verification failed");
      dispatch("error", { error: msg });
      if (retryCount < RETRY_LIMIT) {
        retryCount++;
        setHint("Challenge failed (" + msg + ") \u2014 retrying\u2026");
        setTimeout(run, 1000 * retryCount);
      } else {
        setHint("Challenge failed (" + msg + ") \u2014 click the widget to retry.");
        delete W.dataset.kiwiStarted;
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
      setStatus("Solver version mismatch", "Version Error", "kiwi:solver-mismatch");
      setHint("The solver worker is out of date \u2014 reload the page to load the current version.");
      setProgress(0);
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
      setStatus("Worker unavailable", "Unavailable", "kiwi:worker-unavailable");
      setHint("Worker unavailable \u2014 Argon2id needs a Web Worker that this page's CSP blocks; retry, or configure data-kiwi-worker-src.");
      setProgress(0);
      announce("Worker unavailable");
      dispatch("worker-unavailable", { reason: reason || "worker-creation-failed" });
      delete W.dataset.kiwiStarted;
    }
    // BFCache restore (audit #54): a persisted pageshow must NOT auto-solve —
    // it clears the solved state and leaves the widget idle, ready to
    // reacquire on the next interaction or page re-init.
    function reset() {
      resetToIdle();
      delete W.dataset.kiwiStarted;
    }
    kiwiResetHooks.push({ el: W, reset: reset });
    // The Retry button re-inits exactly like the click/tap reacquire path.
    if (retryEl && !retryEl.dataset.kiwiRetryBound) {
      retryEl.dataset.kiwiRetryBound = "1";
      kiwiAddListener(retryEl, "click", function () {
        if (W.dataset.kiwiStarted || W.dataset.kiwiDestroyed) return;
        delete W.dataset.kiwiStarted;
        initWidget(W);
      });
    }
    // destroy() teardown: idle the runtime state (countdown, telemetry,
    // blob URL, token) exactly like resetToIdle does.
    kiwiCleanups.set(W, function () { resetToIdle(); });

    async function run() {
      try {
        setStatus("Connecting\u2026", "Wait", "connecting");
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
        var timeoutAttr = W.getAttribute("data-kiwi-fetch-timeout-ms") || container.getAttribute("data-kiwi-fetch-timeout-ms") || "";
        var fetchTimeoutMs = parseInt(timeoutAttr, 10);
        if (!(fetchTimeoutMs > 0)) fetchTimeoutMs = KIWI_FETCH_TIMEOUT_MS;
        var abortController = new AbortController();
        var abortTimer = setTimeout(function () { abortController.abort(); }, fetchTimeoutMs);
        var resp, data;
        try {
          resp = await fetch(endpoint, { method:"POST", credentials:"same-origin", cache:"no-store", redirect:"error", referrerPolicy:"no-referrer", headers:{"Accept":"application/json","Content-Type":"application/json"}, body: JSON.stringify(reqBody), signal: abortController.signal });
          if (!resp.ok) throw new Error("Challenge failed");
          data = await resp.json();
        } finally {
          clearTimeout(abortTimer);
        }
        // No weaker challenge (audit #62): the response algorithm may only
        // be equal or stronger than requested — a server downgrade (argon2id
        // requested, sha256 returned) is a FAILED challenge, never a weaker
        // solve. The client may only ever accept what it asked for or more.
        if (algorithm === "argon2id" && (data.algorithm || "sha256") !== "argon2id") throw new Error("Challenge downgraded");
        if (data.ttlSecs) startCountdown(data.ttlSecs);
        setStatus("Verifying\u2026", "Working", "solving");
        announce("Checking\u2026");
        dispatch("verifying");
        var result = null;
        if ((data.algorithm || "sha256") === "argon2id") {
          // Round-13 invariant: memory-hard challenges ALWAYS run in the
          // same-origin worker. There is no synchronous CHUNK=1 fallback
          // and no weaker-profile retry — a missing or failed worker enters
          // the controlled kiwi:worker-unavailable state.
          result = await solveWithWorker(data, setProgress, container);
          if (result && result.mismatch) { solverMismatch(); return; }
          if (!result || result.unavailable) { workerUnavailable(result ? result.reason : "solve-failed"); return; }
        } else {
          result = await solve(data.prefix, b64decode(data.salt), data.targetBits, "sha256", data.mKib||0, data.t||1, data.p||1, setProgress);
        }
        if (!result) throw new Error("Exhausted");
        tokenEl.value = btoa(data.nonce + "." + result.counter + "." + result.duration + "." + JSON.stringify(telemetry.build()));
        setBinding(requestBinding || "");
        retryCount = 0;
        setStatus("Verified", "Success", "done"); setHint("Proof-of-work verified locally."); setProgress(100); clearInterval(countdownTimer); if (countdownEl) countdownEl.textContent = "";
        announce("Verification complete");
        dispatch("verified", { nonce: data.nonce });
        telemetry.stop();
      } catch (e) { fail(e.message); }
    }
    dispatch("ready");
    run();
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
      var cleanup = kiwiCleanups.get(W);
      if (cleanup) { try { cleanup(); } catch (err) {} kiwiCleanups.delete(W); }
      kiwiRemoveListeners(W);
      var retryEl = W.querySelector("[data-kiwi-retry]");
      if (retryEl) kiwiRemoveListeners(retryEl);
      delete W.dataset.kiwiStarted;
      W.removeAttribute("data-state");
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

  window.KiwiCaptcha = { init: initWidget, render: function(s) { document.querySelectorAll(s).forEach(initWidget); }, workerSource: KIWI_WORKER_SRC, buildId: KIWI_SOLVER_BUILD_ID, observe: kiwiObserve, destroy: kiwiDestroy };
  var runInit = function() {
    document.querySelectorAll("[data-kiwi-widget]").forEach(function (W) {
      // Click-to-reacquire: after a reset or a settled failure the widget
      // is idle and ready for a fresh challenge on the next interaction
      // (audit #54/#55). Bound once per element.
      if (!W.dataset.kiwiRetryBound) {
        W.dataset.kiwiRetryBound = "1";
        kiwiAddListener(W, "pointerdown", function () {
          if (!W.dataset.kiwiStarted) initWidget(W);
        });
      }
      initWidget(W);
    });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runInit); else runInit();
})();
