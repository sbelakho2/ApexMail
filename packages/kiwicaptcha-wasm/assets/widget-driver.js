(function() {
  var encoder = new TextEncoder();

  // ── Argon2id worker source (embedded) ───────────────────────────────
  // Same-origin Web Worker for the memory-hard Argon2id solver. The worker
  // must run off the main thread (each 64 MiB hash blocks the UI for tens of
  // ms). The worker source is embedded here as a string constant so the
  // driver can create the worker from a Blob URL (no network, same-origin by
  // construction); when the wasm glue is present as an inline <script> in
  // the page its source is prepended to the Blob, and the worker also tries
  // importScripts("kiwicaptacha-wasm.js") for file-based deployments
  // (data-kiwi-worker-src). Keep this literal EXACTLY in sync with
  // assets/kiwi-worker.js (the standalone asset); it must not contain
  // backticks, ${ or a closing-script-tag sequence (the driver is inlined
  // into pages by the renderers).
  var KIWI_WORKER_SRC = `(function () {
  "use strict";

  var loader = null;
  try { importScripts("kiwicaptacha-wasm.js"); } catch (e) {}
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
          post({ type: "done", counter: res });
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
            post({ type: "done", counter: res });
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
            post({ type: "done", counter: counter });
            return;
          }
        }
      }
      if (counter % 1000 === 0) post({ type: "progress", counter: counter });
    }
    free(w, pp, prefix.length); free(w, sp, salt.length);
    post({ type: "failed", reason: "exhausted" });
  }

  self.onmessage = function (ev) {
    var m = ev.data || {};
    if (m.type !== "solve") return;
    try {
      solveMessage(m);
    } catch (e) {
      post({ type: "failed", reason: "error: " + (e && e.message) });
    }
  };
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
      if (algorithm === "argon2id") {
        if (!w || !w.solve_argon2_chunk || !wasmAllocatorPresent() || m_kib < 8 * p) { resolve(null); return; }
        var argMax = Math.min(MAX_SHA_HASHES, Math.max(1024, expectedHashes * 8));
        // CHUNK = 1: each Argon2id hash is a single synchronous WASM call, so
        // the main thread yields between every memory-hard hash — at the
        // documented 64 MiB desktop profile, a batch of 16 would otherwise
        // block the UI for a noticeable period (responsiveness fix).
        // No pure-JS Argon2id fallback exists: an allocation failure means the
        // challenge cannot be solved (wasm is disabled permanently).
        if (!ensureBuffers()) { resolve(null); return; }
        function argon2Chunk() {
          try {
            var res = w.solve_argon2_chunk(pp, prefixBytes.length, sp, saltBytes.length, targetBits, m_kib, t, p, counter, CHUNK);
            if (res !== -1) { wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); resolve({ counter: res, duration: Math.round(performance.now() - solveStart) }); return; }
          } catch (e) { wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); console.error("KiwiCaptcha: Argon2 solve failed", e); resolve(null); return; }
          counter += CHUNK; if (counter >= argMax) { wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); resolve(null); return; }
          onProgress(Math.min(95, (counter * 100) / expectedHashes));
          fastYield(argon2Chunk);
        }
        fastYield(argon2Chunk); return;
      }
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
  // The memory-hard solver is moved off the main thread when possible: the
  // worker is constructed from a Blob URL built from local code (the
  // embedded KIWI_WORKER_SRC plus the inline wasm glue source), or from the
  // asset URL when data-kiwi-worker-src is set — never from a network URL.
  // If the worker cannot be created (no Worker support, CSP blocks Blob
  // workers) or the solve fails inside it, the driver falls back to the
  // synchronous chunked path (CHUNK=1), so behavior is unchanged in
  // restricted environments.
  function kiwiFindGlueSource() {
    // The renderers embed the wasm glue inline as a <script> before this
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
      if (typeof Worker === "undefined") { resolve(null); return; }
      var worker = null;
      try {
        var workerSrc = container.getAttribute("data-kiwi-worker-src");
        if (workerSrc) {
          worker = new Worker(workerSrc);
        } else {
          var glue = kiwiFindGlueSource();
          var blobSrc = (glue ? "var window = self;" + glue + "\n" : "") + KIWI_WORKER_SRC;
          worker = new Worker(URL.createObjectURL(new Blob([blobSrc], { type: "application/javascript" })));
        }
      } catch (e) { resolve(null); return; }
      if (!worker) { resolve(null); return; }
      window.__kiwiWorkerUsed = true;
      var workerStart = performance.now();
      var expectedHashes = Math.pow(2, data.targetBits);
      var settled = false;
      worker.onmessage = function(ev) {
        var msg = ev.data || {};
        if (msg.type === "progress") {
          onProgress(Math.min(95, (msg.counter * 100) / expectedHashes));
        } else if (msg.type === "done") {
          settled = true;
          worker.terminate();
          resolve({ counter: msg.counter, duration: Math.round(performance.now() - workerStart) });
        } else if (msg.type === "failed") {
          settled = true;
          worker.terminate();
          console.error("KiwiCaptcha worker failed:", msg.reason);
          resolve(null);
        }
      };
      worker.onerror = function(ev) {
        if (settled) return;
        settled = true;
        worker.terminate();
        console.error("KiwiCaptcha worker error:", ev && ev.message, ev && ev.filename, ev && ev.lineno);
        resolve(null);
      };
      var prefixBytes = encoder.encode(data.prefix);
      var saltBytes = b64decode(data.salt);
      try {
        worker.postMessage({
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
        if (!settled) { settled = true; worker.terminate(); resolve(null); }
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

  function initWidget(W) {
    if (!W || W.dataset.kiwiStarted) return;
    W.dataset.kiwiStarted = "1";
    var container = W.closest(".kiwi-container") || W;
    var statusEl = W.querySelector("[data-kiwi-label]"), pillEl = W.querySelector("[data-kiwi-badge]"), fillEl = W.querySelector("[data-kiwi-bar]"), hintEl = W.querySelector("[data-kiwi-info]"), countdownEl = W.querySelector("[data-kiwi-timer]"), tokenEl = W.querySelector("[data-kiwi-token]") || container.querySelector("[data-kiwi-token]"), trackEl = W.querySelector(".kiwi-track");
    var telemetry = telemetrySession(container, W);
    function setStatus(label, pillText, state) {
      if (statusEl) statusEl.textContent = label;
      if (pillEl) pillEl.textContent = pillText;
      if (W) {
        W.setAttribute("data-state", state);
        /* Sync ARIA checkbox state for screen readers (industry standard). */
        if (state === "done") { W.setAttribute("aria-checked", "true"); W.setAttribute("role", "checkbox"); }
        else { W.setAttribute("aria-checked", "false"); }
        /* Errors get assertive announcement (role=alert); everything else polite. */
        if (state === "failed") { W.setAttribute("role", "alert"); W.setAttribute("aria-live", "assertive"); }
        else { W.setAttribute("role", "checkbox"); W.setAttribute("aria-live", "polite"); }
      }
    }
    function setHint(text) { if (hintEl) hintEl.textContent = text; }
    function setProgress(pct) {
      var clamped = Math.max(0, Math.min(100, pct));
      if (fillEl) fillEl.setAttribute("data-progress", String(clamped));
      /* Sync aria-valuenow on the progressbar role (WCAG 4.1.2). */
      if (trackEl) trackEl.setAttribute("aria-valuenow", String(clamped));
    }
    
    var countdownTimer = null;
    function startCountdown(ttlSecs) {
      var remaining = ttlSecs;
      var tick = function() { if (countdownEl) countdownEl.textContent = remaining > 0 ? remaining + "s" : "expired"; };
      tick(); clearInterval(countdownTimer);
      countdownTimer = setInterval(function() { remaining--; tick(); if (remaining <= 0) clearInterval(countdownTimer); }, 1000);
    }
    function fail(msg) { setStatus(msg || "Failed", "Error", "failed"); setHint("Please reload to retry."); setProgress(0); if (tokenEl) tokenEl.value = ""; clearInterval(countdownTimer); telemetry.stop(); }

    async function run() {
      try {
        setStatus("Connecting\u2026", "Wait", "connecting");
        var endpoint = kiwiEndpoint(W.getAttribute("data-kiwi-endpoint") || container.getAttribute("data-kiwi-endpoint") || "/api/kcaptcha/challenge");
        var scope = W.getAttribute("data-kiwi-scope") || container.getAttribute("data-kiwi-scope");
        if (!scope) {
          scope = "login";
          var p = window.location.pathname.toLowerCase();
          if (p.indexOf("signup")>=0||p.indexOf("register")>=0) scope="signup";
          else if (p.indexOf("forgot")>=0) scope="forgot-password";
        }
        var algorithm = W.getAttribute("data-kiwi-algorithm") || container.getAttribute("data-kiwi-algorithm") || "sha256";
        var reqBody = { scope: scope };
        if (algorithm !== "sha256") reqBody.algorithm = algorithm;
        var resp = await fetch(endpoint, { method:"POST", credentials:"same-origin", cache:"no-store", referrerPolicy:"no-referrer", headers:{"Accept":"application/json","Content-Type":"application/json"}, body: JSON.stringify(reqBody) });
        if (!resp.ok) throw new Error("Challenge failed");
        var data = await resp.json();
        if (data.ttlSecs) startCountdown(data.ttlSecs);
        setStatus("Verifying\u2026", "Working", "solving");
        var result = null;
        if ((data.algorithm || "sha256") === "argon2id") {
          // Memory-hard challenges run in a same-origin worker when
          // available; the synchronous CHUNK=1 path is the fallback.
          result = await solveWithWorker(data, setProgress, container);
          if (!result) result = await solve(data.prefix, b64decode(data.salt), data.targetBits, "argon2id", data.mKib||0, data.t||1, data.p||1, setProgress);
        } else {
          result = await solve(data.prefix, b64decode(data.salt), data.targetBits, "sha256", data.mKib||0, data.t||1, data.p||1, setProgress);
        }
        if (!result) throw new Error("Exhausted");
        tokenEl.value = btoa(data.nonce + "." + result.counter + "." + result.duration + "." + JSON.stringify(telemetry.build()));
        setStatus("Verified", "Success", "done"); setHint("Proof-of-work verified locally."); setProgress(100); clearInterval(countdownTimer); if (countdownEl) countdownEl.textContent = "";
        telemetry.stop();
      } catch (e) { fail(e.message); }
    }
    run();
  }

  window.KiwiCaptcha = { init: initWidget, render: function(s) { document.querySelectorAll(s).forEach(initWidget); }, workerSource: KIWI_WORKER_SRC };
  var runInit = function() { document.querySelectorAll("[data-kiwi-widget]").forEach(initWidget); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runInit); else runInit();
})();
