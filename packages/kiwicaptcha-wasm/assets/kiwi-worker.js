/* KiwiCaptcha worker solver — standalone same-origin asset.
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
 *   out: { type: "ready", buildId } on startup (solver protocol id)
 *        { type: "progress", counter } every 1000 hashes
 *        { type: "done", counter, buildId }  |  { type: "failed", reason }
 *
 * SHA-256 is solved via the wasm exports (solve_sha256_chunk) with a
 * pure-JS SHA-256 fallback; Argon2id is solved via solve_argon2_chunk (the
 * same wasm the main thread uses — no pure-JS Argon2 exists).
 */
(function () {
  "use strict";

  // Solver PROTOCOL id: a compatibility/ABI generation LABEL reported
  // in the handshake for debugging. MUST equal the widget driver's
  // KIWI_SOLVER_PROTOCOL_ID constant. The ENFORCED check is the numeric
  // protocol version against the wasm glue's exported
  // solver_protocol_version() (verified below BEFORE ready). Together
  // they prove driver+worker+wasm speak the same protocol generation —
  // exact artifact identity is guaranteed by the release tag +
  // SHA256SUMS + SRI + attestation, not by these values.
  var KIWI_SOLVER_PROTOCOL_ID = "2026-08-r1";
  var KIWI_SOLVER_PROTOCOL_VERSION = 1;

  // The wasm glue exposes itself as `window.__kiwiCaptchaWasm`, so the
  // worker establishes the `window` alias (same prelude the widget driver
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
  // plain number (an integer needs no decode). Any failure returns null
  // (fail closed).
  function wasmProtocolVersion(w) {
    if (!w || typeof w.solver_protocol_version !== "function") return null;
    try {
      var v = w.solver_protocol_version();
      return typeof v === "number" ? v : null;
    } catch (e) {
      return null;
    }
  }

  // Startup handshake: BEFORE any solve work,
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
