(function() {
  var encoder = new TextEncoder();

  // ── Solver PROTOCOL id ──
  // A protocol/ABI generation label, bumped when the solver protocol or
  // worker contract changes. The worker reports the SAME id in its
  // handshakes AND verifies the glue's solver_protocol_id() before ready;
  // the driver refuses any worker whose id differs (a stale cached worker
  // must never contribute). Protocol compatibility ONLY: exact-artifact
  // identity is the release tag + SHA256SUMS + SRI + attestation.
  var KIWI_SOLVER_PROTOCOL_ID = "2026-09-r1";

  // ── Challenge fetch timeout ──
  // A hung endpoint must never wedge the widget: the fetch carries an
  // AbortController aborting after this many ms into the controlled
  // error state. data-kiwi-fetch-timeout-ms overrides per widget.
  var KIWI_FETCH_TIMEOUT_MS = 15000;

  // ── Solve deadline margin ──
  // The solver stops at (expiry estimate − this margin): a solve that
  // would outlive the challenge is waste. 500 ms covers the final chunk
  // and token-write path; only over-long solves truncate.
  var KIWI_SOLVE_DEADLINE_MARGIN_MS = 500;

  // ── Abandonment-notify cooldown ──
  // The cancellation notification is rate-limited per widget: once per
  // nonce plus this window, so a retry loop never spams the endpoint.
  var KIWI_CANCEL_COOLDOWN_MS = 5000;

  // ── Argon2id / rsw worker source (carried by the wasm glue) ──
  // The worker runs off the main thread (each 64 MiB hash blocks the UI).
  // Its source is NOT embedded here: the glue carries the identical
  // bytes as window.__kiwiCaptchaWasm.workerSource, GENERATED from
  // assets/kiwi-worker.js by the kiwicaptcha-embed-worker tool (CI
  // --check fails on drift). Inline mode reads the copy off the glue;
  // files mode fetches the versioned worker.<hash>.js asset. The worker
  // must not contain a closing-script-tag sequence (the glue is inlined);
  // the generator rejects one.
  function kiwiWorkerSourceFromGlue(glueText) {
    if (!glueText) return null;
    // The glue's generated section assigns the worker source as a single
    // JSON string literal; the match is deterministic for our own format.
    var m = glueText.match(/workerSource\s*=\s*"((?:[^"\\]|\\.)*)"/);
    if (!m) return null;
    try { return JSON.parse('"' + m[1] + '"'); } catch (e) { return null; }
  }
  function kiwiEmbeddedWorkerSource() {
    var g = (typeof window !== "undefined" && window.__kiwiCaptchaWasm && typeof window.__kiwiCaptchaWasm.workerSource === "string")
      ? window.__kiwiCaptchaWasm.workerSource
      : null;
    if (g) return g;
    // The glue's page object may be absent (compat loader: the glue is
    // fetched, never executed on the page) — extract the bytes from the
    // glue text; kiwiFindGlueSource / kiwiCompatGlueValue resolve lazily.
    return kiwiWorkerSourceFromGlue(kiwiFindGlueSource() || kiwiCompatGlueValue());
  }

  // ── Optimized yielding ───────────────────────────────────
  var channel = new MessageChannel();
  var yieldQueue = [];
  channel.port1.onmessage = function() { if (yieldQueue.length) yieldQueue.shift()(); };
  function fastYield(fn) { yieldQueue.push(fn); channel.port2.postMessage(0); }

  // ── WASM solver ──────────────────────────────────────────
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
  // Copy bytes into wasm memory (explicit alloc/free: the raw-
  // pointer ABI avoids wasm-bindgen's Vec/slice glue). Uses the
  // crate's own `alloc`/`dealloc` exports (stable names, never DCE'd
  // by wasm-opt), falling back to wasm-bindgen's generated symbols
  // when present. The Rust `alloc` returns null (0) on allocation
  // failure: callers MUST check for it and fall back to the pure-JS
  // solver path.
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

  // ── Optimized synchronous SHA-256 (pure JS, recycled buffers) ─
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
  // ── Time-budgeted SHA chunks ──────
  // Each chunk runs hashes until approximately this much wall time has
  // elapsed (the wasm solver enforces the same budget inside its loop
  // and reports partial progress; the pure-JS fallback checks
  // performance.now()). The synchronous work per yield is bounded by
  // wall time (~8-12 ms), never by a hash count, and CHUNK stays the
  // absolute max hashes per call (the hard bound alongside
  // MAX_SHA_HASHES).
  var SHA_CHUNK_TIME_BUDGET_MS = 10;
  function solve(prefix, saltBytes, targetBits, algorithm, m_kib, t, p, onProgress, deadline) {
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
      // This function ONLY ever solves SHA-256. Argon2id is memory-hard
      // and must run in the same-origin worker; the main thread NEVER runs
      // an Argon2 hash. The argon2id path in run() routes a missing/failed
      // worker to the controlled kiwi:worker-unavailable state instead of
      // ever calling solve() for a memory-hard challenge.
      var useWasm = wasmUsable();
      var CHUNK = useWasm ? 50000 : 8000;
      function chunk() {
        // The solve deadline (challenge expiry − margin): abort BETWEEN
        // chunks — a solve that would outlive the challenge is pure waste
        // and the token would be rejected anyway. The driver's retry flow
        // re-acquires a fresh challenge.
        if (deadline && performance.now() >= deadline) { resolve({ deadline: true }); return; }
        if (useWasm) {
          try {
            if (ensureBuffers()) {
              var res = w.solve_sha256_chunk(pp, prefixBytes.length, sp, saltBytes.length, targetBits, counter, CHUNK);
              if (res >= 0) { wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); resolve({ counter: res, duration: Math.round(performance.now() - solveStart) }); return; }
              // -1 = the whole CHUNK window was scanned; -(scanned + 1)
              // = the time budget elapsed after `scanned` hashes. Both
              // resume at the exact next counter, never skipping work.
              counter += res === -1 ? CHUNK : -res - 1;
            } else {
              // Allocation failed: wasm is disabled permanently — fall back to JS.
              console.warn("KiwiCaptcha: WASM allocation failed, disabling WASM and falling back to JS");
              useWasm = false;
            }
          } catch (e) { wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); console.error("KiwiCaptcha: WASM solve failed, falling back to JS", e); useWasm = false; }
        }
        if (!useWasm) {
          var end = Math.min(counter + CHUNK, MAX_SHA_HASHES);
          var chunkStart = performance.now();
          var inChunk = 0;
          for (; counter < end; counter++, inChunk++) {
            if (leadingZeros(deriveHash(prefixBytes, counter, saltBytes)) >= targetBits) {
              resolve({ counter: counter, duration: Math.round(performance.now() - solveStart) }); return;
            }
            if ((inChunk & 255) === 0 && performance.now() - chunkStart >= SHA_CHUNK_TIME_BUDGET_MS) break;
          }
        }
        if (counter >= MAX_SHA_HASHES) { resolve(null); return; }
        onProgress(Math.min(92, (counter * 100) / expectedHashes));
        fastYield(chunk);
      }
      fastYield(chunk);
    });
  }

  // ── Same-origin Argon2id/rsw Web Worker ──
  // Memory-hard (argon2id) and time-lock (rsw) solves run ONLY in the
  // same-origin worker, never on the main thread; a missing or failed
  // worker enters the controlled kiwi:worker-unavailable state with no
  // weaker-profile retry. The worker machinery lives in the lazy
  // widget-risk.js module (loaded when a memory-hard challenge arrives);
  // the core keeps only the glue/worker-source extraction helpers below.
  // postMessage BOUNDARY: the driver never posts to the parent page; all
  // postMessage is worker-internal (solve traffic, the MessageChannel
  // yield, the sandboxed execution iframe run by widget-risk.js). The
  // single window message listener accepts only messages whose
  // event.source is that iframe's contentWindow and whose per-run id
  // matches, so forged page traffic is ignored.
  var kiwiInstanceCounter = 0;
  function kiwiFindGlueSource() {
    // The renderers embed the wasm glue inline before this driver; its
    // source contains the "var KIWI_WASM_B64" assignment — the unique
    // marker, deliberately the assignment form, so an inlined driver copy
    // can never be mistaken for the glue. The glue is a self-contained
    // IIFE, so its text can run inside the worker with a `var window =
    // self` prelude to expose self.__kiwiCaptchaWasm.
    try {
      var scripts = document.scripts || [];
      for (var i = 0; i < scripts.length; i++) {
        var text = scripts[i].textContent || "";
        if (text.indexOf("var KIWI_WASM_B64") !== -1 && text.indexOf("__kiwiCaptchaWasm") !== -1) {
          return text;
        }
      }
    } catch (e) {}
    return null;
  }



  // ── Same-origin enforcement ──
  // The challenge endpoint must resolve to the page's own origin — a
  // cross-origin endpoint would leak the scope and solve behavior to a
  // third party, so it is refused outright.
  function kiwiEndpoint(raw) {
    var url = new URL(raw, window.location.href);
    if (url.origin !== window.location.origin) {
      throw new Error("KiwiCaptcha refuses cross-origin challenge endpoints");
    }
    return url.href;
  }

  // ── Challenge response schema validation ──
  // The same-origin endpoint's bytes are untrusted, so the widget only
  // solves a well-formed issuance: sha256|argon2id|rsw, non-empty
  // nonce/prefix/salt (base64), targetBits an integer in the issuance
  // ceiling (sha256/rsw 1..20, argon2id 1..10), argon2id parameters in
  // range (t 3..6, p 1, mKib 8*p..65536), ttlSecs 1..300, and for rsw a
  // base64 modulus of exactly 256 bytes with the sequential cost T in
  // the t slot (10,000..300,000). A malformed response is a
  // challenge-content failure entering the bounded-retry state, so a
  // forged targetBits-0 response can never be "solved" and an
  // out-of-contract ceiling can never burn the CPU budget.
  function kiwiValidateChallenge(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Challenge malformed");
    var alg = data.algorithm === undefined ? "sha256" : data.algorithm;
    if (alg !== "sha256" && alg !== "argon2id" && alg !== "rsw") throw new Error("Challenge malformed");
    if (typeof data.nonce !== "string" || data.nonce.length < 1) throw new Error("Challenge malformed");
    if (typeof data.prefix !== "string" || data.prefix.length < 1) throw new Error("Challenge malformed");
    if (typeof data.salt !== "string" || data.salt.length < 1) throw new Error("Challenge malformed");
    try {
      var saltBytes = b64decode(data.salt);
    } catch (e) {
      throw new Error("Challenge malformed");
    }
    if (!saltBytes || saltBytes.length < 1) throw new Error("Challenge malformed");
    var targetBits = data.targetBits;
    if (typeof targetBits !== "number" || !isFinite(targetBits) || Math.floor(targetBits) !== targetBits) throw new Error("Challenge malformed");
    if (targetBits < 1 || targetBits > (alg === "argon2id" ? 10 : 20)) throw new Error("Challenge malformed");
    if (alg === "argon2id") {
      var mKib = data.mKib, t = data.t, p = data.p;
      if (typeof mKib !== "number" || !isFinite(mKib) || Math.floor(mKib) !== mKib || mKib < 8) throw new Error("Challenge malformed");
      if (mKib > 65536) throw new Error("Challenge malformed");
      if (typeof t !== "number" || !isFinite(t) || Math.floor(t) !== t || t < 3 || t > 6) throw new Error("Challenge malformed");
      if (typeof p !== "number" || !isFinite(p) || Math.floor(p) !== p || p !== 1) throw new Error("Challenge malformed");
      if (mKib < 8 * p) throw new Error("Challenge malformed");
    }
    if (alg === "rsw") {
      // The rsw contract: the base64 modulus decodes to exactly 256
      // bytes (the 2048-bit composite), and the sequential cost T rides
      // the time-cost slot within the issuance range. The pinned
      // target_bits (1) passes the uniform gate above and is never
      // consulted by the solver.
      var rswT = data.t, rswP = data.p, rswM = data.mKib;
      if (typeof rswT !== "number" || !isFinite(rswT) || Math.floor(rswT) !== rswT || rswT < 10000 || rswT > 300000) throw new Error("Challenge malformed");
      if (typeof rswP !== "number" || rswP !== 1) throw new Error("Challenge malformed");
      if (typeof rswM !== "number" || rswM !== 0) throw new Error("Challenge malformed");
      if (typeof data.rsw_modulus !== "string" || data.rsw_modulus.length < 1) throw new Error("Challenge malformed");
      try {
        var rswBytes = b64decode(data.rsw_modulus);
        if (!rswBytes || rswBytes.length !== 256) throw new Error("Challenge malformed");
      } catch (e) {
        throw new Error("Challenge malformed");
      }
    }
    if (data.ttlSecs !== undefined && (typeof data.ttlSecs !== "number" || !isFinite(data.ttlSecs) || Math.floor(data.ttlSecs) !== data.ttlSecs || data.ttlSecs < 1 || data.ttlSecs > 300)) throw new Error("Challenge malformed");
    // The optional ExecutionChallengeV1 program (base64): bounded,
    // non-empty, standard base64. When present the driver must run it —
    // a malformed program is a challenge-content failure, never a solve.
    if (data.execution_program !== undefined) {
      if (typeof data.execution_program !== "string" || data.execution_program.length < 1 || data.execution_program.length > 4096) throw new Error("Challenge malformed");
      try {
        var execBytes = b64decode(data.execution_program);
        if (!execBytes || execBytes.length < 8) throw new Error("Challenge malformed");
      } catch (e) {
        throw new Error("Challenge malformed");
      }
    }
  }

  // ── Accessibility helpers ──
  // The role="status" announcer (data-kiwi-status) is the ONLY
  // aria-live traffic: no checkbox semantics (an auto-solving proof of
  // work is not a checkbox), and only meaningful transitions are
  // announced; countdown/progress stay strictly visual.
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
  // ── Localization (WCAG 3.1.2) ──
  // `lang` is a first-class option (options.lang / data-kiwi-lang /
  // navigator.language in that order); the resolved language is written
  // onto the widget subtree (dir for RTL packs) and the untranslated
  // fallback stays English, marked lang="en".
  //
  // The eager core ships only the English pack and the fallback path;
  // the other packs (de, fr, es, it, nl, pl, pt, ar) live in the lazy
  // widget-locales.js module, loaded once per page only when a widget's
  // resolved language is non-default. A null placeholder per language
  // keeps resolution synchronous: a widget whose pack is pending paints
  // the English fallback and re-paints when the module registers.
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
    // The lazy widget-locales.js module fills these placeholders with
    // the same language codes it ships.
    de: null, fr: null, es: null, it: null, nl: null, pl: null, pt: null, ar: null
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
      if (kiwiLocalePacks[base] !== undefined) return base;
    }
    return kiwiFallbackLang;
  }
  function kiwiPackFor(lang) { return kiwiLocalePacks[lang] || kiwiLocalePacks[kiwiFallbackLang]; }
  // The lazy widget-locales.js module's packs land here through the
  // bridge (first-wins, so a duplicate execution cannot overwrite
  // live packs).
  function kiwiAddLocalePacks(packs) {
    if (!packs || typeof packs !== "object") return;
    for (var k in packs) {
      if (packs[k] && typeof packs[k] === "object" && !kiwiLocalePacks[k]) kiwiLocalePacks[k] = packs[k];
    }
  }
  // Integrator callbacks must be observable — an exception is rethrown
  // on a microtask (never corrupting Kiwi's own lifecycle, never
  // double-invoking) so migration failures are diagnosable in the
  // console.
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

  // Per-widget generation + cancellation handles. Every async
  // continuation (fetch, worker, retry, expiry) captures the generation
  // it started under and refuses to touch state once the generation is
  // no longer current; reset()/remove()/destroy() bump the generation
  // and abort/terminate/clear the handles, so a stale generation can
  // never write a token, invoke a callback or flip state.
  var kiwiWidgets = {}; // widgetId -> {W, options, state, token, gen, abortController, abortTimer, worker, retryTimer, countdownTimer, expiryTimer, errorFired, responseKey, start}
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
    // No fixed DOM id. The driver locates elements by local traversal
    // only (closest/querySelector); data-kiwi-instance is a unique
    // per-widget debugging marker, not a hook.
    if (!W.dataset.kiwiInstance) {
      W.dataset.kiwiInstance = "kiwi-" + (++kiwiInstanceCounter) + "-" + Math.random().toString(36).slice(2, 8);
    }
    // Formal widget instances — widgetId == data-kiwi-instance.
    var widgetId = W.dataset.kiwiInstance;
    // The generation counter MUST CONTINUE across re-inits — a restart
    // at 1 would let a stale in-flight run look current again after a
    // reset cancelled it.
    var prevRecord = kiwiWidgets[widgetId];
    var newGen = prevRecord ? prevRecord.gen + 1 : 1;
    // The decoy state is PRIVATE per widget (never on the DOM): the
    // authenticated name, the deferred flag, the strategy/wrapper-class
    // picks and the owned decoy nodes. It SURVIVES re-inits (an
    // expiry-triggered re-solve must still see a filled decoy), carried
    // over from the previous record.
    var decoyState = (prevRecord && prevRecord.decoyState) ? prevRecord.decoyState : { name: null, deferred: false, nodes: [], className: null, variant: null };
    kiwiWidgets[widgetId] = { W: W, options: options, state: "solving", token: "", gen: newGen, abortController: null, abortTimer: null, worker: null, retryTimer: null, countdownTimer: null, expiryTimer: null, errorFired: false, responseKey: "hkey-" + Math.random().toString(36).slice(2, 10), start: null, decoyState: decoyState };
    // Neutral role: the widget is a passive status/group — not a
    // checkbox and not focusable; the retry button is. Compatibility
    // wrappers stay semantically neutral: role/lang/dir/name belong on
    // the visible widget root, never on the provider wrapper.
    var compatInnerWidget = W.querySelector && W !== (W.querySelector("[data-kiwi-widget]") || W) ? W.querySelector("[data-kiwi-widget]") : null;
    var a11yRoot = compatInnerWidget || W;
    if (!compatInnerWidget && !W.getAttribute("role")) W.setAttribute("role", "group");
    var container = W.closest(".kiwi-container") || W;
    // The accessible group name is the translated label string — the
    // markup's static aria-label is replaced at init with the resolved
    // locale, so the name can never diverge from the visible UI language.
    var kiwiWidgetRoot = W;
    // Resolve the language and write it onto the widget subtree (lang +
    // dir for RTL packs): options.lang -> data-kiwi-lang on the widget /
    // container -> navigator.language; the untranslated fallback is
    // explicitly lang="en". document.currentScript is NULL during async
    // init, so the attribute is read from the subtree.
    var kiwiLangAttr = (W.getAttribute ? W.getAttribute("data-kiwi-lang") : null)
      || (container && container.getAttribute ? container.getAttribute("data-kiwi-lang") : null);
    // Precedence: instance overrides -> provider language (Turnstile
    // language) -> loader hl= -> navigator.language -> English.
    var kiwiProviderLang = options && options.language ? String(options.language) : null;
    var kiwiWidgetLang = kiwiResolveLang({
      lang: (options && options.lang) || kiwiLangAttr || kiwiProviderLang || undefined
    });
    // The pack is English while a non-default pack is pending; the
    // subtree lang mirrors what is on screen: the resolved language once
    // registered, else lang="en" for the fallback.
    var kiwiWidgetPack = kiwiPackFor(kiwiWidgetLang);
    var kiwiLangMark = (kiwiWidgetLang === kiwiFallbackLang || kiwiLocalePacks[kiwiWidgetLang]) ? kiwiWidgetLang : kiwiFallbackLang;
    a11yRoot.setAttribute("lang", kiwiLangMark);
    if (kiwiWidgetPack.dir) a11yRoot.setAttribute("dir", kiwiWidgetPack.dir);
    // The accessible group name is the translated label string.
    a11yRoot.setAttribute("aria-label", kiwiWidgetPack.label);
    function kiwiT(key) { return (kiwiWidgetPack[key] !== undefined) ? kiwiWidgetPack[key] : kiwiLocalePacks[kiwiFallbackLang][key] || key; }
    var labelEl = W.querySelector("[data-kiwi-label]"), pillEl = W.querySelector("[data-kiwi-badge]"), fillEl = W.querySelector("[data-kiwi-bar]"), hintEl = W.querySelector("[data-kiwi-info]"), countdownEl = W.querySelector("[data-kiwi-timer]"), tokenEl = W.querySelector("[data-kiwi-token]") || container.querySelector("[data-kiwi-token]"), trackEl = W.querySelector(".kiwi-track");
    var announcerEl = W.querySelector("[data-kiwi-status]") || createAnnouncer(W);
    // The mascot is decorative next to the already-labelled widget:
    // hide it from assistive technology, defensively.
    var iconSvg = W.querySelector(".kiwi-icon-wrapper svg");
    if (iconSvg) { iconSvg.setAttribute("aria-hidden", "true"); iconSvg.setAttribute("focusable", "false"); }
    // The wink is an SVG SMIL <animate>: CSS animation:none cannot stop
    // SMIL, so reduced-motion users get the element REMOVED on init, and
    // a matchMedia change listener also removes it when the OS setting
    // flips (a removed wink stays removed).
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
    // Privacy-aware telemetry (widget-local, mode-gated): the session
    // machinery lives in the lazy widget-telemetry.js module; an "off"
    // widget (the default) never loads it and the stub embeds the empty
    // "{}" blob like the historical eager session. An enabled mode
    // starts the load OPPORTUNISTICALLY at init, but the flow NEVER
    // awaits it (audit finding 1): telemetry is opt-in evidence, never a
    // gate. The session attaches only if the module registers BEFORE
    // this generation's request went out (requestSent); otherwise this
    // generation solves with the empty stub — never a half-session.
    var telemetryMode = "off";
    if (W) telemetryMode = W.getAttribute("data-kiwi-telemetry") || telemetryMode;
    if (container && container !== W) telemetryMode = container.getAttribute("data-kiwi-telemetry") || telemetryMode;
    if (telemetryMode !== "minimal" && telemetryMode !== "full") telemetryMode = "off";
    var requestSent = false;
    var kiwiTelemetrySession = null;
    if (telemetryMode !== "off") {
      kiwiEnsureModule("telemetry", container, W).then(function (module) {
        if (!kiwiGenerationCurrent(widgetId, newGen)) return;
        if (requestSent) return;
        if (module && module.create) kiwiTelemetrySession = module.create(container, W, telemetryMode);
      });
    }
    var telemetry = {
      build: function () { return kiwiTelemetrySession ? kiwiTelemetrySession.build() : {}; },
      stop: function () { if (kiwiTelemetrySession) kiwiTelemetrySession.stop(); }
    };
    // options.scope is AUTHORITATIVE: the compatibility loader passes
    // the data-sitekey as the scope and the server maps it through the
    // allowlist; DOM/path heuristics overriding it would silently
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
    // Lifecycle events: kiwi:ready | kiwi:verifying | kiwi:verified |
    // kiwi:error | kiwi:worker-unavailable, dispatched on the widget
    // element, bubbling, not cancelable, detail {scope, ...}.
    function dispatch(name, detail) {
      var ev = new CustomEvent("kiwi:" + name, {
        bubbles: true,
        cancelable: false,
        detail: Object.assign({ scope: scope }, detail || {})
      });
      W.dispatchEvent(ev);
    }
    function announce(text) { if (announcerEl) announcerEl.textContent = text; }
    // The state attribute belongs on the VISIBLE .kiwi-widget — the
    // stylesheet keys the pulse/success/failure styling and the Retry
    // button visibility on .kiwi-widget[data-state=...]. When initWidget's
    // W is a provider wrapper (.g-recaptcha/.h-captcha/.cf-turnstile),
    // target the inner widget element.
    var stateEl = (W.matches && W.matches(".kiwi-widget"))
      ? W
      : (W.querySelector ? W.querySelector("[data-kiwi-widget]") || W : W);
    // ── Semantic display-state view model ──
    // The visible state is ONE view object {statusKey, badgeKey,
    // domState, hintKey, replacements} set by kiwiSetView() and rendered
    // by kiwiPaintView(); every legacy status/hint write funnels through
    // it, so the painted DOM always matches the recorded view and a late
    // language settlement repaints exactly the CURRENT state. hintKey is
    // optional; replacements expand {placeholder} spans with kiwiT().
    function kiwiExpandView(tpl, replacements) {
      if (!tpl || !replacements) return tpl;
      for (var k in replacements) {
        if (Object.prototype.hasOwnProperty.call(replacements, k) && typeof replacements[k] === "string") {
          tpl = tpl.split("{" + k + "}").join(replacements[k]);
        }
      }
      return tpl;
    }
    var view = null;
    function kiwiSetView(v) {
      view = v;
      kiwiPaintView();
    }
    function kiwiPaintView() {
      var v = view;
      if (!v || !v.statusKey) return;
      if (labelEl) labelEl.textContent = kiwiT(v.statusKey);
      if (pillEl) pillEl.textContent = kiwiT(v.badgeKey);
      if (stateEl) stateEl.setAttribute("data-state", v.domState);
      if (v.hintKey && hintEl) hintEl.textContent = kiwiExpandView(kiwiT(v.hintKey), v.replacements);
      if (retryEl) retryEl.textContent = kiwiWidgetPack.retryButton;
    }
    // Paint the resolved language immediately: the static template is
    // English until the driver runs; the fallback stays marked lang="en"
    // until localized.
    kiwiSetView({ statusKey: "label", badgeKey: "badgeIdle", domState: "idle", hintKey: "hintProtected" });
    // Explicit-execution mode (Turnstile execution: "execute"): the
    // widget is rendered and registered but the challenge does NOT start
    // until execute(). "pending" is distinct from "idle": idle means
    // ready for MANUAL reacquisition after a credential existed; pending
    // means the challenge has never run and waits for execute().
    var deferredExecution = (options && options.execution === "execute")
      || (W.getAttribute ? W.getAttribute("data-execution") === "execute" : false);
    if (deferredExecution) {
      kiwiRecordState("pending", "");
      kiwiSetView({ statusKey: "label", badgeKey: "badgeIdle", domState: "pending", hintKey: "hintProtected" });
    }
    // Lazy non-default locale packs (WCAG 3.1.2): a widget whose pack is
    // not registered loads widget-locales.js here (the loader dedups).
    // Settlement is a pure language swap repainting the CURRENT view.
    // The flow NEVER awaits the module: run() proceeds immediately with
    // the English fallback and a late pack repaints whatever state is
    // current. A failed module keeps English (lang="en"), warns; a
    // translation is never a gate.
    if (kiwiWidgetLang !== kiwiFallbackLang && !kiwiLocalePacks[kiwiWidgetLang]) {
      var kiwiLocalesAttrs = kiwiModuleAssetAttrs("locales", container, W);
      function kiwiApplyLangSettled() {
        kiwiWidgetPack = kiwiPackFor(kiwiWidgetLang);
        a11yRoot.setAttribute("lang", kiwiWidgetLang);
        if (kiwiWidgetPack.dir) a11yRoot.setAttribute("dir", kiwiWidgetPack.dir);
        a11yRoot.setAttribute("aria-label", kiwiWidgetPack.label);
        kiwiPaintView();
      }
      kiwiEnsureModule("locales", container, W).then(function () {
        if (!kiwiGenerationCurrent(widgetId, newGen)) return;
        if (kiwiLocalePacks[kiwiWidgetLang]) {
          kiwiApplyLangSettled();
        } else if (!kiwiLocalesAttrs) {
          console.warn("KiwiCaptcha: language \"" + kiwiWidgetLang + "\" needs the lazy widget-locales.js module, but the page issued no data-kiwi-locales-src asset; using English");
        }
      });
    }
    function setProgress(pct) {
      if (!fillEl || W.dataset.kiwiDestroyed) return;
      var clamped = Math.max(0, Math.min(100, pct));
      fillEl.setAttribute("data-progress", String(clamped));
    }
    
    var countdownTimer = null;
    var retryCount = 0;
    var RETRY_LIMIT = 2;
    // Widget-instance state helpers (provider-facing lifecycle).
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
      // The expired view keeps the solved-state strings (the label, the
      // Success badge and the verified hint stay on the widget exactly
      // like the legacy expiry path left them) and only flips the DOM
      // state to "expired", so a later language settlement repaints the
      // same expired presentation in the settled pack.
      kiwiSetView({ statusKey: "label", badgeKey: "badgeSuccess", domState: "expired", hintKey: "hintVerified" });
      if (countdownEl) countdownEl.textContent = kiwiT("expired");
      // The credential is gone — the widget is not started anymore, so
      // the (now visible) Retry button can reacquire.
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
    // Request binding: a hidden input carrying the bound value,
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
    // Server-issued decoy machinery lives in the lazy widget-risk.js
    // module (loaded when a decoy or execution program arrives). The
    // record's decoyState stays CORE state: it survives re-inits and
    // every reset/destroy path clears it through the owned-node set
    // below, so a re-solve never echoes a stale decoy name and an
    // application field with the same name is never touched.
    function kiwiClearDecoy() {
      kiwiClearDecoyState(decoyState);
    }
    function resetToIdle() {
      clearInterval(countdownTimer);
      var rc = kiwiWidgets[widgetId];
      if (rc) rc.countdownTimer = null;
      clearExpiryTimer();
      writeResponseAlias("");
      kiwiRecordState("idle", "");
      telemetry.stop();
      // A pending worker object URL is revoked on every reset/re-init
      // path, not just on worker completion (the worker machinery lives
      // in the lazy widget-risk.js module, which owns the URL).
      var riskNow = kiwiModuleApi("risk");
      if (riskNow && riskNow.revokeWorkerUrl) riskNow.revokeWorkerUrl();
      if (tokenEl) tokenEl.value = "";
      setBinding("");
      if (countdownEl) countdownEl.textContent = "";
      kiwiSetView({ statusKey: "label", badgeKey: "badgeIdle", domState: "idle", hintKey: "hintProtected" });
      setProgress(0);
    }
    // Abandoned-challenge notification (the exhaustion/deadline path): a
    // bounded fire-and-forget POST to {endpoint}/cancel carries the
    // abandoned nonce so the server retires the record; failures are
    // ignored and the notification is rate-limited (once per nonce plus
    // a cooldown), always for the challenge just abandoned.
    var lastCancelNotifyAt = 0;
    var lastCancelNonce = "";
    function kiwiNotifyCancel(endpoint, nonce) {
      var now = Date.now();
      if (nonce === lastCancelNonce) return;
      if (now - lastCancelNotifyAt < KIWI_CANCEL_COOLDOWN_MS) return;
      lastCancelNotifyAt = now;
      lastCancelNonce = nonce;
      try {
        // The cancel endpoint is the challenge path plus /cancel: a
        // query-bearing endpoint must not swallow the suffix, or the
        // abandoned record is never retired.
        var cancelUrl = endpoint.split("?")[0] + "/cancel";
        fetch(cancelUrl, {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          redirect: "error",
          referrerPolicy: "no-referrer",
          headers: { "Accept": "application/json", "Content-Type": "application/json" },
          body: JSON.stringify({ nonce: nonce }),
        }).catch(function () {});
      } catch (e) {}
    }
    // Failure recovery: an error never sticks in "failed" — reset to
    // idle, bounded retries with backoff, then idle until the next
    // interaction (click, Retry button, or page re-init).
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
        // The bounded auto-retry keeps the idle DOM state (the label
        // and badge the reset painted) and swaps only the hint for the
        // retrying text; a late language settlement repaints the same
        // view in the settled pack.
        kiwiSetView({ statusKey: "label", badgeKey: "badgeIdle", domState: "idle", hintKey: "hintRetrying", replacements: { msg: msg } });
        // The retry is a cancellable handle — a reset that lands during
        // the backoff must never start a stale run().
        var r = kiwiWidgets[widgetId];
        if (r && r.retryTimer) clearTimeout(r.retryTimer);
        if (r) r.retryTimer = setTimeout(function () { if (r) r.retryTimer = null; run(); }, 1000 * retryCount);
      } else {
        // Terminal failure must surface on the visible widget — the
        // Retry button's visibility is keyed on
        // .kiwi-widget[data-state="failed"].
        kiwiSetView({ statusKey: "label", badgeKey: "badgeFailed", domState: "failed", hintKey: "hintClickRetry", replacements: { msg: msg } });
        delete W.dataset.kiwiStarted;
        if (retryEl) retryEl.style.display = "";
        // The provider error callback fires exactly once per generation,
        // at automatic-retry exhaustion.
        fireErrorCallback(msg);
      }
    }
    // Build-id mismatch: the worker reported a different protocol id
    // than this driver's constant. The stale worker must NEVER contribute
    // a solution, and there is no fallback (retrying cannot change the
    // cached worker the page was served).
    function solverMismatch() {
      clearInterval(countdownTimer);
      telemetry.stop();
      if (tokenEl) tokenEl.value = "";
      setBinding("");
      if (countdownEl) countdownEl.textContent = "";
      kiwiSetView({ statusKey: "statusSolverMismatch", badgeKey: "badgeVersionError", domState: "kiwi:solver-mismatch", hintKey: "hintSolver" });
      setProgress(0);
      fireErrorCallback("solver-mismatch");
    }
    // Worker creation or solve failure for a memory-hard challenge
    // enters this controlled state: the token is cleared, nothing is
    // solved on the main thread, the profile is never downgraded. The
    // widget stays reacquirable; a later attempt retries the worker or
    // uses the configured data-kiwi-worker-src static worker.
    function workerUnavailable(reason) {
      clearInterval(countdownTimer);
      telemetry.stop();
      var riskNow = kiwiModuleApi("risk");
      if (riskNow && riskNow.revokeWorkerUrl) riskNow.revokeWorkerUrl();
      if (tokenEl) tokenEl.value = "";
      setBinding("");
      if (countdownEl) countdownEl.textContent = "";
      kiwiSetView({ statusKey: "statusWorkerUnavailable", badgeKey: "badgeUnavailable", domState: "kiwi:worker-unavailable", hintKey: "hintWorker" });
      setProgress(0);
      announce(kiwiT("statusWorkerUnavailable"));
      dispatch("worker-unavailable", { reason: reason || "worker-creation-failed" });
      delete W.dataset.kiwiStarted;
      // Worker conditions are non-retryable within the flow — the
      // provider error callback fires immediately.
      fireErrorCallback("worker-unavailable");
    }
    // ExecutionChallengeV1 interpreter failure (asset fetch/integrity,
    // iframe or timeout) enters this controlled state: the token is
    // cleared, the solution is NEVER submitted without its digest (never
    // a silent success, never a weaker-profile fallback), and the widget
    // stays reacquirable (Retry re-runs the whole flow).
    function executionUnavailable(reason) {
      clearInterval(countdownTimer);
      telemetry.stop();
      if (tokenEl) tokenEl.value = "";
      setBinding("");
      if (countdownEl) countdownEl.textContent = "";
      kiwiSetView({ statusKey: "statusWorkerUnavailable", badgeKey: "badgeUnavailable", domState: "kiwi:execution-unavailable", hintKey: "hintWorker" });
      setProgress(0);
      announce(kiwiT("statusWorkerUnavailable"));
      dispatch("execution-unavailable", { reason: reason || "execution-failed" });
      delete W.dataset.kiwiStarted;
      fireErrorCallback("execution-unavailable");
    }
    // BFCache restore: a persisted pageshow must NOT auto-solve — clear
    // the solved state and leave the widget idle for the next
    // interaction, and CANCEL the in-flight generation (abort fetch,
    // terminate worker, clear timers) so a pre-restore solve can never
    // write a token afterwards.
    function reset() {
      kiwiCancelGeneration(widgetId);
      resetToIdle();
      // The widget reset clears the rendered decoy (tracked name + input):
      // a re-solve must not echo a stale server-issued honeypot name.
      kiwiClearDecoy();
      delete W.dataset.kiwiStarted;
    }
    kiwiResetHooks.push({ el: W, reset: reset });
    // The Retry button re-inits exactly like the click/tap reacquire path.
    if (retryEl && !retryEl.dataset.kiwiRetryBound) {
      retryEl.dataset.kiwiRetryBound = "1";
      kiwiAddListener(retryEl, "click", function () {
        if (W.dataset.kiwiStarted || W.dataset.kiwiDestroyed) return;
        // Reacquisition MUST restore the FULL original configuration —
        // a blank initWidget(W) would fall back to DOM/URL heuristics and
        // the default "login", silently downgrading a sensitive
        // sitekey-mapped scope and losing callbacks/response-field/
        // language/action/cData. The record always carries the INITIAL
        // options; BFCache restore preserves them the same way.
        var preserved = (kiwiWidgets[widgetId] && kiwiWidgets[widgetId].options) || options;
        delete W.dataset.kiwiStarted;
        initWidget(W, preserved);
      });
    }
    // destroy() teardown: idle the runtime state (countdown, telemetry,
    // blob URL, token) exactly like resetToIdle does, and remove the
    // rendered decoy input.
    kiwiCleanups.set(W, function () { resetToIdle(); kiwiClearDecoy(); });

    async function run() {
      // Every continuation is generation-guarded: a reset in flight
      // bumps the generation and aborts/terminates the handles; this run
      // bails without touching state.
      var gen = (kiwiWidgets[widgetId] || {}).gen || 1;
      if (!kiwiGenerationCurrent(widgetId, gen)) return;
      try {
        kiwiSetView({ statusKey: "statusConnecting", badgeKey: "badgeWait", domState: "connecting" });
      // The request is NEVER delayed by a lazy-module load (audit
      // finding 1): telemetry attaches only opportunistically (requestSent
      // refuses a late session), the locale pack settles by repainting,
      // the coarse client context is built in the eager core. The risk
      // module is read from the registry and loaded at its REQUIRED
      // trigger points below (an armed response's worker/execution paths
      // fail closed on a missing module).
      var riskApi = kiwiModuleApi("risk");        var endpoint = kiwiEndpoint(W.getAttribute("data-kiwi-endpoint") || container.getAttribute("data-kiwi-endpoint") || "/api/kcaptcha/challenge");
        // Algorithm selection: the client may only choose among the
        // server-offered profiles (sha256 / argon2id / rsw); anything
        // else normalizes to the default, and a solver failure never
        // downgrades a request (failed paths retry the SAME profile).
        var algorithm = W.getAttribute("data-kiwi-algorithm") || container.getAttribute("data-kiwi-algorithm") || "sha256";
        if (algorithm !== "sha256" && algorithm !== "argon2id" && algorithm !== "rsw") algorithm = "sha256";
        var requestBinding = W.getAttribute("data-kiwi-request-binding") || container.getAttribute("data-kiwi-request-binding");
        var reqBody = { scope: scope };
        // EXECUTION CAPABILITY ADVERTISEMENT: when the widget carries the
        // configured interpreter asset (data-kiwi-execution-src +
        // integrity), the driver declares the highest program version it
        // can run via the Kiwi-Execution-Max-Version header (currently 5);
        // the header is ignorable and its absence means version 1.
        var execSrcAttr = (container.getAttribute ? container.getAttribute("data-kiwi-execution-src") : null)
          || (W.getAttribute ? W.getAttribute("data-kiwi-execution-src") : null);
        var execIntegrityAttr = (container.getAttribute ? container.getAttribute("data-kiwi-execution-integrity") : null)
          || (W.getAttribute ? W.getAttribute("data-kiwi-execution-integrity") : null);
        var reqHeaders = { "Accept": "application/json", "Content-Type": "application/json" };
        if (execSrcAttr && execIntegrityAttr) reqHeaders["Kiwi-Execution-Max-Version"] = "5";
        if (algorithm !== "sha256") reqBody.algorithm = algorithm;
        if (requestBinding) reqBody.request_binding = requestBinding;
        // CHAIN TICKET: a server-issued ticket (data-kiwi-chain-ticket or
        // options.chainTicket) is presented for the server's stage-2 gate
        // (bounded [A-Za-z0-9._:-]{1,256}; a malformed value is never
        // sent). It is CLEARED after the solve: one-shot, never re-
        // presented by a re-solve.
        var chainTicket = (options && typeof options.chainTicket === "string" && options.chainTicket)
          || (container.getAttribute ? container.getAttribute("data-kiwi-chain-ticket") : null)
          || (W.getAttribute ? W.getAttribute("data-kiwi-chain-ticket") : null);
        if (typeof chainTicket === "string" && /^[A-Za-z0-9._:-]{1,256}$/.test(chainTicket)) {
          reqBody.chain_ticket = chainTicket;
        }
        // RISK-V2 (the coarse descriptor moved into the EAGER core in
        // audit finding 1): built from coarse navigator/window signals
        // under the explicit data-kiwi-risk-context="coarse" opt-in, so
        // the opt-in never needs the lazy module before issuance. The
        // filled-decoy markers (ownership-based read of this widget's own
        // decoy node, truncated to the server's 256-byte bound) ride the
        // request as probabilistic evidence, never a gate; an absent
        // module degrades to the default no-signal state.
        var riskContext = null;
        if (W) riskContext = W.getAttribute("data-kiwi-risk-context") || riskContext;
        if (container && container !== W) riskContext = container.getAttribute("data-kiwi-risk-context") || riskContext;
        if (riskContext === "coarse") {
          var clientContext = kiwiBuildClientContext();
          if (clientContext) reqBody.client_context = clientContext;
        }
        if (riskApi && riskApi.readHoneypot) {
          var honeypot = riskApi.readHoneypot(decoyState, tokenEl);
          if (honeypot) {
            reqBody.decoy_field = honeypot.name;
            reqBody.honeypot = honeypot.value;
          }
        }
        // Provider-compatible metadata is declared by the WIDGET at
        // issuance (data-action / data-cdata, or params.action/cData); a
        // Siteverify request can never supply it.
        var kiwiAction = (container.getAttribute ? container.getAttribute("data-action") : null)
          || (W.getAttribute ? W.getAttribute("data-action") : null)
          || (options && options.action ? String(options.action) : null);
        var kiwiCdata = (container.getAttribute ? container.getAttribute("data-cdata") : null)
          || (W.getAttribute ? W.getAttribute("data-cdata") : null)
          || (options && options.cData ? String(options.cData) : null);
        if (kiwiAction) reqBody.action = kiwiAction;
        if (kiwiCdata) reqBody.cdata = kiwiCdata;
        // The public sitekey rides the request so the server resolves
        // (sitekey, action) -> security scope — the client never chooses
        // protected scope names.
        if (options && options.sitekey) reqBody.sitekey = String(options.sitekey);
        var timeoutAttr = W.getAttribute("data-kiwi-fetch-timeout-ms") || container.getAttribute("data-kiwi-fetch-timeout-ms") || "";
        var fetchTimeoutMs = parseInt(timeoutAttr, 10);
        if (!(fetchTimeoutMs > 0)) fetchTimeoutMs = KIWI_FETCH_TIMEOUT_MS;
        var abortController = new AbortController();
        var abortTimer = setTimeout(function () { abortController.abort(); }, fetchTimeoutMs);
        var rw = kiwiWidgets[widgetId];
        if (rw) { rw.abortController = abortController; rw.abortTimer = abortTimer; }
        // The request is SENT from here on: a telemetry module
        // registering after this point is refused for this generation,
        // so the token never carries a half-session.
        requestSent = true;
        var resp, data;
        try {
          resp = await fetch(endpoint, { method:"POST", credentials:"same-origin", cache:"no-store", redirect:"error", referrerPolicy:"no-referrer", headers: reqHeaders, body: JSON.stringify(reqBody), signal: abortController.signal });
          if (!resp.ok) throw new Error("Challenge failed");
          try {
            data = await resp.json();
          } catch (e) {
            // A non-JSON body is a challenge-content failure — the
            // parser's message would leak response text onto the error
            // surface, so a stable driver-owned message replaces it.
            throw new Error("Challenge malformed");
          }
        } finally {
          clearTimeout(abortTimer);
          var rw2 = kiwiWidgets[widgetId];
          if (rw2 && rw2.abortTimer === abortTimer) rw2.abortTimer = null;
        }
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        // No weaker challenge: the response algorithm may only equal or
        // exceed the request (a downgrade is a FAILED challenge); an rsw
        // request demands an rsw response exactly.
        var returnedAlgorithm = data.algorithm || "sha256";
        if ((algorithm === "argon2id" && returnedAlgorithm !== "argon2id")
          || (algorithm === "rsw" && returnedAlgorithm !== "rsw")) throw new Error("Challenge downgraded");
        // The response shape gate: a forged or malformed challenge is a
        // challenge-content failure (the bounded-retry state), never a
        // solve.
        kiwiValidateChallenge(data);
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        // RISK-V2 DECOY FIELD: the server-issued decoy name is rendered
        // as a hidden input next to the token (never auto-filled), in the
        // lazy widget-risk.js module, ensured before the solve starts; an
        // unloadable module degrades to the no-honeypot state (evidence,
        // never a gate).
        if (!riskApi && kiwiRiskResponseNeeds(data)) {
          riskApi = await kiwiEnsureModule("risk", container, W);
          if (!kiwiGenerationCurrent(widgetId, gen)) return;
        }
        if (riskApi && riskApi.renderDecoy) riskApi.renderDecoy(data, decoyState, tokenEl);
        if (data.ttlSecs) startCountdown(data.ttlSecs);
        kiwiSetView({ statusKey: "statusVerifying", badgeKey: "badgeWorking", domState: "solving" });
        announce(kiwiT("checking"));
        dispatch("verifying");
        // The solve deadline: the challenge expires ttlSecs after receipt;
        // the solver aborts KIWI_SOLVE_DEADLINE_MARGIN_MS before that
        // estimate (a solve that would outlive the challenge is waste). 0
        // = no deadline (missing ttl).
        var deadline = data.ttlSecs > 0 ? performance.now() + data.ttlSecs * 1000 - KIWI_SOLVE_DEADLINE_MARGIN_MS : 0;
        var result = null;
        if ((data.algorithm || "sha256") === "argon2id" || (data.algorithm || "sha256") === "rsw") {
          // Memory-hard (argon2id) and time-lock (rsw) challenges ALWAYS
          // run in the same-origin worker: no synchronous fallback, no
          // weaker-profile retry. A missing/failed worker (or unloadable
          // widget-risk.js) enters kiwi:worker-unavailable. The handle is
          // stored on the record so a cancelled generation terminates it.
          if (!riskApi || !riskApi.solveWorker) {
            riskApi = await kiwiEnsureModule("risk", container, W);
            if (!kiwiGenerationCurrent(widgetId, gen)) return;
          }
          if (!riskApi || !riskApi.solveWorker) { workerUnavailable("worker-unavailable"); return; }
          var workerHandle = riskApi.solveWorker(data, setProgress, container, deadline);
          var wr = kiwiWidgets[widgetId];
          if (wr) wr.worker = workerHandle.terminate;
          result = await workerHandle.promise;
          var wr2 = kiwiWidgets[widgetId];
          if (wr2 && wr2.worker === workerHandle.terminate) wr2.worker = null;
          if (!kiwiGenerationCurrent(widgetId, gen)) return;
          if (result && result.mismatch) { solverMismatch(); return; }
          if (result && result.deadline) throw new Error("Expired");
          if (!result || result.unavailable) { workerUnavailable(result ? result.reason : "solve-failed"); return; }
        } else {
          result = await solve(data.prefix, b64decode(data.salt), data.targetBits, "sha256", data.mKib||0, data.t||1, data.p||1, setProgress, deadline);
        }
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        if (result && result.deadline) throw new Error("Expired");
        if (!result) throw new Error("Exhausted");
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        // EXECUTIONCHALLENGEV1: an armed response carries an
        // execution_program. The driver runs it in the sandboxed
        // ephemeral interpreter (lazily loaded execution.<hash>.js,
        // deduped per page, SRI-preflight-verified) and appends the
        // digest to the token. Any failure enters kiwi:execution-
        // unavailable, never a silent success or weaker-profile fallback;
        // a SHA-only challenge pays zero interpreter bytes.
        var executionDigest = null;
        var executionTrace = null;
        if (data.execution_program) {
          var execResult = null;
          try {
            // The execution runner lives in the lazy widget-risk.js
            // module (the armed-evidence machinery; the risk-armed
            // server issues the decoy and execution arms together). An
            // armed program whose module cannot load enters
            // kiwi:execution-unavailable, never a silent success.
            if (!riskApi || !riskApi.runExecution) {
              riskApi = await kiwiEnsureModule("risk", container, W);
              if (!kiwiGenerationCurrent(widgetId, gen)) return;
            }
            if (!riskApi || !riskApi.runExecution) { executionUnavailable("execution-unavailable"); return; }
            execResult = await riskApi.runExecution(data.execution_program, data.nonce, container, W);
          } catch (e) {
            if (!kiwiGenerationCurrent(widgetId, gen)) return;
            executionUnavailable(typeof e === "string" ? e : (e && e.message ? e.message : "execution-failed"));
            return;
          }
          if (!kiwiGenerationCurrent(widgetId, gen)) return;
          if (!execResult) { executionUnavailable("execution-failed"); return; }
          executionDigest = execResult.digest;
          executionTrace = execResult.trace;
        }
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        var execEvidence = null;
        if (executionDigest && executionTrace) {
          execEvidence = executionDigest + ":" + btoa(executionTrace).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        }
        // Token shape: an rsw proof has no search counter, so the
        // counter segment holds 0 and the final value rides as the final
        // 512-hex segment; every other algorithm keeps the counter proof.
        var counterSegment = (data.algorithm || "sha256") === "rsw" ? 0 : result.counter;
        var proofSegment = (data.algorithm || "sha256") === "rsw"
          ? (typeof result.proof === "string" && /^[0-9a-f]{512}$/.test(result.proof) ? "." + result.proof : null)
          : null;
        if ((data.algorithm || "sha256") === "rsw" && !proofSegment) throw new Error("Exhausted");
        tokenEl.value = btoa(data.nonce + "." + counterSegment + "." + result.duration + "." + JSON.stringify(telemetry.build()) + (execEvidence ? "." + execEvidence : "") + (proofSegment || ""));
        setBinding(requestBinding || "");
        // The deferred decoy strategy creates its input after the first
        // solve (the module's flushDecoy — registered whenever a deferred
        // state exists, because the module recorded it).
        if (riskApi && riskApi.flushDecoy) riskApi.flushDecoy(decoyState, tokenEl);
        // CHAIN TICKET LIFECYCLE: the solve completed — the presented
        // ticket was consumed at issuance, so the attribute/option is
        // cleared and a re-solve never re-presents it.
        if (container && container.removeAttribute) container.removeAttribute("data-kiwi-chain-ticket");
        if (W && W.removeAttribute) W.removeAttribute("data-kiwi-chain-ticket");
        if (options && typeof options === "object") options.chainTicket = null;
        retryCount = 0;
        kiwiSetView({ statusKey: "label", badgeKey: "badgeSuccess", domState: "done", hintKey: "hintVerified" }); setProgress(100); clearInterval(countdownTimer); if (countdownEl) countdownEl.textContent = "";
        announce(kiwiT("statusVerified"));
        var token = tokenEl.value;
        kiwiRecordState("verified", token);
        writeResponseAlias(token);
        dispatch("verified", { nonce: data.nonce, token: token });
        // Provider-style solved-token expiry: the server stays
        // authoritative (an expired record is rejected); this client
        // timer is UX convenience mirroring incumbent token lifetimes.
        scheduleExpiry(data.ttlSecs || 0);
        if (options.callback) { try { options.callback(token); } catch (e) {} }
        telemetry.stop();
      } catch (e) {
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        // The abandonment path: the bounded search exhausted or the
        // deadline passed — the challenge is abandoned. The server is
        // informed (fire-and-forget, rate-limited) for the abandoned
        // nonce only; a transport failure or a user reset never sends the
        // notification.
        if (data && typeof data.nonce === "string" && (e.message === "Expired" || e.message === "Exhausted")) {
          kiwiNotifyCancel(endpoint, data.nonce);
        }
        fail(e.message);
      }
    }
    // The flow start is NEVER gated on a lazy module (audit finding 1):
    // run() proceeds immediately (English fallback, empty telemetry
    // stub) and a late settlement repaints whatever state is current.
    // execute() starts the same ungated flow.
    var kiwiFlowStarted = false;
    function kiwiStartFlow() {
      if (kiwiFlowStarted) return;
      kiwiFlowStarted = true;
      run();
    }
    dispatch("ready");
    if (!deferredExecution) kiwiStartFlow();
    var kiwiRec = kiwiWidgets[widgetId];
    if (kiwiRec) kiwiRec.start = kiwiStartFlow;
    return widgetId;
  }

  // ── BFCache restore ──
  // A persisted pageshow restores the page WITHOUT re-running init, so a
  // solved widget would otherwise keep its stale token. Reset every live
  // widget and reacquire on the next interaction instead.
  var kiwiResetHooks = [];

  // ── Per-widget lifecycle bookkeeping ──
  // The rendered server-issued decoy input is owned per widget: the
  // authoritative created-node set lives in the PRIVATE decoy state on
  // the record (carried across re-inits), and every reset path removes
  // ONLY the nodes in that owned set, never by name match, so an
  // application field with the same name is never touched.
  function kiwiClearDecoyState(state) {
    if (!state) return;
    var nodes = state.nodes || [];
    state.nodes = [];
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      if (!node || !node.parentNode) continue;
      try { node.parentNode.removeChild(node); } catch (e) {}
    }
    state.name = null;
    state.deferred = false;
    state.className = null;
    state.variant = null;
  }
  // destroy(element|selector) reverses EVERYTHING initWidget attached:
  // listeners (registered per element so they can be removed by
  // reference), the countdown/telemetry/blob-URL runtime state and the
  // BFCache hook. A destroyed widget is marked data-kiwi-destroyed and
  // initWidget refuses to resurrect it; the SPA owns the DOM node.
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

  // ── SPA lifecycle observer (OPT-IN) ──
  // SPAs that insert widgets dynamically call
  // window.KiwiCaptcha.observe(document.body) once; the MutationObserver
  // auto-inits every [data-kiwi-widget] that appears later. Not started
  // automatically: a page that wants strict init control never gets
  // surprise challenges.
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

  // ── Provider-style public API ──
  // Native KiwiCaptcha exposes the incumbent lifecycle: render() ->
  // stable id, reset/getResponse/execute/remove/isExpired/ready. The
  // compatibility globals delegate to the SAME instances.
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
    // Reset is cancellation — the superseded generation's fetch is
    // aborted, its worker terminated, its retry/expiry timers cleared;
    // the new initWidget starts generation +1.
    kiwiCancelGeneration(id);
    var W = r.W;
    if (W) {
      // The reset clears the rendered decoy (owned nodes + private
      // state): a re-solve must not echo a stale server-issued honeypot
      // name, and only Kiwi-owned nodes are ever removed.
      kiwiClearDecoyState(r.decoyState);
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
    // A widget rendered in explicit-execution mode (data-state "pending")
    // starts its deferred challenge here; once started, the record state
    // is "solving" so a second execute() just awaits the same run.
    if (r.state === "pending" && typeof r.start === "function") {
      r.state = "solving";
      r.start();
    } else if (r.W && !r.W.dataset.kiwiStarted) {
      delete r.W.dataset.kiwiStarted;
      initWidget(r.W, r.options);
      var r2 = kiwiWidgets[id];
      if (r2 && r2.state === "pending" && typeof r2.start === "function") {
        r2.state = "solving";
        r2.start();
      }
    }
    return new Promise(function (resolve, reject) {
      var W = r.W;
      var onVerified = function () {
        var cur = kiwiWidgets[id];
        resolve(cur ? (cur.token || "") : "");
      };
      var onError = function (ev) {
        // fail() dispatches {error: msg} — the promise must reject with
        // the ACTUAL reason, not the generic fallback.
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
    workerSource: kiwiEmbeddedWorkerSource() || null,
    protocolId: KIWI_SOLVER_PROTOCOL_ID,
    buildId: KIWI_SOLVER_PROTOCOL_ID,
    observe: kiwiObserve,
    destroy: kiwiDestroy
  };
  // ── Lazy widget modules + internal bridge ──────
  // The server-armed machinery ships as lazy modules registering on
  // the internal bridge: widget-risk.js (worker solve tier, execution
  // runner, decoy/risk-v2), widget-locales.js (non-default packs),
  // widget-telemetry.js (opt-in session), widget-compat.js (inside the
  // /api.js response, never fetched). A module on the page registers
  // itself; otherwise the core injects a same-origin SRI-pinned
  // <script src integrity=...> for the page-issued content-addressed
  // URL only when a trigger fires. Native SRI fails closed on a digest
  // mismatch, the immutable URL serves only the pinned bytes, the
  // cache dedups per page (one fetch per kind), the load is bounded to
  // three attempts and a hung REQUIRED load cannot wedge forever
  // (10 s watchdog). Audit finding 1: only the REQUIRED loads (an
  // armed response's worker/execution paths) are awaited; the
  // opportunistic loads never gate the challenge request.
  var kiwiModuleApis = {};
  var kiwiModuleLoads = {};
  function kiwiModuleApi(kind) {
    return kiwiModuleApis[kind] || null;
  }
  // The armed-response trigger predicate: a valid authenticated decoy
  // name or an execution program. Mirrors widget-risk.js, so a
  // decoy-less SHA-256 page never loads the module.
  function kiwiRiskResponseNeeds(data) {
    return !!(data && typeof data === "object" && !Array.isArray(data)
      && ((typeof data.decoy_field === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(data.decoy_field))
        || data.execution_program));
  }
  function kiwiModuleAttr(kind, el, attr) {
    return el && el.getAttribute ? el.getAttribute("data-kiwi-" + kind + "-" + attr) : null;
  }
  function kiwiModuleAssetAttrs(kind, container, W) {
    var src = kiwiModuleAttr(kind, container, "src") || kiwiModuleAttr(kind, W, "src");
    var integrity = kiwiModuleAttr(kind, container, "integrity") || kiwiModuleAttr(kind, W, "integrity");
    return (src && integrity) ? { src: src, integrity: integrity } : null;
  }
  var KIWI_MODULE_ATTEMPTS = 3;
  var KIWI_MODULE_TIMEOUT_MS = 10000;
  function kiwiLoadModuleAsset(kind, attrs) {
    return new Promise(function (resolve) {
      var attempt = 0;
      var settled = false;
      var watchdog = null;
      function finish(api) {
        if (settled) return;
        settled = true;
        if (watchdog) clearTimeout(watchdog);
        resolve(api || null);
      }
      function tryInject() {
        var script = document.createElement("script");
        script.src = attrs.src;
        script.integrity = attrs.integrity;
        script.setAttribute("data-kiwi-module", kind);
        script.onload = function () {
          // The module registers synchronously while its IIFE executes,
          // so the registry entry at the load event is the completion
          // signal; a loaded asset that never registered is refused
          // (defense in depth over the content-addressed URL).
          var api = kiwiModuleApis[kind] || null;
          if (!api) console.warn("KiwiCaptcha: " + kind + " module loaded but did not register; refusing it");
          finish(api);
        };
        script.onerror = function () {
          if (attempt < KIWI_MODULE_ATTEMPTS - 1) {
            attempt++;
            setTimeout(tryInject, 250 * attempt);
            return;
          }
          console.warn("KiwiCaptcha: " + kind + " module asset unavailable (" + attrs.src + ")");
          finish(null);
        };
        (document.head || document.documentElement).appendChild(script);
      }
      watchdog = setTimeout(function () {
        console.warn("KiwiCaptcha: " + kind + " module load timed out");
        finish(null);
      }, KIWI_MODULE_TIMEOUT_MS);
      tryInject();
    });
  }
  // Ensure a module kind is registered, loading its page-issued asset on
  // demand; resolves the module API or null when no URL was issued or
  // the load failed (callers degrade per channel above).
  function kiwiEnsureModule(kind, container, W) {
    var api = kiwiModuleApis[kind];
    if (api) return Promise.resolve(api);
    if (!kiwiModuleLoads[kind]) {
      var attrs = kiwiModuleAssetAttrs(kind, container, W);
      if (!attrs) return Promise.resolve(null);
      kiwiModuleLoads[kind] = kiwiLoadModuleAsset(kind, attrs);
    }
    return kiwiModuleLoads[kind];
  }
  // ── Coarse client-context descriptor + byte-bounded truncation ─
  // Moved from the lazy widget-risk.js module into the EAGER core
  // (audit finding 1): the descriptor rides every challenge request
  // under the explicit data-kiwi-risk-context="coarse" opt-in, and
  // issuance must never wait for the lazy module. Built ONCE per page
  // from coarse navigator/window signals (the server accepts
  // /^[a-z0-9+_,=:-]{1,64}$/D) ONLY under the opt-in (default off, so
  // no device-capability or screen-size signal ever leaves the page
  // without it). Deliberately COARSE: viewport class, touch
  // capability, language family, timezone-offset class — no
  // canvas/audio/font-list/GPU fingerprinting, no stable IDs, nothing
  // identifying across sessions. Missing capability contributes
  // nothing; nothing available omits the field. The bridge exposes
  // both helpers so the lazy module reads the same context and reuses
  // the byte-bound truncation for its decoy/honeypot evidence.
  var kiwiClientContext = null;
  function kiwiBuildClientContext() {
    if (kiwiClientContext !== null) return kiwiClientContext;
    var parts = [];
    var viewport = 0;
    if (typeof window !== "undefined" && window.innerWidth) viewport = window.innerWidth;
    parts.push(viewport < 600 ? "v1" : (viewport < 1200 ? "v2" : "v3"));
    var coarsePointer = false;
    try {
      var pm = window.matchMedia ? window.matchMedia("(pointer: coarse)") : null;
      coarsePointer = !!(pm && pm.matches);
    } catch (e) {}
    parts.push("t" + (coarsePointer ? "1" : "0"));
    if (navigator && typeof navigator.language === "string" && navigator.language) {
      var family = navigator.language.trim().toLowerCase().split(/[_-]/)[0] || "";
      if (family.length > 3) family = family.slice(0, 3);
      if (/^[a-z]{2,3}$/.test(family)) parts.push("l" + family);
    }
    try {
      if (typeof Date !== "undefined" && typeof Date.prototype.getTimezoneOffset === "function") {
        var offsetHours = Math.round(-new Date().getTimezoneOffset() / 60);
        parts.push(offsetHours < -8 ? "z0" : (offsetHours < -2 ? "z1" : (offsetHours <= 2 ? "z2" : (offsetHours <= 8 ? "z3" : "z4"))));
      }
    } catch (e) {}
    if (parts.length === 0) { kiwiClientContext = null; return null; }
    kiwiClientContext = parts.join(",");
    return kiwiClientContext;
  }
  // Truncate to the server's BYTE bound (e.g. the 256-byte honeypot
  // ceiling): code units are cut with a binary search over the UTF-8
  // byte length, so a multi-byte filler can never exceed the bound and
  // 422 the request.
  function kiwiBoundBytes(s, maxBytes) {
    if (encoder.encode(s).length <= maxBytes) return s;
    var lo = 0, hi = s.length;
    while (lo < hi) {
      var mid = (lo + hi + 1) >> 1;
      if (encoder.encode(s.slice(0, mid)).length <= maxBytes) lo = mid; else hi = mid - 1;
    }
    return s.slice(0, lo);
  }
  // The internal module bridge (window.__kiwiCaptchaCore): the lazy
  // module files run as separate scripts with no shared closure state,
  // so the core exposes the small surface they need: register()
  // (first-wins per kind), the worker/glue helpers and the
  // provider-compatible functions widget-compat.js delegates to. The
  // bridge is deliberately NOT the public window.KiwiCaptcha surface.
  var kiwiBridge = null;
  function kiwiCompatGlueValue() {
    return kiwiBridge ? kiwiBridge.compatGlue : null;
  }
  function kiwiBridgeRecord(id) {
    return kiwiWidgets[id] || null;
  }
  kiwiBridge = {
    register: function (kind, api) {
      if (kind && api && typeof api === "object" && !kiwiModuleApis[kind]) {
        kiwiModuleApis[kind] = api;
        // widget-locales.js also registers its packs here (register is
        // the executed signal the asset loader waits for).
        if (kind === "locales" && api.packs) kiwiAddLocalePacks(api.packs);
      }
    },
    protocolId: KIWI_SOLVER_PROTOCOL_ID,
    compatGlue: null,
    core: {
      render: kiwiRender,
      reset: kiwiReset,
      getResponse: kiwiGetResponse,
      execute: kiwiExecute,
      remove: kiwiRemove,
      isExpired: kiwiIsExpired,
      safeCallback: kiwiSafeCallback,
      normalizeLang: kiwiNormalizeLang,
      resolveTarget: kiwiResolveTarget,
      record: kiwiBridgeRecord,
      findGlueSource: kiwiFindGlueSource,
      embeddedWorkerSource: kiwiEmbeddedWorkerSource,
      buildClientContext: kiwiBuildClientContext,
      boundBytes: kiwiBoundBytes
    }
  };
  window.__kiwiCaptchaCore = kiwiBridge;
  var runInit = function() {
    document.querySelectorAll("[data-kiwi-widget]").forEach(function (W) {
      // No pointerdown-only activation: after a reset or settled
      // failure the widget is idle; the native Retry button is the
      // reacquire control for EVERY input method.
      initWidget(W);
    });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runInit); else runInit();
})();


