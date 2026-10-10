(function() {
  // Idempotency guard: the first copy owns the API, bridge and scan.
  // The flag lives on a Symbol key, never a string-named window property:
  // DOM clobbering (`<img name="__kiwiDriverLoaded">`) installs a named
  // element property that a plain truthiness read cannot distinguish from
  // our own marker, which would skip initialization and leave the widget
  // dead on any page where such markup exists. Symbols are unreachable
  // from DOM named properties, and Symbol.for shares the key across
  // script copies in the same realm.
  var KIWI_BOOT = Symbol.for("kiwicaptcha.driver-loaded");
  var KIWI_BOOT_REUSE = Symbol.for("kiwicaptcha.driver-reused");
  if (typeof window !== "undefined" && window[KIWI_BOOT]) {
    window[KIWI_BOOT_REUSE] = (window[KIWI_BOOT_REUSE] || 0) + 1;
    // Turbo/htmx re-executes body scripts after replacing the body: the
    // new DOM may hold widgets the first scan never saw, so rescan
    // through the bridge instead of returning silently (a login form
    // must never submit an empty token because the scan was skipped).
    var reusedCore = window.__kiwiCaptchaCore;
    if (reusedCore && reusedCore.core && typeof reusedCore.core.scan === "function") {
      reusedCore.core.scan(document);
    }
    return;
  }
  if (typeof window !== "undefined") window[KIWI_BOOT] = true;
  var encoder = new TextEncoder();

  // ── Solver PROTOCOL id ──
  // Bumped when the worker protocol changes. The worker reports the same
  // id and verifies the glue's protocol version before ready; the driver
  // refuses a differing id (protocol compatibility only — artifact
  // identity is the release tag + SHA256SUMS + SRI + attestation).
  var KIWI_SOLVER_PROTOCOL_ID = "2026-09-r1";

  // ── Challenge fetch timeout ──
  // A hung endpoint must never wedge the widget: the fetch carries an
  // AbortController aborting after this many ms into the controlled
  // error state. data-kiwi-fetch-timeout-ms overrides per widget.
  var KIWI_FETCH_TIMEOUT_MS = 15000;

  // ── Telemetry initialization budget ──
  // The pre-fetch telemetry wait is bounded by its own 2 s deadline and
  // is completely independent of the challenge fetch timeout: an
  // enabled telemetry mode must never consume (or abort) the challenge
  // request's clock.
  var KIWI_TELEMETRY_INIT_TIMEOUT_MS = 2000;

  // ── Solve deadline margin ──
  // The solver stops at (expiry estimate − this margin): a solve that
  // would outlive the challenge is waste. 500 ms covers the final chunk
  // and token-write path; only over-long solves truncate.
  var KIWI_SOLVE_DEADLINE_MARGIN_MS = 500;

  // ── Solve wall-clock ceiling ──
  // Every solve is bounded even without an expiry estimate: a response
  // without ttlSecs gets this fallback deadline from the solve start
  // (and a longer estimate is capped by it), so the search can never
  // run unbounded.
  var KIWI_SOLVE_DEADLINE_CEILING_MS = 120000;

  // ── Abandonment-notify cooldown ──
  // The cancellation notification is rate-limited per widget: once per
  // nonce plus this window, so a retry loop never spams the endpoint.
  var KIWI_CANCEL_COOLDOWN_MS = 5000;

  // Client expiry margin: the server TTL starts at ISSUANCE, so the
  // client anchors expiry at receipt + ttl − margin, never at solve
  // completion + ttl (which showed Success after server expiry).
  var KIWI_EXPIRY_MARGIN_MS = 2000;

  // ── Supported external configuration attributes ──
  // The one data-kiwi-* configuration list: the native path reads it
  // through kiwiConfigValue, compat copies it onto the render target.
  var KIWI_CONFIG_ATTRS = [
    "data-kiwi-endpoint",
    "data-kiwi-scope",
    "data-kiwi-algorithm",
    "data-kiwi-request-binding",
    "data-kiwi-risk-context",
    "data-kiwi-fetch-timeout-ms",
    "data-kiwi-chain-ticket",
    "data-kiwi-worker-src",
    "data-kiwi-worker-integrity",
    "data-kiwi-runtime-src",
    "data-kiwi-runtime-integrity",
    "data-kiwi-execution-src",
    "data-kiwi-execution-integrity",
    "data-kiwi-locales-src",
    "data-kiwi-locales-integrity",
    "data-kiwi-risk-src",
    "data-kiwi-risk-integrity",
    "data-kiwi-telemetry",
    "data-kiwi-telemetry-src",
    "data-kiwi-telemetry-integrity",
    "data-kiwi-lang",
  ];
  // W wins over container; unknown names are refused (one gate).
  function kiwiConfigValue(W, container, name) {
    if (KIWI_CONFIG_ATTRS.indexOf(name) === -1) return null;
    var value = W && W.getAttribute ? W.getAttribute(name) : null;
    if ((value === null || value === "") && container && container !== W && container.getAttribute) {
      value = container.getAttribute(name);
    }
    return value;
  }
  // Copy supported attributes; a value already on target wins.
  function kiwiCopySupportedConfiguration(source, target) {
    if (!source || !target || !source.getAttribute || !target.setAttribute) return 0;
    var copied = 0;
    for (var i = 0; i < KIWI_CONFIG_ATTRS.length; i++) {
      var name = KIWI_CONFIG_ATTRS[i];
      if (source.hasAttribute(name) && !target.hasAttribute(name)) {
        target.setAttribute(name, source.getAttribute(name));
        copied++;
      }
    }
    return copied;
  }

  // ── Worker source (argon2id / rsw / glue-less SHA-256) ──
  // Runs off the main thread (a 64 MiB hash or glue-less SHA search
  // would block the UI). Embedded via the glue's workerSource, GENERATED
  // from assets/kiwi-worker.js by tools/embed-worker (CI --check fails
  // on drift); inline mode reads the glue copy, files mode fetches the
  // versioned worker asset.
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
  // Copy bytes into wasm memory (explicit alloc/free avoids
  // wasm-bindgen Vec/slice glue), using the crate's stable exports with
  // a fallback to generated symbols. `alloc` returns 0 on failure:
  // callers must check and fall back to the pure-JS solver.
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

  // ── Synchronous SHA-256 (pure JS, module-scoped scratch) ──
  // Split so the solver can cache the prefix midstate (see deriveHash):
  // sha256Compress advances _h over whole blocks, sha256Output renders.
  var _h = new Uint32Array(8), _w = new Uint32Array(64);
  var _k = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function sha256Init() {
    _h[0] = 0x6a09e667; _h[1] = 0xbb67ae85; _h[2] = 0x3c6ef372; _h[3] = 0xa54ff53a;
    _h[4] = 0x510e527f; _h[5] = 0x9b05688c; _h[6] = 0x1f83d9ab; _h[7] = 0x5be0cd19;
  }
  function sha256Compress(view, start, end) {
    var a, b, c, d, e, f, g, hh, s0, s1, ch, maj, t1, t2;
    for (var i = start; i < end; i += 64) {
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
  }
  function sha256Output(result) {
    for (var i = 0; i < 8; i++) {
      result[i * 4] = (_h[i] >>> 24) & 0xff; result[i * 4 + 1] = (_h[i] >>> 16) & 0xff;
      result[i * 4 + 2] = (_h[i] >>> 8) & 0xff; result[i * 4 + 3] = _h[i] & 0xff;
    }
  }
  function sha256sync(data, result) {
    sha256Init();
    var l = data.length * 8;
    var padLen = (data.length % 64 < 56) ? (56 - data.length % 64) : (120 - data.length % 64);
    var msg = new Uint8Array(data.length + padLen + 8);
    msg.set(data); msg[data.length] = 0x80;
    var view = new DataView(msg.buffer);
    view.setUint32(msg.length - 4, l, false);
    sha256Compress(view, 0, msg.length);
    sha256Output(result);
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
  var _hashBuf = new Uint8Array(32);
  // Midstate cache: the constant prefix's full blocks compress once per
  // (prefix identity, total length) shape and each derivation resumes
  // from the cached state — no per-hash buffer/DataView allocation and
  // no prefix re-hash. The total length key changes only when the
  // counter gains a digit, so stale challenges can never be reused.
  var _mid = { prefix: null, totalLen: -1, resumeAt: 0, msg: null, view: null, state: new Uint32Array(8) };
  function deriveHash(prefixBytes, counter, saltBytes) {
    var cStr = counter.toString(), cLen = cStr.length, totalLen = prefixBytes.length + cLen + saltBytes.length;
    if (_mid.prefix !== prefixBytes || _mid.totalLen !== totalLen) {
      var padLen = (totalLen % 64 < 56) ? (56 - totalLen % 64) : (120 - totalLen % 64);
      var msg = new Uint8Array(totalLen + padLen + 8);
      msg.set(prefixBytes, 0);
      msg[totalLen] = 0x80;
      var view = new DataView(msg.buffer);
      view.setUint32(msg.length - 4, totalLen * 8, false);
      var fullPrefixBlocksEnd = prefixBytes.length - (prefixBytes.length % 64);
      sha256Init();
      sha256Compress(view, 0, fullPrefixBlocksEnd);
      _mid.state.set(_h);
      _mid.prefix = prefixBytes;
      _mid.totalLen = totalLen;
      _mid.resumeAt = fullPrefixBlocksEnd;
      _mid.msg = msg;
      _mid.view = view;
    }
    var m = _mid.msg;
    m.set(prefixBytes.subarray(_mid.resumeAt, prefixBytes.length), _mid.resumeAt);
    for (var i = 0; i < cLen; i++) m[prefixBytes.length + i] = cStr.charCodeAt(i);
    m.set(saltBytes, prefixBytes.length + cLen);
    _h.set(_mid.state);
    sha256Compress(_mid.view, _mid.resumeAt, m.length);
    sha256Output(_hashBuf);
    return _hashBuf;
  }

  // A 20-bit challenge exhausts at e^-20 (~2e-9) instead of the ~0.85%
  // a 5M cap left; the challenge deadline caps it further.
  var MAX_SHA_HASHES = 20000000;
  var SHA_CHUNK_TIME_BUDGET_MS = 10;
  function solve(prefix, saltBytes, targetBits, algorithm, m_kib, t, p, onProgress, deadline, isCancelled) {
    return new Promise(async function(resolve) {
      var prefixBytes = encoder.encode(prefix), expectedHashes = Math.pow(2, targetBits), solveStart = performance.now(), counter = 0;
      var w = await initWasm();
      // Persistent WASM-side buffers: allocated once and reused across all
      // chunks, eliminating malloc/free churn on every 50k-hash iteration
      // (the hottest loop in the SHA-256 solver).
      var pp = 0, sp = 0;
      // SINGLE exit path: every terminal path (solution, exhaustion,
      // deadline, cancellation) releases the WASM buffers and resolves
      // exactly once.
      var settled = false;
      function release() {
        if (w) { wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); }
        pp = 0;
        sp = 0;
      }
      function finish(result) {
        if (settled) return;
        settled = true;
        release();
        resolve(result);
      }
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
        if (settled) return;
        // Cancellation (reset/remove/destroy/BFCache) stops the loop at
        // the next chunk boundary instead of burning CPU.
        if (isCancelled && isCancelled()) { finish({ cancelled: true }); return; }
        // The solve deadline (challenge expiry − margin): abort BETWEEN
        // chunks — a solve that would outlive the challenge is pure waste
        // and the token would be rejected anyway. The driver's retry flow
        // re-acquires a fresh challenge.
        if (deadline && performance.now() >= deadline) { finish({ deadline: true }); return; }
        if (useWasm) {
          try {
            if (ensureBuffers()) {
              // The wasm window is bounded by the remaining hash budget,
              // so the search never scans past the cap even mid-chunk.
              var want = Math.min(CHUNK, MAX_SHA_HASHES - counter);
              if (want <= 0) { finish(null); return; }
              var res = w.solve_sha256_chunk(pp, prefixBytes.length, sp, saltBytes.length, targetBits, counter, want);
              if (res >= 0) { finish({ counter: res, duration: Math.round(performance.now() - solveStart) }); return; }
              // -1 = the whole CHUNK window was scanned; -(scanned + 1)
              // = the time budget elapsed after `scanned` hashes. Both
              // resume at the exact next counter, never skipping work.
              counter += res === -1 ? want : -res - 1;
              if (counter >= MAX_SHA_HASHES) { finish(null); return; }
            } else {
              // Allocation failed: wasm is disabled permanently — fall back to JS.
              console.warn("KiwiCaptcha: WASM allocation failed, disabling WASM and falling back to JS");
              useWasm = false;
            }
          } catch (e) { release(); console.error("KiwiCaptcha: WASM solve failed, falling back to JS", e); useWasm = false; }
        }
        if (!useWasm) {
          var end = Math.min(counter + CHUNK, MAX_SHA_HASHES);
          var chunkStart = performance.now();
          var inChunk = 0;
          for (; counter < end; counter++, inChunk++) {
            if (leadingZeros(deriveHash(prefixBytes, counter, saltBytes)) >= targetBits) {
              finish({ counter: counter, duration: Math.round(performance.now() - solveStart) }); return;
            }
            if ((inChunk & 255) === 0 && performance.now() - chunkStart >= SHA_CHUNK_TIME_BUDGET_MS) break;
          }
        }
        if (counter >= MAX_SHA_HASHES) { finish(null); return; }
        onProgress(Math.min(92, (counter * 100) / expectedHashes));
        fastYield(chunk);
      }
      fastYield(chunk);
    });
  }

  var kiwiInstanceCounter = 0;
  function kiwiFindGlueSource() {
    // The glue's unique inlined marker is the "var KIWI_WASM_B64"
    // assignment (never mistakable for this driver). A `var window =
    // self` prelude exposes it inside the worker.
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

  // ── Credential-field normalization ──
  // A hidden input's value reflects into its content attribute,
  // publishing the credential to CSS/serialization; Kiwi fields use the
  // non-reflecting hidden-text mode so it lives only in IDL value and
  // form data.
  function kiwiNormalizeField(input) {
    if (!input || input.tagName !== "INPUT") return input;
    if (input.getAttribute("type") === "hidden" || input.type === "hidden") {
      input.type = "text";
      input.setAttribute("hidden", "");
      try { input.style.display = "none"; } catch (e) {}
    }
    // Even an empty value attribute matches the [value] selector; only
    // an empty attribute is removed, never a page-preset value.
    if (input.getAttribute("value") === "") input.removeAttribute("value");
    return input;
  }

  function kiwiValidateChallenge(data) {
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Challenge malformed");
    var alg = data.algorithm === undefined ? "sha256" : data.algorithm;
    if (alg !== "sha256" && alg !== "argon2id" && alg !== "rsw") throw new Error("Challenge malformed");
    // The canonical server nonce shape: standard base64 of 32 random
    // bytes (44 chars, one padding =). Constraining the nonce up front
    // keeps it inside btoa's Latin-1 domain, so the token write can
    // never fail after a full solve.
    if (typeof data.nonce !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(data.nonce)) throw new Error("Challenge malformed");
    if (typeof data.prefix !== "string" || data.prefix.length < 1 || data.prefix.length > 4096) throw new Error("Challenge malformed");
    if (typeof data.salt !== "string" || data.salt.length < 1 || data.salt.length > 512) throw new Error("Challenge malformed");
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
  var kiwiLocalePacks = {
    en: { dir: "ltr",
      label: "Security Check", badgeIdle: "Idle", badgeWait: "Wait",
      badgeWorking: "Working", badgeSuccess: "Success", badgeFailed: "Failed",
      badgeVersionError: "Version Error", badgeUnavailable: "Unavailable", badgeExpired: "Expired",
      statusConnecting: "Connecting\u2026", statusVerifying: "Verifying\u2026",
      statusVerified: "Verification complete", statusFailed: "Verification failed",
      statusExpired: "Verification expired", statusWorkerUnavailable: "Check could not start",
      statusExecutionUnavailable: "Check incomplete",
      statusSolverMismatch: "Solver version mismatch",
      hintProtected: "Protected", hintRetrying: "Challenge failed ({msg}) \u2014 retrying\u2026",
      hintClickRetry: "Challenge failed ({msg}) \u2014 press the Retry button to try again.",
      hintVerified: "Proof-of-work verified locally.",
      hintWorker: "The security check could not start on this device \u2014 press the Retry button to try again.",
      hintExecution: "The security check could not complete \u2014 press the Retry button to try again.",
      hintExpired: "The check expired \u2014 press the Retry button to run it again.",
      hintSolver: "The solver worker is out of date \u2014 reload the page to load the current version.",
      errConnection: "the connection failed", errMalformed: "the server returned an unexpected response",
      errExhausted: "the check took too long", errExpired: "the challenge expired",
      errGeneric: "the check could not complete",
      expired: "expired", retryButton: "Retry", checking: "Checking\u2026" },
    // Filled by the lazy widget-locales.js module. Every shipped
    // regional pack needs its own placeholder (without "pt-br" the
    // resolver returns "pt" before the module lands, so two widgets on
    // one page could disagree); locale-csp.spec.mjs pins the sync.
    de: null, fr: null, es: null, it: null, nl: null, pl: null, pt: null, "pt-br": null, ar: null
  };
  var kiwiFallbackLang = "en";
  function kiwiNormalizeLang(pref) {
    if (typeof pref !== "string") return "";
    // The full tag is preserved (region included): the resolver tries
    // the exact pack before the base pack.
    return pref.trim().toLowerCase().replace(/_/g, "-") || "";
  }
  // Resolution: explicit per-widget lang, then <html lang>, then
  // navigator.language — an unsupported explicit language falls through
  // instead of collapsing to English. Regional tags try their exact pack
  // (pt-br) before the base pack (pt).
  function kiwiLangCandidates(pref) {
    var norm = kiwiNormalizeLang(pref);
    if (!norm) return [];
    var out = [norm];
    var base = norm.split(/[-_]/)[0];
    if (base && base !== norm) out.push(base);
    return out;
  }
  function kiwiResolveLang(options) {
    var prefs = [];
    if (options && typeof options.lang === "string" && options.lang) prefs.push(options.lang);
    if (typeof document !== "undefined") {
      var htmlLang = null;
      try { htmlLang = document.documentElement ? document.documentElement.getAttribute("lang") : null; } catch (e) {}
      if (htmlLang) prefs.push(htmlLang);
    }
    if (typeof navigator !== "undefined" && navigator.language) prefs.push(navigator.language);
    for (var i = 0; i < prefs.length; i++) {
      var candidates = kiwiLangCandidates(prefs[i]);
      for (var c = 0; c < candidates.length; c++) {
        if (kiwiLocalePacks[candidates[c]] !== undefined) return candidates[c];
      }
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
  // triggers the same re-init path as the click/tap reacquire.
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

  // Per-widget generation + cancellation handles: every async
  // continuation captures its generation and refuses stale writes;
  // reset/remove/destroy bump it and retire the handles.
  // Null-prototype dictionary: widgetId comes from the page's
  // data-kiwi-instance attribute, so a plain {} would let a crafted
  // instance id of "__proto__" set this map's [[Prototype]] and make
  // every other widgetId inherit a forged record.
  var kiwiWidgets = Object.create(null); // widgetId -> {W, options, state, token, gen, abortController, abortTimer, worker, retryTimer, countdownTimer, expiryTimer, errorFired, responseKey, start}
  function kiwiGenerationCurrent(id, gen) {
    var r = kiwiWidgets[id];
    return !!(r && r.gen === gen);
  }
  function kiwiCancelGeneration(id) {
    var r = kiwiWidgets[id];
    if (!r) return;
    r.gen++; // any in-flight generation is stale from here on
    r.errorFired = false;
    // Every execute() promise awaiting this generation rejects with the
    // cancel reason — a destroyed or reset widget must never leave a
    // caller's await pending forever.
    var pending = r.pendingExecute;
    r.pendingExecute = null;
    if (pending) {
      for (var pi = 0; pi < pending.length; pi++) {
        try { pending[pi](); } catch (e) {}
      }
    }
    if (r.abortController) { try { r.abortController.abort(); } catch (e) {} r.abortController = null; }
    if (r.abortTimer) { clearTimeout(r.abortTimer); r.abortTimer = null; }
    if (r.worker) { try { r.worker.terminate(); } catch (e) {} r.worker = null; }
    if (r.retryTimer) { clearTimeout(r.retryTimer); r.retryTimer = null; }
    if (r.countdownTimer) { clearInterval(r.countdownTimer); r.countdownTimer = null; }
    if (r.expiryTimer) { clearTimeout(r.expiryTimer); r.expiryTimer = null; }
  }
  function initWidget(W, options) {
    if (!W || W.dataset.kiwiStarted || W.dataset.kiwiDestroyed) return null;
    // Automatic initialization (DOM-ready, observer, implicit compat
    // render) honors the module-failure backoff; only explicit retries
    // clear it through kiwiClearModuleBackoff.
    options = options || {};
    // The response-field alias name is page-author controlled, so only
    // the bounded field-name shape reaches the alias writer — anything
    // else (a selector-bearing value) drops the alias and keeps the
    // internal token field, never a synthesized selector.
    if (options.responseField !== undefined && options.responseField !== false
      && (typeof options.responseField !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(options.responseField))) {
      console.warn("KiwiCaptcha: response-field-name rejected (allowed: 1-64 of [A-Za-z0-9_-]); using the internal token field");
      options.responseField = false;
    }
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
    // Cancel the superseded generation (retry/abort/worker/countdown),
    // but carry pending execute() hooks into the new one: they await THIS
    // widget and the retry continues the same run. (An explicit
    // reset/remove cancels before re-init, so those callers still see it.)
    var carriedExecuteHooks = prevRecord ? prevRecord.pendingExecute : null;
    if (prevRecord) {
      prevRecord.pendingExecute = null;
      kiwiCancelGeneration(widgetId);
    }
    var newGen = prevRecord ? prevRecord.gen + 1 : 1;
    // The decoy state is PRIVATE per widget (never on the DOM): the
    // authenticated name, the deferred flag, the strategy/wrapper-class
    // picks and the owned decoy nodes. It SURVIVES re-inits (an
    // expiry-triggered re-solve must still see a filled decoy), carried
    // over from the previous record.
    var decoyState = (prevRecord && prevRecord.decoyState) ? prevRecord.decoyState : { name: null, deferred: false, nodes: [], className: null, variant: null };
    kiwiWidgets[widgetId] = { W: W, options: options, state: "solving", token: "", gen: newGen, abortController: null, abortTimer: null, worker: null, retryTimer: null, countdownTimer: null, expiryTimer: null, errorFired: false, pendingExecute: carriedExecuteHooks && carriedExecuteHooks.length ? carriedExecuteHooks : null, responseKey: "hkey-" + Math.random().toString(36).slice(2, 10), start: null, decoyState: decoyState };
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
    var kiwiLangAttr = kiwiConfigValue(W, container, "data-kiwi-lang");
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
    var labelEl = W.querySelector("[data-kiwi-label]"), pillEl = W.querySelector("[data-kiwi-badge]"), fillEl = W.querySelector("[data-kiwi-bar]"), hintEl = W.querySelector("[data-kiwi-info]"), countdownEl = W.querySelector("[data-kiwi-timer]"), tokenEl = kiwiNormalizeField(W.querySelector("[data-kiwi-token]") || container.querySelector("[data-kiwi-token]")), trackEl = W.querySelector(".kiwi-track");
    var announcerEl = W.querySelector("[data-kiwi-status]") || createAnnouncer(W);
    // The mascot is decorative next to the already-labelled widget:
    // hide it from assistive technology, defensively.
    var iconSvg = W.querySelector(".kiwi-icon-wrapper svg");
    if (iconSvg) { iconSvg.setAttribute("aria-hidden", "true"); iconSvg.setAttribute("focusable", "false"); }
    var retryEl = W.querySelector("[data-kiwi-retry]") || createRetryButton(W, kiwiWidgetPack.retryButton);
    var telemetryMode = kiwiConfigValue(W, container, "data-kiwi-telemetry") || "off";
    if (telemetryMode !== "minimal" && telemetryMode !== "full") telemetryMode = "off";
    var requestSent = false;
    var kiwiTelemetrySession = null;
    // The session must exist BEFORE the request: the token is built
    // with telemetry.build(), so a session created in a later microtask
    // would never attach (every token {}) — run() awaits the module
    // briefly; an already-registered module is used synchronously.
    function kiwiCreateTelemetrySession() {
      if (kiwiTelemetrySession) return true;
      var module = kiwiModuleApi("telemetry");
      if (module && module.create) {
        kiwiTelemetrySession = module.create(container, W, telemetryMode);
        return true;
      }
      return false;
    }
    if (telemetryMode !== "off") {
      if (!kiwiCreateTelemetrySession()) {
        kiwiEnsureModule("telemetry", container, W).then(function () {
          if (!kiwiGenerationCurrent(widgetId, newGen)) return;
          if (requestSent && !kiwiTelemetrySession) return;
          kiwiCreateTelemetrySession();
        });
      }
    }
    var telemetry = {
      build: function () { return kiwiTelemetrySession ? kiwiTelemetrySession.build() : {}; },
      stop: function () { if (kiwiTelemetrySession) kiwiTelemetrySession.stop(); }
    };
    // options.scope is AUTHORITATIVE (explicit > container attribute >
    // path heuristics): a heuristic override would silently downgrade
    // admin_login/financial_action challenges to the login policy.
    var scope = (options && typeof options.scope === "string" && options.scope)
      || kiwiConfigValue(W, container, "data-kiwi-scope");
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
    // Lazy locale packs (WCAG 3.1.2): the module loads here (deduped)
    // and a late pack repaints the current view. The flow never awaits
    // it: run() proceeds on the English fallback, and a failure keeps
    // English with a warning — a translation is never a gate.
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
      // The stylesheet paints exact 10..100 buckets; the solver reports a
      // continuous float (and the worker path forwards its own float).
      // Round to the nearest bucket so the bar actually moves during the
      // solve instead of sitting at 0% until success.
      var bucket = Math.round(clamped / 10) * 10;
      fillEl.setAttribute("data-progress", String(bucket));
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
      if (!host) return;
      // The alias fields are located by iterating and comparing names —
      // never by interpolating the name into a selector. The incumbent
      // shapes are covered: reCAPTCHA/hCaptcha use a hidden <textarea>
      // (mirrored here too), Turnstile a hidden <input>.
      var aliasTargets = [];
      var hostFields = host.querySelectorAll("input,textarea");
      for (var ai = 0; ai < hostFields.length; ai++) {
        if (hostFields[ai].name === options.responseField) aliasTargets.push(hostFields[ai]);
        // hCaptcha populates the reCAPTCHA field as well, so an
        // integration reading only g-recaptcha-response keeps working.
        else if (options.responseField === "h-captcha-response" && hostFields[ai].name === "g-recaptcha-response") aliasTargets.push(hostFields[ai]);
      }
      if (aliasTargets.length === 0) {
        var input = document.createElement("input");
        input.type = "hidden";
        input.name = options.responseField;
        host.insertBefore(input, tokenEl.nextSibling);
        aliasTargets.push(input);
      }
      for (var ti = 0; ti < aliasTargets.length; ti++) {
        try { kiwiNormalizeField(aliasTargets[ti]); aliasTargets[ti].value = value || ""; } catch (e) {}
      }
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
      // Each presentation step is individually guarded: a failing alias
      // or binding write can never strand the lifecycle — the started
      // flag, the expired dispatch, the announcement and the callback
      // always run.
      try { if (tokenEl) tokenEl.value = ""; } catch (e) {}
      try { setBinding(""); } catch (e) {}
      try { writeResponseAlias(""); } catch (e) {}
      try {
        // The expired credential must not keep the Success presentation.
        kiwiSetView({ statusKey: "label", badgeKey: "badgeExpired", domState: "expired", hintKey: "hintExpired" });
        if (countdownEl) countdownEl.textContent = kiwiT("expired");
      } catch (e) {}
      // The credential is gone — the widget is not started anymore, so
      // the (now visible) Retry button can reacquire.
      delete W.dataset.kiwiStarted;
      dispatch("expired", {});
      announce(kiwiT("statusExpired"));
      if (options.expiredCallback) { try { options.expiredCallback(); } catch (e) {} }
    }
    // Fires at the receipt-anchored deadline (never at completion).
    function scheduleExpiryAt(deadlineAt) {
      clearExpiryTimer();
      if (!deadlineAt) return;
      var r = kiwiWidgets[widgetId];
      if (!r) return;
      r.expiryTimer = setTimeout(expireWidget, Math.max(0, deadlineAt - performance.now()));
    }
    // The timer counts down to the same receipt-anchored deadline.
    function startCountdown(ttlSecs, deadlineAt) {
      var remaining = ttlSecs;
      var tick = function() {
        if (deadlineAt) remaining = Math.max(0, Math.ceil((deadlineAt - performance.now()) / 1000));
        if (countdownEl) countdownEl.textContent = remaining > 0 ? remaining + "s" : kiwiT("expired");
      };
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
      kiwiNormalizeField(input);
      input.value = value || "";
    }
    // Decoy rendering lives in lazy widget-risk.js, but decoyState is
    // core state: it survives re-inits and resets clear only the
    // owned-node set below, never by name — a stale decoy is never
    // echoed and an application field of the same name is untouched.
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
      // A pending worker object URL is still revoked on every reset path:
      // reset()/destroy() run through kiwiCancelGeneration() first, whose
      // terminate handle tears the solve down (the lazy module's per-solve
      // teardown owns the URL — never a page-global revoke).
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
        // Strip BOTH the query and any #fragment: an endpoint like
        // "/challenge#step-2" would otherwise build "/challenge#step-2/cancel".
        var cancelUrl = endpoint.split(/[?#]/)[0] + "/cancel";
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
    // Driver-owned failures map to translated text; raw internals never
    // reach the widget (they stay in the event detail / console).
    function kiwiErrorKeyFor(msg) {
      var m = String(msg || "");
      if (m === "Expired") return "errExpired";
      if (m === "Exhausted") return "errExhausted";
      if (m.indexOf("Challenge malformed") === 0 || m.indexOf("Challenge downgraded") === 0) return "errMalformed";
      if (m.indexOf("Challenge failed") === 0 || m.indexOf("signal is aborted") !== -1
        || m.indexOf("Failed to fetch") !== -1 || m.indexOf("NetworkError") !== -1) return "errConnection";
      return "errGeneric";
    }
    function fail(msg) {
      resetToIdle();
      announce(kiwiT("statusFailed"));
      var userMsg = kiwiT(kiwiErrorKeyFor(msg));
      if (retryCount < RETRY_LIMIT) {
        retryCount++;
        // Transient failure: kiwi:retrying (never kiwi:error), so
        // execute() does not reject on an auto-recovered failure.
        dispatch("retrying", { error: msg, attempt: retryCount });
        kiwiSetView({ statusKey: "label", badgeKey: "badgeIdle", domState: "idle", hintKey: "hintRetrying", replacements: { msg: userMsg } });
        // The retry is a cancellable handle — a reset that lands during
        // the backoff must never start a stale run().
        var r = kiwiWidgets[widgetId];
        if (r && r.retryTimer) clearTimeout(r.retryTimer);
        if (r) r.retryTimer = setTimeout(function () { if (r) r.retryTimer = null; run(); }, 1000 * retryCount);
      } else {
        // Terminal failure: kiwi:error fires once per generation, at
        // retry exhaustion, with the Retry button visible.
        dispatch("error", { error: msg });
        kiwiSetView({ statusKey: "label", badgeKey: "badgeFailed", domState: "failed", hintKey: "hintClickRetry", replacements: { msg: userMsg } });
        delete W.dataset.kiwiStarted;
        if (retryEl) retryEl.style.display = "";
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
      announce(kiwiT("statusSolverMismatch"));
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
      // No URL cleanup here: this state is reached only after the solve
      // handle settled (its teardown revoked the blob URL) or before any
      // worker was created.
      if (tokenEl) tokenEl.value = "";
      setBinding("");
      if (countdownEl) countdownEl.textContent = "";
      kiwiSetView({ statusKey: "statusWorkerUnavailable", badgeKey: "badgeUnavailable", domState: "kiwi:worker-unavailable", hintKey: "hintWorker" });
      setProgress(0);
      announce(kiwiT("statusWorkerUnavailable"));
      // Developer diagnostics stay on the console; the visible hint is
      // visitor-facing text.
      console.warn("KiwiCaptcha: off-main-thread solver unavailable (" + (reason || "worker-creation-failed")
        + "); check the worker asset attributes (data-kiwi-worker-src/integrity, data-kiwi-runtime-src/integrity) and the page CSP");
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
      // A dedicated execution state with its own hint and Retry (the
      // worker hint is wrong here; Retry re-runs the whole flow).
      kiwiSetView({ statusKey: "statusExecutionUnavailable", badgeKey: "badgeUnavailable", domState: "kiwi:execution-unavailable", hintKey: "hintExecution" });
      setProgress(0);
      announce(kiwiT("statusExecutionUnavailable"));
      console.warn("KiwiCaptcha: execution interpreter unavailable (" + (reason || "execution-failed") + ")");
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
    // One BFCache hook per element: a re-init replaces its hook instead
    // of growing the array (destroy() removes the element's hook).
    var kiwiHook;
    var kiwiHookIdx;
    for (kiwiHookIdx = 0; kiwiHookIdx < kiwiResetHooks.length && kiwiResetHooks[kiwiHookIdx].el !== W; kiwiHookIdx++) {}
    kiwiHook = { el: W, reset: reset };
    if (kiwiHookIdx < kiwiResetHooks.length) kiwiResetHooks[kiwiHookIdx] = kiwiHook;
    else kiwiResetHooks.push(kiwiHook);
    // Move focus to the widget group before Retry hides the focused
    // button (WCAG 2.4.3: users must not be dropped to <body>).
    function kiwiFocusWidgetGroup() {
      if (!a11yRoot || !a11yRoot.setAttribute) return;
      if (!a11yRoot.hasAttribute("tabindex")) a11yRoot.setAttribute("tabindex", "-1");
      try { a11yRoot.focus(); } catch (e) {}
    }
    // The Retry button re-inits exactly like the click/tap reacquire path.
    if (retryEl && !retryEl.dataset.kiwiRetryBound) {
      retryEl.dataset.kiwiRetryBound = "1";
      kiwiAddListener(retryEl, "click", function () {
        if (W.dataset.kiwiDestroyed) return;
        if (W.dataset.kiwiStarted) {
          // During the auto-retry backoff an explicit Retry supersedes
          // the pending timer instead of being refused.
          var rec = kiwiWidgets[widgetId];
          if (!(rec && rec.retryTimer && rec.state === "idle")) return;
        }
        // Restore the FULL original configuration: a blank initWidget
        // would fall back to DOM/URL heuristics, silently downgrading a
        // sitekey-mapped scope and losing callbacks/response-field/
        // language/action/cData. The record carries the initial options.
        var preserved = (kiwiWidgets[widgetId] && kiwiWidgets[widgetId].options) || options;
        // Retry button: explicit retry clears the backoff.
        kiwiClearModuleBackoff();
        kiwiFocusWidgetGroup();
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
      var expiryDeadlineAt = null;
      try {
        kiwiSetView({ statusKey: "statusConnecting", badgeKey: "badgeWait", domState: "connecting" });
        var riskApi = kiwiModuleApi("risk");
        var endpoint = kiwiEndpoint(kiwiConfigValue(W, container, "data-kiwi-endpoint") || "/api/kcaptcha/challenge");
        // Algorithm selection: the client may only choose among the
        // server-offered profiles (sha256 / argon2id / rsw); anything
        // else normalizes to the default, and a solver failure never
        // downgrades a request (failed paths retry the same profile).
        var algorithm = kiwiConfigValue(W, container, "data-kiwi-algorithm") || "sha256";
        if (algorithm !== "sha256" && algorithm !== "argon2id" && algorithm !== "rsw") algorithm = "sha256";
        var requestBinding = kiwiConfigValue(W, container, "data-kiwi-request-binding");
        var reqBody = { scope: scope };
        // EXECUTION CAPABILITY ADVERTISEMENT: when the widget carries the
        // configured interpreter asset (data-kiwi-execution-src +
        // integrity), the driver declares the highest program version it
        // can run via the Kiwi-Execution-Max-Version header (currently 6);
        // the header is ignorable and its absence means version 1.
        var execSrcAttr = kiwiConfigValue(W, container, "data-kiwi-execution-src");
        var execIntegrityAttr = kiwiConfigValue(W, container, "data-kiwi-execution-integrity");
        var reqHeaders = { "Accept": "application/json", "Content-Type": "application/json" };
        if (execSrcAttr && execIntegrityAttr) reqHeaders["Kiwi-Execution-Max-Version"] = "6";
        if (algorithm !== "sha256") reqBody.algorithm = algorithm;
        if (requestBinding) reqBody.request_binding = requestBinding;
        // CHAIN TICKET: a server-issued ticket (data-kiwi-chain-ticket or
        // options.chainTicket) is presented for the server's stage-2 gate
        // (bounded [A-Za-z0-9._:-]{1,256}; a malformed value is never
        // sent). It is CLEARED after the solve: one-shot, never re-
        // presented by a re-solve.
        var chainTicket = (options && typeof options.chainTicket === "string" && options.chainTicket)
          || kiwiConfigValue(W, container, "data-kiwi-chain-ticket");
        if (typeof chainTicket === "string" && /^[A-Za-z0-9._:-]{1,256}$/.test(chainTicket)) {
          reqBody.chain_ticket = chainTicket;
        }
        var riskContext = kiwiConfigValue(W, container, "data-kiwi-risk-context");
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
        var timeoutAttr = kiwiConfigValue(W, container, "data-kiwi-fetch-timeout-ms") || "";
        var fetchTimeoutMs = parseInt(timeoutAttr, 10);
        if (!(fetchTimeoutMs > 0)) fetchTimeoutMs = KIWI_FETCH_TIMEOUT_MS;
        // Attach telemetry before sending, on its own bounded budget: it
        // must never consume the challenge-fetch timeout (the fetch
        // deadline starts immediately before the fetch call, below).
        if (telemetryMode !== "off" && !kiwiTelemetrySession) {
          try {
            var telemetryFallbackTimer = null;
            await Promise.race([
              kiwiEnsureModule("telemetry", container, W),
              new Promise(function (res) {
                telemetryFallbackTimer = setTimeout(res, KIWI_TELEMETRY_INIT_TIMEOUT_MS);
              }),
            ]);
            // The module won (or the race settled): retire the fallback
            // timer so no useless timer stays queued.
            if (telemetryFallbackTimer !== null) {
              clearTimeout(telemetryFallbackTimer);
              telemetryFallbackTimer = null;
            }
          } catch (e) {}
          if (kiwiGenerationCurrent(widgetId, gen)) kiwiCreateTelemetrySession();
        }
        // A reset/destroy during the telemetry wait supersedes this
        // generation: the stale continuation must return before the
        // request is sent (or the controller created), never POST a
        // challenge for a widget that no longer exists.
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        // The request is SENT from here on: a telemetry module
        // registering after this point is refused for this generation,
        // so the token never carries a half-session.
        requestSent = true;
        // The challenge fetch deadline starts HERE, immediately before
        // the request: data-kiwi-fetch-timeout-ms bounds the challenge
        // POST itself, never the widget initialization ahead of it.
        var abortController = new AbortController();
        var abortTimer = setTimeout(function () { abortController.abort(); }, fetchTimeoutMs);
        var rw = kiwiWidgets[widgetId];
        if (rw) { rw.abortController = abortController; rw.abortTimer = abortTimer; }
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
        // Receipt-anchored expiry (server TTL started at issuance).
        if (data.ttlSecs) {
          // The margin is capped at a quarter of the TTL so very short
          // challenge lifetimes (fixtures, test keys) still get a real
          // window instead of an already-expired one.
          var expiryMargin = Math.min(KIWI_EXPIRY_MARGIN_MS, Math.max(0, data.ttlSecs * 250));
          expiryDeadlineAt = performance.now() + data.ttlSecs * 1000 - expiryMargin;
          startCountdown(data.ttlSecs, expiryDeadlineAt);
        }
        kiwiSetView({ statusKey: "statusVerifying", badgeKey: "badgeWorking", domState: "solving" });
        announce(kiwiT("checking"));
        dispatch("verifying");
        // The solve deadline is the challenge TTL minus the abort
        // margin (a solve outliving the challenge is waste), falling back
        // to and capped by the wall-clock ceiling.
        var solveDeadlineEstimate = data.ttlSecs > 0
          ? data.ttlSecs * 1000 - KIWI_SOLVE_DEADLINE_MARGIN_MS
          : KIWI_SOLVE_DEADLINE_CEILING_MS;
        if (solveDeadlineEstimate > KIWI_SOLVE_DEADLINE_CEILING_MS) solveDeadlineEstimate = KIWI_SOLVE_DEADLINE_CEILING_MS;
        var deadline = performance.now() + solveDeadlineEstimate;
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
          var workerHandle = riskApi.solveWorker(data, setProgress, container, deadline, W);
          var wr = kiwiWidgets[widgetId];
          if (wr) wr.worker = workerHandle;
          result = await workerHandle.promise;
          var wr2 = kiwiWidgets[widgetId];
          if (wr2 && wr2.worker === workerHandle) wr2.worker = null;
          if (!kiwiGenerationCurrent(widgetId, gen)) return;
          if (result && result.mismatch) { solverMismatch(); return; }
          if (result && result.deadline) throw new Error("Expired");
          if (!result || result.unavailable) { workerUnavailable(result ? result.reason : "solve-failed"); return; }
        } else {
          if (!wasmLoader) {
            if (!riskApi || !riskApi.solveWorker) {
              riskApi = await kiwiEnsureModule("risk", container, W);
              if (!kiwiGenerationCurrent(widgetId, gen)) return;
            }
            if (riskApi && riskApi.solveWorker) {
              var shaWorkerHandle = riskApi.solveWorker(data, setProgress, container, deadline, W);
              var shr = kiwiWidgets[widgetId];
              if (shr) shr.worker = shaWorkerHandle;
              var shaWorkerResult = await shaWorkerHandle.promise;
              var shr2 = kiwiWidgets[widgetId];
              if (shr2 && shr2.worker === shaWorkerHandle) shr2.worker = null;
              if (!kiwiGenerationCurrent(widgetId, gen)) return;
              // Only a genuine worker solution counts here; every failure
              // mode (missing module, asset/integrity refusal, worker
              // error, protocol mismatch, deadline) falls through to the
              // in-page solver below.
              if (shaWorkerResult && !shaWorkerResult.unavailable && !shaWorkerResult.mismatch
                && !shaWorkerResult.deadline && typeof shaWorkerResult.counter === "number") {
                result = shaWorkerResult;
              }
            }
          }
          if (!result) {
            result = await solve(data.prefix, b64decode(data.salt), data.targetBits, "sha256", data.mKib||0, data.t||1, data.p||1, setProgress, deadline, function () { return !kiwiGenerationCurrent(widgetId, gen) || !W.isConnected; });
          }
        }
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
        if (result && result.cancelled) return;
        if (result && result.deadline) throw new Error("Expired");
        if (!result) throw new Error("Exhausted");
        if (!kiwiGenerationCurrent(widgetId, gen)) return;
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
        // UX-only expiry timer at the receipt-derived deadline; the
        // server remains authoritative.
        scheduleExpiryAt(expiryDeadlineAt);
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

  var kiwiResetHooks = [];

  // ── Per-widget lifecycle bookkeeping ──
  // The decoy input's created-node set is private per record and
  // survives re-inits; resets remove only those nodes, never by name.
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
        // The registry entry dies with the widget (the mirror of
        // kiwiRemove): a destroyed element never leaves a stale record
        // behind.
        delete kiwiWidgets[W.dataset.kiwiInstance];
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
  // compatibility globals delegate to the same instances.
  function kiwiResolveTarget(target) {
    if (!target) return null;
    if (typeof target === "string") {
      var el = document.getElementById(target);
      if (!el) {
        // A page-supplied selector string may be syntactically invalid:
        // render("invalid selector") must return 0 like the incumbent,
        // never throw out of the provider API.
        try {
          var list = document.querySelectorAll(target);
          return list.length ? list[0] : null;
        } catch (e) {
          return null;
        }
      }
      return el;
    }
    return target.nodeType === 1 ? target : null;
  }
  function kiwiRenderTarget(target, options) {
    var el = kiwiResolveTarget(target);
    if (!el) return 0;
    return initWidget(el, options) || 0;
  }
  function kiwiRender(target, options) {
    // Explicit provider re-render: a user-driven retry.
    kiwiClearModuleBackoff();
    return kiwiRenderTarget(target, options);
  }
  function kiwiReset(id) {
    var r = kiwiWidgets[id];
    if (!r) return;
    // Explicit reset: a user-driven retry.
    kiwiClearModuleBackoff();
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
      // The alias lookup iterates and compares names — the validated
      // name is never interpolated into a selector. The hCaptcha
      // mirror field clears with the primary.
      if (r.options && r.options.responseField && t) {
        var host = t.parentNode;
        var resetFields = host ? host.querySelectorAll("input,textarea") : [];
        for (var ri = 0; ri < resetFields.length; ri++) {
          var resetName = resetFields[ri].name;
          if (resetName === r.options.responseField
            || (r.options.responseField === "h-captcha-response" && resetName === "g-recaptcha-response")) {
            resetFields[ri].value = "";
          }
        }
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
      var settled = false;
      // Settlement retires this promise's own cancellation hook from the
      // current record (nulling the list when it empties): a widget that
      // completes and stays verified must not retain every settled
      // execute() closure until the next reset or destroy.
      var removeCancelHook = function () {
        var cur = kiwiWidgets[id];
        if (!cur || !cur.pendingExecute) return;
        var hookIndex = cur.pendingExecute.indexOf(onCancel);
        if (hookIndex !== -1) cur.pendingExecute.splice(hookIndex, 1);
        if (cur.pendingExecute.length === 0) cur.pendingExecute = null;
      };
      var detach = function () {
        removeCancelHook();
        if (W) {
          W.removeEventListener("kiwi:verified", onVerified);
          W.removeEventListener("kiwi:error", onError);
        }
      };
      var onVerified = function () {
        if (settled) return;
        settled = true;
        detach();
        var cur = kiwiWidgets[id];
        resolve(cur ? (cur.token || "") : "");
      };
      var onError = function (ev) {
        if (settled) return;
        settled = true;
        detach();
        // fail() dispatches {error: msg} — the promise must reject with
        // the ACTUAL reason, not the generic fallback.
        var detail = (ev && ev.detail) || {};
        var reason = detail.error || detail.reason || "kiwicaptcha: solve failed";
        reject(new Error(String(reason)));
      };
      // The cancel hook settles this promise when reset()/remove()/
      // destroy() cancel the awaited generation — a destroyed widget
      // must never leave the caller's await pending forever.
      var onCancel = function () {
        if (settled) return;
        settled = true;
        detach();
        reject(new Error("kiwicaptcha: solve cancelled"));
      };
      if (W) {
        W.addEventListener("kiwi:verified", onVerified, { once: true });
        W.addEventListener("kiwi:error", onError, { once: true });
      }
      var cur = kiwiWidgets[id];
      if (cur && cur.state === "verified") { onVerified(); return; }
      if (cur) {
        if (!cur.pendingExecute) cur.pendingExecute = [];
        cur.pendingExecute.push(onCancel);
      }
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
  // Installed as an own property (defineProperty), not a plain
  // assignment: a clobbering element with id/name "KiwiCaptcha" is a
  // Window named property that a later plain write can leave shadowed on
  // read, so the provider API would appear missing. defineProperty
  // materializes an ordinary own property that wins over the named one.
  var kiwiPublicApi = {
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
  try {
    Object.defineProperty(window, "KiwiCaptcha", {
      value: kiwiPublicApi,
      writable: true,
      configurable: true,
      enumerable: true
    });
  } catch (e) {
    window.KiwiCaptcha = kiwiPublicApi;
  }
  // Null-prototype dictionaries: module kind strings are compared and
  // stored by name, so a plain {} would be pollutable via "__proto__".
  var kiwiModuleApis = Object.create(null);
  // In-flight deduplication only: a settled promise is retired, and a
  // terminal failure records a short backoff instead of being memoized
  // for the page lifetime.
  var kiwiModuleLoads = Object.create(null);
  var kiwiModuleFailedAt = Object.create(null);
  var KIWI_MODULE_FAILURE_BACKOFF_MS = 5000;
  // Explicit retries only.
  function kiwiClearModuleBackoff() {
    kiwiModuleFailedAt = Object.create(null);
  }
  function kiwiModuleApi(kind) {
    return kiwiModuleApis[kind] || null;
  }
  // The armed-response trigger predicate: a valid authenticated decoy
  // name or an execution program. Mirrors widget-risk.js; the decoy and
  // the execution runner are the only response-driven reasons the
  // module is needed before the solve dispatch (a glue-less page's
  // SHA-256 solve dispatches it separately, at the solve phase).
  function kiwiRiskResponseNeeds(data) {
    return !!(data && typeof data === "object" && !Array.isArray(data)
      && ((typeof data.decoy_field === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(data.decoy_field))
        || data.execution_program));
  }
  function kiwiModuleAssetAttrs(kind, container, W) {
    var src = kiwiConfigValue(W, container, "data-kiwi-" + kind + "-src");
    var integrity = kiwiConfigValue(W, container, "data-kiwi-" + kind + "-integrity");
    return (src && integrity) ? { src: src, integrity: integrity } : null;
  }
  var KIWI_MODULE_ATTEMPTS = 3;
  var KIWI_MODULE_TIMEOUT_MS = 10000;
  // Registration provenance: a loader-issued asset may only register the
  // kind it was issued for, so a compromised (even SRI-valid) asset of
  // one kind can never claim another kind's digest-pinned role. Inline
  // modules keep the legacy contract.
  var kiwiModuleScriptKinds = new WeakMap();
  function kiwiLoadModuleAsset(kind, attrs) {
    return new Promise(function (resolve) {
      var attempt = 0;
      var settled = false;
      var watchdog = null;
      var retryTimer = null;
      var script = null;
      function dropScript() {
        // A failed or refused script node never stays in the document.
        if (script && script.parentNode) script.parentNode.removeChild(script);
        script = null;
      }
      function finish(api) {
        if (settled) return;
        settled = true;
        if (watchdog) clearTimeout(watchdog);
        // Terminal settlement cancels a pending retry script.
        if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
        if (!api) dropScript();
        resolve(api || null);
      }
      function tryInject() {
        if (settled) return;
        script = document.createElement("script");
        script.src = attrs.src;
        script.integrity = attrs.integrity;
        script.setAttribute("data-kiwi-module", kind);
        kiwiModuleScriptKinds.set(script, kind);
        script.onload = function () {
          if (settled) return;
          // The module registers synchronously while its IIFE executes,
          // so the registry entry at the load event is the completion
          // signal; a loaded asset that never registered is refused
          // (defense in depth over the content-addressed URL).
          var api = kiwiModuleApis[kind] || null;
          if (!api) console.warn("KiwiCaptcha: " + kind + " module loaded but did not register; refusing it");
          finish(api);
        };
        script.onerror = function () {
          if (settled) return;
          dropScript();
          if (attempt < KIWI_MODULE_ATTEMPTS - 1) {
            attempt++;
            retryTimer = setTimeout(tryInject, 250 * attempt);
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
    var failedAt = kiwiModuleFailedAt[kind];
    if (failedAt !== undefined) {
      // The short backoff throttles automatic retries only; a successful
      // registration or an explicit reset clears it.
      if (Date.now() - failedAt < KIWI_MODULE_FAILURE_BACKOFF_MS) return Promise.resolve(null);
      delete kiwiModuleFailedAt[kind];
    }
    if (!kiwiModuleLoads[kind]) {
      var attrs = kiwiModuleAssetAttrs(kind, container, W);
      if (!attrs) return Promise.resolve(null);
      var load = kiwiLoadModuleAsset(kind, attrs);
      kiwiModuleLoads[kind] = load;
      load.then(function (loaded) {
        // Retire the settled promise: success stays cached by the module
        // registry, a failure only records the backoff timestamp.
        if (kiwiModuleLoads[kind] === load) delete kiwiModuleLoads[kind];
        if (loaded) delete kiwiModuleFailedAt[kind];
        else kiwiModuleFailedAt[kind] = Date.now();
      });
    }
    return kiwiModuleLoads[kind];
  }
  var kiwiClientContext = null;
  function kiwiBuildClientContext() {
    if (kiwiClientContext !== null) return kiwiClientContext;
    // Stable components ONLY: pointer type, language family and timezone
    // class. The viewport is deliberately excluded — a phone rotation, a
    // window resize or a split-screen layout would otherwise flip the
    // consistency tag and add the session-inconsistency weight to a
    // legitimate user. The viewport remains available separately to the
    // rest of the page context, but it is never part of this tag.
    var parts = [];
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
  // The internal module bridge (window.__kiwiCaptchaCore): lazy modules
  // run as separate scripts, so the core exposes register() (first wins
  // per kind), the worker/glue helpers and the provider-compatible
  // functions. Deliberately NOT the public window.KiwiCaptcha surface.
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
        var cs = null;
        try { cs = document.currentScript; } catch (e) {}
        var issuedKind = cs ? (kiwiModuleScriptKinds.get(cs) || null) : null;
        if (issuedKind && issuedKind !== kind) {
          console.warn("KiwiCaptcha: refused a " + kind + " registration from a " + issuedKind + " module asset");
          return;
        }
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
      renderImplicit: kiwiRenderTarget,
      reset: kiwiReset,
      getResponse: kiwiGetResponse,
      execute: kiwiExecute,
      remove: kiwiRemove,
      isExpired: kiwiIsExpired,
      safeCallback: kiwiSafeCallback,
      normalizeLang: kiwiNormalizeLang,
      // The one configuration reader (widget element wins over the
      // container) so the lazy modules never re-implement precedence.
      configValue: kiwiConfigValue,
      resolveTarget: kiwiResolveTarget,
      record: kiwiBridgeRecord,
      // Registry bookkeeping for inspection: the live widget-record
      // count and the BFCache hook-array length (the lifecycle hygiene
      // specs assert destroy()/re-init keep both bounded).
      counts: function () {
        return { widgets: Object.keys(kiwiWidgets).length, resetHooks: kiwiResetHooks.length };
      },
      copySupportedConfiguration: kiwiCopySupportedConfiguration,
      clearModuleBackoff: kiwiClearModuleBackoff,
      findGlueSource: kiwiFindGlueSource,
      embeddedWorkerSource: kiwiEmbeddedWorkerSource,
      buildClientContext: kiwiBuildClientContext,
      boundBytes: kiwiBoundBytes,
      // The DOM scan, exposed so a reused driver copy (Turbo/htmx
      // navigation) can initialize the newly parsed widgets without
      // re-binding the core. initWidget is idempotent per element, so a
      // scan over an already-live subtree is a no-op for live widgets.
      scan: kiwiScan
    }
  };
  // Same own-property install as the public API: a clobbered
  // `__kiwiCaptchaCore` named property must never shadow the real bridge
  // on read (lazy modules would fall back to their degraded paths and the
  // worker tier would silently disappear).
  try {
    Object.defineProperty(window, "__kiwiCaptchaCore", {
      value: kiwiBridge,
      writable: true,
      configurable: true,
      enumerable: true
    });
  } catch (e) {
    window.__kiwiCaptchaCore = kiwiBridge;
  }
  function kiwiScan(root) {
    // Turbo/htmx navigation swaps the DOM without destroy(): a widget
    // element removed from the document keeps its registry record, so an
    // in-flight generation would run on against a detached node and the
    // record would keep counting as live. Cancel and delete every record
    // whose element is disconnected BEFORE scanning (the same
    // cancel-then-delete mirror kiwiDestroy() uses).
    for (var deadId in kiwiWidgets) {
      var deadRecord = kiwiWidgets[deadId];
      if (deadRecord && deadRecord.W && !deadRecord.W.isConnected) {
        kiwiCancelGeneration(deadId);
        delete kiwiWidgets[deadId];
      }
    }
    (root || document).querySelectorAll("[data-kiwi-widget]").forEach(function (W) {
      // No pointerdown-only activation: after a reset or settled
      // failure the widget is idle; the native Retry button is the
      // reacquire control for EVERY input method.
      initWidget(W);
    });
  }
  var runInit = function() { kiwiScan(document); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runInit); else runInit();
})();


