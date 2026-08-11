(function() {
  var encoder = new TextEncoder();
  
  // ── Global Telemetry ────────────────────────────────────────────────
  var mouseEvents = 0, keyEvents = 0, eventTimings = [];
  function recordEvent(e) {
    if (e.type === "keydown" && e.repeat) return;
    if (eventTimings.length < 50) eventTimings.push(Math.round(performance.now()));
    if (e.type === "keydown") keyEvents++; else mouseEvents++;
  }
  if (typeof window !== "undefined" && !window.__kiwiTelemetry) {
    window.__kiwiTelemetry = true;
    document.addEventListener("pointerdown", recordEvent, {passive:true});
    document.addEventListener("keydown", recordEvent, {passive:true});
    document.addEventListener("wheel", recordEvent, {passive:true});
    document.addEventListener("click", recordEvent, {passive:true});
    document.addEventListener("touchstart", recordEvent, {passive:true});
  }

  // ── Optimized yielding ──────────────────────────────────────────────
  var channel = new MessageChannel();
  var yieldQueue = [];
  channel.port1.onmessage = function() { if (yieldQueue.length) yieldQueue.shift()(); };
  function fastYield(fn) { yieldQueue.push(fn); channel.port2.postMessage(0); }

  // ── WASM solver ──────────────────────────────────────────────────────
  var wasm = null;
  var wasmLoader = (typeof window !== "undefined" && window.__kiwiCaptchaWasm) ? window.__kiwiCaptchaWasm : null;
  async function initWasm() {
    if (wasm) return wasm;
    if (!wasmLoader) return null;
    try { wasm = await wasmLoader.load(); if (wasm.init_panic_hook) wasm.init_panic_hook(); return wasm; }
    catch (e) { console.warn("KiwiCaptcha: WASM init failed", e); return null; }
  }
  // Copy bytes into wasm memory (explicit alloc/free — the raw-pointer ABI
  // avoids wasm-bindgen's Vec/slice glue entirely). Uses the crate's own
  // `alloc`/`dealloc` exports (stable names, never DCE'd by wasm-opt) and
  // falls back to wasm-bindgen's generated symbols when present.
  function wasmAlloc(w, bytes) {
    var ptr = 0;
    if (w.alloc) {
      ptr = w.alloc(bytes.length);
    } else if (w.__wbindgen_malloc) {
      ptr = w.__wbindgen_malloc(bytes.length, 1);
    } else {
      return 0;
    }
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
        return !!(w && w.solve_sha256_chunk && (w.alloc || w.__wbindgen_malloc));
      }
      function wasmAllocatorPresent() {
        return !!(w && (w.alloc || w.__wbindgen_malloc) && (w.dealloc || w.__wbindgen_free));
      }
      function ensureBuffers() {
        if (wasmAllocatorPresent() && pp === 0) {
          pp = wasmAlloc(w, prefixBytes); sp = wasmAlloc(w, saltBytes);
        }
      }
      if (algorithm === "argon2id") {
        if (!w || !w.solve_argon2_chunk || !wasmAllocatorPresent() || m_kib < 8 * p) { resolve(null); return; }
        var argMax = Math.min(MAX_SHA_HASHES, Math.max(1024, expectedHashes * 8)), CHUNK = 16;
        ensureBuffers();
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
            ensureBuffers();
            var res = w.solve_sha256_chunk(pp, prefixBytes.length, sp, saltBytes.length, targetBits, counter, CHUNK);
            if (res !== -1) { wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); resolve({ counter: res, duration: Math.round(performance.now() - solveStart) }); return; }
            counter += CHUNK;
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

  function initWidget(W) {
    if (!W || W.dataset.kiwiStarted) return;
    W.dataset.kiwiStarted = "1";
    var container = W.closest(".kiwi-container") || W;
    var statusEl = W.querySelector("[data-kiwi-label]"), pillEl = W.querySelector("[data-kiwi-badge]"), fillEl = W.querySelector("[data-kiwi-bar]"), hintEl = W.querySelector("[data-kiwi-info]"), countdownEl = W.querySelector("[data-kiwi-timer]"), tokenEl = W.querySelector("[data-kiwi-token]") || container.querySelector("[data-kiwi-token]");
    function setStatus(label, pillText, state) { if (statusEl) statusEl.textContent = label; if (pillEl) pillEl.textContent = pillText; if (W) W.setAttribute("data-state", state); }
    function setHint(text) { if (hintEl) hintEl.textContent = text; }
    function setProgress(pct) { if (fillEl) fillEl.setAttribute("data-progress", String(Math.max(0, Math.min(100, pct)))); }
    
    var countdownTimer = null;
    function startCountdown(ttlSecs) {
      var remaining = ttlSecs;
      var tick = function() { if (countdownEl) countdownEl.textContent = remaining > 0 ? remaining + "s" : "expired"; };
      tick(); clearInterval(countdownTimer);
      countdownTimer = setInterval(function() { remaining--; tick(); if (remaining <= 0) clearInterval(countdownTimer); }, 1000);
    }
    function fail(msg) { setStatus(msg || "Failed", "Error", "failed"); setHint("Please reload to retry."); setProgress(0); if (tokenEl) tokenEl.value = ""; clearInterval(countdownTimer); }

    async function run() {
      try {
        setStatus("Connecting\u2026", "Wait", "connecting");
        var endpoint = W.getAttribute("data-kiwi-endpoint") || container.getAttribute("data-kiwi-endpoint") || "/api/kcaptcha/challenge";
        var scope = W.getAttribute("data-kiwi-scope") || container.getAttribute("data-kiwi-scope");
        if (!scope) {
          scope = "login";
          var p = window.location.pathname.toLowerCase();
          if (p.indexOf("signup")>=0||p.indexOf("register")>=0) scope="signup";
          else if (p.indexOf("forgot")>=0) scope="forgot-password";
        }
        var resp = await fetch(endpoint, { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({scope:scope}) });
        if (!resp.ok) throw new Error("Challenge failed");
        var data = await resp.json();
        if (data.ttlSecs) startCountdown(data.ttlSecs);
        setStatus("Verifying\u2026", "Working", "solving");
        var result = await solve(data.prefix, b64decode(data.salt), data.targetBits, data.algorithm||"sha256", data.mKib||0, data.t||1, data.p||1, setProgress);
        if (!result) throw new Error("Exhausted");
        var telemetry = { wd: navigator.webdriver===true, hc: navigator.hardwareConcurrency||0, dm: navigator.deviceMemory||0, me: mouseEvents, ke: keyEvents, et: eventTimings, sw: window.screen.width, sh: window.screen.height };
        tokenEl.value = btoa(data.nonce + "." + result.counter + "." + result.duration + "." + JSON.stringify(telemetry));
        setStatus("Verified", "Success", "done"); setHint("Human verified locally."); setProgress(100); clearInterval(countdownTimer); if (countdownEl) countdownEl.textContent = "";
      } catch (e) { fail(e.message); }
    }
    run();
  }

  window.KiwiCaptcha = { init: initWidget, render: function(s) { document.querySelectorAll(s).forEach(initWidget); } };
  var runInit = function() { document.querySelectorAll("[data-kiwi-widget]").forEach(initWidget); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runInit); else runInit();
})();
