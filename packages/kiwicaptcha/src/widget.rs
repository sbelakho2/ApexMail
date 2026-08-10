//! KiwiCaptcha widget — premium, zero-dependency proof-of-work security.
//! Developed by Bel Consulting OÜ.
//!
//! The widget renders a self-contained `<div>` with an inline `<script>` that:
//! 1. Fetches a challenge from `/api/kcaptcha/challenge`
//! 2. Solves the proof-of-work (WASM solver with a pure-JS SHA-256 fallback)
//! 3. Submits a signed solution token via a hidden input.
//!
//! The solver dispatches on the challenge's explicit `algorithm` field
//! (`"sha256"` or `"argon2id"`), never on a numeric heuristic, so it always
//! computes exactly what the server will verify.

use crate::kiwi_mark_svg;

/// The generated WASM solver + glue, embedded as a self-contained script that
/// exposes `window.__kiwiCaptchaWasm.load()` (returns the wasm exports).
/// Regenerate with `packages/kiwicaptcha-wasm/build.sh`.
const KIWI_WASM_EMBED: &str = include_str!("../../kiwicaptcha-wasm/assets/kiwicaptcha-wasm.js");

/// Render the premium KiwiCaptcha widget HTML block.
pub fn kiwi_widget_html() -> String {
    let svg = kiwi_mark_svg();
    format!(
        r#"<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
  .kiwi-container {{
    --kiwi-primary: #f43f5e;
    --kiwi-primary-rgb: 244, 63, 94;
    --kiwi-success: #10b981;
    --kiwi-bg: #ffffff;
    --kiwi-text: #0f172a;
    --kiwi-text-muted: #64748b;
    --kiwi-border: #e2e8f0;
    --kiwi-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.05), 0 4px 6px -2px rgba(0, 0, 0, 0.02);
    --kiwi-radius: 20px;
    
    display: inline-flex;
    align-items: center;
    width: 100%;
    max-width: 440px;
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    position: relative;
    box-sizing: border-box;
  }}
  @media (prefers-color-scheme: dark) {{
    .kiwi-container {{
      --kiwi-bg: #1e293b;
      --kiwi-text: #f8fafc;
      --kiwi-text-muted: #94a3b8;
      --kiwi-border: #334155;
      --kiwi-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.1);
    }}
  }}
  .kiwi-widget {{
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 14px 18px;
    background: var(--kiwi-bg);
    border: 1px solid var(--kiwi-border);
    border-radius: var(--kiwi-radius);
    color: var(--kiwi-text);
    box-shadow: var(--kiwi-shadow);
    transition: all 0.5s cubic-bezier(0.16, 1, 0.3, 1);
    width: 100%;
    position: relative;
    overflow: hidden;
    cursor: default;
    user-select: none;
  }}
  .kiwi-widget:hover {{ transform: translateY(-2px); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); border-color: var(--kiwi-primary); }}
  
  .kiwi-icon-wrapper {{
    flex-shrink: 0;
    width: 52px;
    height: 52px;
    border-radius: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(var(--kiwi-primary-rgb), 0.08);
    color: var(--kiwi-primary);
    transition: all 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
    position: relative;
  }}
  .kiwi-widget[data-state="solving"] .kiwi-icon-wrapper {{ animation: kiwi-float 2s infinite ease-in-out; }}
  .kiwi-widget[data-state="done"] .kiwi-icon-wrapper {{
    background: var(--kiwi-success) !important;
    color: #ffffff !important;
    transform: rotate(360deg) scale(1.1);
  }}
  @keyframes kiwi-float {{ 0%, 100% {{ transform: translateY(0); }} 50% {{ transform: translateY(-4px); }} }}
  
  .kiwi-main {{ flex: 1; min-width: 0; }}
  .kiwi-top {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }}
  .kiwi-label {{ font-size: 15px; font-weight: 700; color: var(--kiwi-text); letter-spacing: -0.02em; }}
  .kiwi-badge {{
    font-size: 9px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    padding: 2px 8px;
    border-radius: 6px;
    background: var(--kiwi-border);
    color: var(--kiwi-text-muted);
    transition: all 0.4s ease;
  }}
  .kiwi-widget[data-state="solving"] .kiwi-badge {{ background: rgba(var(--kiwi-primary-rgb), 0.15) !important; color: var(--kiwi-primary) !important; }}
  .kiwi-widget[data-state="done"] .kiwi-badge {{ background: rgba(16, 185, 129, 0.15) !important; color: var(--kiwi-success) !important; }}
  
  .kiwi-track {{ height: 4px; width: 100%; border-radius: 2px; background: var(--kiwi-border); overflow: hidden; }}
  .kiwi-bar {{
    height: 100%;
    background: linear-gradient(90deg, var(--kiwi-primary), #fda4af);
    transition: width 0.6s cubic-bezier(0.65, 0, 0.35, 1);
    width: 0%;
  }}
  .kiwi-widget[data-state="done"] .kiwi-bar {{ background: var(--kiwi-success); }}
  
  .kiwi-bottom {{ display: flex; justify-content: space-between; align-items: center; margin-top: 8px; }}
  .kiwi-info {{ font-size: 11px; color: var(--kiwi-text-muted); font-weight: 500; margin: 0; }}
  .kiwi-timer {{ font-size: 10px; font-weight: 700; color: var(--kiwi-primary); font-variant-numeric: tabular-nums; }}
  
  /* Premium Finish Anim */
  .kiwi-glow {{
    position: absolute;
    top: 0; left: -100%; width: 50%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
    transform: skewX(-25deg);
    pointer-events: none;
  }}
  .kiwi-widget[data-state="done"] .kiwi-glow {{ animation: kiwi-shine 1s ease-in-out forwards; }}
  @keyframes kiwi-shine {{ 100% {{ left: 200%; }} }}
</style>
<div class="kiwi-container" id="kiwicaptcha-root">
  <div class="kiwi-widget" data-kiwi-widget data-state="idle" role="status" aria-live="polite">
    <div class="kiwi-icon-wrapper">
      {svg}
      <div class="kiwi-glow"></div>
    </div>
    <div class="kiwi-main">
      <div class="kiwi-top">
        <span class="kiwi-label" data-kiwi-label>Security Check</span>
        <span class="kiwi-badge" data-kiwi-badge>Idle</span>
      </div>
      <div class="kiwi-track">
        <div class="kiwi-bar" data-kiwi-bar></div>
      </div>
      <div class="kiwi-bottom">
        <p class="kiwi-info" data-kiwi-info>Protected by KiwiCaptcha</p>
        <span class="kiwi-timer" data-kiwi-timer></span>
      </div>
    </div>
    <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
  </div>
</div>
<script>
{wasm_embed}
</script>
<script>
(function() {{
  var encoder = new TextEncoder();
  
  // ── Global Telemetry ────────────────────────────────────────────────
  var mouseEvents = 0, keyEvents = 0, eventTimings = [];
  function recordEvent(e) {{
    if (e.type === "keydown" && e.repeat) return;
    if (eventTimings.length < 50) eventTimings.push(Math.round(performance.now()));
    if (e.type === "keydown") keyEvents++; else mouseEvents++;
  }}
  if (typeof window !== "undefined" && !window.__kiwiTelemetry) {{
    window.__kiwiTelemetry = true;
    document.addEventListener("pointerdown", recordEvent, {{passive:true}});
    document.addEventListener("keydown", recordEvent, {{passive:true}});
    document.addEventListener("wheel", recordEvent, {{passive:true}});
    document.addEventListener("click", recordEvent, {{passive:true}});
    document.addEventListener("touchstart", recordEvent, {{passive:true}});
  }}

  // ── Optimized yielding ──────────────────────────────────────────────
  var channel = new MessageChannel();
  var yieldQueue = [];
  channel.port1.onmessage = function() {{ if (yieldQueue.length) yieldQueue.shift()(); }};
  function fastYield(fn) {{ yieldQueue.push(fn); channel.port2.postMessage(0); }}

  // ── WASM solver ──────────────────────────────────────────────────────
  var wasm = null;
  var wasmLoader = (typeof window !== "undefined" && window.__kiwiCaptchaWasm) ? window.__kiwiCaptchaWasm : null;
  async function initWasm() {{
    if (wasm) return wasm;
    if (!wasmLoader) return null;
    try {{ wasm = await wasmLoader.load(); if (wasm.init_panic_hook) wasm.init_panic_hook(); return wasm; }}
    catch (e) {{ console.warn("KiwiCaptcha: WASM init failed", e); return null; }}
  }}
  // Copy bytes into wasm memory (explicit alloc/free — the raw-pointer ABI
  // avoids wasm-bindgen's Vec/slice glue entirely). Uses the crate's own
  // `alloc`/`dealloc` exports (stable names, never DCE'd by wasm-opt) and
  // falls back to wasm-bindgen's generated symbols when present.
  function wasmAlloc(w, bytes) {{
    var ptr = 0;
    if (w.alloc) {{
      ptr = w.alloc(bytes.length);
    }} else if (w.__wbindgen_malloc) {{
      ptr = w.__wbindgen_malloc(bytes.length, 1);
    }} else {{
      return 0;
    }}
    new Uint8Array(w.memory.buffer).set(bytes, ptr);
    return ptr;
  }}
  function wasmFree(w, ptr, len) {{
    if (!ptr) return;
    if (w.dealloc) {{
      try {{ w.dealloc(ptr, len); }} catch (_) {{}}
    }} else if (w.__wbindgen_free) {{
      w.__wbindgen_free(ptr, len, 1);
    }}
  }}

  // ── Optimized synchronous SHA-256 (pure JS, recycled buffers) ───────
  var _h = new Uint32Array(8), _w = new Uint32Array(64);
  var _k = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function sha256sync(data, result) {{
    _h[0] = 0x6a09e667; _h[1] = 0xbb67ae85; _h[2] = 0x3c6ef372; _h[3] = 0xa54ff53a;
    _h[4] = 0x510e527f; _h[5] = 0x9b05688c; _h[6] = 0x1f83d9ab; _h[7] = 0x5be0cd19;
    var l = data.length * 8;
    var padLen = (data.length % 64 < 56) ? (56 - data.length % 64) : (120 - data.length % 64);
    var msg = new Uint8Array(data.length + padLen + 8);
    msg.set(data); msg[data.length] = 0x80;
    var view = new DataView(msg.buffer);
    view.setUint32(msg.length - 4, l, false);
    var a, b, c, d, e, f, g, hh, s0, s1, ch, maj, t1, t2;
    for (var i = 0; i < msg.length; i += 64) {{
      for (var j = 0; j < 16; j++) _w[j] = view.getUint32(i + j * 4, false);
      for (j = 16; j < 64; j++) {{
        var x = _w[j - 15]; s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var y = _w[j - 2]; s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        _w[j] = (_w[j - 16] + s0 + _w[j - 7] + s1) | 0;
      }}
      a = _h[0]; b = _h[1]; c = _h[2]; d = _h[3]; e = _h[4]; f = _h[5]; g = _h[6]; hh = _h[7];
      for (j = 0; j < 64; j++) {{
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ch = (e & f) ^ (~e & g); t1 = (hh + s1 + ch + _k[j] + _w[j]) | 0;
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        maj = (a & b) ^ (a & c) ^ (b & c); t2 = (s0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }}
      _h[0] = (_h[0] + a) | 0; _h[1] = (_h[1] + b) | 0; _h[2] = (_h[2] + c) | 0; _h[3] = (_h[3] + d) | 0;
      _h[4] = (_h[4] + e) | 0; _h[5] = (_h[5] + f) | 0; _h[6] = (_h[6] + g) | 0; _h[7] = (_h[7] + hh) | 0;
    }}
    for (i = 0; i < 8; i++) {{
      result[i * 4] = (_h[i] >>> 24) & 0xff; result[i * 4 + 1] = (_h[i] >>> 16) & 0xff;
      result[i * 4 + 2] = (_h[i] >>> 8) & 0xff; result[i * 4 + 3] = _h[i] & 0xff;
    }}
  }}
  function b64decode(str) {{
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    return Uint8Array.from(atob(str), function(c) {{ return c.charCodeAt(0); }});
  }}
  function leadingZeros(bytes) {{
    var n = 0;
    for (var i = 0; i < bytes.length; i++) {{
      if (bytes[i] === 0) {{ n += 8; }}
      else {{ var b = bytes[i]; while ((b & 128) === 0) {{ n++; b <<= 1; }} break; }}
    }}
    return n;
  }}
  var _hashBuf = new Uint8Array(32), _inputBuf = null;
  function deriveHash(prefixBytes, counter, saltBytes) {{
    var cStr = counter.toString(), cLen = cStr.length, totalLen = prefixBytes.length + cLen + saltBytes.length;
    if (!_inputBuf || _inputBuf.length !== totalLen) _inputBuf = new Uint8Array(totalLen);
    _inputBuf.set(prefixBytes, 0);
    for (var i = 0; i < cLen; i++) _inputBuf[prefixBytes.length + i] = cStr.charCodeAt(i);
    _inputBuf.set(saltBytes, prefixBytes.length + cLen);
    sha256sync(_inputBuf, _hashBuf);
    return _hashBuf;
  }}

  var MAX_SHA_HASHES = 5000000;
  function solve(prefix, saltBytes, targetBits, algorithm, m_kib, t, p, onProgress) {{
    return new Promise(async function(resolve) {{
      var prefixBytes = encoder.encode(prefix), expectedHashes = Math.pow(2, targetBits), solveStart = performance.now(), counter = 0;
      var w = await initWasm();
      // Persistent WASM-side buffers: allocated once and reused across all
      // chunks, eliminating malloc/free churn on every 50k-hash iteration
      // (the hottest loop in the SHA-256 solver).
      var pp = 0, sp = 0;
      function ensureBuffers() {{
        if (w && w.__wbindgen_malloc && pp === 0) {{
          pp = wasmAlloc(w, prefixBytes); sp = wasmAlloc(w, saltBytes);
        }}
      }}
      if (algorithm === "argon2id") {{
        if (!w || !w.solve_argon2_chunk || !w.__wbindgen_malloc || m_kib < 8 * p) {{ resolve(null); return; }}
        var argMax = Math.min(MAX_SHA_HASHES, Math.max(1024, expectedHashes * 8)), CHUNK = 16;
        ensureBuffers();
        function argon2Chunk() {{
          try {{
            var res = w.solve_argon2_chunk(pp, prefixBytes.length, sp, saltBytes.length, targetBits, m_kib, t, p, counter, CHUNK);
            if (res !== -1) {{ wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); resolve({{ counter: res, duration: Math.round(performance.now() - solveStart) }}); return; }}
          }} catch (e) {{ wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); console.error("KiwiCaptcha: Argon2 solve failed", e); resolve(null); return; }}
          counter += CHUNK; if (counter >= argMax) {{ wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); resolve(null); return; }}
          onProgress(Math.min(95, (counter * 100) / expectedHashes));
          fastYield(argon2Chunk);
        }}
        fastYield(argon2Chunk); return;
      }}
      var CHUNK = w && w.solve_sha256_chunk ? 50000 : 8000;
      function chunk() {{
        if (w && w.solve_sha256_chunk && w.__wbindgen_malloc) {{
          try {{
            ensureBuffers();
            var res = w.solve_sha256_chunk(pp, prefixBytes.length, sp, saltBytes.length, targetBits, counter, CHUNK);
            if (res !== -1) {{ wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); resolve({{ counter: res, duration: Math.round(performance.now() - solveStart) }}); return; }}
            counter += CHUNK;
          }} catch (e) {{ wasmFree(w, pp, prefixBytes.length); wasmFree(w, sp, saltBytes.length); console.error("KiwiCaptcha: WASM solve failed", e); w = null; }}
        }}
        if (!w) {{
          var end = Math.min(counter + CHUNK, MAX_SHA_HASHES);
          for (; counter < end; counter++) if (leadingZeros(deriveHash(prefixBytes, counter, saltBytes)) >= targetBits) {{
            resolve({{ counter: counter, duration: Math.round(performance.now() - solveStart) }}); return;
          }}
        }}
        if (counter >= MAX_SHA_HASHES) {{ resolve(null); return; }}
        onProgress(Math.min(92, (counter * 100) / expectedHashes));
        fastYield(chunk);
      }}
      fastYield(chunk);
    }});
  }}

  function initWidget(W) {{
    if (!W || W.dataset.kiwiStarted) return;
    W.dataset.kiwiStarted = "1";
    var statusEl = W.querySelector("[data-kiwi-label]"), pillEl = W.querySelector("[data-kiwi-badge]"), fillEl = W.querySelector("[data-kiwi-bar]"), hintEl = W.querySelector("[data-kiwi-info]"), countdownEl = W.querySelector("[data-kiwi-timer]"), tokenEl = W.querySelector("[data-kiwi-token]");
    function setStatus(label, pillText, state) {{ if (statusEl) statusEl.textContent = label; if (pillEl) pillEl.textContent = pillText; if (W) W.setAttribute("data-state", state); }}
    function setHint(text) {{ if (hintEl) hintEl.textContent = text; }}
    function setProgress(pct) {{ if (fillEl) fillEl.style.width = Math.max(0, Math.min(100, pct)) + "%"; }}
    
    var countdownTimer = null;
    function startCountdown(ttlSecs) {{
      var remaining = ttlSecs;
      var tick = function() {{ if (countdownEl) countdownEl.textContent = remaining > 0 ? remaining + "s" : "expired"; }};
      tick(); clearInterval(countdownTimer);
      countdownTimer = setInterval(function() {{ remaining--; tick(); if (remaining <= 0) clearInterval(countdownTimer); }}, 1000);
    }}
    function fail(msg) {{ setStatus(msg || "Failed", "Error", "failed"); setHint("Please reload to retry."); setProgress(0); if (tokenEl) tokenEl.value = ""; clearInterval(countdownTimer); }}

    async function run() {{
      try {{
        setStatus("Connecting\u2026", "Wait", "connecting");
        var scope = "login", p = window.location.pathname.toLowerCase();
        if (p.indexOf("signup")>=0||p.indexOf("register")>=0) scope="signup";
        else if (p.indexOf("forgot")>=0) scope="forgot-password";
        var resp = await fetch("/api/kcaptcha/challenge", {{ method:"POST", headers:{{"Content-Type":"application/json"}}, body: JSON.stringify({{scope:scope}}) }});
        if (!resp.ok) throw new Error("Challenge failed");
        var data = await resp.json();
        if (data.ttlSecs) startCountdown(data.ttlSecs);
        setStatus("Verifying\u2026", "Working", "solving");
        var result = await solve(data.prefix, b64decode(data.salt), data.targetBits, data.algorithm||"sha256", data.mKib||0, data.t||1, data.p||1, setProgress);
        if (!result) throw new Error("Exhausted");
        var telemetry = {{ wd: navigator.webdriver===true, hc: navigator.hardwareConcurrency||0, dm: navigator.deviceMemory||0, me: mouseEvents, ke: keyEvents, et: eventTimings, sw: window.screen.width, sh: window.screen.height }};
        tokenEl.value = btoa(data.nonce + "." + result.counter + "." + result.duration + "." + JSON.stringify(telemetry));
        setStatus("Verified", "Success", "done"); setHint("Human verified locally."); setProgress(100); clearInterval(countdownTimer); if (countdownEl) countdownEl.textContent = "";
      }} catch (e) {{ fail(e.message); }}
    }}
    run();
  }}

  window.KiwiCaptcha = {{ init: initWidget, render: function(s) {{ document.querySelectorAll(s).forEach(initWidget); }} }};
  var runInit = function() {{ document.querySelectorAll("[data-kiwi-widget]").forEach(initWidget); }};
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runInit); else runInit();
}})();
</script>"#,
        svg = svg,
        wasm_embed = KIWI_WASM_EMBED,
    )
}
