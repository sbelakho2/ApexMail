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
  .kiwi-widget {{
    --kiwi-brand: #e11d48;
    --kiwi-brand-light: #fff1f2;
    --kiwi-success: #10b981;
    --kiwi-success-light: #ecfdf5;
    --kiwi-error: #ef4444;
    --kiwi-bg: #ffffff;
    --kiwi-text: #1e293b;
    --kiwi-text-muted: #64748b;
    --kiwi-border: #f1f5f9;
    --kiwi-radius: 16px;
    --kiwi-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);

    display: flex;
    align-items: center;
    gap: 16px;
    padding: 16px;
    background: var(--kiwi-bg);
    border: 1px solid var(--kiwi-border);
    border-radius: var(--kiwi-radius);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: var(--kiwi-text);
    box-shadow: var(--kiwi-shadow);
    transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    width: 100%;
    max-width: 420px;
    position: relative;
    overflow: hidden;
    box-sizing: border-box;
    cursor: default;
    user-select: none;
  }}
  @media (prefers-color-scheme: dark) {{
    .kiwi-widget {{
      --kiwi-bg: #0f172a;
      --kiwi-text: #f8fafc;
      --kiwi-text-muted: #94a3b8;
      --kiwi-border: #1e293b;
      --kiwi-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.4);
    }}
    .kiwi-icon-box {{ background: linear-gradient(135deg, #4c0519, #881337) !important; }}
    .kiwi-pill {{ background: #1e293b !important; color: #94a3b8 !important; border-color: #334155 !important; }}
    .kiwi-progress-container {{ background: #1e293b !important; }}
  }}
  .kiwi-widget:hover {{ transform: translateY(-2px); box-shadow: 0 10px 20px -5px rgba(0,0,0,0.1); }}
  .kiwi-widget * {{ box-sizing: border-box; }}
  .kiwi-icon-box {{
    flex-shrink: 0;
    width: 48px;
    height: 48px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #fff1f2, #ffe4e6);
    color: var(--kiwi-brand);
    transition: all 0.5s cubic-bezier(0.68, -0.55, 0.265, 1.55);
    position: relative;
  }}
  .kiwi-widget[data-state="solving"] .kiwi-icon-box {{ animation: kiwi-pulse 2s infinite ease-in-out; }}
  .kiwi-widget[data-state="done"] .kiwi-icon-box {{
    background: linear-gradient(135deg, #d1fae5, #10b981) !important;
    color: #ffffff !important;
    transform: rotate(360deg) scale(1.1);
  }}
  @keyframes kiwi-pulse {{ 0% {{ transform: scale(1); }} 50% {{ transform: scale(1.05); }} 100% {{ transform: scale(1); }} }}

  .kiwi-content {{ flex: 1; min-width: 0; }}
  .kiwi-header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }}
  .kiwi-status {{ font-size: 14px; font-weight: 600; color: var(--kiwi-text); letter-spacing: -0.01em; }}
  .kiwi-pill {{
    font-size: 10px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 3px 10px;
    border-radius: 20px;
    background: #f8fafc;
    color: #64748b;
    border: 1px solid #e2e8f0;
    transition: all 0.3s ease;
  }}
  .kiwi-widget[data-state="solving"] .kiwi-pill {{ background: #fff1f2 !important; color: #e11d48 !important; border-color: #fda4af !important; }}
  .kiwi-widget[data-state="done"] .kiwi-pill {{ background: #ecfdf5 !important; color: #059669 !important; border-color: #6ee7b7 !important; }}

  .kiwi-progress-container {{ height: 6px; width: 100%; border-radius: 3px; background: #f1f5f9; overflow: hidden; position: relative; }}
  .kiwi-progress-fill {{
    height: 100%;
    background: linear-gradient(90deg, var(--kiwi-brand), #fb7185);
    transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1);
    width: 0%;
    border-radius: 3px;
  }}
  .kiwi-widget[data-state="done"] .kiwi-progress-fill {{ background: linear-gradient(90deg, #10b981, #34d399); }}

  .kiwi-footer {{ display: flex; justify-content: space-between; align-items: center; margin-top: 10px; }}
  .kiwi-hint {{ font-size: 11px; color: var(--kiwi-text-muted); font-weight: 500; margin: 0; opacity: 0.8; }}
  .kiwi-countdown {{ font-size: 10px; font-weight: 800; color: var(--kiwi-brand); font-variant-numeric: tabular-nums; }}

  /* Whimsy: Sparkles on completion */
  .kiwi-sparkle {{ position: absolute; width: 4px; height: 4px; border-radius: 50%; background: #fbbf24; opacity: 0; pointer-events: none; }}
  .kiwi-widget[data-state="done"] .kiwi-sparkle {{ animation: sparkle-fly 0.8s ease-out forwards; }}
  @keyframes sparkle-fly {{
    0% {{ transform: translate(0,0) scale(0); opacity: 1; }}
    100% {{ transform: translate(var(--tx), var(--ty)) scale(1.5); opacity: 0; }}
  }}
</style>
<div class="kiwi-widget" id="kiwicaptcha-widget" data-kiwi-widget role="status" aria-live="polite" aria-label="Security verification" data-state="idle">
  <div class="kiwi-icon-box" data-kiwi-icon>
    {svg}
    <div class="kiwi-sparkle" style="--tx:-20px;--ty:-20px"></div>
    <div class="kiwi-sparkle" style="--tx:20px;--ty:-15px"></div>
    <div class="kiwi-sparkle" style="--tx:15px;--ty:20px"></div>
    <div class="kiwi-sparkle" style="--tx:-15px;--ty:15px"></div>
  </div>
  <div class="kiwi-content">
    <div class="kiwi-header">
      <span class="kiwi-status" data-kiwi-status>Preparing...</span>
      <span class="kiwi-pill" data-kiwi-pill>Idle</span>
    </div>
    <div class="kiwi-progress-container">
      <div class="kiwi-progress-fill" data-kiwi-fill></div>
    </div>
    <div class="kiwi-footer">
      <p class="kiwi-hint" data-kiwi-hint>Privacy-first verification by Bel Consulting.</p>
      <span class="kiwi-countdown" data-kiwi-countdown></span>
    </div>
  </div>
  <input type="hidden" name="kiwi__token" id="kiwi-token-input" value="" />
</div>
<script>
{wasm_embed}
</script>
<script>
(function() {{
  var W = document.querySelector("[data-kiwi-widget]");
  if (!W || W.dataset.kiwiStarted) return;
  W.dataset.kiwiStarted = "1";
  var statusEl = W.querySelector("[data-kiwi-status]");
  var pillEl = W.querySelector("[data-kiwi-pill]");
  var fillEl = W.querySelector("[data-kiwi-fill]");
  var hintEl = W.querySelector("[data-kiwi-hint]");
  var countdownEl = W.querySelector("[data-kiwi-countdown]");
  var tokenEl = document.getElementById("kiwi-token-input");
  var encoder = new TextEncoder();

  function setStatus(label, pillText, state) {{
    if (statusEl) statusEl.textContent = label;
    if (pillEl) pillEl.textContent = pillText;
    if (W) W.setAttribute("data-state", state);
  }}
  function setHint(text) {{ if (hintEl) hintEl.textContent = text; }}
  function setProgress(pct) {{
    if (fillEl) fillEl.style.width = Math.max(0, Math.min(100, pct)) + "%";
  }}

  // ── Interaction telemetry ────────────────────────────────────────────
  // Only DISCRETE, human-initiated events are recorded for the entropy
  // check: pointerdown, non-repeat keydown, wheel, click. Coalesced
  // mousemove and OS key auto-repeat are excluded — both produce naturally
  // uniform intervals and would otherwise trigger false bot positives.
  var mouseEvents = 0, keyEvents = 0;
  var eventTimings = [];
  function recordEvent(e) {{
    if (e.type === "keydown" && e.repeat) return;
    if (eventTimings.length < 50) eventTimings.push(Math.round(performance.now()));
    if (e.type === "keydown") keyEvents++;
    else mouseEvents++;
  }}
  document.addEventListener("pointerdown", recordEvent, {{passive:true}});
  document.addEventListener("keydown", recordEvent, {{passive:true}});
  document.addEventListener("wheel", recordEvent, {{passive:true}});
  document.addEventListener("click", recordEvent, {{passive:true}});
  document.addEventListener("touchstart", recordEvent, {{passive:true}});

  // ── Optimized synchronous SHA-256 (pure JS, recycled buffers) ───────
  //    The WASM solver is preferred; this is the fallback for browsers
  //    without WebAssembly.
  var _h = new Uint32Array(8);
  var _w = new Uint32Array(64);
  var _k = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);

  function sha256sync(data, result) {{
    _h[0] = 0x6a09e667; _h[1] = 0xbb67ae85; _h[2] = 0x3c6ef372; _h[3] = 0xa54ff53a;
    _h[4] = 0x510e527f; _h[5] = 0x9b05688c; _h[6] = 0x1f83d9ab; _h[7] = 0x5be0cd19;

    var l = data.length * 8;
    var padLen = (data.length % 64 < 56) ? (56 - data.length % 64) : (120 - data.length % 64);
    var msg = new Uint8Array(data.length + padLen + 8);
    msg.set(data);
    msg[data.length] = 0x80;
    var view = new DataView(msg.buffer);
    view.setUint32(msg.length - 4, l, false);

    var a, b, c, d, e, f, g, hh, s0, s1, ch, maj, t1, t2;
    for (var i = 0; i < msg.length; i += 64) {{
      for (var j = 0; j < 16; j++) {{
        _w[j] = view.getUint32(i + j * 4, false);
      }}
      for (j = 16; j < 64; j++) {{
        var x = _w[j - 15];
        s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var y = _w[j - 2];
        s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        _w[j] = (_w[j - 16] + s0 + _w[j - 7] + s1) | 0;
      }}
      a = _h[0]; b = _h[1]; c = _h[2]; d = _h[3]; e = _h[4]; f = _h[5]; g = _h[6]; hh = _h[7];
      for (j = 0; j < 64; j++) {{
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ch = (e & f) ^ (~e & g);
        t1 = (hh + s1 + ch + _k[j] + _w[j]) | 0;
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = (s0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }}
      _h[0] = (_h[0] + a) | 0; _h[1] = (_h[1] + b) | 0; _h[2] = (_h[2] + c) | 0; _h[3] = (_h[3] + d) | 0;
      _h[4] = (_h[4] + e) | 0; _h[5] = (_h[5] + f) | 0; _h[6] = (_h[6] + g) | 0; _h[7] = (_h[7] + hh) | 0;
    }}
    for (i = 0; i < 8; i++) {{
      result[i * 4] = (_h[i] >>> 24) & 0xff;
      result[i * 4 + 1] = (_h[i] >>> 16) & 0xff;
      result[i * 4 + 2] = (_h[i] >>> 8) & 0xff;
      result[i * 4 + 3] = _h[i] & 0xff;
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

  var _hashBuf = new Uint8Array(32);
  var _inputBuf = null;

  // SHA-256(prefix || counter || salt) — synchronous.
  function deriveHash(prefixBytes, counter, saltBytes) {{
    var cStr = counter.toString();
    var cLen = cStr.length;
    var totalLen = prefixBytes.length + cLen + saltBytes.length;
    if (!_inputBuf || _inputBuf.length !== totalLen) _inputBuf = new Uint8Array(totalLen);
    _inputBuf.set(prefixBytes, 0);
    for (var i = 0; i < cLen; i++) _inputBuf[prefixBytes.length + i] = cStr.charCodeAt(i);
    _inputBuf.set(saltBytes, prefixBytes.length + cLen);
    sha256sync(_inputBuf, _hashBuf);
    return _hashBuf;
  }}

  // Optimized yielding using MessageChannel (bypasses 4ms setTimeout clamping)
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
    try {{
      wasm = await wasmLoader.load();
      // Surface Rust panics via console.error instead of silent traps.
      if (wasm.init_panic_hook) {{
        try {{ wasm.init_panic_hook(); }} catch (_) {{}}
      }}
      return wasm;
    }} catch (e) {{
      console.warn("KiwiCaptcha: WASM init failed, falling back to JS", e);
      return null;
    }}
  }}

  // Copy bytes into wasm memory (explicit malloc/free — the raw-pointer ABI
  // avoids wasm-bindgen's Vec/slice glue entirely).
  function wasmAlloc(w, bytes) {{
    var ptr = w.__wbindgen_malloc(bytes.length, 1);
    new Uint8Array(w.memory.buffer).set(bytes, ptr);
    return ptr;
  }}
  function wasmFree(w, ptr, len) {{
    if (w.__wbindgen_free) w.__wbindgen_free(ptr, len, 1);
  }}

  // Solver cap: 5M hashes for SHA-256 (99.1% success at 20 bits). Argon2id
  // uses its own tighter cap (see solveArgon2) because every hash is slow.
  var MAX_SHA_HASHES = 5000000;

  function solve(prefix, saltBytes, targetBits, algorithm, m_kib, t, p) {{
    return new Promise(async function(resolve) {{
      var prefixBytes = encoder.encode(prefix);
      var expectedHashes = Math.pow(2, targetBits);
      var solveStart = performance.now();
      var counter = 0;
      var w = await initWasm();

      if (algorithm === "argon2id") {{
        // Argon2id has no JS fallback (memory-hard hashing is only feasible
        // in WASM). If the WASM solver is unavailable or the parameters are
        // out of range, the challenge cannot be solved — fail cleanly.
        if (!w || !w.solve_argon2_chunk || !w.__wbindgen_malloc || m_kib < 8 * p) {{
          resolve(null);
          return;
        }}
        // Cap the search: expected hashes * 8 with a floor, bounded so a
        // pathological challenge cannot peg the CPU forever.
        var argMax = Math.min(MAX_SHA_HASHES, Math.max(1024, expectedHashes * 8));
        // Chunk to yield to the UI; each Argon2 hash is slow, so keep chunks
        // small (16 hashes) for responsive progress.
        var CHUNK = 16;
        function argon2Chunk() {{
          try {{
            var pp = wasmAlloc(w, prefixBytes);
            var sp = wasmAlloc(w, saltBytes);
            var res = w.solve_argon2_chunk(pp, prefixBytes.length, sp, saltBytes.length, targetBits, m_kib, t, p, counter, CHUNK);
            wasmFree(w, pp, prefixBytes.length);
            wasmFree(w, sp, saltBytes.length);
            if (res !== -1) {{
              resolve({{ counter: res, duration: Math.round(performance.now() - solveStart) }});
              return;
            }}
          }} catch (e) {{
            console.error("KiwiCaptcha: Argon2 WASM solve failed", e);
            resolve(null);
            return;
          }}
          counter += CHUNK;
          if (counter >= argMax) {{ resolve(null); return; }}
          setProgress(Math.min(95, (counter * 100) / expectedHashes));
          fastYield(argon2Chunk);
        }}
        fastYield(argon2Chunk);
        return;
      }}

      // SHA-256: WASM chunked solver with a pure-JS fallback.
      var CHUNK = w && w.solve_sha256_chunk ? 50000 : 8000;
      function chunk() {{
        if (w && w.solve_sha256_chunk && w.__wbindgen_malloc) {{
          try {{
            var pp = wasmAlloc(w, prefixBytes);
            var sp = wasmAlloc(w, saltBytes);
            var res = w.solve_sha256_chunk(pp, prefixBytes.length, sp, saltBytes.length, targetBits, counter, CHUNK);
            wasmFree(w, pp, prefixBytes.length);
            wasmFree(w, sp, saltBytes.length);
            if (res !== -1) {{
              resolve({{ counter: res, duration: Math.round(performance.now() - solveStart) }});
              return;
            }}
            counter += CHUNK;
          }} catch (e) {{
            console.error("KiwiCaptcha: WASM solve failed, falling back", e);
            w = null;
          }}
        }}
        if (!w) {{
          var end = counter + CHUNK;
          if (end > MAX_SHA_HASHES) end = MAX_SHA_HASHES;
          for (; counter < end; counter++) {{
            if (leadingZeros(deriveHash(prefixBytes, counter, saltBytes)) >= targetBits) {{
              resolve({{ counter: counter, duration: Math.round(performance.now() - solveStart) }});
              return;
            }}
          }}
        }}
        if (counter >= MAX_SHA_HASHES) {{ resolve(null); return; }}
        setProgress(Math.min(92, (counter * 100) / expectedHashes));
        fastYield(chunk);
      }}
      fastYield(chunk);
    }});
  }}

  // ── Widget driver ──────────────────────────────────────────────────
  var countdownTimer = null;
  function startCountdown(ttlSecs) {{
    if (!countdownEl) return;
    var remaining = ttlSecs;
    function tick() {{ if (remaining > 0) countdownEl.textContent = remaining + "s"; }}
    tick();
    stopCountdown();
    countdownTimer = setInterval(function() {{
      remaining--;
      if (remaining < 0) {{ countdownEl.textContent = "expired"; clearInterval(countdownTimer); countdownTimer = null; return; }}
      countdownEl.textContent = remaining + "s";
    }}, 1000);
  }}
  function stopCountdown() {{
    if (countdownTimer) {{ clearInterval(countdownTimer); countdownTimer = null; }}
    if (countdownEl) countdownEl.textContent = "";
  }}
  function fail(msg) {{
    setStatus(msg || "Verification failed", "Failed", "failed");
    setHint("Please reload the page to retry.");
    setProgress(0);
    if (tokenEl) tokenEl.value = "";
    stopCountdown();
  }}

  async function run() {{
    try {{
      setStatus("Requesting challenge\u2026", "Connecting", "connecting");
      setHint("Contacting verification server\u2026");
      var scope = "login";
      var p = window.location.pathname.toLowerCase();
      if (p.indexOf("signup")>=0||p.indexOf("register")>=0) scope="signup";
      else if (p.indexOf("forgot")>=0) scope="forgot-password";
      else if (p.indexOf("reset")>=0) scope="reset-password";

      var resp = await fetch("/api/kcaptcha/challenge", {{
        method:"POST", headers:{{"Content-Type":"application/json"}},
        body: JSON.stringify({{scope:scope}})
      }});
      if (!resp.ok) throw new Error("challenge request failed: " + resp.status);
      var data = await resp.json();
      if (data.ttlSecs) startCountdown(data.ttlSecs);

      // The server explicitly states the algorithm ("sha256" | "argon2id").
      var algorithm = data.algorithm || "sha256";
      setStatus("Proof-of-work verification\u2026", "Verifying", "solving");
      setHint(algorithm === "argon2id" ? "Running a memory-hard hash challenge locally." : "Running a short hash challenge locally.");
      var result = await solve(data.prefix, b64decode(data.salt), data.targetBits, algorithm, data.mKib || 0, data.t || 1, data.p || 1);
      if (!result) throw new Error("solver exhausted");

      var telemetry = {{
        wd: navigator.webdriver === true,
        hc: navigator.hardwareConcurrency || 0,
        dm: navigator.deviceMemory || 0,
        pl: navigator.plugins ? navigator.plugins.length : 0,
        la: navigator.language || "",
        cd: window.screen.colorDepth || 0,
        me: mouseEvents, ke: keyEvents,
        et: eventTimings,
        sw: window.screen.width || 0, sh: window.screen.height || 0,
        iw: window.innerWidth || 0, ih: window.innerHeight || 0
      }};
      var plain = data.nonce + "." + result.counter + "." + result.duration + "." + JSON.stringify(telemetry);
      var token = btoa(plain);
      if (tokenEl) tokenEl.value = token;
      setStatus("Verified \u2014 you may continue", "Verified", "done");
      setHint("No tracking. No third parties. Computed locally.");
      setProgress(100);
      stopCountdown();
    }} catch (e) {{
      fail("Verification failed \u2014 " + (e.message || "please reload"));
    }}
  }}

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run);
  else run();
}})();
</script>"#,
        svg = svg,
        wasm_embed = KIWI_WASM_EMBED,
    )
}
