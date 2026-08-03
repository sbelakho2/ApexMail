//! KiwiCaptcha widget — server-rendered HTML with embedded Rust/WASM solver.
//!
//! The widget embeds the compiled WASM binary (base64), the wasm-bindgen JS
//! glue, and a minimal inline script that calls `initSync()` + `solve_challenge()`.
//! The heavy PBKDF2 brute-force runs in Rust/WASM, not JavaScript.

use base64::Engine;
use crate::kiwi_mark_svg;

/// WASM binary (embedded at compile time).
static KIWI_WASM: &[u8] = include_bytes!("../wasm/pkg/kiwicaptcha_wasm_bg.wasm");

/// Render the KiwiCaptcha widget HTML block.
pub fn kiwi_widget_html() -> String {
    let wasm_b64 = base64::engine::general_purpose::STANDARD.encode(KIWI_WASM);
    let svg = kiwi_mark_svg();

    format!(
        r#"<div class="kiwi-widget rounded-sm border border-surface-200 bg-card p-4 sm:p-6" id="kiwicaptcha-widget" data-kiwi-widget role="status" aria-live="polite">
  <div class="flex items-start gap-4">
    <div class="flex items-center justify-center w-10 h-10 rounded-sm bg-brand-50 text-brand-600 shrink-0">{svg}</div>
    <div class="flex-1 min-w-0">
      <div class="flex items-center justify-between gap-3">
        <span class="text-xs font-bold uppercase tracking-tight text-surface-700" data-kiwi-status>Preparing verification&hellip;</span>
        <span class="kiwi-pill inline-flex items-center gap-1.5 rounded-sm border border-surface-200 bg-card px-2 py-1 text-[10px] font-bold uppercase tracking-widest text-surface-400" data-kiwi-pill>Idle</span>
      </div>
      <div class="mt-3 h-1.5 w-full rounded-full bg-surface-100 overflow-hidden">
        <div class="kiwi-fill h-full rounded-full bg-brand-500 transition-all duration-300" style="width:0%"></div>
      </div>
      <p class="mt-2 text-[11px] leading-[1.5] text-surface-400" data-kiwi-hint></p>
    </div>
  </div>
  <input type="hidden" name="kiwi__token" id="kiwi-token-input" value="" />
</div>
<script>
(function() {{
  var W = document.querySelector('[data-kiwi-widget]');
  if (!W) return;
  var statusEl = W.querySelector('[data-kiwi-status]');
  var pillEl = W.querySelector('[data-kiwi-pill]');
  var fillEl = W.querySelector('.kiwi-fill');
  var tokenEl = document.getElementById('kiwi-token-input');
  var hintEl = W.querySelector('[data-kiwi-hint]');

  function setStatus(label, pill, state) {{
    if (statusEl) statusEl.textContent = label;
    if (pillEl) {{ pillEl.textContent = pill; pillEl.className = pillEl.className.replace(/idle|solving|done|failed/,'') + ' ' + state; }}
    if (fillEl) fillEl.style.width = state === 'done' ? '100%' : state === 'failed' ? '0%' : (parseFloat(fillEl.style.width)||0) + '%';
  }}

  function fail() {{
    setStatus('Verification failed — please reload', 'Failed', 'failed');
    if (tokenEl) tokenEl.value = '';
  }}

  var mouseEvents = 0, keyEvents = 0;
  document.addEventListener('mousemove', function(){{mouseEvents++;}},{{passive:true}});
  document.addEventListener('keydown', function(){{keyEvents++;}},{{passive:true}});

  // ── WASM glue (minimal wasm-bindgen runtime) ──────────────────────────
  var wasmMemory;
  var wasmExports;

  function getUint8Memory() {{
    if (!wasmMemory || !wasmMemory.buffer || wasmMemory.buffer.byteLength === 0) {{
      wasmMemory = new Uint8Array(wasmExports.memory.buffer);
    }}
    return wasmMemory;
  }}

  var WASM_VECTOR_LEN = 0;
  var cachedEncoder = new TextEncoder();

  function passStringToWasm(arg) {{
    var buf = cachedEncoder.encode(arg);
    var ptr = wasmExports.__wbindgen_malloc(buf.length, 1) >>> 0;
    getUint8Memory().subarray(ptr, ptr + buf.length).set(buf);
    WASM_VECTOR_LEN = buf.length;
    return ptr;
  }}

  var cachedDecoder = new TextDecoder('utf-8', {{ ignoreBOM: true, fatal: true }});
  function getStringFromWasm(ptr, len) {{
    return cachedDecoder.decode(getUint8Memory().subarray(ptr, ptr + len));
  }}

  function initSync(moduleBytes) {{
    var mod = new WebAssembly.Module(moduleBytes);
    var imports = {{
      "./kiwicaptcha_wasm_bg.js": {{
        __wbg_now_c704fcb7b522dabf: function() {{ return performance.now(); }},
        __wbindgen_init_externref_table: function() {{}}
      }}
    }};
    var inst = new WebAssembly.Instance(mod, imports);
    wasmExports = inst.exports;
    wasmExports.__wbindgen_start();
    return wasmExports;
  }}

  function solve_challenge(prefix, saltB64, iterations, targetBits) {{
    var p0 = passStringToWasm(prefix);
    var l0 = WASM_VECTOR_LEN;
    var p1 = passStringToWasm(saltB64);
    var l1 = WASM_VECTOR_LEN;
    var ret = wasmExports.solve_challenge(p0, l0, p1, l1, iterations, targetBits);
    if (ret[0] !== 0) {{
      var s = getStringFromWasm(ret[0], ret[1]);
      wasmExports.__wbindgen_free(ret[0], ret[1] * 1, 1);
      return s;
    }}
    return null;
  }}

  // ── Widget driver ─────────────────────────────────────────────────────
  async function run() {{
    try {{
      setStatus('Requesting challenge\\u2026', 'Connecting', 'solving');

      var scope = 'login';
      var p = window.location.pathname.toLowerCase();
      if (p.indexOf('signup')>=0||p.indexOf('register')>=0) scope='signup';
      else if (p.indexOf('forgot')>=0) scope='forgot-password';
      else if (p.indexOf('reset')>=0) scope='reset-password';

      var resp = await fetch('/api/kcaptcha/challenge', {{
        method:'POST', headers:{{'Content-Type':'application/json'}},
        body: JSON.stringify({{scope:scope}})
      }});
      if (!resp.ok) throw new Error('challenge request failed');
      var data = await resp.json();

      if (data.challenge === 'dev') {{
        if (tokenEl) tokenEl.value = btoa('dev.0.0.{{}}');
        setStatus('Dev mode', 'Dev', 'done');
        return;
      }}

      // Init WASM and solve
      var wasmBytes = Uint8Array.from(atob("{wasm_b64}"), function(c){{return c.charCodeAt(0);}});
      initSync(wasmBytes);

      setStatus('Computing proof-of-work\\u2026', 'Verifying', 'solving');
      var jsonResult = solve_challenge(data.prefix, data.salt, data.mKib||50000, data.targetBits);
      if (!jsonResult) throw new Error('solver exhausted');

      var obj = JSON.parse(jsonResult);
      var telemetry = {{
        wd: navigator.webdriver === true,
        hc: navigator.hardwareConcurrency || 0,
        dm: navigator.deviceMemory || 0,
        me: mouseEvents,
        ke: keyEvents,
        sw: window.screen.width || 0,
        sh: window.screen.height || 0,
        iw: window.innerWidth || 0,
        ih: window.innerHeight || 0
      }};
      var plain = data.nonce + '.' + obj.counter + '.' + obj.duration_ms + '.' + JSON.stringify(telemetry);
      if (tokenEl) tokenEl.value = btoa(plain);
      setStatus('Verified — you may continue', 'Verified', 'done');
      if (fillEl) fillEl.style.width = '100%';
    }} catch (e) {{
      fail();
    }}
  }}

  if (window.crypto && window.crypto.subtle) {{
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run);
    else run();
  }} else {{
    setStatus('Browser not supported', 'Unsupported', 'idle');
  }}
}})();
</script>"#
    )
}
