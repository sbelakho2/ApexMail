//! KiwiCaptcha widget — server-rendered HTML + Rust/WASM proof-of-work.
//!
//! The widget embeds a compiled WASM binary (base64 data URL) and a minimal
//! inline JavaScript loader.  The WASM module contains the PBKDF2 brute-force
//! solver — the heavy computation runs in Rust/WASM, not JavaScript.

use crate::kiwi_mark_svg;

/// The compiled WASM binary (embedded at compile time via `include_bytes!`).
static KIWI_WASM: &[u8] = include_bytes!("../wasm/pkg/kiwicaptcha_wasm_bg.wasm");

/// Render the full KiwiCaptcha widget HTML block.
///
/// The returned HTML is a `<div>` containing the status indicator, progress
/// bar, hidden `kiwi__token` input, and an inline `<script>` that loads the
/// embedded WASM solver.  The host application's CSP middleware injects the
/// page nonce into every `<script>` tag automatically.
pub fn kiwi_widget_html() -> String {
    let wasm_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        KIWI_WASM,
    );
    let svg = kiwi_mark_svg();

    format!(
        r#"<div class="kiwi-widget rounded-sm border border-surface-200 bg-card p-4 sm:p-6" id="kiwicaptcha-widget" role="status" aria-live="polite">
  <div class="flex items-start gap-4">
    <div class="flex items-center justify-center w-10 h-10 rounded-sm bg-brand-50 text-brand-600 shrink-0">
      {svg}
    </div>
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
  var statusEl = document.querySelector('[data-kiwi-status]');
  var pillEl = document.querySelector('[data-kiwi-pill]');
  var fillEl = document.querySelector('.kiwi-fill');
  var tokenEl = document.getElementById('kiwi-token-input');
  var hintEl = document.querySelector('[data-kiwi-hint]');

  function setStatus(label, pill, state) {{
    if (statusEl) statusEl.textContent = label;
    if (pillEl) {{ pillEl.textContent = pill; pillEl.className = pillEl.className.replace(/idle|solving|done|failed/,'') + ' ' + state; }}
    if (fillEl) fillEl.style.width = state === 'done' ? '100%' : state === 'failed' ? '0%' : (parseFloat(fillEl.style.width)||0) + '%';
  }}

  function fail() {{
    setStatus('Verification failed — please reload', 'Failed', 'failed');
    if (tokenEl) tokenEl.value = '';
  }}

  // Collect lightweight telemetry
  var mouseEvents = 0, keyEvents = 0;
  document.addEventListener('mousemove', function(){{mouseEvents++;}},{{passive:true}});
  document.addEventListener('keydown', function(){{keyEvents++;}},{{passive:true}});

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

      // Instantiate the embedded WASM solver
      var wasmBytes = Uint8Array.from(atob("{wasm_b64}"), function(c){{return c.charCodeAt(0);}});
      var wasmModule = await WebAssembly.instantiate(wasmBytes, {{}});
      var solve = wasmModule.instance.exports.solve_challenge;

      setStatus('Computing proof-of-work\\u2026', 'Verifying', 'solving');

      var jsonResult = solve(data.prefix, data.salt, data.mKib||50000, data.targetBits);
      if (!jsonResult) throw new Error('solver exhausted');

      var result = JSON.parse(jsonResult);

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
      var plain = data.nonce + '.' + result.counter + '.' + result.duration_ms + '.' + JSON.stringify(telemetry);
      var token = btoa(plain);
      if (tokenEl) tokenEl.value = token;
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

/// Deprecated name kept for backward compatibility with existing call sites.
pub use kiwi_widget_html as KIWI_WIDGET_HTML;
