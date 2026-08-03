//! KiwiCaptcha widget — inline HTML + JS proof-of-work.
//!
//! The widget renders a self-contained `<div>` with an inline `<script>` that:
//! 1. Fetches a challenge from `/api/kcaptcha/challenge`
//! 2. Solves PBKDF2-HMAC-SHA256 in the browser via WebCrypto
//! 3. Fills the hidden `kiwi__token` input with the encoded solution

use crate::kiwi_mark_svg;

/// Render the full KiwiCaptcha widget HTML block.
pub fn kiwi_widget_html() -> String {
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
  var W = document.querySelector("[data-kiwi-widget]");
  if (!W) return;
  var statusEl = W.querySelector("[data-kiwi-status]");
  var pillEl = W.querySelector("[data-kiwi-pill]");
  var fillEl = W.querySelector(".kiwi-fill");
  var tokenEl = document.getElementById("kiwi-token-input");

  function setStatus(label, pill, state) {{
    if (statusEl) statusEl.textContent = label;
    if (pillEl) {{ pillEl.textContent = pill; pillEl.className = pillEl.className.replace(/idle|solving|done|failed/,"") + " " + state; }}
    if (fillEl) fillEl.style.width = state === "done" ? "100%" : state === "failed" ? "0%" : (parseFloat(fillEl.style.width)||0) + "%";
  }}

  function fail(msg) {{
    setStatus(msg || "Verification failed — please reload", "Failed", "failed");
    if (tokenEl) tokenEl.value = "";
  }}

  var mouseEvents = 0, keyEvents = 0;
  document.addEventListener("mousemove", function(){{mouseEvents++;}},{{passive:true}});
  document.addEventListener("keydown", function(){{keyEvents++;}},{{passive:true}});

  // ── PBKDF2-HMAC-SHA256 via WebCrypto (zero dependencies) ──────────
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

  async function deriveHash(prefix, counter, saltBytes, iterations) {{
    var password = new TextEncoder().encode(prefix + counter);
    var algo = {{ name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: iterations }};
    var key = await crypto.subtle.importKey("raw", password, {{name:"PBKDF2"}}, false, ["deriveBits"]);
    return crypto.subtle.deriveBits(algo, key, 256);
  }}

  async function solve(prefix, saltB64, iterations, targetBits) {{
    var salt = b64decode(saltB64);
    var solveStart = performance.now();
    for (var counter = 0; counter < 500000; counter++) {{
      var buf = await deriveHash(prefix, counter, salt, iterations);
      var bytes = new Uint8Array(buf);
      if (leadingZeros(bytes) >= targetBits) {{
        return {{ counter: counter, duration: Math.round(performance.now() - solveStart) }};
      }}
      if (counter % 500 === 0) {{
        if (fillEl) fillEl.style.width = Math.min(95, (counter * 100) / Math.pow(2, targetBits)) + "%";
        await new Promise(function(r) {{ setTimeout(r, 0); }});
      }}
    }}
    return null;
  }}

  // ── Widget driver ──────────────────────────────────────────────────
  async function run() {{
    try {{
      setStatus("Requesting challenge\u2026", "Connecting", "solving");
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

      setStatus("Computing proof-of-work\u2026", "Verifying", "solving");
      var result = await solve(data.prefix, data.salt, data.mKib || 50000, data.targetBits);
      if (!result) throw new Error("solver exhausted");

      var telemetry = {{
        wd: navigator.webdriver === true,
        hc: navigator.hardwareConcurrency || 0,
        dm: navigator.deviceMemory || 0,
        me: mouseEvents, ke: keyEvents,
        sw: window.screen.width || 0, sh: window.screen.height || 0,
        iw: window.innerWidth || 0, ih: window.innerHeight || 0
      }};
      // btoa is safe here: nonce (base64), counter (decimal), duration (decimal),
      // and telemetry (JSON) are all ASCII, so no Latin-1 encoding issues arise.
      var plain = data.nonce + "." + result.counter + "." + result.duration + "." + JSON.stringify(telemetry);
      var token = btoa(plain);
      if (tokenEl) tokenEl.value = token;
      setStatus("Verified \u2014 you may continue", "Verified", "done");
      if (fillEl) fillEl.style.width = "100%";
    }} catch (e) {{
      fail("Verification failed \u2014 " + (e.message || "please reload"));
    }}
  }}

  if (window.crypto && window.crypto.subtle) {{
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run);
    else run();
  }} else {{
    setStatus("Browser not supported", "Unsupported", "idle");
  }}
}})();
</script>"#
    )
}
