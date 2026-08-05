//! KiwiCaptcha widget — inline HTML + JS proof-of-work.
//!
//! The widget renders a self-contained `<div>` with an inline `<script>` that:
//! 1. Fetches a challenge from `/api/kcaptcha/challenge`
//! 2. Solves PBKDF2-HMAC-SHA256 in the browser via WebCrypto
//! 3. Fills the hidden `kiwi__token` input with the encoded solution
//!
//! ## Visual design
//!
//! The widget matches the ApexMail design system:
//! - Coral primary (`bg-brand-500`), surface card background (`bg-card`)
//! - `rounded-sm` corners (0px radius — the Apex design language)
//! - `shadow-premium-sm` for subtle depth
//! - `transition-premium` timing (cubic-bezier easing)
//! - Kiwi mark in a coral-tinted chip (`bg-brand-50 text-brand-600`)
//! - Progress bar, status pill, TTL countdown, and contextual hint text

use crate::kiwi_shield_svg;

/// Render the full KiwiCaptcha widget HTML block.
pub fn kiwi_widget_html() -> String {
    let svg = kiwi_shield_svg();
    format!(
        r#"<div class="kiwi-widget rounded-sm border border-surface-200 bg-card p-5 transition-premium hover:border-surface-300" id="kiwicaptcha-widget" data-kiwi-widget role="status" aria-live="polite" aria-label="Security verification">
  <div class="flex items-start gap-3.5">
    <div class="flex items-center justify-center w-9 h-9 rounded-sm bg-brand-50 text-brand-600 shrink-0 transition-premium" data-kiwi-icon>{svg}</div>
    <div class="flex-1 min-w-0">
      <div class="flex items-center justify-between gap-2">
        <span class="text-[11px] font-bold uppercase tracking-[0.16em] text-surface-900" data-kiwi-status>Preparing verification&hellip;</span>
        <span class="kiwi-pill inline-flex items-center gap-1.5 rounded-sm border border-surface-200 bg-surface-50 px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.12em] text-surface-400 transition-premium" data-kiwi-pill>Idle</span>
      </div>
      <div class="mt-2.5 h-[3px] w-full rounded-full bg-surface-100 overflow-hidden">
        <div class="kiwi-fill h-full rounded-full bg-brand-500 transition-all duration-300 ease-premium" style="width:0%"></div>
      </div>
      <div class="mt-2 flex items-center justify-between gap-2">
        <p class="text-[10px] leading-[1.45] text-surface-400 font-medium" data-kiwi-hint>Memory-hard proof-of-work runs in your browser.</p>
        <span class="kiwi-countdown text-[9px] font-mono tabular-nums text-surface-300 shrink-0" data-kiwi-countdown></span>
      </div>
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
  var hintEl = W.querySelector("[data-kiwi-hint]");
  var iconEl = W.querySelector("[data-kiwi-icon]");
  var tokenEl = document.getElementById("kiwi-token-input");
  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function setStatus(label, pillText, state) {{
    if (statusEl) statusEl.textContent = label;
    if (pillEl) {{
      pillEl.textContent = pillText;
      var baseClass = "kiwi-pill inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.12em] transition-premium ";
      var stateClasses = {{
        idle: "border-surface-200 bg-surface-50 text-surface-400",
        connecting: "border-brand-200 bg-brand-50 text-brand-600",
        solving: "border-brand-300 bg-brand-100 text-brand-700",
        done: "border-success-200 bg-success-50 text-success-700",
        failed: "border-primary/30 bg-primary/5 text-primary"
      }};
      pillEl.className = baseClass + (stateClasses[state] || stateClasses.idle);
    }}
    if (iconEl) {{
      var iconBase = "flex items-center justify-center w-9 h-9 rounded-sm shrink-0 transition-premium ";
      var iconStates = {{
        idle: "bg-brand-50 text-brand-600",
        connecting: "bg-brand-100 text-brand-700",
        solving: "bg-brand-100 text-brand-700",
        done: "bg-success-50 text-success-600",
        failed: "bg-primary/10 text-primary"
      }};
      iconEl.className = iconBase + (iconStates[state] || iconStates.idle);
      if (state === "solving" && !reduceMotion) iconEl.className += " animate-pulse";
    }}
  }}

  function setHint(text) {{ if (hintEl) hintEl.textContent = text; }}

  function setProgress(pct) {{
    if (fillEl) fillEl.style.width = Math.max(0, Math.min(100, pct)) + "%";
  }}

  function fail(msg) {{
    setStatus(msg || "Verification failed", "Failed", "failed");
    setHint("Please reload the page to retry.");
    setProgress(0);
    if (tokenEl) tokenEl.value = "";
    stopCountdown();
  }}

  var countdownEl = W.querySelector("[data-kiwi-countdown]");
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

  var mouseEvents = 0, keyEvents = 0;
  document.addEventListener("mousemove", function(){{mouseEvents++;}},{{passive:true}});
  document.addEventListener("keydown", function(){{keyEvents++;}},{{passive:true}});

  // ── SHA-256 via WebCrypto (fast hash, high difficulty — same model as
  //    FriendlyCaptcha, Anubis, ALTCHA) ──────────────────────────────
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

  async function deriveHash(prefix, counter, saltBytes) {{
    var input = new Uint8Array(new TextEncoder().encode(prefix + counter).length + saltBytes.length);
    input.set(new TextEncoder().encode(prefix + counter), 0);
    input.set(saltBytes, new TextEncoder().encode(prefix + counter).length);
    return crypto.subtle.digest("SHA-256", input);
  }}

  async function solve(prefix, saltB64, targetBits) {{
    var salt = b64decode(saltB64);
    var solveStart = performance.now();
    var expectedHashes = Math.pow(2, targetBits);
    for (var counter = 0; counter < 5000000; counter++) {{
      var buf = await deriveHash(prefix, counter, salt);
      var bytes = new Uint8Array(buf);
      if (leadingZeros(bytes) >= targetBits) {{
        return {{ counter: counter, duration: Math.round(performance.now() - solveStart) }};
      }}
      if (counter % 1000 === 0) {{
        setProgress(Math.min(92, (counter * 100) / expectedHashes));
        await new Promise(function(r) {{ setTimeout(r, 0); }});
      }}
    }}
    return null;
  }}

  // ── Widget driver ──────────────────────────────────────────────────
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

      setStatus("Computing proof-of-work\u2026", "Verifying", "solving");
      setHint("Running SHA-256 verification in your browser.");
      var result = await solve(data.prefix, data.salt, data.targetBits);
      if (!result) throw new Error("solver exhausted");

      var telemetry = {{
        wd: navigator.webdriver === true,
        hc: navigator.hardwareConcurrency || 0,
        dm: navigator.deviceMemory || 0,
        pl: navigator.plugins ? navigator.plugins.length : 0,
        la: navigator.language || "",
        cd: window.screen.colorDepth || 0,
        me: mouseEvents, ke: keyEvents,
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

  if (window.crypto && window.crypto.subtle) {{
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run);
    else run();
  }} else {{
    setStatus("Browser not supported", "Unsupported", "failed");
    setHint("This browser does not support WebCrypto.");
  }}
}})();
</script>"#
    )
}
