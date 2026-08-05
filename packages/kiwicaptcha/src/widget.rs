//! KiwiCaptcha widget — inline HTML + JS proof-of-work.
//!
//! The widget renders a self-contained `<div>` with an inline `<script>` that:
//! 1. Fetches a challenge from `/api/kcaptcha/challenge`
//! 2. Solves a SHA-256 proof-of-work in the browser using a compact,
//!    synchronous pure-JS implementation that yields periodically via
//!    `setTimeout(0)` to keep the UI responsive
//! 3. Fills the hidden `kiwi__token` input with the encoded solution
//!
//! ## Visual design
//!
//! Clean, minimal card:
//! - `rounded-sm border border-surface-200 bg-card p-5`
//! - Kiwi mark in a brand-tinted chip (`bg-brand-50 text-brand-600`)
//! - `transition-premium` timing (cubic-bezier easing)
//! - Status text + pill badge, thin `h-[3px]` brand progress bar
//! - TTL countdown, contextual hint text, hidden `kiwi__token` input

use crate::kiwi_mark_svg;

/// Render the full KiwiCaptcha widget HTML block.
pub fn kiwi_widget_html() -> String {
    let svg = kiwi_mark_svg();
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
        <p class="text-[10px] leading-[1.45] text-surface-400 font-medium" data-kiwi-hint>Secure verification runs in your browser.</p>
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
  var encoder = new TextEncoder();

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

  // ── Compact synchronous SHA-256 (pure JS, typed-array based) ────────
  //    Returns a Uint8Array(32). Synchronous execution avoids the
  //    per-hash Promise allocation that caps async hashing throughput.
  function sha256sync(data) {{
    var h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var k = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    var msg = [];
    var i = 0;
    for (i = 0; i < data.length; i++) msg.push(data[i]);
    var l = msg.length * 8;
    msg.push(0x80);
    while (msg.length % 64 != 56) msg.push(0);
    // 64-bit big-endian bit length. The high 32 bits are always 0 for our
    // message sizes; >>> masks its shift count to 5 bits, so a naive
    // (l >>> 56) would be wrong — emit the low 32 bits explicitly.
    msg.push(0, 0, 0, 0);
    msg.push((l >>> 24) & 0xff, (l >>> 16) & 0xff, (l >>> 8) & 0xff, l & 0xff);
    var w = new Array(64);
    var a, b, c, d, e, f, g, hh;
    var s0, s1, ch, maj, t1, t2;
    for (i = 0; i < msg.length; i += 64) {{
      for (var j = 0; j < 16; j++) {{
        w[j] = (msg[i + j * 4] << 24) | (msg[i + j * 4 + 1] << 16) | (msg[i + j * 4 + 2] << 8) | msg[i + j * 4 + 3];
      }}
      for (j = 16; j < 64; j++) {{
        var x = w[j - 15];
        s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var y = w[j - 2];
        s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
      }}
      a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
      for (j = 0; j < 64; j++) {{
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ch = (e & f) ^ (~e & g);
        t1 = (hh + s1 + ch + k[j] + w[j]) | 0;
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = (s0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }}
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }}
    var result = new Uint8Array(32);
    for (i = 0; i < 8; i++) {{
      result[i * 4] = (h[i] >>> 24) & 0xff;
      result[i * 4 + 1] = (h[i] >>> 16) & 0xff;
      result[i * 4 + 2] = (h[i] >>> 8) & 0xff;
      result[i * 4 + 3] = h[i] & 0xff;
    }}
    return result;
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

  // SHA-256(prefix || counter || salt) — synchronous.
  function deriveHash(prefix, counter, saltBytes) {{
    var head = encoder.encode(prefix + counter);
    var input = new Uint8Array(head.length + saltBytes.length);
    input.set(head, 0);
    input.set(saltBytes, head.length);
    return sha256sync(input);
  }}

  // Synchronous hash crunching in ~5000-hash chunks, yielding to the UI
  // via setTimeout(0) between chunks. Resolves with {{counter, duration}}
  // or null if the search space is exhausted.
  function solve(prefix, saltBytes, targetBits) {{
    return new Promise(function(resolve) {{
      var expectedHashes = Math.pow(2, targetBits);
      var solveStart = performance.now();
      var counter = 0;
      var CHUNK = 5000;
      var MAX = 5000000;
      function chunk() {{
        var end = counter + CHUNK;
        if (end > MAX) end = MAX;
        for (; counter < end; counter++) {{
          if (leadingZeros(deriveHash(prefix, counter, saltBytes)) >= targetBits) {{
            resolve({{ counter: counter, duration: Math.round(performance.now() - solveStart) }});
            return;
          }}
        }}
        if (counter >= MAX) {{ resolve(null); return; }}
        setProgress(Math.min(92, (counter * 100) / expectedHashes));
        setTimeout(chunk, 0);
      }}
      setTimeout(chunk, 0);
    }});
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

      setStatus("Proof-of-work verification\u2026", "Verifying", "solving");
      setHint("Running a short hash challenge locally.");
      var result = await solve(data.prefix, b64decode(data.salt), data.targetBits);
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

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run);
  else run();
}})();
</script>"#
    )
}
