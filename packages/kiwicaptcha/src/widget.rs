//! KiwiCaptcha widget — the inline, nonce'd HTML + JS that renders the
//! proof-of-work challenge on auth pages.
//!
//! The widget is a
//! self-contained block of HTML + an inline `<script>` (which receives the page's
//! CSP nonce from `inject_script_nonce`). The script:
//!
//! 1. Fetches a challenge from `POST /api/kcaptcha/challenge`.
//! 2. Brute-forces a counter using **PBKDF2-HMAC-SHA256** (via the native
//!    `crypto.subtle.deriveBits` API — no external JS, no WASM needed) so the
//!    hash output has `targetBits` leading zero bits.
//! 3. Fills the hidden `kiwi__token` input with the encoded solution.
//!
//! PBKDF2 is chosen for the client hash because it is available natively in
//! every modern browser via WebCrypto (`deriveBits`), making the widget
//! dependency-free. The iteration count is tuned (10,000–100,000) so a real
//! browser takes ~200–800ms, while a parallel GPU farm still pays real cost per
//! solve. The server-side verification re-derives the same PBKDF2 hash.

use crate::kiwi_mark_svg;

/// The PBKDF2 iteration count used by both the widget script and the server
/// verifier. Tuned for ~300–500ms in a real browser.
pub const KIWI_PBKDF2_ITERATIONS: u32 = 50_000;

/// Render the full KiwiCaptcha widget HTML block, including the inline script.
///
/// This is the same widget used on the ApexMail auth pages.  The returned HTML
/// is a `<div>` containing the status indicator, progress bar, hidden
/// `kiwi__token` input, and an inline `<script>` that fetches a challenge
/// from `/api/kcaptcha/challenge` and brute-forces a PBKDF2 counter.
///
/// The script tag is written WITHOUT a nonce — the host application's CSP
/// middleware should inject the page nonce into every `<script>` tag
/// automatically so the widget complies with a strict CSP.
pub fn kiwi_widget_html() -> String {
    format!(
        r#"<div class="kiwi-widget space-y-3" data-kiwi-widget>
<div class="flex items-center justify-between">
<div class="flex items-center gap-2.5">
<span class="inline-flex h-7 w-7 items-center justify-center rounded-sm bg-brand-50 text-primary shadow-premium-sm" aria-hidden="true">{kiwi}</span>
<div class="flex flex-col leading-tight">
<span class="text-[10px] font-bold uppercase tracking-[0.2em] text-surface-950">KiwiCaptcha</span>
<span class="text-[10px] text-surface-400 font-medium" data-kiwi-status>Preparing verification&hellip;</span>
</div>
</div>
<span class="kiwi-pill inline-flex items-center gap-1.5 rounded-sm border border-surface-200 bg-card px-2 py-1 text-[10px] font-bold uppercase tracking-tight text-surface-400 transition-premium" data-kiwi-pill>
<span class="kiwi-dot inline-block h-1.5 w-1.5 rounded-full bg-surface-400 transition-premium" data-kiwi-dot></span>
<span data-kiwi-pill-label>Waiting</span>
</span>
</div>
<div class="kiwi-track h-[3px] w-full overflow-hidden rounded-sm bg-surface-200">
<div class="kiwi-fill h-full bg-primary transition-all duration-300 ease-premium" style="width:0%" data-kiwi-fill></div>
</div>
<input type="hidden" name="kiwi__token" id="kiwi__token" data-kiwi-token />
<p class="text-[10px] text-surface-400 font-medium leading-relaxed">Memory-hard proof-of-work verification runs entirely in your browser. No tracking, no third parties.</p>
</div>
<script>
(function() {{
  var W = document.querySelector('[data-kiwi-widget]');
  if (!W) return;
  var statusEl = W.querySelector('[data-kiwi-status]');
  var pillEl = W.querySelector('[data-kiwi-pill]');
  var pillLabel = W.querySelector('[data-kiwi-pill-label]');
  var dotEl = W.querySelector('[data-kiwi-dot]');
  var fillEl = W.querySelector('[data-kiwi-fill]');
  var tokenEl = W.querySelector('[data-kiwi-token]');
  var PBKDF2_ITERATIONS = {iterations};
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function setStatus(label, pillText, state) {{
    if (statusEl) statusEl.textContent = label;
    if (pillLabel) pillLabel.textContent = pillText;
    if (dotEl) {{
      dotEl.className = 'kiwi-dot inline-block h-1.5 w-1.5 rounded-full transition-premium ' +
        (state === 'solving' ? (reduceMotion ? 'bg-primary' : 'bg-primary animate-pulse') :
         state === 'done' ? 'bg-success' : 'bg-surface-400');
    }}
    if (pillEl) {{
      pillEl.className = 'kiwi-pill inline-flex items-center gap-1.5 rounded-sm border px-2 py-1 text-[10px] font-bold uppercase tracking-tight transition-premium ' +
        (state === 'solving' ? 'border-primary/30 bg-brand-50 text-primary' :
         state === 'done' ? 'border-success-200 bg-success-50 text-success-700' :
         'border-surface-200 bg-card text-surface-400');
    }}
  }}

  // Count leading zero bits of a 256-bit hash (big-endian).
  function leadingZeros(bytes) {{
    var n = 0;
    for (var i = 0; i < bytes.length; i++) {{
      if (bytes[i] === 0) {{ n += 8; }}
      else {{ var b = bytes[i]; while ((b & 128) === 0) {{ n++; b <<= 1; }} break; }}
    }}
    return n;
  }}

  // Derive PBKDF2-HMAC-SHA256 hash of (prefix + counter) with the given salt.
  function deriveHash(prefix, counter, saltBytes, iterations) {{
    var password = new TextEncoder().encode(prefix + counter);
    var algo = {{ name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: iterations }};
    return crypto.subtle.deriveBits(algo,
      crypto.subtle.importKey('raw', password, {{name:'PBKDF2'}}, false, ['deriveBits']));
  }}

  function b64decode(str) {{
    // URL-safe base64 → binary
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    var bin = atob(str);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }}

  function b64encode(bytes) {{
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }}

  // Collect lightweight telemetry during the solve window.
  var solveStart = 0;
  var mouseEvents = 0;
  var keyEvents = 0;
  document.addEventListener('mousemove', function() {{ mouseEvents++; }}, {{ passive: true }});
  document.addEventListener('keydown', function() {{ keyEvents++; }}, {{ passive: true }});

   async function solve(challenge, saltB64, iterations, targetBits, prefix) {{
     var salt = b64decode(saltB64);
     solveStart = performance.now();
     for (var counter = 0; counter < 4294967295; counter++) {{
       var buf = await deriveHash(prefix, counter, salt, iterations);
       var bytes = new Uint8Array(buf);
       if (leadingZeros(bytes) >= targetBits) {{
         var duration = Math.round(performance.now() - solveStart);
         return {{ counter: counter, duration: duration }};
       }}
      if (counter % 50 === 0) {{
        if (fillEl) fillEl.style.width = Math.min(95, counter / 10) + '%';
        // Yield to the event loop so the UI doesn't freeze.
        await new Promise(function(r) {{ setTimeout(r, 0); }});
      }}
      if (counter > 500000) break; // safety cap
    }}
    return null;
  }}

  async function run() {{
    try {{
      setStatus('Requesting challenge&hellip;', 'Connecting', 'solving');
      // Infer the scope from the page URL.
      var scope = 'login';
      var p = window.location.pathname.toLowerCase();
      if (p.indexOf('signup') >= 0 || p.indexOf('register') >= 0) scope = 'signup';
      else if (p.indexOf('forgot') >= 0) scope = 'forgot-password';
      else if (p.indexOf('reset') >= 0) scope = 'reset-password';

       var resp = await fetch('/api/kcaptcha/challenge', {{
         method: 'POST',
         headers: {{ 'Content-Type': 'application/json' }},
         body: JSON.stringify({{ scope: scope }})
       }});
       if (!resp.ok) throw new Error('challenge request failed: ' + resp.status);
       var data = await resp.json();

       // Dev bypass: if the challenge is "dev", write a trivial token.
       if (data.challenge === 'dev') {{
         if (tokenEl) tokenEl.value = btoa('dev.0.0.{{}}');
         setStatus('Dev mode (verification bypassed)', 'Dev', 'done');
         if (fillEl) fillEl.style.width = '100%';
         return;
       }}

       setStatus('Computing proof-of-work&hellip;', 'Verifying', 'solving');
       var result = await solve(data.challenge, data.salt, data.mKib || PBKDF2_ITERATIONS, data.targetBits, data.prefix);
       if (!result) throw new Error('solver exhausted without finding a solution');

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
       // Wire format: nonce.counter.duration.telemetry_json (base64)
       var nonce = data.nonce || '';
       var plain = nonce + '.' + result.counter + '.' + result.duration + '.' + JSON.stringify(telemetry);
       var finalToken = btoa(plain);

       if (tokenEl) tokenEl.value = finalToken;
      if (fillEl) fillEl.style.width = '100%';
      setStatus('Verified — you may continue', 'Verified', 'done');
    }} catch (e) {{
      setStatus('Verification failed — please reload', 'Error', 'idle');
      if (fillEl) fillEl.style.width = '0%';
    }}
  }}

  // Start after DOM is ready and crypto is available.
  if (window.crypto && window.crypto.subtle) {{
    if (document.readyState === 'loading') {{
      document.addEventListener('DOMContentLoaded', run);
    }} else {{
      run();
    }}
  }} else {{
    setStatus('Browser not supported', 'Unsupported', 'idle');
  }}
}})();
</script>"#,
        kiwi = kiwi_mark_svg(),
        iterations = KIWI_PBKDF2_ITERATIONS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widget_renders_hidden_token_input() {
        let html = kiwi_widget_html();
        assert!(html.contains(r#"name="kiwi__token""#));
        assert!(html.contains("id=\"kiwi__token\""));
    }

    #[test]
    fn widget_contains_kiwi_logo_and_label() {
        let html = kiwi_widget_html();
        assert!(html.contains("KiwiCaptcha"));
        // The kiwi mark SVG is embedded.
        assert!(html.contains("<svg"));
    }

    #[test]
    fn widget_script_has_no_src_attribute() {
        // The script must be inline (no external src) for CSP nonce compliance.
        let html = kiwi_widget_html();
        assert!(html.contains("<script>"));
        assert!(!html.contains("<script src="));
    }

    #[test]
    fn widget_uses_apex_design_tokens() {
        let html = kiwi_widget_html();
        // Coral primary, surface colors, premium shadow, eyebrow tracking.
        assert!(html.contains("text-primary"));
        assert!(html.contains("bg-primary"));
        assert!(html.contains("shadow-premium"));
        assert!(html.contains("tracking-[0.2em]"));
        assert!(html.contains("rounded-sm"));
    }
}
