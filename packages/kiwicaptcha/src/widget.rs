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
const KIWI_DRIVER_JS: &str = include_str!("../../kiwicaptcha-wasm/assets/widget-driver.js");
const KIWI_CSS: &str = include_str!("../../kiwicaptcha-wasm/assets/widget.css");
const KIWI_WASM_EMBED: &str = include_str!("../../kiwicaptcha-wasm/assets/kiwicaptcha-wasm.js");

/// Render the premium KiwiCaptcha widget HTML block.
pub fn kiwi_widget_html() -> String {
    let svg = kiwi_mark_svg();
    let container_html = format!(
        "<style>\n{css}\n</style>\n<div class=\"kiwi-container\" id=\"kiwicaptcha-root\">\n  <div class=\"kiwi-widget\" data-kiwi-widget data-state=\"idle\" role=\"status\" aria-live=\"polite\">\n    <div class=\"kiwi-icon-wrapper\">\n      {svg}\n      <div class=\"kiwi-glow\"></div>\n    </div>\n    <div class=\"kiwi-main\">\n      <div class=\"kiwi-top\">\n        <span class=\"kiwi-label\" data-kiwi-label>Security Check</span>\n        <span class=\"kiwi-badge\" data-kiwi-badge>Idle</span>\n      </div>\n      <div class=\"kiwi-track\">\n        <div class=\"kiwi-bar\" data-kiwi-bar></div>\n      </div>\n      <div class=\"kiwi-bottom\">\n        <p class=\"kiwi-info\" data-kiwi-info>Protected by KiwiCaptcha</p>\n        <span class=\"kiwi-timer\" data-kiwi-timer></span>\n      </div>\n    </div>\n    <input type=\"hidden\" name=\"kiwi__token\" data-kiwi-token value=\"\" />\n  </div>\n</div>\n",
        css = KIWI_CSS,
        svg = svg,
    );
    format!(
        "{container_html}<script>\n{}\n</script>\n<script>\n{}\n</script>",
        KIWI_WASM_EMBED, KIWI_DRIVER_JS
    )
}
