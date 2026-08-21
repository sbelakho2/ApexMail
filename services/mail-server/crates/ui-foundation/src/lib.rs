#![deny(unsafe_code)]
pub mod axum_router;
pub mod csrf;
pub mod data;
pub mod icons;
pub mod leptos_views;
pub mod marketing;
pub mod pixel_parity;
pub mod primitives;
pub mod routing;
pub mod shell;
pub mod ssr;
pub mod tokens;

#[cfg(test)]
mod migration_tests;

pub const FOUNDATION_MANIFEST_JSON: &str =
    include_str!("../../../../../docs/development/ui-rust-foundation-manifest.json");
pub const GLOBALS_CSS: &str = include_str!("../assets/globals.css");
/// Client-side hydration script for the web + control-plane surfaces.
///
/// Served by the API host at `/assets/console.js` (same pattern as
/// `GLOBALS_CSS` at `/assets/globals.css`): the api-server mounts a
/// one-line `get` route returning this constant. Plain browser JS, no
/// build step; pure helpers plus a local, dependency-free QR encoder are
/// exported for tests (`node assets/console.test.js`).
pub const CONSOLE_JS: &str = include_str!("../assets/console.js");

#[cfg(test)]
mod tests {
    use super::{CONSOLE_JS, GLOBALS_CSS};

    #[test]
    fn globals_css_keeps_light_background_utilities_legible_in_dark_mode() {
        assert!(GLOBALS_CSS.contains(".dark .bg-white"));
        assert!(GLOBALS_CSS.contains("background-color: rgb(var(--card)"));
        assert!(GLOBALS_CSS.contains("@media (prefers-color-scheme: dark)"));
        assert!(GLOBALS_CSS.contains(":root:not(.light) .bg-white"));
        assert!(GLOBALS_CSS.contains("bg-success-300.text-surface-950"));
        assert!(GLOBALS_CSS.contains(".dark .bg-white\\/90"));
        assert!(GLOBALS_CSS.contains(".dark .bg-surface-950"));
        assert!(GLOBALS_CSS.contains("background-color: rgb(9 9 11"));
        assert!(GLOBALS_CSS.contains(".dark .apex-cp-hero"));
        assert!(GLOBALS_CSS.contains(".dark .apex-console-main"));
        assert!(GLOBALS_CSS.contains(".dark .apex-auth-notice"));
        assert!(GLOBALS_CSS.contains(".dark input.bg-background"));
        assert!(GLOBALS_CSS.contains("-webkit-text-fill-color: rgb(var(--foreground)"));
    }

    /// The console script must never phone home: no third-party script
    /// sources, no external URLs of any kind (fetches go to same-origin
    /// paths only).
    #[test]
    fn console_js_is_non_empty_and_contains_no_external_urls() {
        assert!(!CONSOLE_JS.trim().is_empty());
        assert!(CONSOLE_JS.len() > 5000, "hydration script suspiciously small");
        for forbidden in ["https://", "http://", "chart.googleapis.com"] {
            assert!(
                !CONSOLE_JS.contains(forbidden),
                "CONSOLE_JS must not reference {forbidden}"
            );
        }
    }

    /// The QR renderer used by the MFA page must be local (no Google Charts
    /// or any third-party QR service) and the asset must expose the text
    /// fallback path the MFA markup relies on.
    #[test]
    fn console_js_ships_local_qr_encoder_and_hydration_hooks() {
        assert!(CONSOLE_JS.contains("qrEncodeText"));
        assert!(CONSOLE_JS.contains("qrToCanvas"));
        assert!(CONSOLE_JS.contains("data-copy-target"));
        assert!(CONSOLE_JS.contains("serializeEntries"));
        assert!(CONSOLE_JS.contains("data-api-form"));
        assert!(CONSOLE_JS.contains("data-alert-dialog-target"));
        assert!(CONSOLE_JS.contains("data-view-state"));
        assert!(CONSOLE_JS.contains("data-rows-target"));
        assert!(CONSOLE_JS.contains("data-bind"));
        assert!(CONSOLE_JS.contains("role=\"combobox\""));
        assert!(CONSOLE_JS.contains("data-theme-toggle"));
    }
}
