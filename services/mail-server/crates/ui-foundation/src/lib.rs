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

#[cfg(test)]
mod tests {
    use super::GLOBALS_CSS;

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
}
