#![deny(unsafe_code)]
pub mod axum_router;
pub mod charts;
pub mod csrf;
pub mod data;
pub mod flash;
pub mod icons;
pub mod leptos_views;
pub mod marketing;
pub mod pixel_parity;
pub mod primitives;
pub mod qr;
pub mod routing;
pub mod shell;
pub mod ssr;
pub mod tokens;
pub mod view_data;

#[cfg(test)]
mod migration_tests;

pub const FOUNDATION_MANIFEST_JSON: &str =
    include_str!("../../../../../docs/development/ui-rust-foundation-manifest.json");
pub const GLOBALS_CSS: &str = include_str!("../assets/globals.css");
pub const GLOBALS_INPUT_CSS: &str = include_str!("../assets/globals.input.css");
/// Source-of-truth marketing stylesheet (the Zola build compiles it into
/// static/css/styles.css). Included so the brand palette is pinned at its
/// source, not only in build output.
pub const MARKETING_INPUT_CSS: &str =
    include_str!("../../../../../apps/marketing-zola/static/css/input.css");

/// Whether the embedded marketing pages are the REAL Zola build output
/// (`apps/marketing-zola/public` present at compile time) rather than the
/// build script's placeholders for a bare checkout (ci/README.md §9 F5).
/// Tests that assert real page content should skip when this is `false`.
pub const MARKETING_PUBLIC_BUILT: bool = cfg!(marketing_public_built);

#[cfg(test)]
mod tests {
    use super::{GLOBALS_CSS, GLOBALS_INPUT_CSS, MARKETING_INPUT_CSS};

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

    /// The stylesheet is a pure-CSS artifact: dark mode MUST be fully
    /// functional from `prefers-color-scheme` alone — the zero-JS console
    /// has no bootstrap script to toggle a `.dark` class at runtime.
    #[test]
    fn globals_css_dark_mode_needs_no_scripts() {
        assert!(GLOBALS_CSS.contains("@media (prefers-color-scheme: dark)"));
        // `:root:not(.light)` matches when no class is ever set, which is
        // exactly the no-JS situation.
        assert!(GLOBALS_CSS.contains(":root:not(.light) .bg-white"));
    }

    // ─── Brand palette pins (red & black) ─────────────────────────────
    //
    // Regression guard for the 2026-08 palette regressions:
    //   - ffc54b4a (2026-07-31) swapped the console brand from the deep
    //     red #dc2626 (220 38 38) on zinc to coral #dd524c (221 82 76)
    //     on blue-tinted slate;
    //   - b874f4f9 (2026-08-11) swapped the marketing brand from the red
    //     scale to Apex Indigo #6366F1 (99 102 241).
    // These tests pin the RESTORED red/black brand token values at their
    // source (the token block feeds every utility via var()).

    /// Console/CP brand tokens: deep red #dc2626 on near-black zinc #09090b.
    #[test]
    fn brand_palette_is_red_and_black() {
        for source in [GLOBALS_CSS, GLOBALS_INPUT_CSS] {
            // Deep red brand accent (#dc2626 = 220 38 38).
            assert!(
                source.contains("--primary: 220 38 38;"),
                "primary must be #dc2626"
            );
            assert!(
                source.contains("--destructive: 220 38 38;"),
                "destructive must be #dc2626"
            );
            assert!(
                source.contains("--ring: 220 38 38;"),
                "ring must be #dc2626"
            );
            assert!(
                source.contains("--error: 220 38 38;"),
                "error must be #dc2626"
            );
            assert!(
                source.contains("--brand-500: 220 38 38;"),
                "brand-500 must be #dc2626"
            );
            assert!(
                source.contains("--brand-600: 185 28 28;"),
                "brand-600 must be #b91c1c"
            );
            assert!(
                source.contains("--brand-950: 45 10 10;"),
                "brand-950 must be #2d0a0a"
            );
            // Near-black zinc neutrals.
            assert!(
                source.contains("--foreground: 9 9 11;"),
                "foreground must be zinc-950 #09090b"
            );
            assert!(
                source.contains("--surface-950: 9 9 11;"),
                "surface-950 must be zinc-950 #09090b"
            );
            assert!(
                source.contains("--surface-200: 228 228 231;"),
                "surface-200 must be zinc-200 #e4e4e7"
            );
            // The coral regression values must stay gone.
            assert!(
                !source.contains("221 82 76"),
                "coral #dd524c (221 82 76) must not appear — the brand is #dc2626"
            );
            assert!(
                !source.contains("15 17 22"),
                "blue-tinted slate foreground (15 17 22) must not appear — the brand neutrals are zinc"
            );
        }
    }

    /// Dark mode is surface-only: the brand red tokens are NOT overridden
    /// in the dark blocks, so the restored palette works in dark mode
    /// exactly as before the regression.
    #[test]
    fn dark_mode_keeps_the_red_brand() {
        for source in [GLOBALS_CSS, GLOBALS_INPUT_CSS] {
            let dark_block_start = source.find(".dark {").expect("dark token block");
            let dark_block = &source[dark_block_start..dark_block_start + 1200];
            assert!(
                !dark_block.contains("--primary:"),
                "dark mode must not override the brand accent"
            );
            assert!(
                dark_block.contains("--background: 9 9 11;"),
                "dark background must stay near-black zinc"
            );
            assert!(
                dark_block.contains("--foreground: 250 250 250;"),
                "dark foreground must stay zinc-50"
            );
        }
    }

    /// Marketing brand tokens: red scale (accent #EF4444, deep #DC2626)
    /// with the #DC2626 → #991B1B gradient.
    #[test]
    fn marketing_palette_is_red() {
        assert!(
            MARKETING_INPUT_CSS.contains("--brand-500: 239 68 68;"),
            "marketing brand-500 must be #ef4444"
        );
        assert!(
            MARKETING_INPUT_CSS.contains("--brand-600: 220 38 38;"),
            "marketing brand-600 must be #dc2626"
        );
        assert!(
            MARKETING_INPUT_CSS.contains("--brand-950: 69 10 10;"),
            "marketing brand-950 must be #450a0a"
        );
        assert!(
            MARKETING_INPUT_CSS.contains("--primary: 239 68 68;"),
            "marketing primary must be #ef4444"
        );
        assert!(
            MARKETING_INPUT_CSS.contains("linear-gradient(135deg, #dc2626, #991b1b)"),
            "brand gradient must be red"
        );
        // The indigo regression values must stay gone.
        assert!(
            !MARKETING_INPUT_CSS.contains("99 102 241"),
            "indigo #6366f1 (99 102 241) must not appear — the brand is red"
        );
        assert!(
            !MARKETING_INPUT_CSS.contains("30 27 75"),
            "indigo brand-950 (30 27 75) must not appear — dark brand tints are red"
        );
        assert!(
            !MARKETING_INPUT_CSS.contains("#6366f1") && !MARKETING_INPUT_CSS.contains("#4338ca"),
            "indigo gradient hexes must not appear"
        );
    }

    /// The views reference the brand tokens through the utility classes
    /// that compile against them (bg-primary / text-primary /
    /// bg-brand-*), proving the served markup carries the red brand.
    #[test]
    fn views_reference_the_brand_tokens() {
        let dashboard =
            crate::axum_router::render_route("web", "/dashboard").expect("web dashboard renders");
        assert!(
            dashboard.contains("bg-primary") || dashboard.contains("text-primary"),
            "console views must reference the primary token utilities"
        );
        assert!(
            GLOBALS_CSS.contains(".bg-primary"),
            "globals.css must emit .bg-primary"
        );
        assert!(
            GLOBALS_CSS.contains(".bg-brand-500"),
            "globals.css must emit .bg-brand-500"
        );
        assert!(
            GLOBALS_CSS.contains(".text-primary"),
            "globals.css must emit .text-primary"
        );
        // The emitted utilities must bind to the token variables (so the
        // pinned token values are what actually renders).
        assert!(GLOBALS_CSS.contains("background-color: rgb(var(--primary)"));
        assert!(GLOBALS_CSS.contains("color: rgb(var(--brand-400)"));
    }

    /// The marketing cookie banner (served from the Zola build output)
    /// must carry real no-JS consent links to the /consent endpoint and
    /// the server-side visibility marker.
    #[test]
    fn marketing_banner_is_no_js_with_real_consent_links() {
        let home = crate::axum_router::render_route("marketing", "/")
            .expect("marketing home renders (from the zola build output)");
        assert!(
            home.contains("id=cookie-consent-banner")
                || home.contains("id=\"cookie-consent-banner\""),
            "banner must be present in the built marketing page"
        );
        assert!(
            home.contains("data-consent-state=pending")
                || home.contains("data-consent-state=\"pending\""),
            "banner must carry the pending state marker for the server-side flip"
        );
        assert!(
            home.contains("/consent?choice=necessary"),
            "banner must link the necessary-only choice to /consent"
        );
        assert!(
            home.contains("/consent?choice=all"),
            "banner must link the accept-all choice to /consent"
        );
        // The old JS hook attributes may remain as inert data-* markers,
        // but no <button> may sit inside the banner's action row anymore.
        let banner_start = home
            .find("cookie-consent-banner")
            .unwrap_or_else(|| panic!("banner element found"));
        let banner = &home[banner_start
            ..home[banner_start..]
                .find("</div></div></div>")
                .map(|end| banner_start + end + "</div></div></div>".len())
                .unwrap_or(home.len())];
        assert!(
            !banner.contains("<button"),
            "inert consent buttons must not ship — the zero-JS banner uses links"
        );
    }
}
