#![deny(unsafe_code)]
pub mod axum_router;
pub mod charts;
pub mod csrf;
pub mod data;
pub mod explorer;
pub mod fixture_states;
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
pub mod tracking_domain;
pub mod view_data;

// ─── UI/UX CI gates (test-only) ────────────────────────────────────────
// Gate A: golden skeletons. Gate B: chrome consistency. Gate D: form
// hygiene. Gate I: link integrity. Gate J: theme contrast. Gate K: class
// integrity. Shared helpers in gate_support.
#[cfg(test)]
mod chrome_tests;
#[cfg(test)]
mod form_hygiene_tests;
#[cfg(test)]
mod gate_support;
#[cfg(test)]
mod golden_tests;
#[cfg(test)]
mod link_integrity_tests;

// Gate J: theme-safe tinted surfaces (pale static tints need an explicit
// text colour — the colour scheme flips the inherited one).
#[cfg(test)]
mod theme_contrast_tests;

// Gate K: every class a rendered page uses is defined in globals.css
// (the stylesheet is a prebuilt artifact; unknown classes render as nothing).
#[cfg(test)]
mod class_integrity_tests;

#[cfg(test)]
mod migration_tests;

/// The stylesheet URL every SSR document links, with a content-hash query.
///
/// The routes `/assets/globals.css` is served from carry no hash, so a plain
/// `/assets/globals.css` URL can be served from a browser or proxy cache for
/// as long as the cache entry's freshness allows — a CSS change then leaves
/// open tabs (and warm caches) rendering the PREVIOUS build (dogfood
/// 2026-10-06: a redesigned page kept rendering the old sheet). The query is
/// derived from the sheet itself, so a changed sheet is a changed URL and
/// every cache misses exactly once. The handler still answers conditional
/// requests with a 304 for the warmth of that one request.
pub fn globals_css_url() -> &'static str {
    static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URL.get_or_init(|| {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        GLOBALS_CSS.hash(&mut hasher);
        format!("/assets/globals.css?v={:x}", hasher.finish())
    })
    .as_str()
}

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
    fn globals_css_url_is_content_hashed() {
        // The URL must carry a content-derived query so a changed sheet is a
        // changed URL (dogfood 2026-10-06: an unhashed sheet kept open tabs
        // on the previous build's CSS).
        let url = super::globals_css_url();
        assert!(url.starts_with("/assets/globals.css?v="), "{url}");
        let version = url.trim_start_matches("/assets/globals.css?v=");
        assert!(
            version.len() >= 8 && version.chars().all(|c| c.is_ascii_hexdigit()),
            "version must be a hex hash of the sheet: {version}"
        );
        // Stable within a build.
        assert_eq!(url, super::globals_css_url());
    }

    #[test]
    fn every_document_links_the_hashed_stylesheet() {
        for html in [
            crate::leptos_views::web_root_layout("x", "t"),
            crate::leptos_views::control_plane_root_layout_with_title("x", "t"),
            crate::leptos_views::web_campaign_preview_page("<p>x</p>"),
        ] {
            assert!(
                html.contains(super::globals_css_url()),
                "document must link the content-hashed stylesheet"
            );
            assert!(
                !html.contains("href=\"/assets/globals.css\""),
                "no document may link the bare, unhashed stylesheet"
            );
        }
    }

    #[test]
    fn globals_css_dark_mode_needs_no_scripts() {
        assert!(GLOBALS_CSS.contains("@media (prefers-color-scheme: dark)"));
        // `:root:not(.light)` matches when no class is ever set, which is
        // exactly the no-JS situation.
        assert!(GLOBALS_CSS.contains(":root:not(.light) .bg-white"));
    }

    /// Review §5.1 lib.rs: validate the light and dark token blocks
    /// INDEPENDENTLY. Each block is parsed on its own (never by diffing one
    /// against the other's text), and the two dark authorities — the `.dark`
    /// class the toggle uses and the `:root:not(.light)` media twin the
    /// zero-JS console takes — must agree exactly, so a theme cannot work on
    /// only one of the two paths.
    #[test]
    fn light_and_dark_token_blocks_validate_independently() {
        use crate::tokens::block_tokens;
        let light = block_tokens(GLOBALS_INPUT_CSS, ":root");
        let dark = block_tokens(GLOBALS_INPUT_CSS, ".dark");
        let media = block_tokens(GLOBALS_INPUT_CSS, ":root:not(.light)");

        assert!(light.len() >= 50, "light token block: {}", light.len());
        assert!(dark.len() >= 15, "dark token block: {}", dark.len());
        assert_eq!(media.len(), dark.len(), "the dark blocks are twins");

        // 1. No dark token may be a name the light block does not define —
        //    an unknown name would silently never apply.
        for name in dark.keys().chain(media.keys()) {
            assert!(
                light.contains_key(name),
                "{name} is defined only in a dark block"
            );
        }
        // 2. The class twin and the media twin carry the SAME values.
        for (name, value) in &dark {
            assert_eq!(media.get(name), Some(value), "{name} differs between twins");
        }
        // 3. The core surface tokens are present in every block (a gutted
        //    dark block would otherwise satisfy the equality check above).
        for core in [
            "--background",
            "--foreground",
            "--card",
            "--border",
            "--muted-foreground",
            "--surface-100",
        ] {
            assert!(light.contains_key(core), "light missing {core}");
            assert!(dark.contains_key(core), "dark missing {core}");
            assert!(media.contains_key(core), "media twin missing {core}");
        }
        // 4. The compiled artifact carries the same light authority.
        let artifact_light = block_tokens(GLOBALS_CSS, ":root");
        for (name, value) in &light {
            assert_eq!(
                artifact_light.get(name),
                Some(value),
                "{name} artifact drift"
            );
        }
    }

    /// Review §5.2 tailwind.config.js: every authoritative renderer that can
    /// emit a console/CP class is in the content scan (a renderer outside it
    /// ships undefined classes that render as nothing).
    #[test]
    fn tailwind_content_scan_covers_every_class_emitting_renderer() {
        let config = include_str!("../tailwind.config.js");
        for required in [
            "'./src/**/*.rs'",
            "'./assets/globals.input.css'",
            "'../../api-server/src/**/*.rs'",
        ] {
            assert!(
                config.contains(required),
                "tailwind.config.js content scan must include {required}"
            );
        }
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

    /// Surface-separation policy (owner review 2026-10-06: "lots of grey on
    /// grey or grey on black"). WCAG ratios are the wrong yardstick for
    /// large fills — they compress at both ends of the scale — so the ladder
    /// is pinned in CIE L*: every consecutive surface step and every hairline
    /// must differ by a just-noticeable amount (ΔL* ≥ 3 for fills, ≥ 2.5 for
    /// borders), in BOTH themes. Live audit after this policy: low-separation
    /// fills 1208 → 45 (all card-vs-page pairs whose edge is carried by a
    /// crisp border), faint borders 216 → 0.
    #[test]
    fn surface_ladder_steps_are_perceptible_in_both_themes() {
        fn lstar(rgb: &str) -> f64 {
            let parts: Vec<f64> = rgb
                .split_whitespace()
                .map(|v| v.parse::<f64>().expect("token channel"))
                .collect();
            assert_eq!(parts.len(), 3, "token {rgb:?} must be three channels");
            let lin = |v: f64| {
                let v = v / 255.0;
                if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            let y = 0.2126 * lin(parts[0]) + 0.7152 * lin(parts[1]) + 0.0722 * lin(parts[2]);
            if y > 0.008856 {
                116.0 * y.cbrt() - 16.0
            } else {
                903.3 * y
            }
        }
        // Pull a "R G B" token's value out of a stylesheet.
        fn token(sheet: &str, name: &str) -> String {
            // The two stylesheets write tokens differently (`--x: 1 2 3` in the
            // console, `--x:1 2 3` in the marketing sheet), so accept both.
            let idx = sheet
                .find(name)
                .unwrap_or_else(|| panic!("missing token {name}"));
            let rest = &sheet[idx + name.len()..];
            let rest = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            rest.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_string()
        }
        let ladders: [(&str, &str, &str, &str, &str, &str); 2] = [
            // sheet, page, card, inset, border
            (
                "console",
                GLOBALS_CSS,
                "--background",
                "--card",
                "--surface-100",
                "--border",
            ),
            // The marketing sheet has no `--border` token: its hairlines are
            // the surface-200 step.
            (
                "marketing",
                MARKETING_INPUT_CSS,
                "--background",
                "--card",
                "--surface-100",
                "--surface-200",
            ),
        ];
        for (name, sheet, page_t, card_t, inset_t, border_t) in ladders {
            let page = token(sheet, page_t);
            let card = token(sheet, card_t);
            let inset = token(sheet, inset_t);
            let border = token(sheet, border_t);
            let dl = |a: &str, b: &str| (lstar(a) - lstar(b)).abs();
            assert!(
                dl(&page, &card) >= 3.0,
                "{name}: the card fill must sit a perceptible step off the page (ΔL*={:.1}, page={page:?}, card={card:?})",
                dl(&page, &card),
            );
            assert!(
                dl(&card, &inset) >= 3.0,
                "{name}: inset surfaces must sit a perceptible step off the card (ΔL*={:.1})",
                dl(&card, &inset),
            );
            assert!(
                dl(&border, &card) >= 2.5,
                "{name}: the hairline must be visible on the card (ΔL*={:.1}, border={border:?})",
                dl(&border, &card),
            );
        }
    }

    /// The palette policy (owner review 2026-10-06), pinned at the source of
    /// BOTH stylesheets so it cannot drift back:
    ///
    /// 1. **No green.** The ApexMail palette is red + near-black/neutral;
    ///    emerald "success" chips and the terminal's green strings read as a
    ///    foreign design element on every page.
    /// 2. **No black-infused two-tone red.** The brand fill is the classic
    ///    flat red (#dc2626); the maroon gradient/blends (#a81818 → #7f1d1d,
    ///    brand-950 #450a0a washes) are gone.
    /// 3. **Surfaces separate.** The dark card fill is 24 24 27 — one clear
    ///    step above the 9 9 11 page, so cards are not grey-on-grey.
    #[test]
    fn palette_policy_no_green_no_maroon_and_separating_surfaces() {
        for (name, sheet) in [
            ("console globals.css", GLOBALS_CSS),
            ("console globals.input.css", GLOBALS_INPUT_CSS),
            ("marketing input.css", MARKETING_INPUT_CSS),
        ] {
            for green in [
                "34 197 94",
                "22 163 74",
                "20 83 45",
                "240 253 244",
                "220 252 231",
                "187 247 208",
                "134 239 172",
                "74 222 128",
                "#22c55e",
                "#34d399",
                "#4ade80",
                "#86efac",
                "#10b981",
                "#059669",
            ] {
                assert!(
                    !sheet.contains(green),
                    "{name} still carries the green palette value {green:?} — success states are neutral ink, never green",
                );
            }
            for maroon in ["#a81818", "#7f1d1d"] {
                assert!(
                    !sheet.contains(maroon),
                    "{name} still carries the black-infused two-tone red {maroon:?} — the brand fill is the flat classic red",
                );
            }
        }
        // Surfaces separate in dark mode.
        assert!(
            GLOBALS_CSS.contains("--card: 24 24 27;"),
            "the console's dark card fill must sit a clear step above the 9 9 11 page",
        );
        assert!(
            MARKETING_INPUT_CSS.contains("--card: 24 24 27;"),
            "the marketing dark card fill must sit a clear step above the 9 9 11 page",
        );
        // The classic red is what the brand fill uses.
        assert!(
            MARKETING_INPUT_CSS
                .contains("--brand-gradient: linear-gradient(135deg, #dc2626, #dc2626);"),
            "the marketing brand fill must be the flat classic red",
        );
    }

    /// Bot-surface wrap + hit-target recipes (dogfood 2026-10-06 ui-visual),
    /// pinned at the source of BOTH stylesheets so the authored sheet and
    /// the built sheet cannot drift apart:
    ///
    /// 1. `.whitespace-pre-wrap` — the assistant transcript turns, the
    ///    AI-draft reply bodies and the demo result blocks are pre-rendered
    ///    multi-line text; without the utility a `<p>` collapses the
    ///    newlines and a `<pre>` keeps `white-space: pre` and scrolls
    ///    sideways. The class was composed in Rust string literals and the
    ///    committed build had dropped it.
    /// 2. the browser `summary` base rule — disclosure summaries are the
    ///    zero-JS console's only expand/collapse control, so they carry the
    ///    24px minimum hit target (WCAG 2.5.8) via block padding; the 16px
    ///    `text-xs` and 20px `text-sm` summary lines sat below it.
    #[test]
    fn bot_surface_wrap_and_hit_target_rules_are_in_both_sheets() {
        for (name, sheet) in [
            ("console globals.css", GLOBALS_CSS),
            ("console globals.input.css", GLOBALS_INPUT_CSS),
        ] {
            assert!(
                sheet.contains(".whitespace-pre-wrap"),
                "{name} must define .whitespace-pre-wrap — the bot surfaces' multi-line content wraps with it",
            );
            assert!(
                sheet.contains("min-height: 1.5rem;") && sheet.contains("padding-block: 0.25rem;"),
                "{name} must carry the 24px summary hit-target rule (min-height + block padding)",
            );
        }
    }

    /// Dark-mode AA pairings for the bot surfaces (dogfood 2026-10-06
    /// ui-visual, relayed from the mailbot live gate): two recipes carry
    /// their own color rules that the generic `.text-primary` / token
    /// remaps never reach —
    ///
    /// 1. `.apex-pill--brand` paints `--primary` (the light-mode brand-700
    ///    red, 185 28 28) which is 2.7:1 on the dark card; dark must step
    ///    the pill to brand-400 (248 113 113).
    /// 2. the success flash/notice ink is the near-black success-900; in
    ///    dark the success-50 wash remaps to 39 39 42, leaving 1.27:1 —
    ///    dark must step the ink to the near-white success-100.
    ///
    /// The zero-JS console takes the `:root:not(.light)` media path, so
    /// each override must exist in BOTH forms in BOTH sheets.
    #[test]
    fn bot_surface_dark_aa_overrides_are_in_both_sheets() {
        for (name, sheet) in [
            ("console globals.css", GLOBALS_CSS),
            ("console globals.input.css", GLOBALS_INPUT_CSS),
        ] {
            for selector in [
                ".dark .apex-pill--brand",
                ":root:not(.light) .apex-pill--brand",
                ".dark .text-success-900",
                ":root:not(.light) .text-success-900",
            ] {
                assert!(
                    sheet.contains(selector),
                    "{name} must carry {selector} — without it the recipe keeps its light pairing in dark",
                );
            }
        }

        // The pairing itself clears AA on the dark card (computed from the
        // shipped token values, both themes' card fills).
        fn luminance(rgb: &str) -> f64 {
            let parts: Vec<f64> = rgb
                .split_whitespace()
                .map(|v| v.parse::<f64>().expect("token channel"))
                .collect();
            let lin = |v: f64| {
                let v = v / 255.0;
                if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * lin(parts[0]) + 0.7152 * lin(parts[1]) + 0.0722 * lin(parts[2])
        }
        fn ratio(a: &str, b: &str) -> f64 {
            let (la, lb) = (luminance(a), luminance(b));
            let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
            (hi + 0.05) / (lo + 0.05)
        }
        let brand_400 = "248 113 113"; // --brand-400
        let dark_card = "24 24 27"; // --card, dark
        let light_card = "255 255 255";
        let light_primary = "185 28 28"; // --primary, light
        assert!(
            ratio(light_primary, light_card) >= 4.5,
            "the light brand pill must clear AA on the light card",
        );
        assert!(
            ratio(brand_400, dark_card) >= 4.5,
            "the dark brand pill must clear AA on the dark card (brand-400 vs 24 24 27)",
        );
        assert!(
            ratio("244 244 245", "39 39 42") >= 4.5,
            "the dark success ink (success-100) must clear AA on the remapped success wash (39 39 42)",
        );
    }

    /// The last two layout-gate pages (dogfood 2026-10-06 ui-visual,
    /// residual sweep), pinned at their source:
    ///
    /// 1. every sales JSON-mutation `<code>` chip wraps its long endpoint —
    ///    `POST /v1/admin/autopilot/decisions/:id/review` is one unbreakable
    ///    token and spilled 72 px out of its card at mobile width;
    /// 2. `.apex-table-wrap` is a positioned scroll container — without
    ///    `position: relative` the sr-only labels inside a table header are
    ///    absolutely positioned against the document and their static
    ///    position widened `/cp/demos` by 23 px at mobile.
    #[test]
    fn sales_code_chips_and_table_wrapper_layout_pins() {
        let sales = crate::axum_router::render_route("control-plane", "/sales")
            .expect("the sales route must render");
        assert!(
            sales.contains("text-primary break-words"),
            "sales code chips must carry break-words — the long endpoint tokens spill their card otherwise",
        );
        let demos = crate::axum_router::render_route("control-plane", "/cp/demos")
            .expect("the demos route must render");
        assert!(
            demos.contains("apex-table-wrap") && demos.contains("apex-table"),
            "the demos sessions table must render inside the shared wrapper",
        );
        for (name, sheet) in [
            ("console globals.css", GLOBALS_CSS),
            ("console globals.input.css", GLOBALS_INPUT_CSS),
        ] {
            // The sheets carry a legacy `.apex-table-wrap` rule (white card,
            // no scroll) ahead of the canonical one; the canonical rule is
            // the one carrying the scroll container. At least one must be
            // positioned too.
            let positioned = sheet.match_indices(".apex-table-wrap").any(|(at, _)| {
                sheet[at..(at + 400).min(sheet.len())].contains("position: relative")
            });
            assert!(
                positioned,
                "{name}: a .apex-table-wrap rule must be position: relative so abspos descendants stay inside the scroll container",
            );
            let scrolls = sheet
                .match_indices(".apex-table-wrap")
                .any(|(at, _)| sheet[at..(at + 400).min(sheet.len())].contains("overflow-x: auto"));
            assert!(
                scrolls,
                "{name}: .apex-table-wrap must keep its horizontal scroll"
            );
        }
    }

    /// Console/CP brand tokens: deep red #dc2626 on near-black zinc #09090b.
    #[test]
    fn brand_palette_is_red_and_black() {
        for source in [GLOBALS_CSS, GLOBALS_INPUT_CSS] {
            // Deep red brand accent (#dc2626 = 220 38 38).
            // Light-mode primary is the brand-700 step (#b91c1c): the
            // #dc2626 fill measured 4.40:1 as TEXT on the 244 244 246 canvas
            // (dogfood 2026-10-06). White on #b91c1c is 6.35:1 — AA for both
            // text and fill roles.
            assert!(
                source.contains("--primary: 185 28 28;"),
                "primary must be the brand-700 red #b91c1c"
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
            // surface-200 deepened to zinc-300: a zinc-200 hairline on the
            // 244 244 246 canvas measured ΔL* < 2.5 (invisible) — the
            // surface-ladder gate pins the perceptible step (2026-10-06).
            assert!(
                source.contains("--surface-200: 212 212 216;"),
                "surface-200 must be zinc-300 #d4d4d8 so hairlines read"
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
        // The console favicon must carry the brand red, not the pre-2026-08
        // indigo (#4f46e5) that survived in the one artifact users see on
        // every tab (audit SM11 F4).
        let favicon = crate::leptos_views::FAVICON_SVG;
        assert!(
            favicon.contains("fill=\"#dc2626\""),
            "favicon fill must be the brand token #dc2626"
        );
        assert!(
            !favicon.contains("4f46e5"),
            "indigo #4f46e5 must not appear in the favicon — the brand is #dc2626"
        );
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
            // brand-600 is the TEXT step for prose links and receipts; on the
            // 244 244 246 canvas #dc2626 measured 4.40:1, so it deepens to the
            // brand-700 red (5.9:1) — the same AA-driven step as the console.
            MARKETING_INPUT_CSS.contains("--brand-600:185 28 28"),
            "marketing brand-600 must be the brand-700 red #b91c1c"
        );
        assert!(
            MARKETING_INPUT_CSS.contains("--brand-950: 69 10 10;"),
            "marketing brand-950 must be #450a0a"
        );
        // The marketing sheet writes tokens without a space after the colon.
        assert!(
            MARKETING_INPUT_CSS.contains("--primary:185 28 28"),
            "marketing primary must be the brand-700 red #b91c1c (AA as text on the light canvas)"
        );
        // The brand fill is the CLASSIC flat red: white on #dc2626 measures
        // 4.76:1 (AA for normal text), so the old maroon two-tone gradient's
        // rationale ("white needs 4.5+ on every stop") is met by the flat
        // fill — and the black-infused maroon is gone (owner review
        // 2026-10-06).
        assert!(
            MARKETING_INPUT_CSS.contains("linear-gradient(135deg, #dc2626, #dc2626)"),
            "brand fill must be the flat classic red (#dc2626), white text at 4.76:1"
        );
        for maroon in ["#a81818", "#7f1d1d"] {
            assert!(
                !MARKETING_INPUT_CSS.contains(maroon),
                "the black-infused maroon {maroon} must not return to the brand fill"
            );
        }
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
