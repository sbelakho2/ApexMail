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
// text colour, the colour scheme flips the inherited one).
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
/// as long as the cache entry's freshness allows, a CSS change then leaves
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
/// The canonical webhook event vocabulary, the ONE list.
///
/// api-server's `KNOWN_WEBHOOK_EVENTS` re-exports this constant, so the
/// validator's accepted names and the console's checkbox group cannot drift
/// apart. The names are the wire contract (they appear in delivered
/// payloads), so they are lowercase dotted identifiers, never display copy.
pub const WEBHOOK_EVENTS: &[&str] = &[
    // Message lifecycle (canonical vocabulary)
    "message.accepted",
    "message.queued",
    "message.attempted",
    "message.deferred",
    "message.delivered",
    "message.bounced",
    "message.complained",
    "message.suppressed",
    "message.opened",
    "message.clicked",
    "message.cancelled",
    // tracking-service
    "recipient.unsubscribed",
    // Campaign lifecycle (customer campaigns; produced by the campaign worker)
    "campaign.started",
    "campaign.ab_winner_selected",
    "campaign.completed",
    // inbox-placement
    "placement_test.completed",
    // inbound email pipeline
    "inbound",
    // Wildcard honoured by every webhook selector
    "*",
];

pub const GLOBALS_CSS: &str = include_str!("../assets/globals.css");
pub const GLOBALS_INPUT_CSS: &str = include_str!("../assets/globals.input.css");
/// The authored design authority (fonts, tokens, base, the apex-*
/// vocabulary). The single source both the console and marketing builds
/// inline; tools/check_ark_mirror.py keeps the marketing copy identical.
pub const ARK_CSS: &str = include_str!("../assets/ark.css");
/// The marketing build's copy of the authority, must be byte-identical.
pub const MARKETING_ARK_CSS: &str =
    include_str!("../../../../../apps/marketing-zola/static/css/ark.css");
/// Whether the embedded marketing pages are the REAL Zola build output
/// (`apps/marketing-zola/public` present at compile time) rather than the
/// build script's placeholders for a bare checkout (ci/README.md §9 F5).
/// Tests that assert real page content should skip when this is `false`.
pub const MARKETING_PUBLIC_BUILT: bool = cfg!(marketing_public_built);

#[cfg(test)]
mod tests {
    use super::GLOBALS_CSS;

    /// The compiled artifact inlines the authority: fonts, tokens and the
    /// apex-* vocabulary all resolve to ark.css content, and the artifact
    /// can never carry elevation, blur, fade gradients or arch radii,
    /// because cssgen cannot emit them and ark.css does not define them.
    /// Strip CSS comments so the law scan reads rules, not documentation
    /// (the authority's header lists banned classes by name).
    fn css_rules(sheet: &str) -> String {
        let mut out = String::with_capacity(sheet.len());
        let mut rest = sheet;
        while let Some(at) = rest.find("/*") {
            out.push_str(&rest[..at]);
            let Some(end) = rest[at..].find("*/") else {
                break;
            };
            rest = &rest[at + end + 2..];
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn compiled_artifact_is_the_ark_authority() {
        let rules = css_rules(GLOBALS_CSS);
        for marker in [
            ".apex-wordmark__apex",
            ".apex-nav-cell .apex-nav-lead",
            ".apex-notice--fail",
            ".apex-evidence .apex-evidence__hatch",
            "--wordmark-apex: 185 28 28",
            "--engrave: repeating-linear-gradient",
        ] {
            assert!(
                rules.contains(marker),
                "compiled artifact must carry the ark authority: {marker}"
            );
        }
        for banned in [
            "shadow-premium",
            "backdrop-blur",
            "transition-premium",
            ".glass",
            "rounded-[",
            "linear-gradient(to",
        ] {
            assert!(
                !rules.contains(banned),
                "compiled artifact must not contain {banned}"
            );
        }
    }

    /// The URL must carry a content-derived query so a changed sheet is a
    /// changed URL (dogfood 2026-10-06: an unhashed sheet kept open tabs
    /// on the previous build's CSS).
    #[test]
    fn globals_css_url_is_content_hashed() {
        let url = super::globals_css_url();
        assert!(url.starts_with("/assets/globals.css?v="), "{url}");
        let version = url.trim_start_matches("/assets/globals.css?v=");
        assert!(
            version.len() >= 8 && version.chars().all(|c| c.is_ascii_hexdigit()),
            "version must be a hex hash of the sheet: {version}"
        );
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

    /// Dark mode must work from `prefers-color-scheme` alone, the zero-JS
    /// console has no bootstrap script to toggle a `.dark` class at runtime.
    #[test]
    fn globals_css_dark_mode_needs_no_scripts() {
        assert!(GLOBALS_CSS.contains("@media (prefers-color-scheme: dark)"));
        assert!(GLOBALS_CSS.contains(":root:not(.light)"));
        // Dark is an inversion, not a second design: every COLOUR token the
        // light block defines must exist in the dark block (theme-invariant
        // tokens, rules, radii, motion, fonts, need only light).
        use crate::tokens::block_tokens;
        let dark = block_tokens(crate::ARK_CSS, ".dark");
        let light = block_tokens(crate::ARK_CSS, ":root");
        assert!(dark.contains_key("--background"));
        assert!(dark.contains_key("--foreground"));
        const COLOR_FAMILIES: [&str; 21] = [
            "--background",
            "--foreground",
            "--card",
            "--popover",
            "--primary",
            "--secondary",
            "--muted",
            "--accent",
            "--border",
            "--input",
            "--ring",
            "--destructive",
            "--warning",
            "--error",
            "--surface-",
            "--brand-",
            "--success-",
            "--info-",
            "--danger-",
            "--wordmark-",
            "--engrave",
        ];
        let mut colour_tokens = 0;
        for name in light.keys() {
            if COLOR_FAMILIES.iter().any(|f| name.starts_with(f)) {
                colour_tokens += 1;
                assert!(
                    dark.contains_key(name),
                    "the dark block drops the colour token {name}"
                );
            }
        }
        assert!(colour_tokens >= 80, "colour token count: {colour_tokens}");
    }

    /// The light token block and its two dark paths (the `.dark` class the
    /// toggle uses and the `:root:not(.light)` media twin the zero-JS
    /// console takes) must agree exactly, so a theme cannot work through
    /// only one of the two paths.
    #[test]
    fn light_and_dark_token_blocks_validate_independently() {
        use crate::tokens::block_tokens;
        let light = block_tokens(crate::ARK_CSS, ":root");
        let dark = block_tokens(crate::ARK_CSS, ".dark");
        let media = block_tokens(crate::ARK_CSS, ":root:not(.light)");

        assert!(light.len() >= 100, "light token block: {}", light.len());
        assert_eq!(media.len(), dark.len(), "the dark blocks are twins");

        for name in dark.keys().chain(media.keys()) {
            assert!(
                light.contains_key(name),
                "{name} is defined only in a dark block"
            );
        }
        for (name, value) in &dark {
            assert_eq!(media.get(name), Some(value), "{name} differs between twins");
        }
        for core in [
            "--background",
            "--foreground",
            "--card",
            "--border",
            "--muted-foreground",
            "--surface-100",
            "--wordmark-mail",
        ] {
            assert!(light.contains_key(core), "light missing {core}");
            assert!(dark.contains_key(core), "dark missing {core}");
            assert!(media.contains_key(core), "media twin missing {core}");
        }
        // The compiled artifact carries the same light authority.
        let artifact_light = block_tokens(GLOBALS_CSS, ":root");
        for (name, value) in &light {
            assert_eq!(
                artifact_light.get(name),
                Some(value),
                "{name} artifact drift"
            );
        }
    }

    /// Review §5.2, cssgen edition: the cssgen recipe must scan every
    /// authoritative renderer that can emit a console/CP class, and cssgen
    /// must be the only CSS build path (all-Rust; no Tailwind, no
    /// JavaScript anywhere in the pipeline).
    #[test]
    fn cssgen_content_scan_covers_every_class_emitting_renderer() {
        let recipe = include_str!("../../../../../tools/dev-start.sh");
        for required in [
            "crates/ui-foundation/src/**/*.rs",
            "crates/api-server/src/**/*.rs",
            "crates/ui-foundation/assets/globals.input.css",
        ] {
            assert!(
                recipe.contains(required),
                "the cssgen content scan must include {required}"
            );
        }
        assert!(
            recipe.contains("--bin cssgen"),
            "dev-start must build stylesheets through cssgen"
        );
        assert!(
            !recipe.contains("tailwind"),
            "no Tailwind may remain in the CSS build path"
        );
    }

    /// ARK surface policy: fills sit in a narrow paper band (canvas, rail,
    /// inset never differ by a jarring step) and HIERARCHY IS CARRIED BY
    /// RULE WEIGHT (3/2/1px ink), not by fill steps or shadows. The ladder
    /// is therefore pinned at exact values, and the hairline must still be
    /// legible against every fill it can touch.
    #[test]
    fn surface_ladder_is_pinned_and_rule_carried() {
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
        let sheet = crate::ARK_CSS;
        let token = |name: &str| -> String {
            let idx = sheet
                .find(&format!("{name}: "))
                .unwrap_or_else(|| panic!("missing token {name}"));
            let rest = &sheet[idx + name.len() + 2..];
            rest.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        // The exact ARK ladder (paper / limestone / mist / hairline / ink).
        assert_eq!(token("--background"), "255 255 255");
        assert_eq!(token("--surface-100"), "246 248 250");
        assert_eq!(token("--surface-200"), "238 242 246");
        assert_eq!(token("--surface-300"), "196 205 213");
        assert_eq!(token("--surface-950"), "14 20 27");
        // The hairline reads on every fill it touches (ΔL* >= 12 vs paper,
        // limestone and mist; >= 30 vs ink).
        let hair = lstar("196 205 213");
        for fill in ["255 255 255", "246 248 250", "238 242 246"] {
            assert!(
                (hair - lstar(fill)).abs() >= 12.0,
                "hairline invisible on {fill}"
            );
        }
        assert!((hair - lstar("14 20 27")).abs() >= 30.0);
        // The rule tokens exist and carry the hierarchy.
        assert_eq!(token("--rule-3"), "3px");
        assert_eq!(token("--rule-2"), "2px");
        assert_eq!(token("--rule-1"), "1px");
        // No elevation exists in the authority. The single sanctioned
        // box-shadow is the tab underline (inset 0 -3px 0, a 3px ink RULE
        // drawn inside the tab, not an elevation).
        let rules = css_rules(sheet);
        for line in rules.lines() {
            if line.contains("box-shadow") {
                assert!(
                    line.contains("inset 0 -3px 0") || line.contains("box-shadow: none"),
                    "the only sanctioned box-shadows are the tab rule and explicit none: {line}"
                );
            }
        }
    }

    /// The palette law, pinned at the authority: ink structure, blue
    /// interaction, amber caution, red destruction and the wordmark, and
    /// NO green and NO purple anywhere, in light or dark.
    #[test]
    fn palette_law_blue_ink_red_no_green_no_purple() {
        let sheet = crate::ARK_CSS;
        assert!(sheet.contains("--primary: 29 79 124;"), "interaction blue");
        assert!(
            sheet.contains("--destructive: 142 42 32;"),
            "destruction red"
        );
        assert!(sheet.contains("--warning: 138 90 16;"), "caution amber");
        assert!(sheet.contains("--foreground: 14 20 27;"), "ink");
        assert_ne!(
            sheet.find("--primary: ").map(|i| &sheet[i..i + 24]),
            sheet.find("--destructive: ").map(|i| &sheet[i..i + 24]),
            "interaction must never share a value with destruction"
        );
        for green in [
            "34 197 94",
            "22 163 74",
            "20 83 45",
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
                "green {green:?} must not exist, verified renders blue"
            );
        }
        for purple in [
            "99 102 241",
            "139 92 246",
            "168 85 247",
            "126 34 206",
            "#6366f1",
            "#4f46e5",
            "#4338ca",
            "#8b5cf6",
            "#a855f7",
        ] {
            assert!(
                !sheet.contains(purple),
                "purple {purple:?} must not exist, no framework indigo"
            );
        }
        // The old red brand and zinc neutrals must stay gone (the wordmark
        // keeps 185 28 28 only as --wordmark-apex).
        assert!(
            !sheet.contains("--primary: 185 28 28"),
            "primary is blue, not the old red"
        );
        assert!(
            !sheet.contains("--foreground: 9 9 11"),
            "foreground is ink, not zinc"
        );
        // The favicon carries the wordmark red and ARK radius 0.
        let favicon = crate::leptos_views::FAVICON_SVG;
        assert!(
            favicon.contains("fill=\"#B91C1C\""),
            "favicon fill is the wordmark red"
        );
        assert!(!favicon.contains("rx="), "favicon is ARK: radius 0");
        assert!(!favicon.contains("4f46e5") && !favicon.contains("dc2626"));
    }

    /// The wordmark is a fixed logo artefact (owner pin): Inter 700, 1.5rem,
    /// tracking -0.05em, "Apex" #B91C1C + "Mail" #09090B (paper in dark),
    /// pixel-equal to web_auth_logo().
    #[test]
    fn the_wordmark_is_pinned() {
        let sheet = crate::ARK_CSS;
        assert!(sheet.contains("--wordmark-apex: 185 28 28;"));
        assert!(sheet.contains("--wordmark-mail: 9 9 11;"));
        assert!(sheet.contains("--font-wordmark: 'Inter Wordmark'"));
        let wm = sheet
            .find(".apex-wordmark {")
            .expect("the wordmark recipe must exist");
        let body = &sheet[wm..wm + 400];
        assert!(body.contains("font-family: var(--font-wordmark)"));
        assert!(body.contains("font-weight: 700"));
        assert!(body.contains("font-size: 1.5rem"));
        assert!(body.contains("letter-spacing: -0.05em"));
        // Inter ships only as the subset the wordmark renders, and is
        // referenced only by the wordmark recipe: every "Inter" occurrence
        // in the authority must be "Inter Wordmark" (the stack or the
        // @font-face family) or "InterWordmark.woff2" (the src).
        let mut stray = 0usize;
        let mut at = 0usize;
        let rules = css_rules(sheet);
        let sheet = rules.as_str();
        while let Some(found) = sheet[at..].find("Inter") {
            at += found;
            if !sheet[at..].starts_with("Inter Wordmark")
                && !sheet[at..].starts_with("InterWordmark.woff2")
            {
                stray += 1;
            }
            at += "Inter".len();
        }
        assert_eq!(stray, 0, "Inter may be referenced only by the wordmark");
        // And the dark twin flips Mail to paper, never the red.
        assert!(sheet.contains("--wordmark-mail: 237 241 244"));
        assert!(sheet.contains("--wordmark-apex: 196 80 70"));
    }

    /// The marketing build inlines a byte-identical copy of the authority.
    #[test]
    fn marketing_carries_the_byte_identical_ark_mirror() {
        assert_eq!(
            crate::ARK_CSS, crate::MARKETING_ARK_CSS,
            "apps/marketing-zola/static/css/ark.css must equal crates/ui-foundation/assets/ark.css (tools/check_ark_mirror.py enforces the same at gate level)"
        );
    }

    /// Wrap + hit-target rules: pre-rendered multi-line content wraps, and
    /// disclosure summaries carry the 24px minimum hit target (WCAG 2.5.8).
    #[test]
    fn wrap_and_hit_target_rules_are_in_both_sheets() {
        for (name, sheet) in [
            ("console globals.css", GLOBALS_CSS),
            ("console globals.input.css", crate::ARK_CSS),
        ] {
            assert!(
                sheet.contains(".whitespace-pre-wrap"),
                "{name} must define .whitespace-pre-wrap",
            );
            assert!(
                sheet.contains("min-height: 1.5rem;") && sheet.contains("padding-block: 0.25rem;"),
                "{name} must carry the 24px summary hit-target rule",
            );
        }
    }

    /// Dark AA pairings computed from the shipped token values: every text
    /// token clears 4.5:1 on its canvas in BOTH themes (muted ink on paper,
    /// light muted on ink, interaction blue on paper, lightened blue on
    /// ink, destruction red on both, amber on both).
    #[test]
    fn text_tokens_clear_aa_on_their_canvases() {
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
        // (text, canvas) pairs that the primitives actually ship.
        for (text, canvas, why) in [
            ("14 20 27", "255 255 255", "ink on paper"),
            ("61 75 89", "255 255 255", "muted ink on paper"),
            ("91 107 122", "255 255 255", "tertiary ink on paper"),
            ("29 79 124", "255 255 255", "interaction blue on paper"),
            ("20 58 92", "255 255 255", "link blue-deep on paper"),
            ("142 42 32", "255 255 255", "destruction red on paper"),
            ("138 90 16", "255 255 255", "caution amber on paper"),
            ("237 241 244", "14 20 27", "ink-mode text on ink"),
            ("192 202 211", "14 20 27", "muted text on ink"),
            ("155 189 220", "14 20 27", "interaction blue on ink"),
            ("224 138 128", "14 20 27", "destruction red on ink"),
            ("210 166 94", "14 20 27", "caution amber on ink"),
            (
                "91 107 122",
                "246 248 250",
                "muted ink on the limestone rail",
            ),
        ] {
            assert!(
                ratio(text, canvas) >= 4.5,
                "{why} must clear AA ({text} on {canvas} = {:.2})",
                ratio(text, canvas)
            );
        }
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
            "inert consent buttons must not ship, the zero-JS banner uses links"
        );
    }
}
