//! GATE J — theme-safe tinted surfaces.
//!
//! The console's `--surface-*` tokens FLIP with the colour scheme, but the
//! static hue palettes (`brand`, `success`, `warning`, `rose`, `amber`,
//! `emerald`, …) do NOT: `bg-brand-50` is a pale panel in BOTH themes. An
//! element that paints such a pale panel and leaves the text colour to
//! inheritance therefore breaks whichever theme the inherited colour does
//! not match — in dark mode the inherited colour is near-white and the
//! notice goes blank.
//!
//! Found by dogfood 2026-10-06: the MFA challenge page hand-rolled its
//! "Two-factor verification required" box as `border-brand-200
//! bg-brand-50/80` with no text colour — measured live at 250,250,250 text
//! on a 207,197,198 panel (≈1.05:1, invisible). The shared
//! `web_auth_notice` primitive had carried the correct pairing (and both
//! themes' CSS) all along; the page bypassed it.
//!
//! The contract: every element carrying a PALE static tint background
//! (`bg-<hue>-50|100|200`, with or without an alpha suffix) must be legible
//! in dark mode by one of exactly two means:
//!
//! 1. an explicit `text-*` colour class on the same element (self-contained
//!    pairing — what the shared notice primitive does), or
//! 2. a dark-mode rule for that exact class in `globals.css` **in the
//!    `:root:not(.light)` form** — the media-query path the zero-JS console
//!    actually takes (`bg-success-50` is themed this way); the `.dark`
//!    class form alone does not count, because no script ever sets it.
//!
//! Low-alpha overlays (`bg-amber-500/10`) composite with whichever theme is
//! active and inherit correctly, so they are exempt; `bg-white/…` and
//! `bg-black/…` are theme-neutral overlays and are exempt too.
//!
//! The 2026-10-06 dogfood finding sat exactly in the gap: `bg-brand-50`
//! (bare) had a media twin, `bg-brand-50/80` (the alpha variant the MFA
//! notice used) had none, and the element carried no text colour.

use crate::gate_support::{attribute_value, gate_documents};

/// Static-palette steps that read as a PALE panel in both themes.
const PALE_STEPS: &[&str] = &["50", "100", "200"];

/// Hue families that live in the static (non-flipping) palette.
const STATIC_HUES: &[&str] = &[
    "brand",
    "success",
    "warning",
    "info",
    "destructive",
    "danger",
    "rose",
    "amber",
    "emerald",
    "red",
    "blue",
    "green",
    "yellow",
    "orange",
    "teal",
    "cyan",
    "indigo",
    "violet",
    "purple",
    "pink",
    "lime",
];

/// Is this class a pale static tint background?
fn is_pale_tint(class_name: &str) -> bool {
    let base = class_name
        .strip_prefix("hover:")
        .or_else(|| class_name.strip_prefix("focus:"))
        .or_else(|| class_name.strip_prefix("active:"))
        .unwrap_or(class_name);
    let Some(rest) = base.strip_prefix("bg-") else {
        return false;
    };
    // Split off an optional alpha suffix: `bg-brand-50/80` → step "50".
    let (color, _alpha) = match rest.split_once('/') {
        Some((color, alpha)) => (color, Some(alpha)),
        None => (rest, None),
    };
    let Some((hue, step)) = color.rsplit_once('-') else {
        return false;
    };
    STATIC_HUES.contains(&hue) && PALE_STEPS.contains(&step)
}

fn carries_explicit_text_color(class_attr: &str) -> bool {
    class_attr
        .split_whitespace()
        .any(|class_name| class_name.starts_with("text-") || class_name.contains(":text-"))
}

/// Every opening tag that carries classes, as (tag-name, class-attribute).
fn classed_opening_tags(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = html[cursor..].find('<') {
        let at = cursor + rel;
        let rest = &html[at + 1..];
        match rest.chars().next() {
            Some(first) if first.is_ascii_alphabetic() => {}
            _ => {
                cursor = at + 1;
                continue;
            }
        }
        let name_len = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .count();
        let Some(end_rel) = rest.find('>') else {
            break;
        };
        let tag = &rest[..end_rel];
        if let Some(class_attr) = attribute_value(tag, "class") {
            out.push((rest[..name_len].to_string(), class_attr.to_string()));
        }
        cursor = at + 1 + end_rel + 1;
    }
    out
}

/// Does `globals.css` re-theme this exact class on the media-query path?
/// The stylesheet's convention writes `:root:not(.light) .bg-success-50` and
/// `:root:not(.light) .bg-brand-50\/80` in its dark block.
fn css_themes_the_class(class_name: &str) -> bool {
    if class_name.contains(':') {
        // Variant classes (hover:/focus:/…) ride a base class in practice.
        return true;
    }
    let selector = format!(":root:not(.light) .{}", class_name.replace('/', "\\/"));
    crate::GLOBALS_CSS.contains(&selector)
}

fn pale_tint_violations(surface: &str, document: &str, html: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for (tag, class_attr) in classed_opening_tags(html) {
        let tints: Vec<&str> = class_attr
            .split_whitespace()
            .filter(|class_name| is_pale_tint(class_name))
            .collect();
        if tints.is_empty() || carries_explicit_text_color(&class_attr) {
            continue;
        }
        let unthemed: Vec<&str> = tints
            .iter()
            .copied()
            .filter(|class_name| !css_themes_the_class(class_name))
            .collect();
        if unthemed.is_empty() {
            continue;
        }
        violations.push(format!(
            "[{surface}] {document}: <{tag}> paints the pale static tint(s) {unthemed:?} with neither an explicit text-* colour nor a `:root:not(.light)` dark rule in globals.css — the inherited colour flips with the theme and this element goes unreadable in dark mode. Use the shared `apex-auth-notice` primitive (web_auth_notice), add the matching text-* class, or theme the class in both dark blocks.",
        ));
    }
    violations
}

/// No rendered console document pairs a pale static background tint with an
/// inherited (theme-flipping) text colour.
#[test]
fn no_pale_static_tint_ships_without_an_explicit_text_colour() {
    let mut violations = Vec::new();
    for surface in ["web", "control-plane"] {
        for (document, html) in gate_documents(surface) {
            violations.extend(pale_tint_violations(surface, &document, &html));
        }
    }
    assert!(
        violations.is_empty(),
        "theme-unsafe tinted surfaces:\n{}",
        violations.join("\n"),
    );
}

#[cfg(test)]
mod pale_tint_detector_tests {
    use super::{is_pale_tint, pale_tint_violations};

    #[test]
    fn recognises_pale_tints_and_exempts_overlays() {
        assert!(is_pale_tint("bg-brand-50"));
        assert!(is_pale_tint("bg-brand-50/80"));
        assert!(is_pale_tint("bg-success-100"));
        assert!(is_pale_tint("bg-amber-200"));
        assert!(is_pale_tint("hover:bg-brand-100"));
        // Low-alpha overlays composite with the active theme.
        assert!(!is_pale_tint("bg-amber-500/10"));
        assert!(!is_pale_tint("bg-warning-300/10"));
        // Theme-neutral overlays and semantic tokens.
        assert!(!is_pale_tint("bg-white/10"));
        assert!(!is_pale_tint("bg-black/25"));
        assert!(!is_pale_tint("bg-card"));
        assert!(!is_pale_tint("bg-surface-50"));
        // Solid accents are theme-stable.
        assert!(!is_pale_tint("bg-brand-700"));
        assert!(!is_pale_tint("bg-success-500"));
        assert!(!is_pale_tint("bg-success-300"));
    }

    #[test]
    fn flags_the_reported_mfa_notice_shape() {
        // The exact live regression: pale panel, no text colour.
        let html = r#"<div class="rounded-xl border border-brand-200 bg-brand-50/80 px-4 py-4"><p class="text-sm font-bold">Two-factor verification required</p></div>"#;
        let found = pale_tint_violations("control-plane", "/login?mfa=1", html);
        assert_eq!(found.len(), 1, "{found:?}");

        // The shared primitive's pairing passes (explicit text colour).
        let ok = r#"<div class="apex-auth-notice rounded-xl border px-4 py-4 border-brand-200 bg-brand-50/80 text-brand-900" data-intent="info"><p class="text-sm font-bold">ok</p></div>"#;
        assert!(pale_tint_violations("control-plane", "/login?mfa=1", ok).is_empty());

        // A bare class the stylesheet themes for the media path passes too.
        let themed = r#"<span class="px-2 py-1 bg-success-50 rounded-full">ok</span>"#;
        assert!(pale_tint_violations("control-plane", "/dashboard", themed).is_empty());

        // …and an unthemed alpha variant with no text colour still fails.
        let unthemed = r#"<div class="px-4 py-4 bg-success-50/80">bad</div>"#;
        assert_eq!(
            pale_tint_violations("control-plane", "/dashboard", unthemed).len(),
            1
        );
    }

    /// `.text-primary` paints `rgb(var(--accent-text))`. If the token is
    /// missing every "red" emphasis (including the wordmark's old markup)
    /// collapses to inherited ink. The token must exist in the stylesheet.
    #[test]
    fn accent_text_token_is_defined_for_text_primary() {
        let sheet = include_str!("../assets/globals.css");
        assert!(
            sheet.contains("--accent-text:"),
            "globals.css must define --accent-text for .text-primary"
        );
        // The brand-600 red used by the two-tone wordmark must stay defined.
        assert!(
            sheet.contains("--brand-600:"),
            "globals.css must define --brand-600 for text-brand-600"
        );
        assert!(
            sheet.contains(".text-brand-600"),
            "globals.css must expose the .text-brand-600 utility"
        );
        assert!(
            sheet.contains(".text-surface-950"),
            "globals.css must expose the .text-surface-950 utility"
        );
    }
}
