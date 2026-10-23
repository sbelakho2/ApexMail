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
    // ARK: pale tints are token-bound — the .dark block redefines every ramp
    // step, so the same class flips to the dark wash automatically. The
    // class is themed when its `bg-<hue>-<step>` token exists in BOTH blocks.
    let Some(rest) = class_name.strip_prefix("bg-") else {
        return true;
    };
    let (color, _alpha) = match rest.split_once('/') {
        Some((c, a)) => (c, Some(a)),
        None => (rest, None),
    };
    let Some((hue, step)) = color.rsplit_once('-') else {
        return false;
    };
    let light = crate::tokens::block_tokens(crate::ARK_CSS, ":root");
    let dark = crate::tokens::block_tokens(crate::ARK_CSS, ".dark");
    light.contains_key(&format!("--{hue}-{step}")) && dark.contains_key(&format!("--{hue}-{step}"))
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
        // The exact live regression, ARK edition: a bare tinted panel with no
        // text colour still trips the detector.
        let html = r#"<div class="border bg-amber-200 px-4 py-4"><p class="apex-em">Two-factor verification required</p></div>"#;
        let found = pale_tint_violations("control-plane", "/login?mfa=1", html);
        assert_eq!(found.len(), 1, "{found:?}");

        // The ARK primitives carry their own token pairing: both pass.
        let ok =
            r#"<div class="apex-auth-notice" data-intent="info"><p class="apex-em">ok</p></div>"#;
        assert!(pale_tint_violations("control-plane", "/login?mfa=1", ok).is_empty());
        let notice = r#"<div class="apex-notice"><b>Done</b><p>ok</p></div>"#;
        assert!(pale_tint_violations("control-plane", "/dashboard", notice).is_empty());

        // …and an unthemed alpha variant with no text colour still fails.
        let unthemed = r#"<div class="px-4 py-4 bg-amber-200">bad</div>"#;
        assert_eq!(
            pale_tint_violations("control-plane", "/dashboard", unthemed).len(),
            1
        );
    }

    /// The wordmark tones are pinned at the authority and the compiled
    /// artifact carries them: `--wordmark-apex` (the logo red) and
    /// `--wordmark-mail` (ink), plus the emphasis token `--accent-text`
    /// that links and `apex-em` derive from. The old framework utilities
    /// (.text-brand-600 / .text-surface-950 / .text-primary) must NOT come
    /// back — the wordmark renders through the primitive classes.
    #[test]
    fn wordmark_and_emphasis_tokens_are_defined_in_the_artifact() {
        let sheet = include_str!("../assets/globals.css");
        assert!(
            sheet.contains("--accent-text: 20 58 92"),
            "globals.css must define --accent-text (the link/emphasis blue-deep)"
        );
        assert!(
            sheet.contains("--wordmark-apex: 185 28 28"),
            "globals.css must carry the fixed wordmark red"
        );
        assert!(
            sheet.contains("--wordmark-mail: 9 9 11"),
            "globals.css must carry the fixed wordmark ink"
        );
        assert!(
            sheet.contains(".apex-wordmark__apex") && sheet.contains(".apex-wordmark__mail"),
            "the wordmark primitive classes must ship"
        );
        for old in [".text-surface-950", ".text-primary"] {
            assert!(
                !sheet.contains(old),
                "the framework utility {} must not return (ark primitives own the tones)",
                old
            );
        }
        // .text-brand-600 exists exactly once: the fixed KiwiCaptcha widget
        // block (runtime-injected classes, resolved to ARK tokens). No view
        // emits it (tools/check_ark_law.py enforces that).
        assert_eq!(
            sheet.matches(".text-brand-600").count(),
            1,
            ".text-brand-600 is Kiwi-widget-only in the artifact"
        );
    }
}
