//! The KiwiCaptcha kiwi bird logo.
//!
//! An elegant, minimal silhouette of a kiwi bird (the flightless bird native to
//! New Zealand — not the fruit). Rendered as inline `<svg>` markup using
//! `currentColor` so it inherits the Apex coral (`--primary` / `#dd524c`) when
//! placed inside a `text-primary` container, matching the rest of the ApexMail
//! icon system (`viewBox="0 0 24 24"`, `fill`/`stroke="currentColor"`).

/// Return the kiwi silhouette as an inline SVG string.
///
/// The SVG is self-contained (no external references) and uses `currentColor`
/// so it adapts to the surrounding text color automatically.
pub fn kiwi_logo_svg() -> &'static str {
    // Kiwi bird silhouette: rounded body, small head, long distinctive beak,
    // stout legs. Drawn as a single filled path for crispness at any size.
    // NOTE: raw string uses r##"..."## because the SVG markup contains "#"
    // sequences (e.g. fill="#fff") that would prematurely close r#"..."#.
    r##"<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" role="img" aria-label="KiwiCaptcha"><path d="M20.6 13.1c-.2-.7-.7-1.3-1.3-1.7.3-.6.4-1.3.3-2-.2-1.4-1.3-2.5-2.7-2.8.1-.5.1-1 0-1.5-.3-1.8-2-3-3.8-2.7-.9.2-1.7.7-2.2 1.5-.6-.2-1.2-.2-1.8 0-1.4.4-2.3 1.7-2.3 3.1-1.3.2-2.4 1.2-2.7 2.6-.1.5-.1 1 0 1.5-.9.4-1.6 1.2-1.8 2.2-.3 1.6.7 3.1 2.2 3.5l.4.1c0 .4 0 .8.1 1.1.3 1.5 1.7 2.6 3.2 2.6h.5c1.2-.2 2.1-1 2.5-2 .5.2 1.1.3 1.6.2 1.2-.2 2.1-1.1 2.4-2.2.9 0 1.7-.6 2-1.5.3-1 0-2-.8-2.6l-.4-.3c.3-.3.6-.7.7-1.1.1-.3.1-.7 0-1.1.3.2.5.5.6.8.1.4 0 .8-.2 1.1.5.1.9.4 1.2.8.4.7.3 1.5-.2 2.1-.2.2-.2.6 0 .8.1.1.3.2.4.2.2 0 .3-.1.4-.2.8-1 1-2.4.4-3.5-.3-.5-.7-.9-1.2-1.1.4-.6.5-1.4.2-2.1z"/><circle cx="16.2" cy="9.4" r="0.7" fill="#fff"/></svg>"##
}

/// A compact "mark" variant — just the kiwi head + beak, suitable for a small
/// badge/chip where the full body is too detailed.
pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M14 5c-2.8 0-5 2.2-5 5 0 .4 0 .8.1 1.2-1.8.4-3.1 2-3.1 3.9 0 .5.1 1 .3 1.5-.2.1-.4.2-.5.3-.3.2-.3.6-.1.8.1.2.3.2.5.2.1 0 .2 0 .3-.1 2-1.3 4.6-1.5 6.8-.7 1.2.4 2.5.4 3.7 0 .3-.1.4-.4.3-.7-.1-.2-.3-.4-.6-.3-1 .3-2.1.3-3.1 0 .8-.9 1.3-2.1 1.3-3.4 0-2.8-2.2-5-5-5zm0 1.5c1.9 0 3.5 1.6 3.5 3.5S15.9 13.5 14 13.5 10.5 11.9 10.5 10 12.1 6.5 14 6.5z"/></svg>"##
}

/// The full "KiwiCaptcha" lockup: kiwi mark + wordmark, as an inline SVG group.
/// Used in the widget header chip.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 120 24" fill="currentColor" aria-hidden="true" role="img" aria-label="KiwiCaptcha"><g transform="translate(0,0)"><path d="M14 5c-2.8 0-5 2.2-5 5 0 .4 0 .8.1 1.2-1.8.4-3.1 2-3.1 3.9 0 .5.1 1 .3 1.5-.2.1-.4.2-.5.3-.3.2-.3.6-.1.8.1.2.3.2.5.2.1 0 .2 0 .3-.1 2-1.3 4.6-1.5 6.8-.7 1.2.4 2.5.4 3.7 0 .3-.1.4-.4.3-.7-.1-.2-.3-.4-.6-.3-1 .3-2.1.3-3.1 0 .8-.9 1.3-2.1 1.3-3.4 0-2.8-2.2-5-5-5zm0 1.5c1.9 0 3.5 1.6 3.5 3.5S15.9 13.5 14 13.5 10.5 11.9 10.5 10 12.1 6.5 14 6.5z"/></g><text x="26" y="16" font-family="Inter, system-ui, sans-serif" font-size="12" font-weight="700" letter-spacing="0.04em">KiwiCaptcha</text></svg>"##
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logos_are_valid_svg_markup() {
        assert!(kiwi_logo_svg().starts_with("<svg"));
        assert!(kiwi_logo_svg().ends_with("</svg>"));
        assert!(kiwi_mark_svg().starts_with("<svg"));
        assert!(kiwi_mark_svg().ends_with("</svg>"));
        assert!(kiwi_lockup_svg().contains("KiwiCaptcha"));
    }

    #[test]
    fn logos_use_current_color_for_apex_theming() {
        // currentColor ensures the kiwi inherits the Apex coral from its parent.
        assert!(kiwi_logo_svg().contains("currentColor"));
        assert!(kiwi_mark_svg().contains("currentColor"));
    }
}
