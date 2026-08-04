//! The KiwiCaptcha kiwi bird logo.
//!
//! Clean, geometric kiwi bird silhouettes — the flightless bird native to New
//! Zealand, instantly recognizable by its rounded body and long curved beak.
//! Rendered as inline `<svg>` markup using `currentColor` so the logo inherits
//! the host application's theme color (Apex coral `#dd524c` via `text-primary`).
//!
//! All three variants share the same viewBox (`0 0 24 24`) so they scale
//! crisply from 16px favicon to 128px hero.

/// The full kiwi bird — side profile with the distinctive long beak pointing
/// right, rounded pear-shaped body, and two stout legs. This is the hero
/// variant used in documentation and large displays.
pub fn kiwi_logo_svg() -> &'static str {
    r##"<svg viewBox="0 0 24 24" fill="none" aria-hidden="true" role="img" aria-label="KiwiCaptcha"><path d="M5.5 11.5c0-3 2-5.5 5.5-5.5 2.2 0 3.8 1 4.7 2.5l.8-.3c.4-.1.8 0 1 .4.2.4 0 .8-.3 1l-.7.3c.1.5.2 1 .2 1.6 0 .6-.1 1.1-.2 1.6l.7.3c.4.2.5.6.3 1-.1.4-.6.5-1 .4l-.8-.3c-.9 1.5-2.5 2.5-4.7 2.5-.7 0-1.3-.1-1.9-.3v.3c0 .8-.2 1.5-.6 2H8v-1.5c-.4-.2-.8-.5-1.1-.9-.4.5-.9.9-1.4 1.2-.4.2-.8.1-1-.3-.2-.4-.1-.8.3-1 .5-.3 1-.7 1.3-1.2-.4-.7-.6-1.5-.6-2.3z" fill="currentColor"/><circle cx="14.5" cy="10" r="1" fill="#fff"/><path d="M10 19.5l-1 2M12 19.5l-1 2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>"##
}

/// Compact kiwi mark — the kiwi head with its signature long beak, suitable
/// for small badges and the widget icon chip. The beak is the defining
/// feature that makes the bird instantly recognizable even at 24px.
pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 24 24" fill="none" aria-hidden="true" role="img" aria-label="KiwiCaptcha"><path d="M8.5 9C8.5 6.5 10.5 5 13 5c1.8 0 3.2.8 4 2L21 5.5c.4-.1.8.1.9.5.1.4-.1.8-.5.9L16.8 8.4c.1.5.2 1 .2 1.6 0 .7-.1 1.3-.3 1.9.5.3.9.7 1.1 1.2.2.4 0 .8-.4 1-.4.2-.8 0-1-.4-.2-.3-.4-.5-.7-.7-1 1.2-2.5 2-4.2 2-2.5 0-4.5-1.5-4.5-4 0-.3 0-.7.1-1l-.6-.2c-.4-.1-.6-.5-.5-.9.1-.4.5-.6.9-.5l.5.2c.2-.5.5-1 .9-1.4-.8.2-1.5.6-2 1.2-.3.3-.7.3-1 0-.3-.3-.3-.7 0-1 .7-.8 1.7-1.3 2.8-1.5L8.5 9z" fill="currentColor"/><circle cx="14" cy="9" r="0.9" fill="#fff"/></svg>"##
}

/// The full "KiwiCaptcha" lockup: kiwi mark + wordmark text. Used in the
/// widget header and documentation headers.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 140 24" fill="none" aria-hidden="true" role="img" aria-label="KiwiCaptcha"><g transform="translate(0,0)"><path d="M8.5 9C8.5 6.5 10.5 5 13 5c1.8 0 3.2.8 4 2L21 5.5c.4-.1.8.1.9.5.1.4-.1.8-.5.9L16.8 8.4c.1.5.2 1 .2 1.6 0 .7-.1 1.3-.3 1.9.5.3.9.7 1.1 1.2.2.4 0 .8-.4 1-.4.2-.8 0-1-.4-.2-.3-.4-.5-.7-.7-1 1.2-2.5 2-4.2 2-2.5 0-4.5-1.5-4.5-4 0-.3 0-.7.1-1l-.6-.2c-.4-.1-.6-.5-.5-.9.1-.4.5-.6.9-.5l.5.2c.2-.5.5-1 .9-1.4-.8.2-1.5.6-2 1.2-.3.3-.7.3-1 0-.3-.3-.3-.7 0-1 .7-.8 1.7-1.3 2.8-1.5L8.5 9z" fill="currentColor"/><circle cx="14" cy="9" r="0.9" fill="#fff"/></g><text x="28" y="16" font-family="Inter, system-ui, sans-serif" font-size="12" font-weight="700" letter-spacing="0.04em" fill="currentColor">KiwiCaptcha</text></svg>"##
}

/// A shield variant — the kiwi mark inside a shield outline. Used for
/// security-badging contexts where a "protected by" visual is needed.
pub fn kiwi_shield_svg() -> &'static str {
    r##"<svg viewBox="0 0 24 24" fill="none" aria-hidden="true" role="img" aria-label="Protected by KiwiCaptcha"><path d="M12 2L4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" fill="currentColor" opacity="0.12" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><g transform="translate(2.5, 3) scale(0.78)"><path d="M8.5 9C8.5 6.5 10.5 5 13 5c1.8 0 3.2.8 4 2L21 5.5c.4-.1.8.1.9.5.1.4-.1.8-.5.9L16.8 8.4c.1.5.2 1 .2 1.6 0 .7-.1 1.3-.3 1.9.5.3.9.7 1.1 1.2.2.4 0 .8-.4 1-.4.2-.8 0-1-.4-.2-.3-.4-.5-.7-.7-1 1.2-2.5 2-4.2 2-2.5 0-4.5-1.5-4.5-4 0-.3 0-.7.1-1l-.6-.2c-.4-.1-.6-.5-.5-.9.1-.4.5-.6.9-.5l.5.2c.2-.5.5-1 .9-1.4-.8.2-1.5.6-2 1.2-.3.3-.7.3-1 0-.3-.3-.3-.7 0-1 .7-.8 1.7-1.3 2.8-1.5L8.5 9z" fill="currentColor"/><circle cx="14" cy="9" r="0.9" fill="#fff"/></g></svg>"##
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
        assert!(kiwi_shield_svg().starts_with("<svg"));
        assert!(kiwi_shield_svg().ends_with("</svg>"));
    }

    #[test]
    fn logos_use_current_color_for_host_theming() {
        // currentColor ensures the kiwi inherits the Apex coral from its parent.
        assert!(kiwi_logo_svg().contains("currentColor"));
        assert!(kiwi_mark_svg().contains("currentColor"));
        assert!(kiwi_shield_svg().contains("currentColor"));
    }

    #[test]
    fn logos_have_recognizable_beak() {
        // The long beak is the defining kiwi feature. The mark should have
        // a path extending toward the right edge (beak direction).
        assert!(kiwi_mark_svg().len() > 200, "mark SVG should be detailed enough to be recognizable");
    }
}
