//! The KiwiCaptcha kiwi bird logo.
//!
//! Clean, simple kiwi bird silhouettes — the flightless bird with its
//! signature long curved beak. Instantly recognizable at any size.

/// Compact kiwi mark — the bird in profile with the distinctive long beak.
/// This is what appears in the widget icon chip.
pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 24 24" fill="none" aria-hidden="true" role="img" aria-label="KiwiCaptcha">
  <path d="M4 14.5c0-3.6 2.9-6.5 6.5-6.5 1.6 0 3 .6 4.1 1.5l3.7-3.7c.3-.3.7-.3 1 0 .3.3.3.7 0 1L16 10.6c.9 1.1 1.5 2.5 1.5 4.1 0 .6-.1 1.2-.3 1.7l.8.3c.4.1.5.5.4.9-.1.4-.5.6-.9.4l-.7-.3c-1.1 1.8-3 3-5.3 3-3.6 0-6.5-2.9-6.5-6.5z" fill="currentColor"/>
  <circle cx="13.5" cy="11" r=".8" fill="#fff"/>
  <path d="M9.5 19.5l-.5 2M11.5 19.5l-.5 2" stroke="currentColor" stroke-width="1" stroke-linecap="round"/>
</svg>"##
}

/// The full kiwi bird — side profile with body, long beak, and legs.
pub fn kiwi_logo_svg() -> &'static str {
    kiwi_mark_svg()
}

/// The full "KiwiCaptcha" lockup: kiwi mark + wordmark text.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 140 24" fill="none" aria-hidden="true" role="img" aria-label="KiwiCaptcha">
  <g>
    <path d="M4 14.5c0-3.6 2.9-6.5 6.5-6.5 1.6 0 3 .6 4.1 1.5l3.7-3.7c.3-.3.7-.3 1 0 .3.3.3.7 0 1L16 10.6c.9 1.1 1.5 2.5 1.5 4.1 0 .6-.1 1.2-.3 1.7l.8.3c.4.1.5.5.4.9-.1.4-.5.6-.9.4l-.7-.3c-1.1 1.8-3 3-5.3 3-3.6 0-6.5-2.9-6.5-6.5z" fill="currentColor"/>
    <circle cx="13.5" cy="11" r=".8" fill="#fff"/>
  </g>
  <text x="28" y="16" font-family="Inter, system-ui, sans-serif" font-size="12" font-weight="700" letter-spacing="0.04em" fill="currentColor">KiwiCaptcha</text>
</svg>"##
}

/// A shield variant — the kiwi mark inside a shield outline.
pub fn kiwi_shield_svg() -> &'static str {
    r##"<svg viewBox="0 0 24 24" fill="none" aria-hidden="true" role="img" aria-label="Protected by KiwiCaptcha">
  <path d="M12 2L4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" fill="currentColor" opacity="0.12" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
  <g transform="translate(3.5, 3) scale(0.7)">
    <path d="M4 14.5c0-3.6 2.9-6.5 6.5-6.5 1.6 0 3 .6 4.1 1.5l3.7-3.7c.3-.3.7-.3 1 0 .3.3.3.7 0 1L16 10.6c.9 1.1 1.5 2.5 1.5 4.1 0 .6-.1 1.2-.3 1.7l.8.3c.4.1.5.5.4.9-.1.4-.5.6-.9.4l-.7-.3c-1.1 1.8-3 3-5.3 3-3.6 0-6.5-2.9-6.5-6.5z" fill="currentColor"/>
    <circle cx="13.5" cy="11" r=".8" fill="#fff"/>
  </g>
</svg>"##
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
    }

    #[test]
    fn logos_use_current_color_for_host_theming() {
        assert!(kiwi_mark_svg().contains("currentColor"));
        assert!(kiwi_shield_svg().contains("currentColor"));
    }
}
