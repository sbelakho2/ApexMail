//! KiwiCaptcha logo — a clean, instantly recognizable kiwi bird.
//!
//! The kiwi's defining features captured in simple geometry:
//! - Egg-shaped body
//! - Long, slender, slightly curved beak (the unmistakable kiwi signature)
//! - Small eye dot
//! - Two short legs
//!
//! At 24px the silhouette reads clearly as a bird with a long beak.

/// Compact kiwi mark for the widget icon chip (24x24).
pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <ellipse cx="9" cy="14" rx="6" ry="5.5" fill="currentColor"/>
  <path d="M14.5 11.5 L23 10.5 L23 11.5 L14.8 13 Z" fill="currentColor"/>
  <circle cx="11.5" cy="11.5" r="1" fill="#fff"/>
  <circle cx="11.8" cy="11.2" r="0.4" fill="currentColor"/>
  <line x1="7" y1="19" x2="6" y2="22" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  <line x1="10" y1="19.5" x2="9.5" y2="22.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
</svg>"##
}

/// Full kiwi bird — same as mark, available for larger displays.
pub fn kiwi_logo_svg() -> &'static str {
    kiwi_mark_svg()
}

/// Lockup: kiwi mark + wordmark text.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 140 24" fill="none" aria-hidden="true">
  <g>
    <ellipse cx="9" cy="14" rx="6" ry="5.5" fill="currentColor"/>
    <path d="M14.5 11.5 L23 10.5 L23 11.5 L14.8 13 Z" fill="currentColor"/>
    <circle cx="11.5" cy="11.5" r="1" fill="#fff"/>
    <circle cx="11.8" cy="11.2" r="0.4" fill="currentColor"/>
    <line x1="7" y1="19" x2="6" y2="22" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    <line x1="10" y1="19.5" x2="9.5" y2="22.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  </g>
  <text x="28" y="16" font-family="Inter, system-ui, sans-serif" font-size="12" font-weight="700" fill="currentColor">KiwiCaptcha</text>
</svg>"##
}

/// Shield variant — kiwi inside a shield outline for "protected by" badges.
pub fn kiwi_shield_svg() -> &'static str {
    r##"<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 2L4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" fill="currentColor" opacity="0.1" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
  <g transform="translate(0.5, 1)">
    <ellipse cx="9" cy="14" rx="5" ry="4.5" fill="currentColor"/>
    <path d="M13.5 11.5 L21 10.5 L21 11.5 L13.7 13 Z" fill="currentColor"/>
    <circle cx="10.5" cy="11.5" r="0.8" fill="#fff"/>
    <line x1="7" y1="18.5" x2="6.5" y2="21" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    <line x1="9.5" y1="19" x2="9" y2="21.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
  </g>
</svg>"##
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logos_are_valid_svg() {
        for svg in [kiwi_mark_svg(), kiwi_logo_svg(), kiwi_lockup_svg(), kiwi_shield_svg()] {
            assert!(svg.starts_with("<svg"));
            assert!(svg.ends_with("</svg>"));
        }
    }

    #[test]
    fn logos_use_current_color() {
        assert!(kiwi_mark_svg().contains("currentColor"));
        assert!(kiwi_shield_svg().contains("currentColor"));
    }
}
