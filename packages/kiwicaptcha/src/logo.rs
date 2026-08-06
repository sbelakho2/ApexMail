//! KiwiCaptcha logo — a clean, elegant kiwi bird silhouette.
//!
//! The kiwi (Apteryx) is a flightless bird native to New Zealand, instantly
//! recognizable by its pear-shaped body and very long slender beak.

/// Compact kiwi mark for the widget icon (24x24 viewBox).
/// The bird faces right: round body, long beak, small head, two short legs.
pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M5 12 C5 8 8 6 11 6 C13 6 14.5 7 15.3 8.5 C16 8.3 19 7.5 22 7.8 C22.4 7.85 22.6 8.1 22.5 8.5 C22.4 8.9 22.1 9.05 21.7 9 C19.5 8.8 17 9.3 16 9.6 C16.6 10.5 17 11.7 17 13 C17 16.5 14 19 11 19 C8 19 5 16.5 5 13 Z" fill="currentColor"/>
  <circle cx="14" cy="9.5" r="0.9" fill="#fff"/>
  <circle cx="14.2" cy="9.3" r="0.35" fill="currentColor"/>
  <path d="M8 19.5 L7.2 22.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  <path d="M11 19.5 L10.5 22.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
</svg>"##
}

/// Full kiwi bird — same as mark.
pub fn kiwi_logo_svg() -> &'static str {
    kiwi_mark_svg()
}

/// Lockup: kiwi mark + wordmark text.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 140 24" fill="none" aria-hidden="true">
  <path d="M5 12 C5 8 8 6 11 6 C13 6 14.5 7 15.3 8.5 C16 8.3 19 7.5 22 7.8 C22.4 7.85 22.6 8.1 22.5 8.5 C22.4 8.9 22.1 9.05 21.7 9 C19.5 8.8 17 9.3 16 9.6 C16.6 10.5 17 11.7 17 13 C17 16.5 14 19 11 19 C8 19 5 16.5 5 13 Z" fill="currentColor"/>
  <circle cx="14" cy="9.5" r="0.9" fill="#fff"/>
  <path d="M8 19.5 L7.2 22.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  <path d="M11 19.5 L10.5 22.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  <text x="28" y="16" font-family="Inter, system-ui, sans-serif" font-size="12" font-weight="700" fill="currentColor">KiwiCaptcha</text>
</svg>"##
}

/// Shield variant — kiwi mark inside a shield.
pub fn kiwi_shield_svg() -> &'static str {
    r##"<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 2L4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" fill="currentColor" opacity="0.1" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
  <g transform="translate(0, 0.5)">
    <path d="M5 12 C5 9 7.5 7.5 10 7.5 C11.5 7.5 12.8 8.2 13.5 9.3 C14 9.15 16 8.7 18 8.9 C18.3 8.93 18.45 9.1 18.4 9.4 C18.35 9.7 18.15 9.8 17.85 9.77 C16.2 9.6 14.5 10 13.8 10.2 C14.2 10.9 14.5 11.8 14.5 12.8 C14.5 15.5 12.3 17.5 10 17.5 C7.7 17.5 5.5 15.5 5.5 12.8 Z" fill="currentColor"/>
    <circle cx="12.5" cy="10" r="0.7" fill="#fff"/>
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
    }
}
