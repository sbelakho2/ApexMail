//! KiwiCaptcha logo — an elegant kiwi bird silhouette.

/// Compact kiwi mark for the widget icon (24x24).
/// The kiwi faces right: plump round body, long slender beak, tiny eye, stubby legs.
pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 32 32" fill="none" aria-hidden="true">
  <path d="M6 20 C6 12 11 8 17 8 C20 8 22 9 23.5 11 L30 9.5 C30.8 9.3 31.5 9.8 31.5 10.5 C31.5 11.2 31 11.7 30.2 11.8 L24 13 C24.6 14.5 25 16.2 25 18 C25 23 21 26 16 26 C11 26 6 23 6 18 Z" fill="currentColor"/>
  <circle cx="20" cy="12.5" r="1.2" fill="#fff"/>
  <circle cx="20.3" cy="12.2" r="0.5" fill="currentColor"/>
  <path d="M12 26.5 L10.5 30.5 M15.5 26.5 L14.5 30.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
</svg>"##
}

/// Full kiwi bird.
pub fn kiwi_logo_svg() -> &'static str {
    kiwi_mark_svg()
}

/// Lockup: kiwi mark + wordmark.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 160 32" fill="none" aria-hidden="true">
  <path d="M6 20 C6 12 11 8 17 8 C20 8 22 9 23.5 11 L30 9.5 C30.8 9.3 31.5 9.8 31.5 10.5 C31.5 11.2 31 11.7 30.2 11.8 L24 13 C24.6 14.5 25 16.2 25 18 C25 23 21 26 16 26 C11 26 6 23 6 18 Z" fill="currentColor"/>
  <circle cx="20" cy="12.5" r="1.2" fill="#fff"/>
  <path d="M12 26.5 L10.5 30.5 M15.5 26.5 L14.5 30.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  <text x="38" y="21" font-family="Inter,system-ui,sans-serif" font-size="14" font-weight="800" letter-spacing="-0.02em" fill="currentColor">KiwiCaptcha</text>
</svg>"##
}

/// Shield variant.
pub fn kiwi_shield_svg() -> &'static str {
    r##"<svg viewBox="0 0 32 32" fill="none" aria-hidden="true">
  <path d="M16 2L6 6v8c0 7 4.5 12 10 14 5.5-2 10-7 10-14V6L16 2z" fill="currentColor" opacity="0.08" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
  <g transform="translate(-2, -1)">
    <path d="M6 20 C6 13 10 10 15 10 C17.5 10 19.5 10.8 21 12.5 L27.5 11 C28.2 10.8 28.8 11.2 28.8 12 C28.8 12.6 28.4 13 27.7 13.2 L22 14.5 C22.5 15.8 22.8 17.2 22.8 18.8 C22.8 23 19.5 25.5 15.5 25.5 C11.5 25.5 7.5 23 7.5 18.5 Z" fill="currentColor"/>
    <circle cx="19" cy="13.5" r="1" fill="#fff"/>
  </g>
</svg>"##
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn logos_valid() {
        assert!(kiwi_mark_svg().starts_with("<svg") && kiwi_mark_svg().ends_with("</svg>"));
        assert!(kiwi_shield_svg().starts_with("<svg"));
    }
    #[test]
    fn logos_use_current_color() {
        assert!(kiwi_mark_svg().contains("currentColor"));
    }
}
