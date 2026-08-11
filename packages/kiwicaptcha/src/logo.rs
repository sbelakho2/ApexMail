//! KiwiCaptcha logo — an elegant, stylized kiwi bird.
//! Released by Bel Consulting OÜ under MIT License.

/// Compact kiwi mark for the widget icon (32x32).
/// Features a stylized, organic kiwi bird with a friendly wink.
pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M26 19c0 5.5-4 10-10 10S7 24.5 7 19c0-6 3-11 7-12 2-0.5 4-0.5 6 0 4 1 6 6 6 12z" fill="currentColor"/>
  <path d="M12.5 8.5c-.8-1.5-1-3.5-.5-5.5.5-2 2-3.5 4-4 2-.5 4 .5 5 2.5.2 1 .5 2 .5 3.5" fill="currentColor"/>
  <path d="M10 7c-4 1-8 3-8.5 3.5-.3.3-.3.8 0 1 1 0.5 8 2.5 9.5 2.5" fill="currentColor"/>
  <path d="M14 29v2m6-2v2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
  <circle cx="16.5" cy="4.5" r="1" fill="white"/>
  <circle cx="17" cy="4" r="0.6" fill="currentColor">
    <animate attributeName="opacity" values="1;1;0;1;1" keyTimes="0;0.95;0.97;0.99;1" dur="5s" repeatCount="indefinite" />
  </circle>
  <path d="M19 14c1.5 0 2.5 1 2.5 2s-1 2-2.5 2-2.5-1-2.5-2 1-2 2.5-2z" fill="white" opacity="0.2"/>
</svg>"##
}

/// Full kiwi bird logo.
pub fn kiwi_logo_svg() -> &'static str {
    kiwi_mark_svg()
}

/// Lockup: kiwi mark + wordmark.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 200 40" fill="none" xmlns="http://www.w3.org/2000/svg">
  <g transform="translate(4, 4) scale(0.9)">
    <path d="M26 19c0 5.5-4 10-10 10S7 24.5 7 19c0-6 3-11 7-12 2-0.5 4-0.5 6 0 4 1 6 6 6 12z" fill="currentColor"/>
    <path d="M12.5 8.5c-.8-1.5-1-3.5-.5-5.5.5-2 2-3.5 4-4 2-.5 4 .5 5 2.5.2 1 .5 2 .5 3.5" fill="currentColor"/>
    <path d="M10 7c-4 1-8 3-8.5 3.5-.3.3-.3.8 0 1 1 0.5 8 2.5 9.5 2.5" fill="currentColor"/>
    <path d="M14 29v2m6-2v2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    <circle cx="16.5" cy="4.5" r="1" fill="white"/>
  </g>
  <text x="48" y="27" font-family="Inter,system-ui,sans-serif" font-size="20" font-weight="700" letter-spacing="-0.02em" fill="currentColor">KiwiCaptcha</text>
</svg>"##
}

/// Shield variant for security contexts.
pub fn kiwi_shield_svg() -> &'static str {
    r##"<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M16 2L6 6v8c0 7 4.5 12 10 14 5.5-2 10-7 10-14V6L16 2z" fill="currentColor" opacity="0.08"/>
  <path d="M16 2L6 6v8c0 7 4.5 12 10 14 5.5-2 10-7 10-14V6L16 2z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
  <g transform="translate(7.5, 7.5) scale(0.53)">
    <path d="M26 19c0 5.5-4 10-10 10S7 24.5 7 19c0-6 3-11 7-12 2-0.5 4-0.5 6 0 4 1 6 6 6 12z" fill="currentColor"/>
    <path d="M12.5 8.5c-.8-1.5-1-3.5-.5-5.5.5-2 2-3.5 4-4 2-.5 4 .5 5 2.5.2 1 .5 2 .5 3.5" fill="currentColor"/>
    <path d="M10 7c-4 1-8 3-8.5 3.5-.3.3-.3.8 0 1 1 0.5 8 2.5 9.5 2.5" fill="currentColor"/>
    <circle cx="16.5" cy="4.5" r="1" fill="white"/>
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
