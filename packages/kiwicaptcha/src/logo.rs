//! KiwiCaptcha logo — an elegant, stylized kiwi bird.
//! Released by Bel Consulting OÜ under MIT License.

/// Compact kiwi mark for the widget icon (32x32).
/// Features a stylized, plump kiwi bird with a friendly wink.
pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M28 20C28 25.5228 23.5228 30 18 30C12.4772 30 8 25.5228 8 20C8 16 10.5 11.5 14.5 10.5C15.5 10.25 17 10 19 10C24.5228 10 28 14.4772 28 20Z" fill="currentColor"/>
  <path d="M14.5 10.5C12.5 9 11.5 6.5 12 4.5C12.5 2.5 14.5 1.5 16.5 2C18.5 2.5 19.5 4.5 19 6.5C18.8 7.5 18.5 8.5 19 10" fill="currentColor"/>
  <path d="M12.5 5L3 9.5C2.5 9.7 2.5 10.3 3 10.5L13.5 12" fill="currentColor"/>
  <circle cx="15.5" cy="5.5" r="1.2" fill="white"/>
  <circle cx="16" cy="5" r="0.6" fill="currentColor">
    <animate attributeName="opacity" values="1;1;0;1;1" keyTimes="0;0.95;0.97;0.99;1" dur="4s" repeatCount="indefinite" />
  </circle>
  <path d="M14 30V32M22 30V32" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
</svg>"##
}

/// Full kiwi bird logo.
pub fn kiwi_logo_svg() -> &'static str {
    kiwi_mark_svg()
}

/// Lockup: kiwi mark + wordmark.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 200 40" fill="none" xmlns="http://www.w3.org/2000/svg">
  <g transform="translate(0, 4)">
    <path d="M28 20C28 25.5228 23.5228 30 18 30C12.4772 30 8 25.5228 8 20C8 16 10.5 11.5 14.5 10.5C15.5 10.25 17 10 19 10C24.5228 10 28 14.4772 28 20Z" fill="currentColor"/>
    <path d="M14.5 10.5C12.5 9 11.5 6.5 12 4.5C12.5 2.5 14.5 1.5 16.5 2C18.5 2.5 19.5 4.5 19 6.5C18.8 7.5 18.5 8.5 19 10" fill="currentColor"/>
    <path d="M12.5 5L3 9.5C2.5 9.7 2.5 10.3 3 10.5L13.5 12" fill="currentColor"/>
    <circle cx="15.5" cy="5.5" r="1.2" fill="white"/>
    <path d="M14 30V32M22 30V32" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  </g>
  <text x="44" y="27" font-family="system-ui,sans-serif" font-size="22" font-weight="800" letter-spacing="-0.03em" fill="currentColor">KiwiCaptcha</text>
</svg>"##
}

/// Shield variant for security contexts.
pub fn kiwi_shield_svg() -> &'static str {
    r##"<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M16 2L6 6v8c0 7 4.5 12 10 14 5.5-2 10-7 10-14V6L16 2z" fill="currentColor" opacity="0.1"/>
  <path d="M16 2L6 6v8c0 7 4.5 12 10 14 5.5-2 10-7 10-14V6L16 2z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
  <g transform="translate(7, 7) scale(0.56)">
    <path d="M28 20C28 25.5228 23.5228 30 18 30C12.4772 30 8 25.5228 8 20C8 16 10.5 11.5 14.5 10.5C15.5 10.25 17 10 19 10C24.5228 10 28 14.4772 28 20Z" fill="currentColor"/>
    <path d="M14.5 10.5C12.5 9 11.5 6.5 12 4.5C12.5 2.5 14.5 1.5 16.5 2C18.5 2.5 19.5 4.5 19 6.5C18.8 7.5 18.5 8.5 19 10" fill="currentColor"/>
    <path d="M12.5 5L3 9.5C2.5 9.7 2.5 10.3 3 10.5L13.5 12" fill="currentColor"/>
    <circle cx="15.5" cy="5.5" r="1.2" fill="white"/>
    <path d="M14 30V32M22 30V32" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
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
