//! KiwiCaptcha logo — an elegant, stylized kiwi bird.
//! Released by Bel Consulting OÜ under MIT License.

/// Compact kiwi mark for the widget icon (32x32).
/// Features a stylized, plump kiwi bird with a friendly wink.
pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M22 18.5C22 23.1944 18.1944 27 13.5 27C8.80558 27 5 23.1944 5 18.5C5 13.8056 8.80558 10 13.5 10C15.1186 10 16.6147 10.4532 17.881 11.2381L25.6464 3.47275C26.037 3.08222 26.6701 3.08222 27.0607 3.47275C27.4512 3.86327 27.4512 4.49644 27.0607 4.88696L19.2953 12.6523C20.9878 14.106 22 16.1848 22 18.5Z" fill="currentColor"/>
  <circle cx="17.5" cy="15.5" r="1.2" fill="white"/>
  <circle cx="18" cy="15" r="0.5" fill="currentColor">
    <animate attributeName="opacity" values="1;1;0;1;1" keyTimes="0;0.95;0.97;0.99;1" dur="5s" repeatCount="indefinite" />
  </circle>
  <path d="M10 27V29.5C10 30.0523 9.55228 30.5 9 30.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  <path d="M17 27V29.5C17 30.0523 17.4477 30.5 18 30.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
</svg>"##
}

/// Full kiwi bird logo.
pub fn kiwi_logo_svg() -> &'static str {
    kiwi_mark_svg()
}

/// Lockup: kiwi mark + wordmark.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 180 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M22 18.5C22 23.1944 18.1944 27 13.5 27C8.80558 27 5 23.1944 5 18.5C5 13.8056 8.80558 10 13.5 10C15.1186 10 16.6147 10.4532 17.881 11.2381L25.6464 3.47275C26.037 3.08222 26.6701 3.08222 27.0607 3.47275C27.4512 3.86327 27.4512 4.49644 27.0607 4.88696L19.2953 12.6523C20.9878 14.106 22 16.1848 22 18.5Z" fill="currentColor"/>
  <circle cx="17.5" cy="15.5" r="1.2" fill="white"/>
  <circle cx="18" cy="15" r="0.5" fill="currentColor"/>
  <path d="M10 27V29.5C10 30.0523 9.55228 30.5 9 30.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  <path d="M17 27V29.5C17 30.0523 17.4477 30.5 18 30.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  <text x="38" y="22" font-family="system-ui,sans-serif" font-size="18" font-weight="700" letter-spacing="-0.04em" fill="currentColor">KiwiCaptcha</text>
</svg>"##
}

/// Shield variant for security contexts.
pub fn kiwi_shield_svg() -> &'static str {
    r##"<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M16 2L6 6v8c0 7 4.5 12 10 14 5.5-2 10-7 10-14V6L16 2z" fill="currentColor" opacity="0.1"/>
  <path d="M16 2L6 6v8c0 7 4.5 12 10 14 5.5-2 10-7 10-14V6L16 2z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
  <g transform="translate(6, 6) scale(0.625)">
    <path d="M22 18.5C22 23.1944 18.1944 27 13.5 27C8.80558 27 5 23.1944 5 18.5C5 13.8056 8.80558 10 13.5 10C15.1186 10 16.6147 10.4532 17.881 11.2381L25.6464 3.47275C26.037 3.08222 26.6701 3.08222 27.0607 3.47275C27.4512 3.86327 27.4512 4.49644 27.0607 4.88696L19.2953 12.6523C20.9878 14.106 22 16.1848 22 18.5Z" fill="currentColor"/>
    <circle cx="17.5" cy="15.5" r="1.2" fill="white"/>
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
