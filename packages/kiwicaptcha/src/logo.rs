//! KiwiCaptcha brand marks.
//! Released by Bel Consulting OÜ under MIT License.

/// The KiwiCaptcha mark: the Spiral Lock (the proof-of-work spiral
/// seated inside the padlock shackle — design round 2026-09-05, no. 8
/// of twelve proposals; see design/logo-proposals.html). Two strokes,
/// 64x64 grid, currentColor, no gradients, animate-free.

pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
  <g stroke="currentColor" stroke-width="6.6" stroke-linecap="round" fill="none">
    <path d="M32 36.5 c0 -4 5.4 -4 5.4 0 c0 5.4 -8.1 6.8 -11 1.4 c-4.1 -6.8 2.7 -14.9 10.4 -13.5 c10.8 1.4 13.5 13.5 6.8 21.6 c-8.1 10.8 -25.7 8.1 -31.1 -5.4 c-5.4 -14.9 6.8 -29.7 23 -28.4"/>
  </g>
  <path d="M21 26 v-4 a11 11 0 0 1 22 0 v4" stroke="currentColor" stroke-width="6.6" stroke-linecap="round" fill="none"/>
</svg>"##
}

/// Full kiwi bird logo.
pub fn kiwi_logo_svg() -> &'static str {
    kiwi_mark_svg()
}

/// Lockup: kiwi mark + wordmark.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 200 40" fill="none" xmlns="http://www.w3.org/2000/svg">
  <g transform="translate(2, -3) scale(0.56)" stroke="currentColor" stroke-width="6.6" stroke-linecap="round" fill="none">
    <path d="M32 36.5 c0 -4 5.4 -4 5.4 0 c0 5.4 -8.1 6.8 -11 1.4 c-4.1 -6.8 2.7 -14.9 10.4 -13.5 c10.8 1.4 13.5 13.5 6.8 21.6 c-8.1 10.8 -25.7 8.1 -31.1 -5.4 c-5.4 -14.9 6.8 -29.7 23 -28.4"/>
    <path d="M21 26 v-4 a11 11 0 0 1 22 0 v4"/>
  </g>
  <text x="48" y="27" font-family="Inter,system-ui,sans-serif" font-size="20" font-weight="700" letter-spacing="-0.02em" fill="currentColor">KiwiCaptcha</text>
</svg>"##
}

/// Shield variant for security contexts.
pub fn kiwi_shield_svg() -> &'static str {
    r##"<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M16 2L6 6v8c0 7 4.5 12 10 14 5.5-2 10-7 10-14V6L16 2z" fill="currentColor" opacity="0.08"/>
  <path d="M16 2L6 6v8c0 7 4.5 12 10 14 5.5-2 10-7 10-14V6L16 2z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
  <g transform="translate(8, 8) scale(0.25)">
    <g transform="translate(0, -5) scale(0.66)" stroke="currentColor" stroke-width="6.6" stroke-linecap="round" fill="none">
      <path d="M32 36.5 c0 -4 5.4 -4 5.4 0 c0 5.4 -8.1 6.8 -11 1.4 c-4.1 -6.8 2.7 -14.9 10.4 -13.5 c10.8 1.4 13.5 13.5 6.8 21.6 c-8.1 10.8 -25.7 8.1 -31.1 -5.4 c-5.4 -14.9 6.8 -29.7 23 -28.4"/>
      <path d="M21 26 v-4 a11 11 0 0 1 22 0 v4"/>
    </g>
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
