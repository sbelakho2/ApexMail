//! KiwiCaptcha logo — an elegant, stylized kiwi bird.
//! Released by Bel Consulting OÜ under MIT License.

/// The KiwiCaptcha mark: the v8 unified kiwi (circular body + beak cone,
/// one continuous path, 64x64, currentColor). Provenance note (2026-09-05
/// brand restoration): this artwork was originally drawn for the kiwi
/// identity and is the KiwiCaptcha product mark — ApexMail's own brand is
/// the separate A-mark + wordmark, and the two are enforced apart by
/// ApexMail's tools/check-kiwi-marketing-isolation.sh.
pub fn kiwi_mark_svg() -> &'static str {
    r##"<svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M 5 42 C 12 30, 18 24, 23.9 22.9 A 20 20 0 1 1 18.3 33.5 C 14 35, 9 40, 5 42 Z" fill="currentColor"/>
</svg>"##
}

/// Full kiwi bird logo.
pub fn kiwi_logo_svg() -> &'static str {
    kiwi_mark_svg()
}

/// Lockup: kiwi mark + wordmark.
pub fn kiwi_lockup_svg() -> &'static str {
    r##"<svg viewBox="0 0 200 40" fill="none" xmlns="http://www.w3.org/2000/svg">
  <g transform="translate(2, 2) scale(0.45)">
    <path d="M 5 42 C 12 30, 18 24, 23.9 22.9 A 20 20 0 1 1 18.3 33.5 C 14 35, 9 40, 5 42 Z" fill="currentColor"/>
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
    <path d="M 5 42 C 12 30, 18 24, 23.9 22.9 A 20 20 0 1 1 18.3 33.5 C 14 35, 9 40, 5 42 Z" fill="currentColor"/>
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
