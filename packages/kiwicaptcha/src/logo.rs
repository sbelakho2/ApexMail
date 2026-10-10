//! KiwiCaptcha brand marks.
//! Released by Bel Consulting OÜ under MIT License.

/// The primary Spiral Lock: a continuous proof-of-work spiral beneath
/// a raised shackle. Two strokes on a 64x64 grid, monochrome through
/// `currentColor`, with no effects or animation. The taller shackle and
/// open center preserve the work-to-access silhouette at favicon sizes.
/// See design/brand-preview.html for optical size and theme specimens.
pub fn kiwi_mark_svg() -> &'static str {
    include_str!("../resources/kiwi-mark.svg").trim()
}

/// Primary KiwiCaptcha logo mark.
pub fn kiwi_logo_svg() -> &'static str {
    kiwi_mark_svg()
}

/// Lockup: the primary Spiral Lock with the KiwiCaptcha wordmark.
pub fn kiwi_lockup_svg() -> &'static str {
    include_str!("../resources/kiwi-lockup.svg").trim()
}

/// Secondary shield emblem for security status and certification contexts.
/// Use the bare Spiral Lock for branding and favicons.
pub fn kiwi_shield_svg() -> &'static str {
    include_str!("../resources/kiwi-shield.svg").trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn logos_valid() {
        for svg in [kiwi_mark_svg(), kiwi_lockup_svg(), kiwi_shield_svg()] {
            assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        }
        assert_eq!(kiwi_logo_svg(), kiwi_mark_svg());
    }
    #[test]
    fn logos_use_current_color() {
        for svg in [kiwi_mark_svg(), kiwi_lockup_svg(), kiwi_shield_svg()] {
            assert!(svg.contains("currentColor"));
        }
    }
}
