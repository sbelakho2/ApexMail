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

/// The fixed humanist wordmark: lowercase "kiwi captcha" as outlined
/// absolute paths (Alegreya Sans Bold; kiwi at 100 units, captcha at 82
/// on the same baseline, the word gap fixed in the master). No text
/// element and no font dependency. See design/lettering.json.
pub fn kiwi_wordmark_svg() -> &'static str {
    include_str!("../resources/kiwi-wordmark.svg").trim()
}

/// Lockup: the primary Spiral Lock with the outlined humanist wordmark.
/// The exact SVG is outlined artwork with no live font dependency.
pub fn kiwi_lockup_svg() -> &'static str {
    include_str!("../resources/kiwi-lockup.svg").trim()
}

/// Stacked lockup: the mark centered above the wordmark for square-ish
/// placements where the horizontal signature cannot be read comfortably.
pub fn kiwi_stacked_svg() -> &'static str {
    include_str!("../resources/kiwi-stacked.svg").trim()
}

/// App container: the platform tile (Ink `#08110C` with the Teal
/// `#9EDFD4` mark). A tile is a container, not an extra enclosing shape
/// in the bare mark; use [`kiwi_mark_svg`] for monochrome toolbar slots.
pub fn kiwi_app_icon_svg() -> &'static str {
    include_str!("../resources/kiwi-app-icon.svg").trim()
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
        for svg in [
            kiwi_mark_svg(),
            kiwi_wordmark_svg(),
            kiwi_lockup_svg(),
            kiwi_stacked_svg(),
            kiwi_app_icon_svg(),
            kiwi_shield_svg(),
        ] {
            assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        }
        assert_eq!(kiwi_logo_svg(), kiwi_mark_svg());
    }
    #[test]
    fn monochrome_marks_use_current_color() {
        for svg in [
            kiwi_mark_svg(),
            kiwi_wordmark_svg(),
            kiwi_lockup_svg(),
            kiwi_stacked_svg(),
            kiwi_shield_svg(),
        ] {
            assert!(svg.contains("currentColor"));
        }
    }
    #[test]
    fn app_icon_uses_the_identity_container_colors() {
        let svg = kiwi_app_icon_svg();
        assert!(svg.contains(r##"fill="#08110C""##));
        assert!(svg.contains(r##"stroke="#9EDFD4""##));
    }
    #[test]
    fn lettering_is_outlined_artwork_without_a_font_dependency() {
        for svg in [kiwi_wordmark_svg(), kiwi_lockup_svg(), kiwi_stacked_svg()] {
            assert!(
                !svg.contains("<text"),
                "the lettering must be outlined paths"
            );
            assert!(
                !svg.contains("font-family"),
                "the lettering must not reference a font"
            );
        }
        assert_eq!(kiwi_wordmark_svg().matches("<path d=").count(), 11);
    }
}
