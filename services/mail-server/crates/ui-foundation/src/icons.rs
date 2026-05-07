use std::collections::HashMap;

use once_cell::sync::Lazy;
use serde::Deserialize;

pub const ICON_BASELINE_SOURCE: &str = include_str!("../baselines/web/icons.baseline.txt");

#[derive(Debug, Deserialize)]
struct IconBaseline {
    glyphs: HashMap<String, String>,
}

static GLYPHS: Lazy<Vec<String>> =
    Lazy::new(|| glyph_registry().keys().cloned().collect::<Vec<_>>());

static GLYPH_REGISTRY: Lazy<HashMap<String, String>> = Lazy::new(build_glyph_registry);

#[derive(Debug, Clone, PartialEq)]
pub struct IconRenderOptions<'a> {
    pub size: u16,
    pub stroke_width: f32,
    pub class_name: Option<&'a str>,
}

impl Default for IconRenderOptions<'_> {
    fn default() -> Self {
        Self {
            size: 20,
            stroke_width: 2.0,
            class_name: None,
        }
    }
}

pub fn glyph_registry() -> &'static HashMap<String, String> {
    &GLYPH_REGISTRY
}

pub fn glyph_markup(name: &str) -> Option<&'static str> {
    glyph_registry().get(name).map(String::as_str)
}

pub fn render_icon(name: &str, options: IconRenderOptions<'_>) -> Option<String> {
    let markup = glyph_markup(name)?;
    let class_name = options
        .class_name
        .map(|value| format!(" class=\"{}\"", value))
        .unwrap_or_default();

    Some(format!(
        "<svg viewBox=\"0 0 24 24\" width=\"{size}\" height=\"{size}\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"{stroke_width}\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"{class_name}>{markup}</svg>",
        size = options.size,
        stroke_width = trim_float(options.stroke_width),
        class_name = class_name,
        markup = markup,
    ))
}

fn build_glyph_registry() -> HashMap<String, String> {
    serde_json::from_str::<IconBaseline>(ICON_BASELINE_SOURCE)
        .expect("icon baseline must parse")
        .glyphs
}

fn trim_float(value: f32) -> String {
    let rendered = format!("{value:.2}");
    rendered
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

pub fn glyph_names() -> &'static [String] {
    GLYPHS.as_slice()
}

pub fn has_glyph(name: &str) -> bool {
    glyph_registry().contains_key(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_known_glyphs() {
        assert!(has_glyph("arrow-right"));
        assert!(has_glyph("lock"));
        assert!(has_glyph("calculator"));
        assert!(has_glyph("shield"));
    }

    #[test]
    fn includes_large_icon_set() {
        assert!(glyph_names().len() >= 90);
    }

    #[test]
    fn renders_svg_for_every_glyph() {
        for glyph in glyph_names() {
            let svg =
                render_icon(glyph, IconRenderOptions::default()).expect("glyph should render");
            assert!(svg.starts_with("<svg "));
            assert!(svg.contains("viewBox=\"0 0 24 24\""));
            assert!(svg.contains("stroke-width=\"2\""));
        }
    }

    #[test]
    fn preserves_scaling_and_alignment() {
        let default_svg = render_icon("arrow-right", IconRenderOptions::default()).unwrap();
        let large_svg = render_icon(
            "arrow-right",
            IconRenderOptions {
                size: 24,
                stroke_width: 2.0,
                class_name: Some("size-lg"),
            },
        )
        .unwrap();

        assert!(default_svg.contains("width=\"20\""));
        assert!(default_svg.contains("height=\"20\""));
        assert!(large_svg.contains("width=\"24\""));
        assert!(large_svg.contains("height=\"24\""));
        assert!(large_svg.contains("stroke-width=\"2\""));
        assert!(large_svg.contains("class=\"size-lg\""));
        assert!(default_svg.contains("stroke-linecap=\"round\""));
        assert!(default_svg.contains("stroke-linejoin=\"round\""));
    }
}
