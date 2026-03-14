use std::collections::HashMap;

use once_cell::sync::Lazy;

pub const ICONS_TSX: &str = include_str!("../../../../../apps/web/src/components/ui/icons.tsx");

static GLYPHS: Lazy<Vec<String>> = Lazy::new(|| {
    glyph_registry().keys().cloned().collect::<Vec<_>>()
});

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
            stroke_width: 1.75,
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
    let mut names = Vec::new();
    let mut in_union = false;

    for line in ICONS_TSX.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("type Glyph =") {
            in_union = true;
            continue;
        }
        if in_union && trimmed.starts_with("const glyphs:") {
            break;
        }
        if in_union && trimmed.starts_with('|') {
            let name = trimmed.trim_start_matches('|').trim();
            let name = name.trim_end_matches(';').trim().trim_matches('"').trim_matches('\'');
            names.push(name.to_string());
        }
    }

    let mut registry = HashMap::new();
    let mut in_glyphs = false;
    let mut current_name: Option<String> = None;
    let mut current_markup: Vec<String> = Vec::new();
    let mut paren_depth = 0_i32;

    for line in ICONS_TSX.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("const glyphs:") {
            in_glyphs = true;
            continue;
        }
        if !in_glyphs {
            continue;
        }
        if trimmed == "};" {
            break;
        }

        if current_name.is_none() {
            if let Some((raw_name, raw_markup)) = trimmed.split_once(':') {
                let name = raw_name.trim().trim_matches('"').trim_matches('\'').to_string();
                current_name = Some(name);
                current_markup.push(raw_markup.trim().to_string());
                paren_depth += paren_delta(trimmed);

                if paren_depth <= 0 && trimmed.ends_with(',') {
                    finalize_icon(&mut registry, &mut current_name, &mut current_markup);
                }
            }
            continue;
        }

        current_markup.push(trimmed.to_string());
        paren_depth += paren_delta(trimmed);
        if paren_depth <= 0 && trimmed.ends_with(',') {
            finalize_icon(&mut registry, &mut current_name, &mut current_markup);
        }
    }

    for name in names {
        registry.entry(name).or_insert_with(String::new);
    }

    registry
}

fn finalize_icon(
    registry: &mut HashMap<String, String>,
    current_name: &mut Option<String>,
    current_markup: &mut Vec<String>,
) {
    let name = current_name.take().expect("icon name should exist when finalizing");
    let joined = current_markup.join("\n");
    let markup = normalize_markup(joined.trim_end_matches(',').trim());
    registry.insert(name, markup);
    current_markup.clear();
}

fn normalize_markup(markup: &str) -> String {
    markup
        .trim_start_matches('(')
        .trim_end_matches(')')
        .replace("<>", "")
        .replace("</>", "")
        .trim()
        .to_string()
}

fn paren_delta(line: &str) -> i32 {
    line.chars().fold(0_i32, |acc, char| match char {
        '(' => acc + 1,
        ')' => acc - 1,
        _ => acc,
    })
}

fn trim_float(value: f32) -> String {
    let rendered = format!("{value:.2}");
    rendered.trim_end_matches('0').trim_end_matches('.').to_string()
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
            let svg = render_icon(glyph, IconRenderOptions::default()).expect("glyph should render");
            assert!(svg.starts_with("<svg "));
            assert!(svg.contains("viewBox=\"0 0 24 24\""));
            assert!(svg.contains("stroke-width=\"1.75\""));
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
