//! HTML-to-plaintext conversion for email fallback bodies.
//!
//! Strips HTML tags, decodes entities, and formats text for
//! readable plaintext email rendering.

use regex::Regex;
use std::sync::LazyLock;

// ─── Regex patterns ────────────────────────────────────────────

static BLOCK_TAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)</?(p|div|br|h[1-6]|li|tr|table|hr|blockquote)\b[^>]*>").unwrap()
});

// #202: Use (?is) flags so `.*?` can match across line breaks in multi-line <a> tags
static LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<a\b[^>]*href\s*=\s*["']([^"']*)["'][^>]*>(.*?)</a>"#).unwrap()
});

static STYLE_SCRIPT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)(?:<style\b[^>]*>.*?</style>|<script\b[^>]*>.*?</script>)").unwrap()
});

static ALL_TAGS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<[^>]+>").unwrap()
});

static MULTI_NEWLINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\n{3,}").unwrap()
});

static MULTI_SPACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[^\S\n]{2,}").unwrap()
});

static HTML_ENTITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"&([a-zA-Z]+|#\d+|#x[0-9a-fA-F]+);").unwrap()
});

// ─── Public API ────────────────────────────────────────────────

/// Convert HTML to readable plaintext for email fallback.
pub fn html_to_plaintext(html: &str) -> String {
    let mut text = html.to_string();

    // 1. Remove style/script blocks entirely
    text = STYLE_SCRIPT_RE.replace_all(&text, "").into_owned();

    // 2. Convert links to "text (url)" format
    text = LINK_RE
        .replace_all(&text, |caps: &regex::Captures| {
            let url = &caps[1];
            let label = &caps[2];
            let label_clean = ALL_TAGS_RE.replace_all(label, "");
            if label_clean.trim().is_empty() {
                url.to_string()
            } else if label_clean.trim() == url {
                url.to_string()
            } else {
                format!("{} ({})", label_clean.trim(), url)
            }
        })
        .into_owned();

    // 3. Convert block-level tags to newlines
    text = BLOCK_TAGS.replace_all(&text, "\n").into_owned();

    // 4. Strip all remaining HTML tags
    text = ALL_TAGS_RE.replace_all(&text, "").into_owned();

    // 5. Decode HTML entities
    text = decode_entities(&text);

    // 6. Normalize whitespace
    text = MULTI_SPACE_RE.replace_all(&text, " ").into_owned();
    text = MULTI_NEWLINE_RE.replace_all(&text, "\n\n").into_owned();

    // 7. Trim lines and overall
    text = text
        .lines()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join("\n");

    text.trim().to_string()
}

/// Decode common HTML entities.
fn decode_entities(text: &str) -> String {
    HTML_ENTITY_RE
        .replace_all(text, |caps: &regex::Captures| {
            let entity = &caps[1];
            match entity {
                "amp" => "&".to_string(),
                "lt" => "<".to_string(),
                "gt" => ">".to_string(),
                "quot" => "\"".to_string(),
                "apos" => "'".to_string(),
                "nbsp" => " ".to_string(),
                "mdash" => "—".to_string(),
                "ndash" => "–".to_string(),
                "hellip" => "…".to_string(),
                "copy" => "©".to_string(),
                "reg" => "®".to_string(),
                "trade" => "™".to_string(),
                "laquo" => "«".to_string(),
                "raquo" => "»".to_string(),
                s if s.starts_with('#') => {
                    let code = if s.starts_with("#x") || s.starts_with("#X") {
                        u32::from_str_radix(&s[2..], 16).ok()
                    } else {
                        s[1..].parse::<u32>().ok()
                    };
                    code.and_then(char::from_u32)
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| format!("&{};", entity))
                }
                _ => format!("&{};", entity),
            }
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_html() {
        let result = html_to_plaintext("<p>Hello World</p>");
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn test_nested_tags() {
        let result = html_to_plaintext("<div><p>Hello</p><p>World</p></div>");
        assert!(result.contains("Hello"));
        assert!(result.contains("World"));
    }

    #[test]
    fn test_link_conversion() {
        let result = html_to_plaintext(
            r#"<p>Visit <a href="https://example.com">our site</a></p>"#,
        );
        assert!(result.contains("our site"));
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_link_same_label_and_url() {
        let result = html_to_plaintext(
            r#"<a href="https://example.com">https://example.com</a>"#,
        );
        assert_eq!(result, "https://example.com");
    }

    #[test]
    fn test_style_removal() {
        let result = html_to_plaintext(
            "<style>body { color: red; }</style><p>Content</p>",
        );
        assert!(!result.contains("color"));
        assert!(result.contains("Content"));
    }

    #[test]
    fn test_script_removal() {
        let result = html_to_plaintext(
            "<script>alert('xss')</script><p>Safe</p>",
        );
        assert!(!result.contains("alert"));
        assert!(result.contains("Safe"));
    }

    #[test]
    fn test_entity_decoding() {
        assert_eq!(decode_entities("&amp;"), "&");
        assert_eq!(decode_entities("&lt;"), "<");
        assert_eq!(decode_entities("&gt;"), ">");
        assert_eq!(decode_entities("&quot;"), "\"");
        assert_eq!(decode_entities("&nbsp;"), " ");
        assert_eq!(decode_entities("&mdash;"), "—");
        assert_eq!(decode_entities("&copy;"), "©");
    }

    #[test]
    fn test_numeric_entities() {
        assert_eq!(decode_entities("&#65;"), "A");
        assert_eq!(decode_entities("&#x41;"), "A");
        assert_eq!(decode_entities("&#8212;"), "—");
    }

    #[test]
    fn test_full_email_html() {
        let html = r#"
        <html>
        <head><style>body{font-family:sans-serif}</style></head>
        <body>
            <div class="container">
                <h1>Welcome!</h1>
                <p>Hello <strong>Alice</strong>,</p>
                <p>Click <a href="https://example.com/verify">here</a> to verify.</p>
                <hr>
                <p>&copy; 2024 ApexMail</p>
            </div>
        </body>
        </html>"#;
        let result = html_to_plaintext(html);
        assert!(result.contains("Welcome!"));
        assert!(result.contains("Alice"));
        assert!(result.contains("https://example.com/verify"));
        assert!(result.contains("©"));
        assert!(!result.contains("<"));
        assert!(!result.contains("font-family"));
    }

    #[test]
    fn test_whitespace_normalization() {
        let result = html_to_plaintext("<p>  Too   many   spaces  </p>");
        assert!(!result.contains("  "));
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(html_to_plaintext(""), "");
    }

    #[test]
    fn test_plain_text_passthrough() {
        let result = html_to_plaintext("Just plain text");
        assert_eq!(result, "Just plain text");
    }

    #[test]
    fn test_br_tags() {
        let result = html_to_plaintext("Line 1<br>Line 2<br/>Line 3");
        assert!(result.contains("Line 1"));
        assert!(result.contains("Line 2"));
        assert!(result.contains("Line 3"));
    }
}
