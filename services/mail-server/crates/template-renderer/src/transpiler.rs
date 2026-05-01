//! Template markup transpilation to intermediate representation.
//!
//! Validates template source, checks for forbidden imports,
//! and resolves `{{ variable }}` placeholders against props.

use regex::Regex;
use std::sync::LazyLock;

use crate::types::{
    AttributeValue, NodeKind, TemplateError, TemplateNode, TranspiledTemplate, ValidationError,
    ValidationResult, ALLOWED_MODULES,
};

// ─── Regex patterns ────────────────────────────────────────────
// These patterns are compile-time constants that are guaranteed to be valid.

static IMPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:import\s+(?:.*?\s+from\s+)?['"]|(?:import|require)\s*\(\s*['"])([^'"]+)['"]"#)
        .expect("IMPORT_RE: invalid regex pattern - this is a bug")
});

static PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}\}")
        .expect("PLACEHOLDER_RE: invalid regex pattern - this is a bug")
});

static TAG_OPEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>")
        .expect("TAG_OPEN_RE: invalid regex pattern - this is a bug")
});

static TAG_CLOSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"</([a-zA-Z][a-zA-Z0-9]*)>")
        .expect("TAG_CLOSE_RE: invalid regex pattern - this is a bug")
});

static SELF_CLOSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)\s*/>")
        .expect("SELF_CLOSE_RE: invalid regex pattern - this is a bug")
});

static ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{([^}]*)\})"#)
        .expect("ATTR_RE: invalid regex pattern - this is a bug")
});

static DANGEROUS_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)\beval\s*\(").expect("DANGEROUS_PATTERNS[0]: invalid regex"),
        Regex::new(r"(?i)\bFunction\s*\(").expect("DANGEROUS_PATTERNS[1]: invalid regex"),
        Regex::new(r"(?i)\bprocess\b").expect("DANGEROUS_PATTERNS[2]: invalid regex"),
        Regex::new(r"(?i)\b__proto__\b").expect("DANGEROUS_PATTERNS[3]: invalid regex"),
        Regex::new(r"(?i)\bconstructor\b\s*\[").expect("DANGEROUS_PATTERNS[4]: invalid regex"),
    ]
});

// ─── Public API ────────────────────────────────────────────────

/// Validate template source without rendering.
pub fn validate_source(source: &str, max_length: usize) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Size check
    if source.len() > max_length {
        errors.push(ValidationError {
            message: format!(
                "Source exceeds max length: {} > {}",
                source.len(),
                max_length
            ),
            line: None,
            column: None,
        });
        return ValidationResult {
            valid: false,
            errors,
            warnings,
        };
    }

    // Check for forbidden imports
    for cap in IMPORT_RE.captures_iter(source) {
        let module = &cap[1];
        if !ALLOWED_MODULES.iter().any(|m| module.starts_with(m)) {
            errors.push(ValidationError {
                message: format!("Forbidden module import: {}", module),
                line: find_line_number(source, cap.get(0).map(|m| m.start()).unwrap_or(0)),
                column: None,
            });
        }
    }

    // Check for dangerous patterns
    for pat in DANGEROUS_PATTERNS.iter() {
        if let Some(m) = pat.find(source) {
            warnings.push(format!(
                "Potentially dangerous pattern at offset {}: {}",
                m.start(),
                m.as_str()
            ));
        }
    }

    // #197:Only count template expression braces `{{ }}`, not CSS/JSON braces.
    // Template double-brace placeholders should be balanced.
    let double_open = source.matches("{{").count();
    let double_close = source.matches("}}").count();
    if double_open != double_close {
        errors.push(ValidationError {
            message: format!(
                "Unbalanced template braces: {} '{{{{' vs {} '}}}}'",
                double_open, double_close
            ),
            line: None,
            column: None,
        });
    }

    // HTML tag balance check
    let open_tags: Vec<&str> = TAG_OPEN_RE
        .captures_iter(source)
        .filter_map(|c| c.get(1).map(|m| m.as_str()))
        .collect();
    let self_closing: usize = SELF_CLOSE_RE.captures_iter(source).count();
    let close_tags: usize = TAG_CLOSE_RE.captures_iter(source).count();

    if open_tags.len().saturating_sub(self_closing) != close_tags {
        warnings.push("HTML tags may be unbalanced".to_string());
    }

    ValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    }
}

/// Transpile a template source string into an intermediate representation.
/// Resolves `{{ variable }}` placeholders and parses HTML structure.
pub fn transpile(
    source: &str,
    max_source_length: usize,
) -> Result<TranspiledTemplate, TemplateError> {
    if source.len() > max_source_length {
        return Err(TemplateError::SourceTooLarge {
            size: source.len(),
            max: max_source_length,
        });
    }

    // Check for forbidden imports
    for cap in IMPORT_RE.captures_iter(source) {
        let module = cap[1].to_string();
        if !ALLOWED_MODULES.iter().any(|m| module.starts_with(m)) {
            return Err(TemplateError::ForbiddenModule { module });
        }
    }

    // Check for dangerous patterns
    for pat in DANGEROUS_PATTERNS.iter() {
        if let Some(m) = pat.find(source) {
            return Err(TemplateError::InvalidSyntax {
                message: format!("Forbidden pattern: {}", m.as_str()),
            });
        }
    }

    // Strip imports (they've been validated)
    let stripped = IMPORT_RE.replace_all(source, "");

    // Parse into nodes
    let nodes = parse_html_to_nodes(&stripped)?;

    // Collect unique imports
    let imports_used: Vec<String> = IMPORT_RE
        .captures_iter(source)
        .map(|c| c[1].to_string())
        .collect();

    Ok(TranspiledTemplate {
        nodes,
        imports_used,
    })
}

/// Resolve `{{ variable }}` placeholders in rendered HTML with props values.
pub fn resolve_placeholders(html: &str, props: &serde_json::Value) -> String {
    PLACEHOLDER_RE
        .replace_all(html, |caps: &regex::Captures| {
            let key = &caps[1];
            resolve_prop(props, key)
        })
        .into_owned()
}

// ─── Internal helpers ──────────────────────────────────────────

fn resolve_prop(props: &serde_json::Value, path: &str) -> String {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = props;
    for part in parts {
        match current.get(part) {
            Some(v) => current = v,
            None => return format!("{{{{ {} }}}}", path), // keep original placeholder
        }
    }
    match current {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn parse_html_to_nodes(source: &str) -> Result<Vec<TemplateNode>, TemplateError> {
    let mut nodes = Vec::new();
    let mut pos = 0;
    let bytes = source.as_bytes();

    while pos < source.len() {
        // Try self-closing tag first
        if let Some(cap) = SELF_CLOSE_RE.captures(&source[pos..]) {
            if let Some(full) = cap.get(0) {
                if full.start() == 0 {
                    let tag = cap[1].to_string();
                    let attrs_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                    let attributes = parse_attributes(attrs_str);
                    nodes.push(TemplateNode {
                        kind: NodeKind::Element { tag },
                        attributes,
                        children: vec![],
                    });
                    pos += full.end();
                    continue;
                }
            }
        }

        // Try opening tag
        if bytes[pos] == b'<' && pos + 1 < source.len() && bytes[pos + 1] != b'/' {
            if let Some(cap) = TAG_OPEN_RE.captures(&source[pos..]) {
                if let Some(full) = cap.get(0) {
                    if full.start() == 0 {
                        let tag = cap[1].to_string();
                        let attrs_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                        let attributes = parse_attributes(attrs_str);

                        // Find matching close tag (simplified:doesn't handle nesting of same tag)
                        let inner_start = pos + full.end();
                        let close_pattern = format!("</{}>", tag);
                        if let Some(close_pos) = source[inner_start..].find(&close_pattern) {
                            let inner = &source[inner_start..inner_start + close_pos];
                            let children = parse_html_to_nodes(inner)?;
                            nodes.push(TemplateNode {
                                kind: NodeKind::Element { tag },
                                attributes,
                                children,
                            });
                            pos = inner_start + close_pos + close_pattern.len();
                            continue;
                        } else {
                            // Self-contained or unclosed — treat as leaf
                            nodes.push(TemplateNode {
                                kind: NodeKind::Element { tag },
                                attributes,
                                children: vec![],
                            });
                            pos += full.end();
                            continue;
                        }
                    }
                }
            }
        }

        // Text node — consume until next '<'
        let text_end = source[pos..]
            .find('<')
            .map(|i| pos + i)
            .unwrap_or(source.len());
        let text = source[pos..text_end].trim();
        if !text.is_empty() {
            // Check for {{ expression }} placeholders
            if PLACEHOLDER_RE.is_match(text) {
                nodes.push(TemplateNode {
                    kind: NodeKind::Expression(text.to_string()),
                    attributes: vec![],
                    children: vec![],
                });
            } else {
                nodes.push(TemplateNode {
                    kind: NodeKind::Text(text.to_string()),
                    attributes: vec![],
                    children: vec![],
                });
            }
        }
        pos = text_end;

        // Skip close tags at current position
        if pos < source.len() {
            if let Some(cap) = TAG_CLOSE_RE.captures(&source[pos..]) {
                if let Some(full) = cap.get(0) {
                    if full.start() == 0 {
                        pos += full.end();
                        continue;
                    }
                }
            }
        }

        // Safety:advance at least 1 char
        if pos < source.len()
            && bytes[pos] == b'<'
            && TAG_OPEN_RE.captures(&source[pos..]).is_none()
            && TAG_CLOSE_RE.captures(&source[pos..]).is_none()
        {
            pos += 1;
        }
    }

    Ok(nodes)
}

fn parse_attributes(attrs_str: &str) -> Vec<(String, AttributeValue)> {
    let mut attrs = Vec::new();
    for cap in ATTR_RE.captures_iter(attrs_str) {
        let name = cap[1].to_string();
        let value = if let Some(v) = cap.get(4) {
            AttributeValue::Dynamic(v.as_str().to_string())
        } else {
            let v = cap
                .get(2)
                .or_else(|| cap.get(3))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            AttributeValue::Static(v)
        };
        attrs.push((name, value));
    }
    attrs
}

fn find_line_number(source: &str, byte_offset: usize) -> Option<u32> {
    let prefix = &source[..byte_offset.min(source.len())];
    Some(prefix.chars().filter(|c| *c == '\n').count() as u32 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_source() {
        let source = r#"<div class="container"><h1>{{ title }}</h1><p>Hello</p></div>"#;
        let result = validate_source(source, 1024);
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_forbidden_import() {
        let source = r#"import fs from 'fs'; <div>hello</div>"#;
        let result = validate_source(source, 1024);
        assert!(!result.valid);
        assert!(result.errors[0].message.contains("fs"));
    }

    #[test]
    fn test_validate_source_too_large() {
        let source = "x".repeat(1025);
        let result = validate_source(&source, 1024);
        assert!(!result.valid);
        assert!(result.errors[0].message.contains("max length"));
    }

    #[test]
    fn test_validate_plain_markup() {
        let source = r#"<section><div>hello</div></section>"#;
        let result = validate_source(source, 4096);
        assert!(result.valid);
    }

    #[test]
    fn test_transpile_simple_html() {
        let source = "<div><p>Hello World</p></div>";
        let result = transpile(source, 4096).unwrap();
        assert!(!result.nodes.is_empty());
        assert!(result.imports_used.is_empty());
    }

    #[test]
    fn test_transpile_forbidden_module() {
        let source = r#"import os from 'os'; <div>hello</div>"#;
        let err = transpile(source, 4096).unwrap_err();
        assert!(matches!(err, TemplateError::ForbiddenModule { .. }));
    }

    #[test]
    fn test_transpile_source_too_large() {
        let source = "x".repeat(100);
        let err = transpile(&source, 50).unwrap_err();
        assert!(matches!(err, TemplateError::SourceTooLarge { .. }));
    }

    #[test]
    fn test_transpile_dangerous_pattern() {
        let source = "<div>eval('alert(1)')</div>";
        let err = transpile(source, 4096).unwrap_err();
        assert!(matches!(err, TemplateError::InvalidSyntax { .. }));
    }

    #[test]
    fn test_resolve_placeholders() {
        let html = "<h1>{{ title }}</h1><p>Hello {{ name }}</p>";
        let props = serde_json::json!({"title": "Welcome", "name": "Alice"});
        let result = resolve_placeholders(html, &props);
        assert_eq!(result, "<h1>Welcome</h1><p>Hello Alice</p>");
    }

    #[test]
    fn test_resolve_nested_prop() {
        let html = "{{ user.name }}";
        let props = serde_json::json!({"user": {"name": "Bob"}});
        let result = resolve_placeholders(html, &props);
        assert_eq!(result, "Bob");
    }

    #[test]
    fn test_resolve_missing_prop_keeps_placeholder() {
        let html = "Hello {{ missing }}";
        let props = serde_json::json!({});
        let result = resolve_placeholders(html, &props);
        assert_eq!(result, "Hello {{ missing }}");
    }

    #[test]
    fn test_resolve_numeric_prop() {
        let html = "Count: {{ count }}";
        let props = serde_json::json!({"count": 42});
        let result = resolve_placeholders(html, &props);
        assert_eq!(result, "Count: 42");
    }

    #[test]
    fn test_parse_attributes_static() {
        let attrs = parse_attributes(r#"class="btn" id="main""#);
        assert_eq!(attrs.len(), 2);
        assert!(matches!(&attrs[0].1, AttributeValue::Static(v) if v == "btn"));
    }

    #[test]
    fn test_parse_attributes_dynamic() {
        let attrs = parse_attributes(r#"onClick={handleClick} class="btn""#);
        assert_eq!(attrs.len(), 2);
        assert!(matches!(&attrs[0].1, AttributeValue::Dynamic(v) if v == "handleClick"));
    }

    #[test]
    fn test_self_closing_tag() {
        let source = r#"<img src="logo.png" />"#;
        let result = transpile(source, 4096).unwrap();
        assert_eq!(result.nodes.len(), 1);
        assert!(
            matches!(&result.nodes[0].kind, NodeKind::Element { .. }),
            "Expected element node"
        );
        if let NodeKind::Element { tag } = &result.nodes[0].kind {
            assert_eq!(tag, "img");
        }
    }

    #[test]
    fn test_find_line_number() {
        let source = "line1\nline2\nline3";
        assert_eq!(find_line_number(source, 0), Some(1));
        assert_eq!(find_line_number(source, 6), Some(2));
        assert_eq!(find_line_number(source, 12), Some(3));
    }
}
