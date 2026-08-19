//! Template markup transpilation to intermediate representation.
//!
//! Validates template source, checks for forbidden imports,
//! and resolves `{{ variable }}` placeholders against props.
//!
//! # Security
//!
//! Validation is performed at two levels:
//! 1. **Regex level** — catches forbidden module imports and dangerous patterns
//!    (e.g. `eval()`, `Function()`, `process`).
//! 2. **AST level** — parses HTML into nodes and validates every element tag and
//!    attribute against the allowlists defined in [`types`] (O-7.1, O-7.2).
//!    Event-handler attributes (on*) are always rejected.

use ego_tree::NodeRef;
use regex::Regex;
use scraper::{Html, Node};
use std::sync::LazyLock;

use crate::types::{
    is_allowed_attribute, is_allowed_element, AttributeValue, NodeKind, TemplateError,
    TemplateNode, TranspiledTemplate, ValidationError, ValidationResult, ALLOWED_MODULES,
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

/// Matches double-quoted `href`/`src` attribute values (the serializer and
/// templates in this crate emit double quotes).
static URL_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(href|src)\s*=\s*"([^"]*)""#)
        .expect("URL_ATTR_RE: invalid regex pattern - this is a bug")
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

    // O-7.1 / O-7.2: AST-level validation — parse HTML into nodes and check
    // every element tag and attribute against the allowlists.
    if let Ok(nodes) = parse_html_to_nodes(source) {
        let ast_errors = validate_ast(&nodes, source);
        errors.extend(ast_errors);
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

    // O-7.1 / O-7.2: AST-level validation — check every element and attribute
    // against the allowlists. This catches disallowed tags, blocked event
    // handlers, and attributes not permitted on specific elements.
    let ast_errors = validate_ast(&nodes, source);
    if !ast_errors.is_empty() {
        let msgs: Vec<String> = ast_errors.iter().map(|e| e.message.clone()).collect();
        return Err(TemplateError::InvalidSyntax {
            message: msgs.join("; "),
        });
    }

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
///
/// Security:
/// - String values are HTML-escaped (`&`, `<`, `>`, `"`, `'`) before
///   substitution so props can never inject markup. Only props whose leaf
///   key ends with `_html` (explicitly-trusted pre-rendered fragments) are
///   substituted raw.
/// - After substitution, every `href`/`src` attribute value is checked:
///   only `http:`/`https:` schemes (and scheme-less relative URLs) are
///   allowed; anything else (`javascript:`, `data:`, `vbscript:`, …) is
///   neutralized to `#`.
pub fn resolve_placeholders(html: &str, props: &serde_json::Value) -> String {
    let substituted = PLACEHOLDER_RE
        .replace_all(html, |caps: &regex::Captures| {
            let key = &caps[1];
            resolve_prop(props, key)
        })
        .into_owned();
    sanitize_url_attributes(&substituted)
}

/// Resolve placeholders WITHOUT HTML escaping or URL sanitization.
///
/// Only for non-HTML contexts (e.g. the plain-text subject line) where
/// escaping would corrupt the output.
pub fn resolve_placeholders_plain(text: &str, props: &serde_json::Value) -> String {
    PLACEHOLDER_RE
        .replace_all(text, |caps: &regex::Captures| {
            let key = &caps[1];
            resolve_prop_raw(props, key)
        })
        .into_owned()
}

// ─── Internal helpers ──────────────────────────────────────────

/// HTML-escape a string so it is inert when interpolated into markup.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

/// Trusted prop paths: leaf key ends with `_html` — documented convention for
/// pre-rendered fragments the template author intentionally injects raw.
fn is_trusted_html_path(path: &str) -> bool {
    path.rsplit('.')
        .next()
        .is_some_and(|leaf| leaf.ends_with("_html"))
}

/// Resolve a prop to its raw string value (no escaping).
fn resolve_prop_raw(props: &serde_json::Value, path: &str) -> String {
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

/// Resolve a prop for interpolation into HTML: escaped unless trusted.
fn resolve_prop(props: &serde_json::Value, path: &str) -> String {
    let raw = resolve_prop_raw(props, path);
    if is_trusted_html_path(path) {
        raw
    } else {
        escape_html(&raw)
    }
}

/// Neutralize dangerous URL schemes in href/src attributes
/// (applied post-substitution so prop-injected URLs are covered too).
fn sanitize_url_attributes(html: &str) -> String {
    URL_ATTR_RE
        .replace_all(html, |caps: &regex::Captures| {
            let attr = &caps[1];
            let value = &caps[2];
            let sanitized = sanitize_url(value);
            if sanitized == value {
                caps[0].to_string()
            } else {
                format!("{attr}=\"{sanitized}\"")
            }
        })
        .into_owned()
}

/// Allow only http/https schemes (or scheme-less relative URLs).
fn sanitize_url(value: &str) -> &str {
    let trimmed = value.trim();
    if let Some(colon) = trimmed.find(':') {
        let scheme = &trimmed[..colon];
        let looks_like_scheme = scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.');
        if looks_like_scheme {
            let lower = scheme.to_ascii_lowercase();
            if lower != "http" && lower != "https" {
                tracing::warn!(
                    url = %trimmed,
                    "Rejected href/src with disallowed scheme; neutralized to '#'"
                );
                return "#";
            }
        }
    }
    trimmed
}

/// Validate every node in the AST against the element and attribute allowlists.
/// Returns a list of validation errors for disallowed elements, blocked
/// attributes, or attributes not permitted on a given element.
#[allow(clippy::only_used_in_recursion)]
fn validate_ast(nodes: &[TemplateNode], source: &str) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    for node in nodes {
        match &node.kind {
            NodeKind::Element { tag } => {
                // O-7.2: Check element against allowlist
                if !is_allowed_element(tag) {
                    errors.push(ValidationError {
                        message: format!("Disallowed HTML element: <{}>", tag),
                        line: None,
                        column: None,
                    });
                }

                // O-7.2: Check each attribute against the per-element allowlist
                for (attr_name, _) in &node.attributes {
                    if !is_allowed_attribute(tag, attr_name) {
                        let msg = if attr_name.to_lowercase().starts_with("on") {
                            format!(
                                "Blocked event-handler attribute '{0}' on <{1}>",
                                attr_name, tag
                            )
                        } else {
                            format!(
                                "Attribute '{0}' is not allowed on element <{1}>",
                                attr_name, tag
                            )
                        };
                        errors.push(ValidationError {
                            message: msg,
                            line: None,
                            column: None,
                        });
                    }
                }

                // Recurse into children
                errors.extend(validate_ast(&node.children, source));
            }
            NodeKind::Text(_) | NodeKind::Expression(_) | NodeKind::Fragment => {}
        }
    }
    errors
}

fn parse_html_to_nodes(source: &str) -> Result<Vec<TemplateNode>, TemplateError> {
    let parse_as_document = should_parse_as_document(source);
    let document = if parse_as_document {
        Html::parse_document(source)
    } else {
        Html::parse_fragment(source)
    };
    let root = if parse_as_document {
        document.tree.root()
    } else {
        fragment_body_node(&document).unwrap_or_else(|| document.tree.root())
    };

    Ok(root
        .children()
        .filter_map(html_node_to_template_node)
        .collect())
}

fn should_parse_as_document(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    lower.contains("<!doctype")
        || lower.contains("<html")
        || lower.contains("<head")
        || lower.contains("<body")
}

fn fragment_body_node(document: &Html) -> Option<NodeRef<'_, Node>> {
    document
        .tree
        .root()
        .children()
        .find(|node| is_element_named(*node, "html"))
        .map(|html| {
            html.children()
                .find(|node| is_element_named(*node, "body"))
                .unwrap_or(html)
        })
}

fn is_element_named(node: NodeRef<'_, Node>, expected: &str) -> bool {
    matches!(node.value(), Node::Element(element) if element.name().eq_ignore_ascii_case(expected))
}

fn html_node_to_template_node(node: NodeRef<'_, Node>) -> Option<TemplateNode> {
    match node.value() {
        Node::Element(element) => {
            let tag = element.name().to_string();
            let attributes = element
                .attrs()
                .map(|(name, value)| (name.to_string(), parse_html_attribute_value(value)))
                .collect();
            let children = node
                .children()
                .filter_map(html_node_to_template_node)
                .collect();

            Some(TemplateNode {
                kind: NodeKind::Element { tag },
                attributes,
                children,
            })
        }
        Node::Text(text) => {
            let text = text.trim();
            if text.is_empty() {
                return None;
            }

            let kind = if PLACEHOLDER_RE.is_match(text) {
                NodeKind::Expression(text.to_string())
            } else {
                NodeKind::Text(text.to_string())
            };

            Some(TemplateNode {
                kind,
                attributes: vec![],
                children: vec![],
            })
        }
        Node::Document
        | Node::Fragment
        | Node::Doctype(_)
        | Node::Comment(_)
        | Node::ProcessingInstruction(_) => None,
    }
}

fn parse_html_attribute_value(value: &str) -> AttributeValue {
    let trimmed = value.trim();
    if let Some(expression) = trimmed
        .strip_prefix('{')
        .and_then(|inner| inner.strip_suffix('}'))
    {
        AttributeValue::Dynamic(expression.trim().to_string())
    } else {
        AttributeValue::Static(value.to_string())
    }
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
    fn test_validate_rejects_disallowed_element() {
        let result = validate_source(r#"<script>alert('x')</script>"#, 4096);
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|error| error.message.contains("Disallowed HTML element")));
    }

    #[test]
    fn test_validate_rejects_event_handler_attribute() {
        let result = validate_source(
            r#"<a href="https://example.com" onclick="alert(1)">x</a>"#,
            4096,
        );
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|error| error.message.contains("Blocked event-handler attribute")));
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
    fn test_transpile_rejects_attribute_not_allowed_on_element() {
        let source = r#"<img href="https://example.com/logo.png" alt="Logo">"#;
        let err = transpile(source, 4096).unwrap_err();
        assert!(matches!(err, TemplateError::InvalidSyntax { .. }));
        assert!(err.to_string().contains("not allowed on element"));
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
    fn test_string_props_are_html_escaped() {
        let html = "<p>{{ message }}</p>";
        let props = serde_json::json!({"message": "<script>alert(1)</script> & \"'"});
        let result = resolve_placeholders(html, &props);
        assert_eq!(
            result,
            "<p>&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;&#x27;</p>"
        );
        assert!(!result.contains("<script"));
    }

    #[test]
    fn test_trusted_html_prop_is_not_escaped() {
        let html = "<div>{{ body_html }}</div>";
        let props = serde_json::json!({"body_html": "<strong>ok</strong>"});
        let result = resolve_placeholders(html, &props);
        assert_eq!(result, "<div><strong>ok</strong></div>");
    }

    #[test]
    fn test_prop_injection_via_attribute_is_neutralized() {
        // Even when the escaped value lands inside an attribute, the
        // injected event handler cannot take effect.
        let html = r#"<div class="{{ cls }}"></div>"#;
        let props = serde_json::json!({"cls": "x\" onmouseover=\"alert(1)"});
        let result = resolve_placeholders(html, &props);
        assert!(!result.contains("onmouseover=\"alert"), "{result}");
    }

    #[test]
    fn test_javascript_url_rejected_in_href() {
        let html = r#"<a href="{{ link }}">click</a>"#;
        let props = serde_json::json!({"link": "javascript:alert(1)"});
        let result = resolve_placeholders(html, &props);
        assert_eq!(result, r##"<a href="#">click</a>"##);
    }

    #[test]
    fn test_data_url_rejected_in_src() {
        let html = r#"<img src="{{ img }}">"#;
        let props = serde_json::json!({"img": "data:text/html;base64,PHNjcmlwdD4="});
        let result = resolve_placeholders(html, &props);
        assert_eq!(result, r##"<img src="#">"##);
    }

    #[test]
    fn test_http_urls_and_relative_urls_pass() {
        let props = serde_json::json!({"a": "https://example.com/x?y=1&z=2", "b": "/logo.png"});
        let result = resolve_placeholders(r#"<a href="{{ a }}"><img src="{{ b }}"></a>"#, &props);
        assert!(result.starts_with(r#"<a href="https://example.com/x?y=1&amp;z=2">"#));
        assert!(result.contains(r#"src="/logo.png""#));
    }

    #[test]
    fn test_obfuscated_javascript_scheme_rejected() {
        let html = r#"<a href="{{ u }}">x</a>"#;
        let props = serde_json::json!({"u": " JaVaScRiPt:alert(1)"});
        let result = resolve_placeholders(html, &props);
        assert_eq!(result, r##"<a href="#">x</a>"##);
    }

    #[test]
    fn test_plain_variant_does_not_escape() {
        let props = serde_json::json!({"name": "Tom & Jerry <b>"});
        let result = resolve_placeholders_plain("Hello {{ name }}", &props);
        assert_eq!(result, "Hello Tom & Jerry <b>");
    }

    #[test]
    fn test_html5_parser_preserves_attributes() {
        let nodes = parse_html_to_nodes(r#"<img src="{logo_url}" alt="Logo">"#).unwrap();
        let attrs = &nodes[0].attributes;

        assert!(attrs.iter().any(|(name, value)| name == "src"
            && matches!(value, AttributeValue::Dynamic(v) if v == "logo_url")));
        assert!(attrs.iter().any(|(name, value)| name == "alt"
            && matches!(value, AttributeValue::Static(v) if v == "Logo")));
    }

    #[test]
    fn test_html5_parser_handles_nested_same_tag() {
        let source = "<div><div><p>Inner</p></div><p>Outer</p></div>";
        let result = transpile(source, 4096).unwrap();

        assert_eq!(result.nodes.len(), 1);
        assert!(matches!(
            &result.nodes[0].kind,
            NodeKind::Element { tag } if tag == "div"
        ));
        assert_eq!(result.nodes[0].children.len(), 2);
        assert!(matches!(
            &result.nodes[0].children[0].kind,
            NodeKind::Element { tag } if tag == "div"
        ));
        assert!(matches!(
            &result.nodes[0].children[1].kind,
            NodeKind::Element { tag } if tag == "p"
        ));
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
