use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Error Codes ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RenderErrorCode {
    TranspileError,
    ExecutionError,
    RenderError,
    NoDefaultExport,
    TemplateNotFound,
    SandboxTimeout,
    SourceTooLarge,
    OutputTooLarge,
    InvalidSyntax,
    ForbiddenModule,
}

impl std::fmt::Display for RenderErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::TranspileError => "TRANSPILE_ERROR",
            Self::ExecutionError => "EXECUTION_ERROR",
            Self::RenderError => "RENDER_ERROR",
            Self::NoDefaultExport => "NO_DEFAULT_EXPORT",
            Self::TemplateNotFound => "TEMPLATE_NOT_FOUND",
            Self::SandboxTimeout => "SANDBOX_TIMEOUT",
            Self::SourceTooLarge => "SOURCE_TOO_LARGE",
            Self::OutputTooLarge => "OUTPUT_TOO_LARGE",
            Self::InvalidSyntax => "INVALID_SYNTAX",
            Self::ForbiddenModule => "FORBIDDEN_MODULE",
        };
        write!(f, "{}", s)
    }
}

// ─── Render Errors ─────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("Transpilation failed: {message}")]
    Transpile {
        message: String,
        line: Option<u32>,
        column: Option<u32>,
    },

    #[error("Execution failed: {message}")]
    Execution { message: String },

    #[error("Render failed: {message}")]
    Render { message: String },

    #[error("No default export found in template")]
    NoDefaultExport,

    #[error("Template not found: {id}")]
    NotFound { id: String },

    #[error("Sandbox timeout after {ms}ms")]
    Timeout { ms: u64 },

    #[error("Source too large: {size} bytes (max {max})")]
    SourceTooLarge { size: usize, max: usize },

    #[error("Output too large: {size} bytes (max {max})")]
    OutputTooLarge { size: usize, max: usize },

    #[error("Invalid template syntax: {message}")]
    InvalidSyntax { message: String },

    #[error("Forbidden module import: {module}")]
    ForbiddenModule { module: String },

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl TemplateError {
    pub fn code(&self) -> RenderErrorCode {
        match self {
            Self::Transpile { .. } => RenderErrorCode::TranspileError,
            Self::Execution { .. } => RenderErrorCode::ExecutionError,
            Self::Render { .. } => RenderErrorCode::RenderError,
            Self::NoDefaultExport => RenderErrorCode::NoDefaultExport,
            Self::NotFound { .. } => RenderErrorCode::TemplateNotFound,
            Self::Timeout { .. } => RenderErrorCode::SandboxTimeout,
            Self::SourceTooLarge { .. } => RenderErrorCode::SourceTooLarge,
            Self::OutputTooLarge { .. } => RenderErrorCode::OutputTooLarge,
            Self::InvalidSyntax { .. } => RenderErrorCode::InvalidSyntax,
            Self::ForbiddenModule { .. } => RenderErrorCode::ForbiddenModule,
            Self::Database(_) => RenderErrorCode::ExecutionError,
        }
    }
}

// ─── Template Types ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub source: String,
    pub version: i32,
    pub compiled: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderOptions {
    /// Template variables / props
    #[serde(default)]
    pub props: serde_json::Value,
    /// Whether to generate plaintext fallback
    #[serde(default = "default_true")]
    pub generate_plaintext: bool,
    /// Whether to minify HTML output
    #[serde(default)]
    pub minify: bool,
    /// Subject line (may contain {{ variable }} placeholders)
    pub subject: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderResult {
    pub html: String,
    pub plaintext: Option<String>,
    pub subject: Option<String>,
    pub metadata: RenderMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderMetadata {
    pub render_time_ms: u64,
    pub html_size_bytes: usize,
    pub plaintext_size_bytes: Option<usize>,
    pub cached: bool,
}

// ─── Transpilation types ───────────────────────────────────────

/// AST node types we recognize during transpilation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Element { tag: String },
    Text(String),
    Expression(String),
    Fragment,
}

/// Transpiled intermediate representation
#[derive(Debug, Clone)]
pub struct TranspiledTemplate {
    pub nodes: Vec<TemplateNode>,
    pub imports_used: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TemplateNode {
    pub kind: NodeKind,
    pub attributes: Vec<(String, AttributeValue)>,
    pub children: Vec<TemplateNode>,
}

#[derive(Debug, Clone)]
pub enum AttributeValue {
    Static(String),
    Dynamic(String), // expression that references props
}

// ─── Validation ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub message: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

// ─── Starter Template ──────────────────────────────────────────

pub const STARTER_TEMPLATE: &str = r#"<html>
  <head>
    <style>
      body { font-family: ui-monospace, 'JetBrains Mono', monospace; margin: 0; padding: 0; }
      .container { max-width: 600px; margin: 0 auto; padding: 20px; }
      .header { background-color: #dc2626; color: white; padding: 24px; text-align: center; }
      .content { padding: 24px; }
      .footer { padding: 16px; text-align: center; color: #71717a; font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h1 style="margin:0;letter-spacing:0.05em">{{ title }}</h1>
      </div>
      <div class="content">
        <p>Hello {{ name }},</p>
        <p>{{ body }}</p>
      </div>
      <div class="footer">
        <p>{{ footer_text }}</p>
      </div>
    </div>
  </body>
</html>"#;

// ─── Module Allowlist ──────────────────────────────────────────

/// Modules allowed in template imports (for security)
pub const ALLOWED_MODULES: &[&str] = &[];

// ─── Element & Attribute Allowlist (O-7.1 / O-7.2) ─────────────

/// HTML elements permitted in email templates.
/// Only these elements may appear in template source; all others are rejected.
pub const ALLOWED_ELEMENTS: &[&str] = &[
    "a",
    "abbr",
    "address",
    "area",
    "article",
    "aside",
    "b",
    "bdo",
    "blockquote",
    "body",
    "br",
    "caption",
    "cite",
    "code",
    "col",
    "colgroup",
    "dd",
    "del",
    "dfn",
    "div",
    "dl",
    "dt",
    "em",
    "figcaption",
    "figure",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "head",
    "header",
    "hgroup",
    "hr",
    "html",
    "i",
    "img",
    "ins",
    "kbd",
    "li",
    "link",
    "main",
    "map",
    "mark",
    "meta",
    "nav",
    "ol",
    "optgroup",
    "option",
    "p",
    "pre",
    "q",
    "rp",
    "rt",
    "ruby",
    "s",
    "samp",
    "section",
    "select",
    "small",
    "source",
    "span",
    "strong",
    "style",
    "sub",
    "summary",
    "sup",
    "table",
    "tbody",
    "td",
    "template",
    "tfoot",
    "th",
    "thead",
    "time",
    "title",
    "tr",
    "u",
    "ul",
    "var",
    "wbr",
];

/// Per-element allowed attributes.
/// Returns the list of additional attributes (beyond global ones) permitted
/// on the given element.
pub fn allowed_attributes_for_element(element: &str) -> &[&str] {
    match element {
        "a" => &["href", "target", "rel", "name", "hreflang", "type"],
        "area" => &[
            "href", "target", "rel", "alt", "coords", "shape", "hreflang", "type",
        ],
        "img" => &[
            "src", "alt", "width", "height", "loading", "align", "border", "hspace", "vspace",
        ],
        "source" => &["src", "srcset", "media", "sizes", "type", "width", "height"],
        "td" | "th" => &[
            "align", "valign", "colspan", "rowspan", "width", "height", "bgcolor", "scope",
            "headers", "abbr", "axis",
        ],
        "caption" => &["align", "valign"],
        "table" => &[
            "width",
            "cellpadding",
            "cellspacing",
            "border",
            "bgcolor",
            "align",
            "summary",
        ],
        "tr" => &["align", "valign", "bgcolor"],
        "col" | "colgroup" => &["span", "width", "align", "valign"],
        "meta" => &["name", "content", "charset", "http-equiv"],
        "link" => &["rel", "href", "type", "title", "media", "sizes"],
        "style" => &["type", "media"],
        "ol" | "ul" => &["type", "start", "reversed", "compact"],
        "li" => &["type", "value"],
        "blockquote" | "q" => &["cite"],
        "del" | "ins" => &["cite", "datetime"],
        "time" => &["datetime"],
        "abbr" | "acronym" => &["title"],
        _ => &[],
    }
}

/// Attribute name prefixes that are ALWAYS blocked (e.g. event handlers).
pub const BLOCKED_ATTRIBUTE_PREFIXES: &[&str] = &[
    "on", "onload", "onclick", "onmouse", "onerror", "onfocus", "onblur", "onsubmit", "onreset",
    "onchange", "onselect", "onscroll",
];

/// Check whether an attribute name is a blocked event handler.
pub fn is_blocked_attribute(name: &str) -> bool {
    let lower = name.to_lowercase();
    BLOCKED_ATTRIBUTE_PREFIXES
        .iter()
        .any(|prefix| lower == *prefix || lower.starts_with(prefix))
}

/// Validate that an element tag is in the allowlist (case-insensitive).
pub fn is_allowed_element(tag: &str) -> bool {
    ALLOWED_ELEMENTS
        .iter()
        .any(|&e| e.eq_ignore_ascii_case(tag))
}

/// Validate that an attribute is allowed on a given element.
pub fn is_allowed_attribute(element: &str, attr: &str) -> bool {
    let el_lower = element.to_lowercase();
    let attr_lower = attr.to_lowercase();

    // Always block event-handler attributes
    if is_blocked_attribute(&attr_lower) {
        return false;
    }

    // Global attributes (id, class, style, lang, dir, hidden, title)
    let global: &[&str] = &[
        "id", "class", "style", "title", "lang", "dir", "hidden", "xmlns", "role", "aria-",
    ];
    if global
        .iter()
        .any(|g| attr_lower == *g || attr_lower.starts_with("aria-"))
    {
        return true;
    }

    // Check element-specific allowlist
    let allowed = allowed_attributes_for_element(&el_lower);
    allowed.contains(&attr_lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        let err = TemplateError::Transpile {
            message: "syntax".into(),
            line: Some(1),
            column: Some(5),
        };
        assert_eq!(err.code(), RenderErrorCode::TranspileError);
        assert!(err.to_string().contains("syntax"));
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(
            RenderErrorCode::TranspileError.to_string(),
            "TRANSPILE_ERROR"
        );
        assert_eq!(
            RenderErrorCode::SandboxTimeout.to_string(),
            "SANDBOX_TIMEOUT"
        );
        assert_eq!(
            RenderErrorCode::ForbiddenModule.to_string(),
            "FORBIDDEN_MODULE"
        );
    }

    #[test]
    fn test_all_error_variants() {
        let cases: Vec<(TemplateError, RenderErrorCode)> = vec![
            (
                TemplateError::Transpile {
                    message: "x".into(),
                    line: None,
                    column: None,
                },
                RenderErrorCode::TranspileError,
            ),
            (
                TemplateError::Execution {
                    message: "x".into(),
                },
                RenderErrorCode::ExecutionError,
            ),
            (
                TemplateError::Render {
                    message: "x".into(),
                },
                RenderErrorCode::RenderError,
            ),
            (
                TemplateError::NoDefaultExport,
                RenderErrorCode::NoDefaultExport,
            ),
            (
                TemplateError::NotFound { id: "x".into() },
                RenderErrorCode::TemplateNotFound,
            ),
            (
                TemplateError::Timeout { ms: 5000 },
                RenderErrorCode::SandboxTimeout,
            ),
            (
                TemplateError::SourceTooLarge {
                    size: 1000,
                    max: 500,
                },
                RenderErrorCode::SourceTooLarge,
            ),
            (
                TemplateError::OutputTooLarge {
                    size: 1000,
                    max: 500,
                },
                RenderErrorCode::OutputTooLarge,
            ),
            (
                TemplateError::InvalidSyntax {
                    message: "x".into(),
                },
                RenderErrorCode::InvalidSyntax,
            ),
            (
                TemplateError::ForbiddenModule {
                    module: "fs".into(),
                },
                RenderErrorCode::ForbiddenModule,
            ),
        ];
        for (err, expected_code) in cases {
            assert_eq!(err.code(), expected_code);
        }
    }

    #[test]
    fn test_render_options_defaults() {
        let json = r#"{"props": {}}"#;
        let opts: RenderOptions = serde_json::from_str(json).unwrap();
        assert!(opts.generate_plaintext);
        assert!(!opts.minify);
        assert!(opts.subject.is_none());
    }

    #[test]
    fn test_starter_template_contains_placeholders() {
        assert!(STARTER_TEMPLATE.contains("{{ title }}"));
        assert!(STARTER_TEMPLATE.contains("{{ name }}"));
        assert!(STARTER_TEMPLATE.contains("{{ body }}"));
        assert!(STARTER_TEMPLATE.contains("{{ footer_text }}"));
    }

    #[test]
    fn test_allowed_modules() {
        assert!(ALLOWED_MODULES.is_empty());
        assert!(!ALLOWED_MODULES.contains(&"fs"));
        assert!(!ALLOWED_MODULES.contains(&"child_process"));
    }

    #[test]
    fn test_node_kind_equality() {
        assert_eq!(
            NodeKind::Element { tag: "div".into() },
            NodeKind::Element { tag: "div".into() }
        );
        assert_ne!(
            NodeKind::Element { tag: "div".into() },
            NodeKind::Element { tag: "span".into() }
        );
        assert_eq!(NodeKind::Fragment, NodeKind::Fragment);
    }

    #[test]
    fn test_render_result_serialization() {
        let result = RenderResult {
            html: "<h1>Hello</h1>".into(),
            plaintext: Some("Hello".into()),
            subject: Some("Test".into()),
            metadata: RenderMetadata {
                render_time_ms: 5,
                html_size_bytes: 14,
                plaintext_size_bytes: Some(5),
                cached: false,
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let de: RenderResult = serde_json::from_str(&json).unwrap();
        assert_eq!(de.html, "<h1>Hello</h1>");
        assert_eq!(de.metadata.render_time_ms, 5);
        assert!(!de.metadata.cached);
    }

    #[test]
    fn test_validation_result() {
        let v = ValidationResult {
            valid: false,
            errors: vec![ValidationError {
                message: "Unexpected token".into(),
                line: Some(3),
                column: Some(10),
            }],
            warnings: vec!["Unused variable".into()],
        };
        assert!(!v.valid);
        assert_eq!(v.errors.len(), 1);
        assert_eq!(v.errors[0].line, Some(3));
    }
}
