//! Typst virtual filesystem world implementation.
//!
//! Provides font loading, template resolution, and a virtual file system
//! so the Typst compiler can resolve `#import` and `#include` directives.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{Datelike, Utc};
use once_cell::sync::Lazy;
use parking_lot::RwLock;

// ---------------------------------------------------------------------------
// Embedded templates (compiled into binary)
// ---------------------------------------------------------------------------

/// All `.typ` templates embedded at compile time.
pub static TEMPLATES: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("invoice", include_str!("templates/invoice.typ"));
    m.insert("dpa", include_str!("templates/dpa.typ"));
    m.insert("compliance_report", include_str!("templates/compliance_report.typ"));
    m.insert("analytics_export", include_str!("templates/analytics_export.typ"));
    m.insert("qbr", include_str!("templates/qbr.typ"));
    m
});

// ---------------------------------------------------------------------------
// TypstWorld — virtual filesystem for the Typst compiler
// ---------------------------------------------------------------------------

/// Holds the compiled template sources and runtime data needed by the Typst
/// compiler.  This is a simplified world that:
///   1. Resolves `/template.typ` from embedded `TEMPLATES`
///   2. Resolves `/data.json` from the caller-supplied JSON string
///   3. Uses system fonts or a bundled fallback set
pub struct TypstWorld {
    /// The template source code
    pub template_source: String,
    /// JSON data as a string (injected as `/data.json`)
    pub data_json: String,
    /// Current date/time for `datetime.today()` in Typst
    pub now: chrono::DateTime<Utc>,
}

impl TypstWorld {
    /// Create a new world for rendering a template with the given JSON data.
    ///
    /// # Arguments
    /// * `template_name` — key in `TEMPLATES` (e.g. `"invoice"`)
    /// * `data_json` — serialized JSON data to inject as `/data.json`
    ///
    /// # Errors
    /// Returns `Err` if the template name is not found.
    pub fn new(template_name: &str, data_json: String) -> Result<Self, WorldError> {
        let source = TEMPLATES
            .get(template_name)
            .ok_or_else(|| WorldError::TemplateNotFound(template_name.to_string()))?;

        Ok(Self {
            template_source: source.to_string(),
            data_json,
            now: Utc::now(),
        })
    }
}

// ---------------------------------------------------------------------------
// Font discovery
// ---------------------------------------------------------------------------

/// System font directories to search (Linux production + macOS dev).
pub static FONT_DIRS: &[&str] = &[
    "/usr/share/fonts",
    "/usr/local/share/fonts",
    "/System/Library/Fonts",
    "/Library/Fonts",
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum WorldError {
    #[error("template not found: {0}")]
    TemplateNotFound(String),
    #[error("font loading error: {0}")]
    FontError(String),
}
