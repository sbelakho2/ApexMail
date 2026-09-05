//! Typst virtual filesystem world implementation.
//!
//! Provides font loading, template resolution, and a virtual file system
//! so the Typst compiler can resolve `#import` and `#include` directives.
//!
//! # Security (O-14.3)
//!
//! Templates are embedded at compile time via [`include_str!`] (preventing
//! filesystem‑based template injection).  As an operational escape hatch the
//! `PDF_TEMPLATES_DIR` environment variable can be set at startup to load
//! templates from an external directory; this allows rule updates without
//! recompilation in controlled deployment environments.  Embedded templates
//! serve as the fallback when the env var is not set.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::Utc;
use once_cell::sync::Lazy;
use tracing::warn;

// ---------------------------------------------------------------------------
// Embedded templates (compiled into binary)
// ---------------------------------------------------------------------------

/// All `.typ` templates embedded at compile time.
pub static TEMPLATES: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("invoice", include_str!("templates/invoice.typ"));
    m.insert("dpa", include_str!("templates/dpa.typ"));
    m.insert(
        "compliance_report",
        include_str!("templates/compliance_report.typ"),
    );
    m.insert(
        "analytics_export",
        include_str!("templates/analytics_export.typ"),
    );
    m.insert("qbr", include_str!("templates/qbr.typ"));
    m
});

// ---------------------------------------------------------------------------
// External template loader (O-14.3)
// ---------------------------------------------------------------------------

/// Validate a caller-supplied template name before it is ever joined onto
/// a filesystem path.
///
/// Allowlist: non-empty, at most 64 characters, each `[A-Za-z0-9_-]`. This
/// excludes path separators, `..`, extensions and every other path-shaped
/// input, so `{PDF_TEMPLATES_DIR}/{template_name}.typ` can only ever
/// address a file directly inside the templates directory (previously
/// `../../secrets/key` style names turned the loader into a read oracle).
pub fn validate_template_name(name: &str) -> Result<(), WorldError> {
    if name.is_empty() || name.len() > 64 {
        return Err(WorldError::InvalidTemplateName(name.to_string()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(WorldError::InvalidTemplateName(name.to_string()));
    }
    Ok(())
}

/// Load a template source, preferring an external file over the embedded copy.
///
/// When `PDF_TEMPLATES_DIR` is set, the function first tries to read
/// `{PDF_TEMPLATES_DIR}/{template_name}.typ`.  If the file does not exist or
/// the env var is unset it falls back to the embedded [`TEMPLATES`] HashMap.
///
/// This allows operators to update template logic without recompiling the
/// binary, while keeping the compile‑time embedded version as a secure
/// default.
///
/// `template_name` must pass [`validate_template_name`] (defense in depth:
/// callers validate too, but the path join happens here).
pub fn load_template_source(template_name: &str) -> Option<String> {
    if let Err(error) = validate_template_name(template_name) {
        warn!(
            template = template_name,
            %error,
            "Rejected path-shaped template name"
        );
        return None;
    }
    // Try external directory first (env‑var driven)
    if let Ok(dir) = std::env::var("PDF_TEMPLATES_DIR") {
        let path: PathBuf = [dir.as_str(), &format!("{}.typ", template_name)]
            .iter()
            .collect();
        if path.exists() {
            return std::fs::read_to_string(&path)
                .map_err(|e| {
                    warn!(
                        template = template_name,
                        path = %path.display(),
                        error = %e,
                        "Failed to read external template — falling back to embedded",
                    );
                })
                .ok();
        }
        warn!(
            template = template_name,
            path = %path.display(),
            "External template not found — falling back to embedded",
        );
    }

    // Fallback to embedded
    TEMPLATES.get(template_name).map(|s| (*s).to_string())
}

// ---------------------------------------------------------------------------
// TypstWorld — virtual filesystem for the Typst compiler
// ---------------------------------------------------------------------------

/// Holds the compiled template sources and runtime data needed by the Typst
/// compiler. This is a simplified world that:/// 1. Resolves `/template.typ` from embedded `TEMPLATES`
/// 2. Resolves `/data.json` from the caller-supplied JSON string
/// 3. Uses system fonts or a bundled fallback set
pub struct TypstWorld {
    /// The template source code
    pub template_source: String,
    /// JSON data as a string (injected as `/data.json`)
    pub data_json: String,
    /// Current date/time for `datetime.today` in Typst
    pub now: chrono::DateTime<Utc>,
}

impl TypstWorld {
    /// Create a new world for rendering a template with the given JSON data.
    ///
    /// Templates are resolved through [`load_template_source`], which prefers
    /// an external file from `PDF_TEMPLATES_DIR` (if set) and falls back to
    /// the embedded `include_str!` copy.
    ///
    /// # Arguments
    /// * `template_name` — key in `TEMPLATES` (e.g. `"invoice"`)
    /// * `data_json` — serialized JSON data to inject as `/data.json`
    ///
    /// # Errors
    /// Returns `Err` if the template name is not found in either location.
    pub fn new(template_name: &str, data_json: String) -> Result<Self, WorldError> {
        // Reject path-shaped names before any filesystem join — a 400 for
        // the caller, not a filesystem read.
        validate_template_name(template_name)?;
        let source = load_template_source(template_name)
            .ok_or_else(|| WorldError::TemplateNotFound(template_name.to_string()))?;

        Ok(Self {
            template_source: source,
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
    #[error("invalid template name: {0}")]
    InvalidTemplateName(String),
    #[error("font loading error: {0}")]
    FontError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_template_names_validate() {
        for name in TEMPLATES.keys() {
            assert!(
                validate_template_name(name).is_ok(),
                "embedded template {name} must pass validation"
            );
        }
        assert!(validate_template_name("invoice_v2-EU").is_ok());
    }

    #[test]
    fn path_shaped_template_names_are_rejected() {
        // Regression: `../../` names were joined onto PDF_TEMPLATES_DIR and
        // read whatever they resolved to (a filesystem read oracle).
        for bad in [
            "../../etc/passwd",
            "../secrets/stripe",
            "foo/bar",
            "foo\\bar",
            "invoice.typ",
            "invoice typ",
            "",
            "中文模板",
            &"x".repeat(65),
        ] {
            assert!(
                validate_template_name(bad).is_err(),
                "name {bad:?} must be rejected"
            );
            assert!(
                load_template_source(bad).is_none(),
                "name {bad:?} must never reach the filesystem"
            );
        }
    }
}
