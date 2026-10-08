//! Typst world implementation: embedded fonts, embedded templates, and the
//! virtual file system the Typst compiler reads.
//!
//! The world resolves exactly three kinds of files:
//!
//! * the main template source (`main.typ`, loaded from [`TEMPLATES`] or, when
//!   `PDF_TEMPLATES_DIR` is set, from that directory),
//! * the request payload (`/data.json`, the caller-supplied JSON string),
//! * any additional file a template `#include`s, which is only reachable when
//!   `PDF_TEMPLATES_DIR` is set (embedded builds must be self-contained).
//!
//! Fonts are the OFL-licensed Noto Sans (Latin/Greek/Cyrillic) and Noto Sans
//! SC (CJK) faces embedded in the binary, so rendering is hermetic: identical
//! inputs produce identical output on every host, with no dependency on the
//! host's font installation.
//!
//! # Security (O-14.3)
//!
//! Templates are embedded at compile time via [`include_str!`] (preventing
//! filesystem-based template injection).  As an operational escape hatch the
//! `PDF_TEMPLATES_DIR` environment variable can be set at startup to load
//! templates from an external directory; this allows rule updates without
//! recompilation in controlled deployment environments.  Embedded templates
//! serve as the fallback when the env var is not set.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{Datelike, Timelike, Utc};
use once_cell::sync::Lazy;
use tracing::warn;

use typst::diag::{FileError, FileResult};
use typst::foundations::{Bytes, Datetime};
use typst::syntax::{FileId, RootedPath, Source, VirtualPath, VirtualRoot};
use typst::text::{Font, FontBook};
use typst::utils::LazyHash;
use typst::{Library, LibraryExt, World};

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
// Embedded Unicode fonts (OFL-licensed Noto Sans)
// ---------------------------------------------------------------------------
// Latin/Greek/Cyrillic coverage comes from Noto Sans Regular; CJK from
// Noto Sans SC Regular. Both are parsed once and offered to the Typst
// compiler through the world's font book; `typst-pdf` subsets and embeds the
// glyphs a document actually uses.
// Licenses: assets/fonts/NotoSans-OFL.txt, assets/fonts/NotoSansSC-OFL.txt.

static FONTS: Lazy<Vec<Font>> = Lazy::new(|| {
    let mut fonts = Vec::new();
    for bytes in [
        include_bytes!("../assets/fonts/NotoSans-Regular.ttf").as_slice(),
        include_bytes!("../assets/fonts/NotoSansSC-Regular.ttf").as_slice(),
    ] {
        fonts.extend(Font::iter(Bytes::new(bytes.to_vec())));
    }
    assert!(
        !fonts.is_empty(),
        "the embedded OFL fonts must parse (NotoSans-Regular.ttf, NotoSansSC-Regular.ttf)"
    );
    fonts
});

static FONT_BOOK: Lazy<LazyHash<FontBook>> =
    Lazy::new(|| LazyHash::new(FontBook::from_fonts(FONTS.iter())));

static LIBRARY: Lazy<LazyHash<Library>> = Lazy::new(|| LazyHash::new(Library::default()));

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
/// binary, while keeping the compile-time embedded version as a secure
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

/// The virtual filesystem backing one render: the template source as
/// `main.typ`, the caller payload as `/data.json`, and (only when
/// `PDF_TEMPLATES_DIR` is set) additional library files under that directory.
pub struct TypstWorld {
    /// `/main.typ` plus `/data.json`, keyed by interned file id.
    files: HashMap<FileId, Source>,
    /// The main template file id.
    main: FileId,
    /// External template directory (include resolution when set).
    external_dir: Option<PathBuf>,
    /// Current date/time for `datetime.today()` in Typst.
    now: chrono::DateTime<Utc>,
}

fn project_file(path: &str) -> Result<FileId, WorldError> {
    let vpath = VirtualPath::new(path).map_err(|e| WorldError::InvalidPath(format!("{path}: {e}")))?;
    Ok(RootedPath::new(VirtualRoot::Project, vpath).intern())
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

        let main = project_file("main.typ")?;
        let data_id = project_file("data.json")?;

        let mut files = HashMap::new();
        files.insert(main, Source::new(main, source));
        files.insert(data_id, Source::new(data_id, data_json));

        Ok(Self {
            files,
            main,
            external_dir: std::env::var("PDF_TEMPLATES_DIR").ok().map(PathBuf::from),
            now: Utc::now(),
        })
    }

    /// Resolve a file id the contents map does not hold: only
    /// `PDF_TEMPLATES_DIR`-backed library files are reachable.
    fn external_file(&self, id: FileId) -> FileResult<Vec<u8>> {
        let Some(dir) = &self.external_dir else {
            return Err(FileError::NotFound(
                Path::new(id.vpath().as_rootless_path()).to_path_buf(),
            ));
        };
        if !matches!(id.root(), VirtualRoot::Project) {
            return Err(FileError::NotFound(
                Path::new(id.vpath().as_rootless_path()).to_path_buf(),
            ));
        }
        let real = dir.join(id.vpath().as_rootless_path());
        std::fs::read(&real).map_err(|_| FileError::NotFound(real))
    }

    /// Test-only: replace the main template source (diagnostics fixtures).
    #[cfg(test)]
    pub(crate) fn set_main_source_for_test(&mut self, source: &str) {
        self.files
            .insert(self.main, Source::new(self.main, source.to_string()));
    }
}

impl World for TypstWorld {
    fn library(&self) -> &LazyHash<Library> {
        &LIBRARY
    }

    fn book(&self) -> &LazyHash<FontBook> {
        &FONT_BOOK
    }

    fn main(&self) -> FileId {
        self.main
    }

    fn source(&self, id: FileId) -> FileResult<Source> {
        match self.files.get(&id) {
            Some(source) => Ok(source.clone()),
            None => {
                let bytes = self.external_file(id)?;
                let text = String::from_utf8(bytes).map_err(|_| FileError::InvalidUtf8)?;
                Ok(Source::new(id, text))
            }
        }
    }

    fn file(&self, id: FileId) -> FileResult<Bytes> {
        match self.files.get(&id) {
            Some(source) => Ok(Bytes::from_string(source.text().to_string())),
            None => Ok(Bytes::new(self.external_file(id)?)),
        }
    }

    fn font(&self, index: usize) -> Option<Font> {
        FONTS.get(index).cloned()
    }

    fn today(&self, _offset: Option<typst::foundations::Duration>) -> Option<Datetime> {
        Datetime::from_ymd_hms(
            self.now.year(),
            self.now.month() as u8,
            self.now.day() as u8,
            self.now.hour() as u8,
            self.now.minute() as u8,
            self.now.second() as u8,
        )
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum WorldError {
    #[error("template not found: {0}")]
    TemplateNotFound(String),
    #[error("invalid template name: {0}")]
    InvalidTemplateName(String),
    #[error("invalid virtual path: {0}")]
    InvalidPath(String),
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

    #[test]
    fn embedded_fonts_parse_with_expected_coverage() {
        let families: Vec<&str> = FONTS
            .iter()
            .map(|font| font.info().family.as_str())
            .collect();
        assert!(
            families.iter().any(|f| *f == "Noto Sans"),
            "Noto Sans must be embedded: {families:?}"
        );
        assert!(
            families.iter().any(|f| *f == "Noto Sans SC"),
            "Noto Sans SC must be embedded: {families:?}"
        );
        assert!(
            FONT_BOOK
                .select_fallback(
                    None,
                    typst::text::FontVariant::new(
                        typst::text::FontStyle::Normal,
                        typst::text::FontWeight::REGULAR,
                        typst::text::FontStretch::Normal,
                    ),
                    "你",
                )
                .is_some(),
            "CJK must resolve through the embedded font book"
        );
    }

    #[test]
    fn payload_and_template_are_reachable_through_the_world() {
        let world = TypstWorld::new("invoice", r#"{"invoice_number":"INV-1"}"#.to_string())
            .expect("world builds");
        let main = world.source(world.main()).expect("main source");
        assert!(
            main.text().contains("ApexMail Invoice"),
            "main.typ must be the invoice template"
        );
        let data_id = project_file("data.json").unwrap();
        let data = world.source(data_id).expect("data source");
        assert_eq!(data.text(), r#"{"invoice_number":"INV-1"}"#);
    }

    #[test]
    fn missing_external_files_are_refused_without_the_env_var() {
        let world = TypstWorld::new("invoice", "{}".to_string()).expect("world builds");
        let other = project_file("secrets.json").unwrap();
        assert!(world.file(other).is_err(), "unlisted files must not resolve");
    }
}
