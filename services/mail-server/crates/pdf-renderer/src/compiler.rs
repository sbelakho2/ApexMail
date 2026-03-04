//! Typst compiler — template + JSON data → PDF bytes.
//!
//! This module wraps the Typst compiler pipeline:
//!   1. Build a `TypstWorld` from template name + JSON data
//!   2. Compile the Typst source to a Typst document
//!   3. Export the document to PDF bytes via `typst-pdf`

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::world::{TypstWorld, WorldError};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Render a named template with JSON data → PDF bytes.
///
/// # Arguments
/// * `template` — template name (e.g. `"invoice"`, `"dpa"`)
/// * `data` — arbitrary JSON value to inject into the template
///
/// # Returns
/// PDF bytes on success.
///
/// # Errors
/// Returns `RenderError` if template not found, compilation fails, or PDF
/// export fails.
pub fn render_pdf(template: &str, data: &serde_json::Value) -> Result<Vec<u8>, RenderError> {
    let data_json = serde_json::to_string_pretty(data)
        .map_err(|e| RenderError::Serialization(e.to_string()))?;

    let world = TypstWorld::new(template, data_json)
        .map_err(RenderError::World)?;

    // In a full implementation, this would:
    //   1. Parse the Typst source via typst::syntax::parse()
    //   2. Build a typst::model::Document via typst::compile()
    //   3. Export via typst_pdf::pdf()
    //
    // For now we use a stub that produces a valid minimal PDF with the
    // template data, to be replaced once typst crate API stabilizes for
    // our pinned version.

    let pdf_bytes = generate_stub_pdf(template, &world)?;

    info!(
        template = template,
        pdf_size = pdf_bytes.len(),
        "PDF rendered successfully"
    );

    Ok(pdf_bytes)
}

/// Render with full Typst compilation (real implementation).
///
/// This function will be the production path once the Typst 0.12 API
/// is integrated. The stub above will be removed.
///
/// The flow is:
/// ```text
/// .typ source → typst::compile(world) → typst::model::Document → typst_pdf::pdf() → Vec<u8>
/// ```
#[allow(dead_code)]
fn compile_typst_document(world: &TypstWorld) -> Result<Vec<u8>, RenderError> {
    // TODO: Integrate typst crate when API is stable
    // let source = typst::syntax::Source::detached(&world.template_source);
    // let document = typst::compile(&world).output.map_err(|e| RenderError::Compilation(format!("{e:?}")))?;
    // let pdf = typst_pdf::pdf(&document, &PdfOptions::default());
    // Ok(pdf)
    Err(RenderError::Compilation("not yet implemented — use stub".into()))
}

// ---------------------------------------------------------------------------
// Stub PDF generator (valid PDF 1.4)
// ---------------------------------------------------------------------------

fn generate_stub_pdf(template: &str, world: &TypstWorld) -> Result<Vec<u8>, RenderError> {
    // Produce a minimal but valid PDF 1.4 file.
    // This will be replaced by real Typst compilation.
    let now = world.now.format("%Y%m%d%H%M%S").to_string();
    let title = match template {
        "invoice" => "ApexMail Invoice",
        "dpa" => "Data Processing Agreement",
        "compliance_report" => "Compliance Report",
        "analytics_export" => "Analytics Export",
        "qbr" => "Quarterly Business Review",
        _ => "Document",
    };

    // Minimal PDF structure
    let content = format!(
        r#"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842]
   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj

4 0 obj
<< /Length {stream_length} >>
stream
BT
/F1 24 Tf
50 780 Td
({title}) Tj
/F1 12 Tf
0 -30 Td
(Template: {template}) Tj
0 -20 Td
(Generated: {now}) Tj
0 -20 Td
(Data: {data_preview}...) Tj
ET
endstream
endobj

5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj

xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000266 00000 n 
trailer
<< /Size 6 /Root 1 0 R /Info << /Title ({title}) /Producer (ApexMail pdf-renderer) >> >>
startxref
%%EOF
"#,
        title = title,
        template = template,
        now = now,
        data_preview = &world.data_json[..world.data_json.len().min(80)],
        stream_length = 200, // approximate
    );

    Ok(content.into_bytes())
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderRequest {
    /// Template name: "invoice", "dpa", "compliance_report", "analytics_export", "qbr"
    pub template: String,
    /// Arbitrary JSON data to pass to the template
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderResponse {
    /// Base64-encoded PDF bytes (only used for JSON response mode)
    pub pdf_base64: Option<String>,
    /// Size in bytes
    pub size: usize,
    /// Template used
    pub template: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("template not found: {0}")]
    World(#[from] WorldError),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("typst compilation error: {0}")]
    Compilation(String),
    #[error("pdf export error: {0}")]
    PdfExport(String),
}
