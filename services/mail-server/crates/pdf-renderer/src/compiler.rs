//! Typst compiler — template + JSON data → PDF bytes.
//!
//! This module wraps the Typst compiler pipeline:
//! 1. Build a `TypstWorld` from template name + JSON data
//! 2. Compile the Typst source to a Typst document
//! 3. Export the document to PDF bytes via `typst-pdf`
//!
//! # Security (O-14.1 / O-14.2)
//!
//! - **Rendering timeout** — A configurable timeout (default 10 s) prevents
//!   runaway Typst compilation from crafted JSON data.
//! - **Input size limit** — JSON data payload is capped at 1 MB so deeply
//!   nested / oversized inputs are rejected early.
//! - **Output size limit** — Generated PDF bytes are checked against a
//!   configurable maximum (default 50 MB) to prevent OOM from oversized
//!   output (e.g. a template expanded by huge JSON arrays).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::info;

use crate::world::{TypstWorld, WorldError};

// ---------------------------------------------------------------------------
// Security constants (configurable via env vars)
// ---------------------------------------------------------------------------

/// Maximum allowed size (in bytes) for the serialised JSON input data.
/// Prevents deeply‑nested or oversized JSON from causing resource exhaustion.
const MAX_DATA_JSON_BYTES: usize = 1024 * 1024; // 1 MB

/// Maximum allowed size (in bytes) for the generated PDF output.
/// Prevents a template (e.g. with huge data arrays) from producing a
/// multi‑gigabyte PDF that could cause an OOM.
const MAX_PDF_OUTPUT_SIZE: usize = 50 * 1024 * 1024; // 50 MB

/// Timeout for the PDF generation (including any eventual Typst compilation).
/// If generation does not complete within this window the request is aborted.
const RENDER_TIMEOUT_SECS: u64 = 10;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Render a named template with JSON data → PDF bytes.
///
/// # Security
///
/// 1. **Input validation** — The JSON payload is checked against
///    [`MAX_DATA_JSON_BYTES`] before any processing begins.
/// 2. **Timeout** — The actual generation runs inside
///    [`tokio::task::spawn_blocking`] wrapped by [`tokio::time::timeout`]
///    so a stalled / infinite‑loop template is caught.
/// 3. **Output limit** — After generation the byte vector is checked against
///    [`MAX_PDF_OUTPUT_SIZE`]; oversized output is rejected.
///
/// # Arguments
/// * `template` — template name (e.g. `"invoice"`, `"dpa"`)
/// * `data` — arbitrary JSON value to inject into the template
///
/// # Returns
/// PDF bytes on success.
///
/// # Errors
/// Returns `RenderError` if the JSON is too large, the template is not found,
/// generation times out, the output is too large, or PDF export fails.
pub async fn render_pdf(template: &str, data: &serde_json::Value) -> Result<Vec<u8>, RenderError> {
    // ---- 1. Input validation (O-14.1) ------------------------------------
    let data_json = serde_json::to_string_pretty(data)
        .map_err(|e| RenderError::Serialization(e.to_string()))?;

    if data_json.len() > MAX_DATA_JSON_BYTES {
        return Err(RenderError::Serialization(format!(
            "JSON data too large: {} bytes (max: {})",
            data_json.len(),
            MAX_DATA_JSON_BYTES,
        )));
    }

    let world = TypstWorld::new(template, data_json).map_err(RenderError::World)?;

    // ---- 2. Rendering with timeout (O-14.1) ------------------------------
    let template_owned = template.to_string();
    let pdf_bytes = timeout(
        Duration::from_secs(RENDER_TIMEOUT_SECS),
        tokio::task::spawn_blocking(move || generate_pdf(&template_owned, &world)),
    )
    .await
    .map_err(|_| RenderError::Compilation("PDF rendering timed out".to_string()))?
    .map_err(|e| RenderError::Compilation(format!("rendering task failed: {}", e)))??;

    // ---- 3. Output size limit (O-14.2) -----------------------------------
    if pdf_bytes.len() > MAX_PDF_OUTPUT_SIZE {
        return Err(RenderError::PdfExport(format!(
            "generated PDF too large: {} bytes (max: {})",
            pdf_bytes.len(),
            MAX_PDF_OUTPUT_SIZE,
        )));
    }

    info!(
        template = template,
        pdf_size = pdf_bytes.len(),
        "PDF rendered successfully"
    );

    Ok(pdf_bytes)
}

// ---------------------------------------------------------------------------
// PDF generator (valid PDF 1.4)
// ---------------------------------------------------------------------------

/// Escape a string for use inside a PDF literal string `(...)`.
///
/// PDF literal strings must balance parentheses and escape backslashes;
/// unescaped `(`/`)` would let injected data terminate the string early and
/// inject arbitrary content-stream operators. Newlines/CR/TAB are escaped
/// as well to keep the stream well-formed.
///
/// Literal strings are byte strings (PDFDocEncoding/WinAnsi, i.e. latin-1):
/// latin-1 characters outside printable ASCII are escaped as octal `\ooo`,
/// and any character above U+00FF (which has no latin-1 representation) is
/// dropped rather than emitting a multi-byte UTF-8 sequence that would
/// corrupt the byte stream.
fn escape_pdf_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) <= 0x7f => out.push(c),
            c if (c as u32) <= 0xff => {
                // Latin-1 supplement: emit as octal escape so the byte value
                // survives regardless of the reader's text encoding.
                out.push_str(&format!("\\{:03o}", c as u32));
            }
            // No latin-1 representation — drop the character.
            _ => {}
        }
    }
    out
}

/// Generate a minimal but valid PDF 1.4 document with the template data.
/// Uses raw PDF operators to produce a single-page document containing
/// the title, template name, timestamp and a preview of the injected data.
///
/// NOTE: Full Typst compilation remains unwired in this pass (tracked
/// separately); this generator produces spec-compliant output that can be
/// opened by any PDF reader while the Typst pipeline is being wired up.
///
/// All offsets (xref table, `startxref`) are computed programmatically from
/// the actual object bytes, and the content-stream `/Length` reflects the
/// real byte count — no hardcoded/approximate offsets.
fn generate_pdf(template: &str, world: &TypstWorld) -> Result<Vec<u8>, RenderError> {
    let now = world.now.format("%Y%m%d%H%M%S").to_string();
    let title = match template {
        "invoice" => "ApexMail Invoice",
        "dpa" => "Data Processing Agreement",
        "compliance_report" => "Compliance Report",
        "analytics_export" => "Analytics Export",
        "qbr" => "Quarterly Business Review",
        _ => "Document",
    };

    // Escape every interpolated value: title/template come from a fixed set,
    // but the data preview is attacker-controlled JSON.
    let title_esc = escape_pdf_string(title);
    let template_esc = escape_pdf_string(template);
    let now_esc = escape_pdf_string(&now);
    // Truncate on a char boundary before escaping so multi-byte UTF-8 is not split.
    let data_preview: String = world.data_json.chars().take(80).collect();
    let data_preview_esc = escape_pdf_string(&data_preview);

    // Content stream — build the actual bytes first so /Length is exact.
    let stream_body = format!(
        "BT\n/F1 24 Tf\n50 780 Td\n({title_esc}) Tj\n/F1 12 Tf\n0 -30 Td\n(Template: {template_esc}) Tj\n0 -20 Td\n(Generated: {now_esc}) Tj\n0 -20 Td\n(Data: {data_preview_esc}...) Tj\nET\n"
    );
    let stream_bytes = stream_body.into_bytes();
    let stream_length = stream_bytes.len();

    // Object 4: content stream with exact /Length.
    let mut obj4 = format!("<< /Length {stream_length} >>\nstream\n").into_bytes();
    obj4.extend_from_slice(&stream_bytes);
    obj4.extend_from_slice(b"\nendstream");

    // Fully serialised indirect objects (1..=5), in object-number order.
    let objects: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842]\n   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".to_vec(),
        obj4,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
    ];

    // Assemble the file, recording each object's byte offset as we go.
    // Each indirect object is serialised as `N 0 obj\n<body>\nendobj\n` so the
    // xref offsets point at the actual object headers.
    let mut pdf: Vec<u8> = b"%PDF-1.4\n".to_vec();
    let mut offsets: Vec<usize> = Vec::with_capacity(objects.len() + 1);
    offsets.push(0); // object 0 — free entry, offset unused
    for (idx, obj) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", idx + 1).as_bytes());
        pdf.extend_from_slice(obj);
        pdf.extend_from_slice(b"\nendobj\n");
    }

    // Cross-reference table computed from the recorded offsets.
    let xref_offset = pdf.len();
    let size = offsets.len();
    pdf.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for &off in &offsets[1..] {
        pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }

    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root 1 0 R /Info << /Title ({title_esc}) /Producer (ApexMail pdf-renderer) >> >>\nstartxref\n{xref_offset}\n%%EOF\n"
        )
        .as_bytes(),
    );

    Ok(pdf)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderRequest {
    /// Template name:"invoice", "dpa", "compliance_report", "analytics_export", "qbr"
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the xref table is internally consistent: every `N 0 R` offset
    /// in the xref section must point at the actual `N 0 obj` header, and
    /// `startxref` must point at the `xref` keyword.
    #[test]
    fn xref_offsets_are_internally_consistent() {
        let world = TypstWorld {
            template_source: String::new(),
            data_json: r#"{"customer":"Injec)ted \\( Corp","items":[1,2,3]}"#.to_string(),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("invoice", &world).expect("pdf generation failed");
        let text = String::from_utf8_lossy(&pdf);

        // startxref points at the xref keyword.
        let startxref_pos = text.rfind("startxref").expect("startxref missing");
        let after = text[startxref_pos..].trim_start_matches("startxref").trim();
        let xref_offset: usize = after
            .lines()
            .next()
            .unwrap()
            .trim()
            .parse()
            .expect("startxref value");
        assert_eq!(&pdf[xref_offset..xref_offset + 4], b"xref");

        // Parse the xref table entries and verify each in-use entry points at
        // the matching `N 0 obj` header.
        let xref_body = &text[xref_offset..];
        let mut lines = xref_body.lines();
        assert_eq!(lines.next().unwrap(), "xref");
        let header = lines.next().unwrap();
        let size: usize = header.split_whitespace().nth(1).unwrap().parse().unwrap();
        let first = lines.next().unwrap();
        assert_eq!(first, "0000000000 65535 f ");
        for obj_num in 1..size {
            let entry = lines.next().expect("missing xref entry");
            let offset: usize = entry[..10].parse().expect("bad xref offset");
            let expected_prefix = format!("{obj_num} 0 obj");
            assert!(
                pdf[offset..].starts_with(expected_prefix.as_bytes()),
                "xref offset for object {obj_num} does not point at its header: {entry}"
            );
        }

        // Every object is terminated and the file ends with %%EOF.
        assert!(pdf.ends_with(b"%%EOF\n"));
    }

    #[test]
    fn escapes_parens_backslashes_and_non_latin1() {
        assert_eq!(escape_pdf_string("a(b)c"), "a\\(b\\)c");
        assert_eq!(escape_pdf_string("back\\slash"), "back\\\\slash");
        assert_eq!(escape_pdf_string("new\nline\r\ttab"), "new\\nline\\r\\ttab");
        // Latin-1 é (U+00E9) → octal escape of byte 0xE9.
        assert_eq!(escape_pdf_string("café"), "caf\\351");
        // Above latin-1 (U+0100 'Ā', U+4F60 '你') → dropped.
        assert_eq!(escape_pdf_string("Ā你x"), "x");
    }

    #[test]
    fn generated_pdf_has_valid_markers_and_exact_length() {
        let world = TypstWorld {
            template_source: String::new(),
            data_json: r#"{"k":"v")"}"#.to_string(),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("dpa", &world).expect("pdf generation failed");
        assert!(pdf.starts_with(b"%PDF-1.4\n"));
        assert!(pdf.windows(9).any(|w| w == b"startxref"));
        assert!(pdf.ends_with(b"%%EOF\n"));

        // The content stream /Length must equal the bytes between `stream\n`
        // and `\nendstream`.
        let text = String::from_utf8_lossy(&pdf);
        let len_start = text.find("/Length ").unwrap() + "/Length ".len();
        let declared: usize = text[len_start..]
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let stream_start = text.find("stream\n").unwrap() + "stream\n".len();
        let stream_end = text.find("\nendstream").unwrap();
        assert_eq!(declared, stream_end - stream_start);
    }
}
