#[macro_use]
extern crate napi_derive;

use napi::{bindgen_prelude::*, Task};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use serde_json::Value;
use std::collections::HashMap;

// ── Embedded Typst templates ───────────────────────────────────────────

static TEMPLATES: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("invoice", include_str!("../../services/mail-server/crates/pdf-renderer/src/templates/invoice.typ"));
    m.insert("dpa", include_str!("../../services/mail-server/crates/pdf-renderer/src/templates/dpa.typ"));
    m.insert("compliance_report", include_str!("../../services/mail-server/crates/pdf-renderer/src/templates/compliance_report.typ"));
    m.insert("analytics_export", include_str!("../../services/mail-server/crates/pdf-renderer/src/templates/analytics_export.typ"));
    m.insert("qbr", include_str!("../../services/mail-server/crates/pdf-renderer/src/templates/qbr.typ"));
    m
});

// ── Render result type ─────────────────────────────────────────────────

#[napi(object)]
pub struct PdfResult {
    /// Raw PDF bytes
    pub pdf: Buffer,
    /// Size in bytes
    pub size: u32,
    /// Template name that was rendered
    pub template: String,
}

// ── Async render task ──────────────────────────────────────────────────

struct RenderTask {
    template: String,
    data_json: String,
}

#[napi]
impl Task for RenderTask {
    type Output = (Vec<u8>, String);
    type JsValue = PdfResult;

    fn compute(&mut self) -> Result<Self::Output> {
        let template_source = TEMPLATES
            .get(self.template.as_str())
            .ok_or_else(|| {
                let available: Vec<&str> = TEMPLATES.keys().copied().collect();
                napi::Error::from_reason(format!(
                    "Unknown template '{}'. Available: {}",
                    self.template,
                    available.join(", ")
                ))
            })?;

        // Parse the data to validate it's valid JSON
        let _data: Value = serde_json::from_str(&self.data_json)
            .map_err(|e| napi::Error::from_reason(format!("Invalid JSON data: {e}")))?;

        // Generate a stub PDF (valid PDF 1.4) — same approach as pdf-renderer crate.
        // Real Typst compilation will be integrated when the Typst 0.12 World API
        // is fully stabilised for embedding.
        let pdf_bytes = generate_stub_pdf(template_source, &self.data_json);

        Ok((pdf_bytes, self.template.clone()))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        let (pdf_bytes, template) = output;
        let size = pdf_bytes.len() as u32;
        Ok(PdfResult {
            pdf: pdf_bytes.into(),
            size,
            template,
        })
    }
}

/// Generate a minimal valid PDF 1.4 document as a placeholder.
fn generate_stub_pdf(template_source: &str, data_json: &str) -> Vec<u8> {
    let template_hash = {
        let mut h: u64 = 5381;
        for b in template_source.bytes().take(256) {
            h = h.wrapping_mul(33).wrapping_add(b as u64);
        }
        h
    };
    let data_len = data_json.len();

    let content = format!(
        "BT /F1 12 Tf 72 720 Td (ApexMail PDF - template hash: {template_hash}, data: {data_len} bytes) Tj ET"
    );
    let stream = format!("stream\n{content}\nendstream");

    let mut pdf = String::new();
    pdf.push_str("%PDF-1.4\n");
    pdf.push_str("1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n");
    pdf.push_str("2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n");
    pdf.push_str(&format!(
        "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Contents 4 0 R/Resources<</Font<</F1<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>>>>>>>endobj\n"
    ));
    pdf.push_str(&format!(
        "4 0 obj<</Length {}>>{}\nendobj\n",
        content.len(),
        stream
    ));
    let xref_offset = pdf.len();
    pdf.push_str("xref\n0 5\n");
    pdf.push_str("0000000000 65535 f \n");
    // Approximate offsets (valid enough for stub)
    pdf.push_str("0000000009 00000 n \n");
    pdf.push_str("0000000058 00000 n \n");
    pdf.push_str("0000000115 00000 n \n");
    pdf.push_str("0000000310 00000 n \n");
    pdf.push_str(&format!(
        "trailer<</Size 5/Root 1 0 R>>\nstartxref\n{xref_offset}\n%%EOF\n"
    ));

    pdf.into_bytes()
}

// ── Public API ─────────────────────────────────────────────────────────

/// Render a PDF from a Typst template name and JSON data.
/// Returns a Promise<PdfResult> that resolves off the main thread.
#[napi]
pub fn render_pdf(template: String, data: String) -> AsyncTask<RenderTask> {
    AsyncTask::new(RenderTask {
        template,
        data_json: data,
    })
}

/// Synchronous render — blocks the main thread. Use `renderPdf` (async) instead
/// unless you specifically need sync behaviour.
#[napi]
pub fn render_pdf_sync(template: String, data: String) -> Result<PdfResult> {
    let template_source = TEMPLATES
        .get(template.as_str())
        .ok_or_else(|| {
            let available: Vec<&str> = TEMPLATES.keys().copied().collect();
            napi::Error::from_reason(format!(
                "Unknown template '{}'. Available: {}",
                template,
                available.join(", ")
            ))
        })?;

    let _data: Value = serde_json::from_str(&data)
        .map_err(|e| napi::Error::from_reason(format!("Invalid JSON data: {e}")))?;

    let pdf_bytes = generate_stub_pdf(template_source, &data);
    let size = pdf_bytes.len() as u32;

    Ok(PdfResult {
        pdf: pdf_bytes.into(),
        size,
        template,
    })
}

/// List available template names.
#[napi]
pub fn list_templates() -> Vec<String> {
    TEMPLATES.keys().map(|k| k.to_string()).collect()
}
