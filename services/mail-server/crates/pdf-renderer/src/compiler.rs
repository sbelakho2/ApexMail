//! Typst compiler — template + JSON data → PDF bytes.
//!
//! This module wraps the Typst compiler pipeline:
//! 1. Build a [`TypstWorld`] from template name + JSON data
//! 2. Compile the Typst source into a `PagedDocument`
//! 3. Export the document to PDF bytes via `typst-pdf`
//!
//! The designed layouts live in `src/templates/*.typ`; every template in
//! [`crate::world::TEMPLATES`] is compiled and exported by this pipeline, so
//! the downloaded PDF is the designed document — not a data export.
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
use tracing::{info, warn};

use typst::diag::SourceDiagnostic;
use typst::foundations::Smart;
use typst::WorldExt;
use typst_layout::PagedDocument;

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

/// Timeout for the PDF generation (including the Typst compilation).
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
/// compilation times out, the output is too large, or PDF export fails.
pub async fn render_pdf(template: &str, data: &serde_json::Value) -> Result<Vec<u8>, RenderError> {
    // ---- 1. Input validation (O-14.1) ------------------------------------
    let data_json =
        serde_json::to_string(data).map_err(|e| RenderError::Serialization(e.to_string()))?;

    if data_json.len() > MAX_DATA_JSON_BYTES {
        return Err(RenderError::Serialization(format!(
            "JSON data too large: {} bytes (max: {})",
            data_json.len(),
            MAX_DATA_JSON_BYTES,
        )));
    }

    let world = TypstWorld::new(template, data_json).map_err(RenderError::World)?;

    // ---- 2. Rendering with timeout (O-14.1) ------------------------------
    let pdf_bytes = timeout(
        Duration::from_secs(RENDER_TIMEOUT_SECS),
        tokio::task::spawn_blocking(move || compile_and_export(&world)),
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
// Typst compile + export
// ---------------------------------------------------------------------------

/// Compile the world's main template into a paged document and export PDF.
///
/// Compilation warnings are logged (they never fail a render); compilation
/// errors are turned into a `RenderError::Compilation` carrying the message
/// and the template location of every diagnostic.
fn compile_and_export(world: &TypstWorld) -> Result<Vec<u8>, RenderError> {
    let warned = typst::compile::<PagedDocument>(world);

    for warning in &warned.warnings {
        warn!(
            diagnostic = %describe(world, warning),
            "typst compilation warning"
        );
    }

    let document = warned
        .output
        .map_err(|errors| RenderError::Compilation(describe_all(world, &errors)))?;

    let options = typst_pdf::PdfOptions {
        ident: Smart::Auto,
        creator: Smart::Auto,
        timestamp: None,
        page_ranges: None,
        standards: typst_pdf::PdfStandards::default(),
        tagged: true,
        pretty: false,
    };
    typst_pdf::pdf(&document, &options)
        .map_err(|error| RenderError::PdfExport(format!("{error:?}")))
}

/// One diagnostic with its template location (when the span points into a
/// known file), e.g. `unknown variable: rates at invoice.typ:187`.
fn describe(world: &TypstWorld, diagnostic: &SourceDiagnostic) -> String {
    let location = world.range(diagnostic.span).and_then(|range| {
        let id = diagnostic.span.id()?;
        Some(format!(
            "{}:{}",
            id.vpath().get_without_slash(),
            range.start
        ))
    });
    match location {
        Some(location) => format!("{} at {}", diagnostic.message, location),
        None => diagnostic.message.to_string(),
    }
}

fn describe_all(world: &TypstWorld, errors: &[SourceDiagnostic]) -> String {
    errors
        .iter()
        .map(|error| describe(world, error))
        .collect::<Vec<_>>()
        .join("; ")
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

    /// The producer payload for an invoice, as built by
    /// `billing_service::invoices::generate_invoice_pdf`.
    fn invoice_payload(currency: &str, total: i64) -> serde_json::Value {
        serde_json::json!({
            "invoice_number": "INV-2025-0042",
            "status": "paid",
            "currency": currency,
            "issued_at": "2025-01-15",
            "due_at": "2025-02-14",
            "paid_at": "2025-01-20",
            "period_start": "2025-01-01",
            "period_end": "2025-01-31",
            "subtotal": 9900,
            "vat_total": 2178,
            "total": total,
            "line_items": [
                { "description": "Professional Plan", "quantity": 1, "unit_price": 9900, "amount": 9900, "vat_rate": 22, "vat_amount": 2178 }
            ],
            "seller": {
                "name": "Bel Consulting OÜ",
                "address": "Sakala 7-2, 10141 Tallinn, Estonia",
                "vat_number": "EE102951727",
                "registry_code": "16588745"
            },
            "bank": { "name": "Wise", "iban": "EE382200221020145685", "bic": "LHVBEE22" },
            "bill_to": {
                "company": "Acme Corp",
                "name": "Jane Doe",
                "address": "123 Main St",
                "city": "Tallinn 10141",
                "country": "EE",
                "vat_number": "EE123456789"
            }
        })
    }

    /// Every render produces a structurally valid PDF document.
    fn assert_pdf(bytes: &[u8]) {
        assert!(bytes.starts_with(b"%PDF-"), "not a PDF: {:?}", &bytes[..4]);
        assert!(
            bytes.windows(5).any(|w| w == b"%%EOF"),
            "missing EOF marker"
        );
        assert!(
            !bytes.windows(8).any(|w| w == b"/Encrypt"),
            "must not encrypt"
        );
    }

    #[tokio::test]
    async fn invoice_renders_the_designed_layout_with_authoritative_currency() {
        let pdf = render_pdf("invoice", &invoice_payload("EUR", 12078))
            .await
            .expect("invoice renders");
        assert_pdf(&pdf);

        // The invoice is a real layout: the extracted text carries the
        // designed sections, not a JSON dump.
        let text = crate::test_extract::extract_text(&pdf);
        assert!(text.contains("INVOICE"), "{text}");
        assert!(text.contains("Bill To:"), "{text}");
        assert!(text.contains("Acme Corp"), "{text}");
        assert!(text.contains("Professional Plan"), "{text}");
        assert!(text.contains("Subtotal"), "{text}");
        // Authoritative currency: EUR renders with its symbol…
        assert!(text.contains('€'), "EUR must render with a symbol: {text}");
        assert!(text.contains("120.78"), "{text}");
        // …and the ISO code is never silently replaced.
        assert!(text.contains("EUR"), "{text}");
        // Payment terms derive from the invoice's own issue/due dates.
        assert!(text.contains("Net 30 days"), "{text}");
        assert!(text.contains("2025-02-14"), "{text}");
        // The old data-export header must be gone.
        assert!(
            !text.contains("full payload"),
            "the data export header must not appear: {text}"
        );
    }

    #[tokio::test]
    async fn invoice_currency_comes_from_the_payload_not_a_hardcoded_euro() {
        let usd = render_pdf("invoice", &invoice_payload("USD", 12078))
            .await
            .expect("usd invoice renders");
        let text = crate::test_extract::extract_text(&usd);
        assert!(text.contains('$'), "USD must render with $: {text}");
        assert!(!text.contains('€'), "USD invoice must not carry €: {text}");
        assert!(text.contains("USD"), "{text}");

        // An unknown code stays the code — never a guessed symbol.
        let xyz = render_pdf("invoice", &invoice_payload("XYZ", 12078))
            .await
            .expect("xyz invoice renders");
        let text = crate::test_extract::extract_text(&xyz);
        assert!(text.contains("XYZ"), "{text}");
        assert!(!text.contains('$') && !text.contains('€'), "{text}");
    }

    #[tokio::test]
    async fn invoice_handles_negative_and_missing_optional_data() {
        let mut payload = invoice_payload("EUR", -500000);
        payload["line_items"] = serde_json::json!([
            { "description": "Credit note — overbilled December", "quantity": 1,
              "unit_price": -500000, "amount": -500000, "vat_rate": 0, "vat_amount": 0 }
        ]);
        payload["bill_to"] = serde_json::Value::Null;
        payload.as_object_mut().unwrap().remove("bank");
        let pdf = render_pdf("invoice", &payload)
            .await
            .expect("credit invoice renders");
        assert_pdf(&pdf);
        let text = crate::test_extract::extract_text(&pdf);
        // Negative amounts keep the sign in front of the symbol.
        assert!(text.contains("-€5000.00"), "{text}");
        // A missing billing address is explicit, not blank.
        assert!(text.contains("Customer details not available"), "{text}");
    }

    /// The Typst pipeline is the intended layout pipeline: the embedded
    /// template source is what gets compiled, and every embedded template
    /// compiles with a realistic payload.
    #[tokio::test]
    async fn every_embedded_template_compiles() {
        let payloads: Vec<(&str, serde_json::Value)> = vec![
            ("invoice", invoice_payload("EUR", 12078)),
            (
                "dpa",
                serde_json::json!({
                    "company_name": "Acme Corp",
                    "effective_date": "2026-01-15",
                    "data_categories": ["Email addresses", "Names"],
                    "processing_purposes": ["Transactional email delivery"],
                    "sub_processors": [{ "name": "Hetzner Online GmbH", "purpose": "Core infrastructure", "location": "Germany/Finland (EEA)" }],
                    "retention_days": 90,
                    "tenant_id": "tenant-1"
                }),
            ),
            (
                "compliance_report",
                serde_json::json!({
                    "tenant_id": "tenant-1",
                    "generated_at": "2026-01-15T10:00:00Z",
                    "enabled_frameworks": ["gdpr", "soc2"],
                    "status": "active",
                    "baa_signed": false,
                    "dpa_signed": true,
                    "zero_retention_mode": false,
                    "encryption_at_rest": true,
                    "encryption_in_transit": true,
                    "audit_log_entries": 128,
                    "data_access_requests": 3,
                    "audit_retention_days": 365
                }),
            ),
            (
                "analytics_export",
                serde_json::json!({
                    "tenant_name": "tenant-1",
                    "date_range": { "from": "2026-01-01", "to": "2026-01-31" },
                    "generated_at": "2026-02-01T00:00:00Z",
                    "summary": {
                        "total_sent": 145230, "total_delivered": 141890, "total_bounced": 2340,
                        "total_opened": 58756, "total_clicked": 12340,
                        "total_unsubscribed": 0, "total_complaints": 0,
                        "delivery_rate": 97.7, "open_rate": 41.4, "click_rate": 8.7,
                        "bounce_rate": 1.6, "complaint_rate": 0.0
                    },
                    "daily_stats": [],
                    "top_campaigns": [],
                    "domain_breakdown": []
                }),
            ),
            (
                "qbr",
                serde_json::json!({
                    "id": "00000000-0000-0000-0000-000000000001",
                    "tenant_id": "tenant-1",
                    "quarter": 4,
                    "year": 2025,
                    "status": "completed",
                    "metrics": {
                        "sent": 450000, "delivered": 441900, "bounced": 5850,
                        "opened": 186000, "clicked": 39500,
                        "delivery_rate": 98.2, "bounce_rate": 1.3,
                        "open_rate": 42.1, "click_rate": 8.9
                    },
                    "insights": [{ "category": "deliverability", "severity": "info", "message": "Delivery rate is stable." }],
                    "recommendations": [{ "priority": "high", "title": "List hygiene", "description": "Remove hard-bouncing contacts." }],
                    "goals": [{ "title": "Reach 99% delivery", "status": "in_progress", "progress_percent": 60.0, "unit": "%", "target_value": 99.0, "current_value": 98.2 }],
                    "created_at": "2026-01-10T00:00:00Z"
                }),
            ),
        ];

        for (template, payload) in payloads {
            let pdf = render_pdf(template, &payload)
                .await
                .unwrap_or_else(|e| panic!("template {template} must compile: {e}"));
            assert_pdf(&pdf);
        }
    }

    #[tokio::test]
    async fn templates_render_cjk_and_cyrillic_through_embedded_fonts() {
        let mut payload = invoice_payload("EUR", 12078);
        payload["line_items"] = serde_json::json!([
            { "description": "年度套餐 / Годовой план", "quantity": 1,
              "unit_price": 9900, "amount": 9900, "vat_rate": 22, "vat_amount": 2178 }
        ]);
        let pdf = render_pdf("invoice", &payload)
            .await
            .expect("unicode invoice renders");
        let text = crate::test_extract::extract_text(&pdf);
        assert!(text.contains("年度套餐"), "CJK must round-trip: {text}");
        assert!(
            text.contains("Годовой план"),
            "Cyrillic must round-trip: {text}"
        );
    }

    // ── Adversarial: hostile payload limits and hostile text ────────────

    /// Oversized JSON is refused before generation; a PDF-shaped but hostile
    /// character payload never panics.
    #[tokio::test]
    async fn oversize_data_is_refused_before_generation() {
        let big = "x".repeat(MAX_DATA_JSON_BYTES);
        let data = serde_json::json!({ "payload": big, "more": big });
        let error = render_pdf("invoice", &data).await.expect_err("must refuse");
        assert!(
            error.to_string().contains("too large"),
            "expected size refusal, got {error}"
        );
    }

    #[tokio::test]
    async fn hostile_text_is_escaped_and_never_breaks_the_render() {
        let mut payload = invoice_payload("EUR", 12078);
        payload["invoice_number"] = serde_json::json!("(INJ) \\ \" <script>alert(1)</script>");
        payload["bill_to"]["company"] = serde_json::json!("<img src=x onerror=alert(1)>");
        let pdf = render_pdf("invoice", &payload)
            .await
            .expect("hostile text renders as text");
        assert_pdf(&pdf);
        let text = crate::test_extract::extract_text(&pdf);
        assert!(text.contains("<img src=x onerror=alert(1)>"), "{text}");
        assert!(text.contains("alert(1)"), "{text}");
    }

    /// A missing template is a typed world error; a path-shaped name is an
    /// invalid-name error (never a filesystem read).
    #[tokio::test]
    async fn template_lookup_errors_are_typed() {
        let missing = render_pdf("no-such-template", &serde_json::json!({}))
            .await
            .expect_err("missing template");
        assert!(
            missing.to_string().contains("no-such-template"),
            "{missing}"
        );
        let hostile = render_pdf("../../etc/passwd", &serde_json::json!({}))
            .await
            .expect_err("path-shaped template");
        assert!(
            matches!(
                hostile,
                RenderError::World(crate::world::WorldError::InvalidTemplateName(_))
            ),
            "{hostile}"
        );
    }

    /// Template diagnostics carry a template-relative location so a broken
    /// template is debuggable from the API error alone.
    #[tokio::test]
    async fn compile_errors_name_the_template_location() {
        let broken = crate::test_extract::world_with_source("#let x = does-not-exist\n#x\n");
        let error = compile_and_export(&broken).expect_err("must not compile");
        let message = error.to_string();
        assert!(
            message.contains("main.typ:"),
            "diagnostic must carry the location: {message}"
        );
    }
}
