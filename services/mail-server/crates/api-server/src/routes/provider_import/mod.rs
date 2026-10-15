//! Provider-export importer — SendGrid, Mailgun, Postmark, Resend.
//!
//! The switching story in one surface: a customer arrives with an export from
//! their previous provider and needs the four artifacts of a real migration in
//! — **suppressions**, **contacts**, **templates** and a **domains DNS
//! report**. This module reads each provider's own export format and writes
//! through the EXISTING canonical paths:
//!
//! | kind | canonical path this importer writes through |
//! |------|----------------------------------------------|
//! | suppressions | the `suppressions` table, with `source = "<provider>_import"` provenance and the SAME `ON CONFLICT (tenant_id, email) DO NOTHING` semantics `routes::suppressions::bulk_suppress` uses |
//! | contacts | [`crate::routes::contacts::import_contact_rows`] — the very validation + chunked upsert `POST /v1/contacts/import` runs, with provider preset column mapping |
//! | templates | [`crate::routes::templates::create_template`] — the canonical create handler (validation, entitlement gate, v1 snapshot, audit row) |
//! | domains | [`crate::routes::domains::required_sender_dns_records`] — the exact record set `GET /v1/domains/:id/dns-records` serves |
//!
//! Nothing here re-implements a writer: an import can never take a shortcut
//! past the gates the canonical routes enforce.
//!
//! # Endpoint
//!
//! ```text
//! POST /v1/import/{provider}/{kind}[?mode=dry_run|commit&source_type=…&format=…&domain=…]
//! GET  /v1/import/reports            (durable commit reports, newest first)
//! GET  /v1/import/reports/{id}
//! ```
//!
//! * `provider` ∈ `sendgrid | mailgun | postmark | resend`
//! * `kind` ∈ `suppressions | contacts | templates | domains`
//! * `mode` defaults to **`dry_run`**: the file is parsed and diffed, nothing
//!   is written. `commit` performs the writes and stores the report durably
//!   (`import_reports`) so the receipt survives the request.
//! * the body is the raw export file. `format` forces `csv`/`json`; by default
//!   the Content-Type then the first byte decide.
//! * `domains` is the read-only report kind: pass `domain=<name or id>` and no
//!   body. It answers a keep/delete/edit plan built from the tenant's own
//!   domain row; no provider API is ever called.
//!
//! # Auth model
//!
//! The canonical [`AuthUser`] credential (`X-API-Key` / session), scoped per
//! kind exactly like the surface it writes through:
//!
//! | kind | required scope |
//! |------|----------------|
//! | suppressions | `suppressions:write` (same as `POST /v1/suppressions/bulk`) |
//! | contacts | `contacts:write` (same as `POST /v1/contacts/import`) |
//! | templates | `templates:write` + the `custom_templates` entitlement (same as `POST /v1/templates`) |
//! | domains | `domains:read` (same as `GET /v1/domains/:id/dns-records`) |
//!
//! Stored reports are readable with the matching per-kind `…:read` scope; a
//! report belonging to another tenant is an opaque 404.
//!
//! # Size contract (>10k)
//!
//! The inline bulk endpoints cap at 10,000 entries each. An import is not
//! bound by those caps: suppressions and contacts are parsed as an incremental
//! cursor (one 500-row chunk in memory at a time — the JSON reader walks the
//! array without ever building the whole document) and written in chunked
//! statements, so a 100k-row file streams through in bounded memory. The one
//! hard limit is [`MAX_PROVIDER_IMPORT_ROWS`], enforced mid-stream with a
//! named refusal, and the platform's 40 MiB body limit above that.
//!
//! # Idempotency
//!
//! Replaying the same file is safe: suppression and contact rows dedupe on
//! `(tenant_id, email)` (existing rows are never overwritten — counted as
//! `duplicates`/conflicts), templates dedupe on `(name)` within the tenant
//! (existing names are counted `skipped_existing`), and the domains report is
//! pure output.

pub mod contacts;
pub mod domains;
pub mod suppressions;
pub mod templates;

#[cfg(test)]
mod tests;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        // `/:provider/:kind` and `/reports…` cannot collide: no provider is
        // named "reports".
        .route("/:provider/:kind", post(import_file))
        .route("/reports", get(list_import_reports))
        .route("/reports/:id", get(get_import_report))
}

// ─── Enumerations ──────────────────────────────────────────────

/// The four providers whose exports this importer reads. Deliberately
/// self-contained (not shared with `routes::compat::Provider`, which models a
/// send WIRE contract): an import reads a file, it never speaks a provider
/// protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportProvider {
    SendGrid,
    Mailgun,
    Postmark,
    Resend,
}

impl ImportProvider {
    pub(crate) fn parse(raw: &str) -> Result<Self, ApiError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sendgrid" => Ok(Self::SendGrid),
            "mailgun" => Ok(Self::Mailgun),
            "postmark" => Ok(Self::Postmark),
            "resend" => Ok(Self::Resend),
            other => Err(ApiError::BadRequest(format!(
                "unknown provider '{other}': expected sendgrid, mailgun, postmark or resend"
            ))),
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::SendGrid => "sendgrid",
            Self::Mailgun => "mailgun",
            Self::Postmark => "postmark",
            Self::Resend => "resend",
        }
    }

    /// The `suppressions.source` provenance token every row this provider
    /// imports carries: `<provider>_import` (VARCHAR(100) fits with room; the
    /// canonical `SuppressionSource::Import` vocabulary lives in the
    /// compliance crate and the table stores free text, so the provider name
    /// is what makes an imported row attributable).
    pub(crate) fn suppression_source(self) -> String {
        format!("{}_import", self.name())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportKind {
    Suppressions,
    Contacts,
    Templates,
    Domains,
}

impl ImportKind {
    pub(crate) fn parse(raw: &str) -> Result<Self, ApiError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "suppressions" => Ok(Self::Suppressions),
            "contacts" => Ok(Self::Contacts),
            "templates" => Ok(Self::Templates),
            "domains" => Ok(Self::Domains),
            other => Err(ApiError::BadRequest(format!(
                "unknown kind '{other}': expected suppressions, contacts, templates or domains"
            ))),
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Suppressions => "suppressions",
            Self::Contacts => "contacts",
            Self::Templates => "templates",
            Self::Domains => "domains",
        }
    }

    /// The write scope the canonical surface for this kind requires — the
    /// import adds no new scope vocabulary, it follows the surface it writes
    /// through.
    pub(crate) fn write_scope(self) -> &'static str {
        match self {
            Self::Suppressions => "suppressions:write",
            Self::Contacts => "contacts:write",
            Self::Templates => "templates:write",
            // The domains report is read-only output.
            Self::Domains => "domains:read",
        }
    }

    /// The read scope a stored report of this kind requires.
    pub(crate) fn read_scope(self) -> &'static str {
        match self {
            Self::Suppressions => "suppressions:read",
            Self::Contacts => "contacts:read",
            Self::Templates => "templates:read",
            Self::Domains => "domains:read",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImportMode {
    /// Parse + diff, write nothing (the default).
    DryRun,
    /// Perform the writes and store the report.
    Commit,
}

impl ImportMode {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "dry_run" => Ok(Self::DryRun),
            "commit" => Ok(Self::Commit),
            other => Err(ApiError::BadRequest(format!(
                "unknown mode '{other}': expected dry_run or commit"
            ))),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::DryRun => "dry_run",
            Self::Commit => "commit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImportFormat {
    Csv,
    Json,
}

impl ImportFormat {
    fn name(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
        }
    }
}

// ─── Request types ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportQuery {
    /// `dry_run` (default — writes nothing) or `commit`.
    #[serde(default)]
    pub mode: Option<String>,
    /// Provider sub-type of a suppression export (`source_type=bounces` …);
    /// when absent the parser infers it from the file's own shape.
    #[serde(default)]
    pub source_type: Option<String>,
    /// `csv` or `json`; when absent the Content-Type then the first byte
    /// decide.
    #[serde(default)]
    pub format: Option<String>,
    /// The domain for `kind=domains` (name or id).
    #[serde(default)]
    pub domain: Option<String>,
    /// Max stored rows in the report's itemized sections (default 50, capped
    /// at 500). Counts are always complete; this only bounds the examples.
    #[serde(default)]
    pub notes_limit: Option<usize>,
}

const DEFAULT_NOTES_LIMIT: usize = 50;
const MAX_NOTES_LIMIT: usize = 500;

/// Hard row bound for a single import file, enforced mid-stream with a named
/// refusal. Far beyond any real export a switcher has (the 40 MiB platform
/// body limit binds far earlier for CSV), so it exists to keep a hostile
/// pathological file from pinning a connection for minutes — not to cap real
/// migrations.
pub(crate) const MAX_PROVIDER_IMPORT_ROWS: usize = 1_000_000;

/// Rows per chunked statement (matches the canonical bulk paths' 500).
pub(crate) const IMPORT_CHUNK_SIZE: usize = 500;

// ─── Report types ──────────────────────────────────────────────

/// One named example: a source row and what happened to it. Emails are NOT
/// echoed (matching the contacts import's "Row N: …" style) — the caller maps
/// the number back to their own file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowNote {
    /// 1-based data row (CSV line, minus the header) or array element index.
    pub row: usize,
    pub note: String,
}

/// Complete counts (never truncated; the itemized example lists are).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportCounts {
    /// Rows read from the file.
    pub rows: usize,
    /// Rows written (created or updated) in commit mode; would-be writes in
    /// dry-run.
    pub imported: usize,
    /// Rows already present (database conflicts) or repeated within the file.
    pub duplicates: usize,
    /// Rows refused by the canonical validators.
    pub invalid: usize,
    /// Templates imported with a `needs_review` marker.
    pub needs_review: usize,
    /// Rows that hit a named database/creation error.
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonCount {
    pub reason: String,
    pub count: usize,
}

/// `kind=suppressions` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuppressionReportSection {
    /// The provider sub-type the file was read as.
    pub source_type: String,
    /// Canonical `reason` token → rows (complete, not truncated).
    pub by_reason: Vec<ReasonCount>,
    /// Rows whose provider timestamp was not parseable (they were imported
    /// with `now()`, listed with a warning rather than guessed).
    pub unparsed_timestamps: usize,
}

/// One template's import row: the conversion is named, the original body is
/// kept, and anything left unconverted is listed — never silently mangled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateImportRow {
    /// 1-based index in the export.
    pub row: usize,
    pub name: String,
    /// `imported` | `skipped_existing` | `failed`.
    pub status: String,
    /// The canonical template id when it was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    /// True when the template carries constructs this renderer cannot honour
    /// exactly (or a semantic conversion was applied): the template was
    /// imported so nothing is lost, and it is marked for review.
    pub needs_review: bool,
    /// Named, verified conversions applied to the body (before → after).
    pub conversions: Vec<ConversionNote>,
    /// Constructs deliberately left verbatim (each one named).
    pub unconverted: Vec<String>,
    /// SHA-256 of the provider's original body (always present).
    pub original_sha256: String,
    /// The provider's original body, kept for review (omitted for bodies over
    /// [`MAX_ORIGINAL_BODY_BYTES`] and for itemization truncation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_body: Option<String>,
    /// The exact error for `status = "failed"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Bodies larger than this are hashed, not echoed (the file itself is the
/// original; mega-bodies stay in the customer's export).
pub(crate) const MAX_ORIGINAL_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionNote {
    /// The provider construct, e.g. `"{{ first_name }}"`.
    pub construct: String,
    /// What was done, e.g. `"trimmed inner whitespace to the canonical
    /// {{variable}} form"`.
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordInstruction {
    /// `keep` | `delete` | `edit`.
    pub action: String,
    pub record_type: String,
    pub hostname: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    pub note: String,
}

/// `kind=domains` section: what to keep (our required records), what the old
/// provider published (delete candidates, "if present"), and the edits that
/// are not a simple delete.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReport {
    pub domain: String,
    /// Provider whose records the delete candidates describe.
    pub from_provider: String,
    pub keep: Vec<RecordInstruction>,
    pub delete_candidates: Vec<RecordInstruction>,
    pub edits: Vec<RecordInstruction>,
    pub conflicts: Vec<String>,
}

/// The report every import answers with; stored verbatim on commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub provider: String,
    pub kind: String,
    pub mode: String,
    pub format: String,
    pub file_sha256: String,
    pub file_bytes: usize,
    pub counts: ImportCounts,
    /// Itemized conflicts (bounded by `notes_limit`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<RowNote>,
    /// Itemized invalid rows (bounded by `notes_limit`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invalid: Vec<RowNote>,
    /// Itemized failures (bounded by `notes_limit`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<RowNote>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressions: Option<SuppressionReportSection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<TemplateImportRow>,
    /// How many template rows were itemized; the counts above stay complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub templates_truncated: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<DomainReport>,
    /// Set on commit: the durable record's id (`GET /v1/import/reports/{id}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
}

impl ImportReport {
    pub(crate) fn base(
        provider: ImportProvider,
        kind: ImportKind,
        mode: ImportMode,
        format: ImportFormat,
        body: &[u8],
    ) -> Self {
        Self {
            provider: provider.name().into(),
            kind: kind.name().into(),
            mode: mode.name().into(),
            format: format.name().into(),
            file_sha256: sha256_hex(body),
            file_bytes: body.len(),
            counts: ImportCounts::default(),
            conflicts: Vec::new(),
            invalid: Vec::new(),
            failed: Vec::new(),
            warnings: Vec::new(),
            suppressions: None,
            templates: Vec::new(),
            templates_truncated: None,
            domain: None,
            report_id: None,
        }
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

// ─── Handler ───────────────────────────────────────────────────

async fn import_file(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((provider, kind)): Path<(String, String)>,
    Query(params): Query<ImportQuery>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<ImportReport>, ApiError> {
    let provider = ImportProvider::parse(&provider)?;
    let kind = ImportKind::parse(&kind)?;
    let mode = match params.mode.as_deref() {
        Some(raw) => ImportMode::parse(raw)?,
        None => ImportMode::DryRun,
    };

    require_scopes(&auth, &[kind.write_scope()])?;

    let notes_limit = params
        .notes_limit
        .unwrap_or(DEFAULT_NOTES_LIMIT)
        .clamp(1, MAX_NOTES_LIMIT);

    let body = body.as_ref();

    let report = match kind {
        ImportKind::Suppressions => {
            let format = sniff_format(&headers, body, params.format.as_deref())?;
            suppressions::import_suppressions(
                &state,
                &auth,
                provider,
                mode,
                format,
                params.source_type.as_deref(),
                notes_limit,
                body,
            )
            .await?
        }
        ImportKind::Contacts => {
            let format = sniff_format(&headers, body, params.format.as_deref())?;
            contacts::import_provider_contacts(
                &state,
                &auth,
                provider,
                mode,
                format,
                notes_limit,
                body,
            )
            .await?
        }
        ImportKind::Templates => {
            let format = sniff_format(&headers, body, params.format.as_deref())?;
            if format != ImportFormat::Json {
                return Err(ApiError::BadRequest(
                    "template exports are JSON; pass format=json or a JSON body".into(),
                ));
            }
            templates::import_templates(&state, &auth, provider, mode, body).await?
        }
        ImportKind::Domains => {
            let domain = params.domain.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "kind=domains needs ?domain=<name or id>; the report is generated from the \
                     tenant's own domain row and writes nothing"
                        .into(),
                )
            })?;
            domains::import_domain_report(&state, &auth, provider, mode, domain).await?
        }
    };

    let mut report = report;
    if mode == ImportMode::Commit {
        // The receipt is best-effort AFTER the writes committed: an import
        // that landed must never be reported as a failure because its report
        // row could not be stored — the response itself still carries the
        // full report (the caller can keep it), and the loss is logged loudly
        // and stated in the report's warnings.
        let id = apexmail_lib::id::generate_id("imp", 22);
        report.report_id = Some(id.clone());
        match store_report(&state, &auth, &report, &id).await {
            Ok(()) => audit_import(&state, &auth, &report, &id).await,
            Err(error) => {
                report.report_id = None;
                report.warnings.push(
                    "the import completed but its receipt could not be stored (database error); \
                     keep this response — GET /v1/import/reports will not list it"
                        .to_string(),
                );
                tracing::error!(
                    tenant_id = %auth.tenant_id,
                    provider = %report.provider,
                    kind = %report.kind,
                    error = %error,
                    "provider-import report could not be stored"
                );
            }
        }
    }
    Ok(Json(report))
}

/// Decide the file format: explicit `?format=`, then the Content-Type, then
/// the first non-whitespace byte. Anything that is neither a plausible CSV nor
/// a JSON document is a named refusal (never a mysterious parse error deeper
/// in).
fn sniff_format(
    headers: &axum::http::HeaderMap,
    body: &[u8],
    explicit: Option<&str>,
) -> Result<ImportFormat, ApiError> {
    if let Some(raw) = explicit {
        return match raw.trim().to_ascii_lowercase().as_str() {
            "csv" => Ok(ImportFormat::Csv),
            "json" => Ok(ImportFormat::Json),
            other => Err(ApiError::BadRequest(format!(
                "unknown format '{other}': expected csv or json"
            ))),
        };
    }

    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if content_type.contains("json") {
        return Ok(ImportFormat::Json);
    }
    if content_type.contains("csv") {
        return Ok(ImportFormat::Csv);
    }

    let first = body.iter().find(|byte| !byte.is_ascii_whitespace());
    match first {
        Some(b'{') | Some(b'[') => Ok(ImportFormat::Json),
        // XLSX/XLS are zip/OLE containers — the importer reads CSV/JSON
        // exports only (a spreadsheet's zip magic would otherwise be parsed as
        // binary CSV and produce a sea of row errors).
        Some(b'P') if body.starts_with(b"PK\x03\x04") => Err(ApiError::BadRequest(
            "this looks like an XLSX file: export the provider data as CSV or JSON \
             (spreadsheets are not read by the provider importer)"
                .into(),
        )),
        Some(b'\xD0') if body.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) => Err(ApiError::BadRequest(
            "this looks like a legacy XLS file: export the provider data as CSV or JSON".into(),
        )),
        Some(_) => Ok(ImportFormat::Csv),
        None => Err(ApiError::BadRequest("the import file is empty".into())),
    }
}

// ─── Durable reports ───────────────────────────────────────────

async fn store_report(
    state: &AppState,
    auth: &AuthUser,
    report: &ImportReport,
    id: &str,
) -> Result<(), sqlx::Error> {
    let value = serde_json::to_value(report).unwrap_or(serde_json::Value::Null);
    sqlx::query(
        "INSERT INTO import_reports (id, tenant_id, provider, kind, mode, file_sha256, report, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&report.provider)
    .bind(&report.kind)
    .bind(&report.mode)
    .bind(&report.file_sha256)
    .bind(&value)
    .bind(Utc::now())
    .execute(&state.db)
    .await?;
    Ok(())
}

/// Best-effort audit row (same contract as `audit_template`): the report row
/// is the truth; a lost audit row is logged loudly, never fatal.
async fn audit_import(state: &AppState, auth: &AuthUser, report: &ImportReport, id: &str) {
    let counts = serde_json::to_value(&report.counts).unwrap_or(serde_json::Value::Null);
    if let Err(error) = crate::audit_log::insert_audit_log_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(&auth.tenant_id),
        auth.user_id.as_deref(),
        "provider_import.committed",
        "import_report",
        Some(id),
        serde_json::json!({
            "provider": report.provider,
            "kind": report.kind,
            "file_sha256": report.file_sha256,
            "counts": counts,
        }),
        None,
        None,
    )
    .await
    {
        tracing::warn!(
            tenant_id = %auth.tenant_id,
            report_id = id,
            error = %error,
            "failed to write provider-import audit row"
        );
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct StoredReportSummary {
    pub id: String,
    pub provider: String,
    pub kind: String,
    pub mode: String,
    pub file_sha256: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReportsQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

async fn list_import_reports(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListReportsQuery>,
) -> Result<Json<Vec<StoredReportSummary>>, ApiError> {
    // A stored report is a read: any import-capable read scope the caller
    // holds suffices (per-row kind scoping would hide the tenant's own
    // history behind an unrelated scope).
    let readable = [
        "suppressions:read",
        "contacts:read",
        "templates:read",
        "domains:read",
    ];
    if !readable
        .iter()
        .any(|scope| require_scopes(&auth, &[scope]).is_ok())
    {
        return Err(ApiError::Forbidden(format!(
            "missing required scope: one of {}",
            readable.join(", ")
        )));
    }

    let offset = params.offset.unwrap_or(0).clamp(0, 100_000);
    let limit = crate::routes::helpers::clamp_limit(params.limit.unwrap_or(25), 100);
    let rows = sqlx::query_as::<_, StoredReportSummary>(
        "SELECT id, provider, kind, mode, file_sha256, created_at
         FROM import_reports WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

async fn get_import_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ImportReport>, ApiError> {
    let stored: Option<(String, String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT kind, provider, mode, report FROM import_reports WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?;
    // Opaque 404 across tenants; the kind's read scope is checked only after
    // the tenant gate, so a foreign id cannot probe scope names either.
    let Some((kind, _provider, _mode, value)) = stored else {
        return Err(ApiError::NotFound("import report not found".into()));
    };
    let kind = ImportKind::parse(&kind)?;
    require_scopes(&auth, &[kind.read_scope()])?;
    let mut report: ImportReport = serde_json::from_value(value).map_err(|error| {
        ApiError::Internal(format!(
            "stored import report could not be decoded: {error}"
        ))
    })?;
    report.report_id = Some(id);
    Ok(Json(report))
}

// ─── Shared engines (one CSV / one JSON reader for every kind) ──

/// The one CSV reader every kind shares, with the SAME settings
/// `routes::contacts::parse_csv_rows` uses (`has_headers(true)`,
/// `flexible(true)`) — provider presets differ in their column mapping, never
/// in the engine.
pub(crate) fn csv_reader(data: &[u8]) -> csv::Reader<&[u8]> {
    csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(data)
}

/// Resolve `field → column index` from a CSV header with case-insensitive,
/// alias-aware matching (`email`/`address`/`EmailAddress`, …). Header cells
/// are trimmed and spaces folded to underscores so real exports
/// (`First Name`, `first_name`) both match.
pub(crate) fn resolve_columns(
    headers: &csv::StringRecord,
    fields: &[(&str, &[&str])],
) -> std::collections::HashMap<String, usize> {
    let normalized: Vec<String> = headers
        .iter()
        .map(|name| name.trim().to_ascii_lowercase().replace([' ', '-'], "_"))
        .collect();
    let mut resolved = std::collections::HashMap::new();
    for (field, aliases) in fields {
        if let Some(index) = normalized
            .iter()
            .position(|name| aliases.iter().any(|alias| name == alias))
        {
            resolved.insert((*field).to_string(), index);
        }
    }
    resolved
}

/// Case-insensitive field lookup on a provider JSON object, first alias wins.
pub(crate) fn json_field<'a>(
    value: &'a serde_json::Value,
    aliases: &[&str],
) -> Option<&'a serde_json::Value> {
    let object = value.as_object()?;
    for alias in aliases {
        if let Some(found) = object.get(*alias) {
            return Some(found);
        }
    }
    // Case-insensitive second pass (Postmark `EmailAddress`, Resend `email`).
    for (key, found) in object {
        if aliases.iter().any(|alias| key.eq_ignore_ascii_case(alias)) {
            return Some(found);
        }
    }
    None
}

pub(crate) fn json_string(value: &serde_json::Value, aliases: &[&str]) -> Option<String> {
    let found = json_field(value, aliases)?;
    match found {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Provider timestamps arrive as RFC 3339 strings or epoch seconds/millis.
/// Returns `None` (never a guess) when the value cannot be parsed.
pub(crate) fn json_timestamp(value: &serde_json::Value, aliases: &[&str]) -> Option<DateTime<Utc>> {
    let found = json_field(value, aliases)?;
    match found {
        serde_json::Value::Number(number) => {
            let raw = number.as_i64()?;
            // Seconds vs milliseconds: anything past 10^11 is milliseconds
            // (10^11 s ≈ year 5138; 10^11 ms ≈ 1973).
            let (seconds, millis) = if raw.abs() >= 100_000_000_000 {
                (raw / 1000, raw % 1000)
            } else {
                (raw, 0)
            };
            DateTime::from_timestamp(seconds, (millis * 1_000_000) as u32)
        }
        serde_json::Value::String(text) => parse_timestamp(text),
        _ => None,
    }
}

pub(crate) fn parse_timestamp(text: &str) -> Option<DateTime<Utc>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(parsed.with_timezone(&Utc));
    }
    // Provider exports commonly use "2026-01-31 12:00:00" (Space-separated,
    // no zone) — UTC is the documented reading for those.
    for format in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, format) {
            return Some(naive.and_utc());
        }
        if let Ok(date) = chrono::NaiveDate::parse_from_str(trimmed, format) {
            return Some(date.and_hms_opt(0, 0, 0)?.and_utc());
        }
    }
    None
}

/// An incremental cursor over the elements of the FIRST JSON array in a
/// document (`[…]`, `{"items": […]}`), so a 100k-entry export is never
/// materialized as one `serde_json::Value` tree: elements are sliced out raw
/// and parsed one at a time by the caller.
pub(crate) struct JsonArrayCursor<'a> {
    bytes: &'a [u8],
    cursor: usize,
    done: bool,
    /// The number of elements yielded so far: the 1-based row number callers
    /// name in errors and report notes.
    yielded: usize,
    /// The object key the array hangs under (`items`, `Bounces`, …), when the
    /// document is an envelope object.
    pub(crate) envelope_key: Option<String>,
}

impl<'a> JsonArrayCursor<'a> {
    /// The number of elements yielded so far (1-based row numbering source).
    pub(crate) fn yielded(&self) -> usize {
        self.yielded
    }

    /// Yield the next element as raw JSON text, or `None` at the end.
    pub(crate) fn next_element(&mut self) -> Result<Option<&'a [u8]>, String> {
        if self.done {
            return Ok(None);
        }
        loop {
            let Some(&byte) = self.bytes.get(self.cursor) else {
                return Err("JSON export is malformed: the array is unterminated".into());
            };
            match byte {
                b']' => {
                    self.done = true;
                    return Ok(None);
                }
                b',' => {
                    self.cursor += 1;
                }
                b'\r' | b'\n' | b'\t' | b' ' => {
                    self.cursor += 1;
                }
                _ => break,
            }
        }
        let start = self.cursor;
        let end = scan_json_value(self.bytes, start)?;
        self.cursor = end;
        self.yielded += 1;
        Ok(Some(&self.bytes[start..end]))
    }
}

/// Open the first JSON array of `bytes` (string-aware scan: `[` inside a
/// string never counts) and return a cursor positioned on its first element.
///
/// The array is confirmed TERMINATED here, in a bounded-memory prepass: a
/// truncated export is a named refusal BEFORE any chunk is written, so a
/// commit can never half-import a malformed file.
pub(crate) fn json_array_cursor(bytes: &[u8]) -> Result<JsonArrayCursor<'_>, String> {
    let start = find_first_array(bytes)?;
    let envelope_key = preceding_key(bytes, start);
    // Depth-track to the matching close bracket (strings ignored). The
    // element scanner reuses the same rules; this pass guarantees the
    // document's own array is complete before the first row is fetched.
    let mut depth = 0usize;
    let mut index = start;
    let mut in_string = false;
    let mut escaped = false;
    while let Some(&byte) = bytes.get(index) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'[' | b'{' => depth += 1,
                b']' | b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(JsonArrayCursor {
                            bytes,
                            cursor: start + 1,
                            done: false,
                            envelope_key,
                            yielded: 0,
                        });
                    }
                }
                _ => {}
            }
        }
        index += 1;
    }
    Err("JSON export is malformed: the records array is unterminated".into())
}

fn find_first_array(bytes: &[u8]) -> Result<usize, String> {
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while let Some(&byte) = bytes.get(index) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b'[' {
            return Ok(index);
        }
        index += 1;
    }
    Err("JSON export carries no array of records at the top level".into())
}

/// The `"key"` immediately preceding the array (`{"items": [ …`), when there
/// is one — purely for the report's transparency.
fn preceding_key(bytes: &[u8], array_start: usize) -> Option<String> {
    let mut index = array_start;
    loop {
        let before = *bytes.get(index.checked_sub(1)?)?;
        match before {
            b' ' | b'\t' | b'\r' | b'\n' | b':' => index -= 1,
            // This is the closing quote of the key; `index` sits just past it.
            b'"' => break,
            _ => return None,
        }
    }
    let close = index - 1;
    let mut cursor = close;
    loop {
        let before = *bytes.get(cursor.checked_sub(1)?)?;
        if before == b'"' {
            let key = String::from_utf8(bytes.get(cursor..close)?.to_vec()).ok()?;
            return Some(key);
        }
        if before == b'\\' {
            return None; // escaped quotes in a key: skip the nicety
        }
        cursor -= 1;
    }
}

/// Scan one JSON value starting at `start`, returning the index just past it.
fn scan_json_value(bytes: &[u8], start: usize) -> Result<usize, String> {
    let first = *bytes
        .get(start)
        .ok_or_else(|| "JSON export is malformed: a record is missing".to_string())?;
    match first {
        b'"' => scan_json_string(bytes, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut index = start;
            let mut in_string = false;
            let mut escaped = false;
            while let Some(&byte) = bytes.get(index) {
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        in_string = false;
                    }
                } else {
                    match byte {
                        b'"' => in_string = true,
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth -= 1;
                            if depth == 0 {
                                return Ok(index + 1);
                            }
                        }
                        _ => {}
                    }
                }
                index += 1;
            }
            Err("JSON export is malformed: a record is unterminated".into())
        }
        _ => {
            // Number / true / false / null: up to the next delimiter.
            let mut index = start;
            while let Some(&byte) = bytes.get(index) {
                if matches!(byte, b',' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                    break;
                }
                index += 1;
            }
            Ok(index)
        }
    }
}

fn scan_json_string(bytes: &[u8], start: usize) -> Result<usize, String> {
    let mut index = start + 1;
    let mut escaped = false;
    while let Some(&byte) = bytes.get(index) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Ok(index + 1);
        }
        index += 1;
    }
    Err("JSON export is malformed: an unterminated string".into())
}

/// Parse one raw element into a JSON object, with the element's 1-based index
/// in the named error.
pub(crate) fn parse_json_element(
    element: &[u8],
    index: usize,
) -> Result<serde_json::Value, ApiError> {
    serde_json::from_slice::<serde_json::Value>(element).map_err(|error| {
        ApiError::BadRequest(format!(
            "JSON export is malformed at record {index}: {error}"
        ))
    })
}

// ─── Shared report helpers ─────────────────────────────────────

/// Push a note into a bounded list. Counts elsewhere are always complete; the
/// lists cap at `limit` so a pathological file cannot turn the report into a
/// second copy of itself.
pub(crate) fn push_note(
    list: &mut Vec<RowNote>,
    limit: usize,
    row: usize,
    note: impl Into<String>,
) {
    if list.len() < limit {
        list.push(RowNote {
            row,
            note: note.into(),
        });
    }
}

pub(crate) fn row_limit_reached(rows: usize) -> Result<(), ApiError> {
    if rows > MAX_PROVIDER_IMPORT_ROWS {
        return Err(ApiError::PayloadTooLarge(format!(
            "import file exceeds {MAX_PROVIDER_IMPORT_ROWS} rows; split it into smaller exports"
        )));
    }
    Ok(())
}

/// The report's status for a spec'd dry-run: importers report what WOULD land.
pub(crate) fn dry_run_suffix(mode: ImportMode) -> &'static str {
    match mode {
        ImportMode::DryRun => " (dry run: nothing was written)",
        ImportMode::Commit => "",
    }
}
