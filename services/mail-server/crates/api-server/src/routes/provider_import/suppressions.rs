//! Provider suppression-list import: SendGrid, Mailgun, Postmark, Resend.
//!
//! # Formats read
//!
//! | provider | export | shape | email | reason source | timestamp |
//! |----------|--------|-------|-------|---------------|-----------|
//! | SendGrid | bounces / blocks / spam-report CSV | `email,created,reason[,status]` (spam reports carry `ip` and no reason) | `email` | `source_type` + `status`/`reason` permanence sniff | `created` |
//! | Mailgun | bounces / unsubscribes / complaints JSON | `{"items":[{address,code,error,created_at}]}` | `address` | `source_type` + `code`/`error` sniff | `created_at` |
//! | Postmark | bounces JSON | `{"TotalCount":n,"Bounces":[{Email,Type,TypeCode,Description,BouncedAt}]}` | `Email` | `Type` | `BouncedAt` |
//! | Resend | suppressions JSON or CSV | `{"data":[{email,reason,created_at}]}` / `email,created,reason` | `email` | `reason`/`type` text | `created_at`/`created` |
//!
//! # Reason mapping (canonical `compliance::suppressions` vocabulary)
//!
//! Imported rows carry the canonical reason tokens wherever the provider's
//! semantic is unambiguous, because the token is what drives the removal
//! policy (`compliance::suppressions::parse_reason` / `removal_allowed`):
//!
//! | provider signal | canonical reason |
//! |-----------------|------------------|
//! | bounce, permanent (`5xx` code/status, "hard", default) | `hard_bounce` |
//! | bounce, transient (`4xx`, "soft", "transient", "temporar") | `temporary` |
//! | block (SendGrid blocks, Postmark `Blocked`) | `customer_block` |
//! | spam report / spam complaint (SendGrid spam reports, Mailgun complaints, Postmark `SpamComplaint`) | `complaint` |
//! | unsubscribe (Mailgun unsubscribes, Postmark `SubscriptionChange`) | `marketing_unsubscribe` |
//!
//! The default inside a bounce file is `hard_bounce`: an imported bounce list
//! is a suppression list, and the conservative reading (non-removable except
//! with admin scope) cannot silently un-suppress an address. The choice is
//! visible per row class in the report's `by_reason` histogram.
//!
//! # Provenance and idempotency
//!
//! Rows are inserted with `source = "<provider>_import"`, 500 per chunked
//! `INSERT … ON CONFLICT (tenant_id, email) DO NOTHING`, exactly the
//! conflict semantics `bulk_suppress` uses. An existing row (manual, bulk,
//! webhook, anything) is NEVER overwritten: it is counted as a duplicate and
//! listed as a conflict. Replaying the same file therefore writes nothing.
//!
//! # Streaming
//!
//! The file is read through an incremental cursor (CSV records one at a time,
//! JSON array elements sliced out of the document one at a time), drained in
//! [`IMPORT_CHUNK_SIZE`]-row working sets, so a 100k-row export is processed
//! in 200 chunk statements with a bounded footprint, the 10,000-entry inline
//! cap does not apply. [`MAX_PROVIDER_IMPORT_ROWS`] bounds the stream with a
//! named refusal.

use chrono::{DateTime, Utc};

use super::{
    csv_reader, json_array_cursor, json_field, json_string, json_timestamp, parse_json_element,
    parse_timestamp, push_note, row_limit_reached, ImportCounts, ImportFormat, ImportKind,
    ImportMode, ImportProvider, ImportReport, JsonArrayCursor, ReasonCount, RowNote,
    SuppressionReportSection, IMPORT_CHUNK_SIZE,
};
use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

/// The provider sub-type an export carries. SendGrid and Mailgun export each
/// suppression class as its OWN file with near-identical columns, so the
/// sub-type is either passed explicitly (`?source_type=`) or inferred from the
/// file's shape (header/field sniffing), always named in the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SuppressionType {
    Bounces,
    Blocks,
    SpamReports,
    Unsubscribes,
    Complaints,
    /// Resend's generic suppressions export.
    Suppressions,
}

impl SuppressionType {
    fn token(self) -> &'static str {
        match self {
            Self::Bounces => "bounces",
            Self::Blocks => "blocks",
            Self::SpamReports => "spam_reports",
            Self::Unsubscribes => "unsubscribes",
            Self::Complaints => "complaints",
            Self::Suppressions => "suppressions",
        }
    }

    /// Parse the caller's `?source_type=` against the values the provider
    /// actually exports, a value from another provider is a named refusal,
    /// never silently reinterpreted.
    fn parse(provider: ImportProvider, raw: &str) -> Result<Self, ApiError> {
        let normalized = raw.trim().to_ascii_lowercase().replace(' ', "_");
        let parsed = match (provider, normalized.as_str()) {
            (ImportProvider::SendGrid, "bounces") => Self::Bounces,
            (ImportProvider::SendGrid, "blocks") => Self::Blocks,
            (ImportProvider::SendGrid, "spam_reports" | "spamreports" | "spam_report") => {
                Self::SpamReports
            }
            (ImportProvider::Mailgun, "bounces") => Self::Bounces,
            (ImportProvider::Mailgun, "unsubscribes" | "unsubscribe") => Self::Unsubscribes,
            (ImportProvider::Mailgun, "complaints" | "complaint") => Self::Complaints,
            (ImportProvider::Postmark, "bounces") => Self::Bounces,
            (ImportProvider::Resend, "suppressions" | "suppression") => Self::Suppressions,
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "unknown source_type '{raw}' for {}: expected {}",
                    provider.name(),
                    match provider {
                        ImportProvider::SendGrid => "bounces, blocks or spam_reports",
                        ImportProvider::Mailgun => "bounces, unsubscribes or complaints",
                        ImportProvider::Postmark => "bounces",
                        ImportProvider::Resend => "suppressions",
                    }
                )))
            }
        };
        Ok(parsed)
    }
}

/// One row read from the file: the raw provider cells only. Validation and
/// reason derivation happen in the engine, so the cursor stays dumb and
/// incremental.
pub(super) struct RawSuppressionRow {
    /// 1-based data row (CSV: file line; JSON: array element index).
    pub row_number: usize,
    /// Empty when the row carries no usable email (counted invalid).
    pub email: String,
    /// The provider's own free-text reason/status/detail cell.
    pub detail: Option<String>,
    /// The provider's own `type`/`reason` classification cell when present.
    pub kind: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    /// The provider timestamp was present but unparseable (reported, imported
    /// with the import time).
    pub timestamp_unparsed: bool,
}

// ─── Incremental cursors ───────────────────────────────────────

/// A provider suppression export, read one chunk at a time.
pub(super) enum SuppressionCursor<'a> {
    Csv {
        reader: csv::Reader<&'a [u8]>,
        layout: CsvLayout,
        /// Sub-type inferred from the file's own shape (named in the report).
        inferred: SuppressionType,
        fallback_row: usize,
    },
    Json {
        cursor: JsonArrayCursor<'a>,
        provider: ImportProvider,
        /// The elements hang under this key (`items`, `Bounces`, `data`, …) —
        /// kept for diagnostics.
        envelope: Option<String>,
    },
}

pub(super) struct CsvLayout {
    email: usize,
    reason: Option<usize>,
    created: Option<usize>,
}

impl<'a> SuppressionCursor<'a> {
    /// The JSON envelope key the records hung under (`items`, `data`, …) —
    /// named in the report's warnings for transparency.
    pub(super) fn envelope_key(&self) -> Option<&str> {
        match self {
            Self::Json { envelope, .. } => envelope.as_deref(),
            Self::Csv { .. } => None,
        }
    }

    /// The sub-type inferred from the file's shape, available after the
    /// cursor was constructed (CSV headers read).
    fn inferred_type(&self) -> SuppressionType {
        match self {
            Self::Csv { inferred, .. } => *inferred,
            Self::Json { provider, .. } => match provider {
                ImportProvider::Mailgun => SuppressionType::Bounces,
                ImportProvider::Postmark => SuppressionType::Bounces,
                _ => SuppressionType::Suppressions,
            },
        }
    }

    /// The next `max` rows, or an empty vec at end of file.
    fn next_chunk(&mut self, max: usize) -> Result<Vec<RawSuppressionRow>, ApiError> {
        let mut rows = Vec::with_capacity(max);
        match self {
            Self::Csv {
                reader,
                layout,
                fallback_row,
                ..
            } => {
                while rows.len() < max {
                    let Some(record) = reader.records().next() else {
                        break;
                    };
                    let record = record.map_err(|error| {
                        ApiError::BadRequest(format!("CSV parse error: {error}"))
                    })?;
                    let row_number = record
                        .position()
                        .map(|position| position.line() as usize)
                        .unwrap_or_else(|| {
                            *fallback_row += 1;
                            *fallback_row
                        });
                    let email = record.get(layout.email).unwrap_or("").to_string();
                    let (created_at, timestamp_unparsed) =
                        read_csv_timestamp(&record, layout.created);
                    rows.push(RawSuppressionRow {
                        row_number,
                        email,
                        detail: layout
                            .reason
                            .and_then(|index| record.get(index))
                            .map(str::to_string)
                            .filter(|text| !text.trim().is_empty()),
                        kind: None,
                        created_at,
                        timestamp_unparsed,
                    });
                }
            }
            Self::Json {
                cursor, provider, ..
            } => {
                while rows.len() < max {
                    let Some(element) = cursor.next_element().map_err(ApiError::BadRequest)? else {
                        break;
                    };
                    let index = cursor.yielded();
                    let value = parse_json_element(element, index)?;
                    rows.push(json_row(*provider, index, &value));
                }
            }
        }
        Ok(rows)
    }
}

fn read_csv_timestamp(
    record: &csv::StringRecord,
    column: Option<usize>,
) -> (Option<DateTime<Utc>>, bool) {
    let Some(raw) = column.and_then(|index| record.get(index)) else {
        return (None, false);
    };
    if raw.trim().is_empty() {
        return (None, false);
    }
    match parse_timestamp(raw) {
        Some(parsed) => (Some(parsed), false),
        None => (None, true),
    }
}

/// Map one JSON element into the raw row, per provider field vocabulary.
fn json_row(
    provider: ImportProvider,
    index: usize,
    value: &serde_json::Value,
) -> RawSuppressionRow {
    let (email_aliases, kind_aliases, detail_aliases, time_aliases): (
        &[&str],
        &[&str],
        &[&str],
        &[&str],
    ) = match provider {
        ImportProvider::Mailgun => (
            &["address", "email", "recipient"],
            &["type", "event", "kind"],
            &["error", "code", "reason", "description"],
            &["created_at", "created", "timestamp"],
        ),
        ImportProvider::Postmark => (
            &["Email", "EmailAddress", "email"],
            &["Type", "type"],
            &["Description", "Details", "description"],
            &["BouncedAt", "bounced_at", "CreatedAt"],
        ),
        // SendGrid's suppression exports are CSV; Resend's JSON shape is the
        // generic email/reason/created_at document.
        ImportProvider::SendGrid | ImportProvider::Resend => (
            &["email", "address"],
            &["type", "event"],
            &["reason", "description", "detail"],
            &["created_at", "created", "timestamp"],
        ),
    };
    let created_raw = json_field(value, time_aliases);
    let created_at = json_timestamp(value, time_aliases);
    RawSuppressionRow {
        row_number: index,
        email: json_string(value, email_aliases).unwrap_or_default(),
        detail: json_string(value, detail_aliases),
        kind: json_string(value, kind_aliases),
        created_at,
        timestamp_unparsed: created_raw.is_some() && created_at.is_none(),
    }
}

/// Open the provider's export as an incremental cursor.
pub(super) fn suppression_cursor<'a>(
    provider: ImportProvider,
    format: ImportFormat,
    data: &'a [u8],
) -> Result<SuppressionCursor<'a>, ApiError> {
    match format {
        ImportFormat::Csv => {
            // Pre-pass: the whole file must parse BEFORE the first chunk is
            // written. Streaming cannot un-write a chunk, and a mid-file
            // quoting error must not leave a half-imported file behind, the
            // pass is O(1) memory (records are visited and discarded) and
            // cheap next to the database work it guards.
            validate_csv_stream(data)?;
            let mut reader = csv_reader(data);
            let headers = reader
                .headers()
                .map_err(|error| ApiError::BadRequest(format!("CSV parse error: {error}")))?
                .clone();
            let columns = super::resolve_columns(
                &headers,
                &[
                    ("email", &["email", "email_address", "address"]),
                    (
                        "reason",
                        &["reason", "status", "detail", "description", "error"],
                    ),
                    (
                        "created",
                        &["created", "created_at", "timestamp", "date", "bounced_at"],
                    ),
                    ("ip", &["ip", "ip_address"]),
                ],
            );
            let email = *columns.get("email").ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "suppression CSV has no email column; headers were: {}",
                    header_list(&headers)
                ))
            })?;
            // Sub-type sniff (named in the report): a SendGrid spam-report
            // export carries an IP column and no reason; bounce and block
            // exports both carry `reason`, told apart by the caller's
            // source_type with bounces as the documented default.
            let inferred = if columns.contains_key("ip") && !columns.contains_key("reason") {
                SuppressionType::SpamReports
            } else {
                SuppressionType::Bounces
            };
            Ok(SuppressionCursor::Csv {
                reader,
                layout: CsvLayout {
                    email,
                    reason: columns.get("reason").copied(),
                    created: columns.get("created").copied(),
                },
                inferred,
                fallback_row: 1,
            })
        }
        ImportFormat::Json => {
            let cursor = json_array_cursor(data).map_err(ApiError::BadRequest)?;
            let envelope = cursor.envelope_key.clone();
            Ok(SuppressionCursor::Json {
                cursor,
                provider,
                envelope,
            })
        }
    }
}

fn header_list(headers: &csv::StringRecord) -> String {
    headers
        .iter()
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Iterate the file once with the SAME reader settings the cursor uses, so a
/// malformed record is a named refusal before any write happens.
fn validate_csv_stream(data: &[u8]) -> Result<(), ApiError> {
    let mut reader = csv_reader(data);
    for record in reader.records() {
        record.map_err(|error| ApiError::BadRequest(format!("CSV parse error: {error}")))?;
    }
    Ok(())
}

// ─── Reason derivation ─────────────────────────────────────────

/// Classify a bounce from the provider's free text. Conservative: anything
/// not clearly transient is `hard_bounce` (a bounce list must keep
/// suppressing).
fn classify_bounce(detail: Option<&str>) -> &'static str {
    let Some(detail) = detail else {
        return "hard_bounce";
    };
    let text = detail.trim().to_ascii_lowercase();
    if text.is_empty() {
        return "hard_bounce";
    }
    let first = text.split_whitespace().next().unwrap_or("");
    // SMTP enhanced/status codes: 4xx leans transient, 5xx permanent.
    if first.starts_with('4') || text.contains("4.7.") || text.contains("4.2.") {
        return "temporary";
    }
    if text.contains("soft") || text.contains("transient") || text.contains("temporar") {
        return "temporary";
    }
    if text.contains("hard") || text.contains("permanent") {
        return "hard_bounce";
    }
    if first.starts_with('5') || text.contains("5.") {
        return "hard_bounce";
    }
    "hard_bounce"
}

/// Postmark's bounce `Type` vocabulary.
fn postmark_reason(kind: Option<&str>, detail: Option<&str>) -> &'static str {
    let kind = kind.unwrap_or("").trim().to_ascii_lowercase();
    match kind.as_str() {
        "spamcomplaint" | "spam_complaint" | "spam" => "complaint",
        "subscriptionchange" | "unsubscribe" => "marketing_unsubscribe",
        "blocked" => "customer_block",
        "softbounce" | "soft_bounce" | "transient" | "automaticfail" | "greylisted" => "temporary",
        "hardbounce" | "hard_bounce" | "manualsuppression" | "invalid" => "hard_bounce",
        _ => classify_bounce(detail),
    }
}

/// Resend's generic suppression reason text.
fn resend_reason(kind: Option<&str>, detail: Option<&str>) -> &'static str {
    let haystack = format!("{} {}", kind.unwrap_or(""), detail.unwrap_or("")).to_ascii_lowercase();
    if haystack.contains("spam") || haystack.contains("complaint") {
        "complaint"
    } else if haystack.contains("unsub") {
        "marketing_unsubscribe"
    } else if haystack.contains("block") {
        "customer_block"
    } else if haystack.contains("soft") || haystack.contains("transient") {
        "temporary"
    } else {
        "hard_bounce"
    }
}

fn derive_reason(
    provider: ImportProvider,
    source_type: SuppressionType,
    row: &RawSuppressionRow,
) -> &'static str {
    match provider {
        ImportProvider::Postmark => postmark_reason(row.kind.as_deref(), row.detail.as_deref()),
        ImportProvider::Resend => resend_reason(row.kind.as_deref(), row.detail.as_deref()),
        ImportProvider::SendGrid | ImportProvider::Mailgun => match source_type {
            SuppressionType::Bounces => classify_bounce(row.detail.as_deref()),
            SuppressionType::Blocks => "customer_block",
            SuppressionType::SpamReports | SuppressionType::Complaints => "complaint",
            SuppressionType::Unsubscribes => "marketing_unsubscribe",
            SuppressionType::Suppressions => {
                resend_reason(row.kind.as_deref(), row.detail.as_deref())
            }
        },
    }
}

// ─── Engine ────────────────────────────────────────────────────

type FreshRow = (usize, String, &'static str, Option<DateTime<Utc>>);

/// Import a provider suppression export through the canonical suppressions
/// table.
pub(crate) async fn import_suppressions(
    state: &AppState,
    auth: &AuthUser,
    provider: ImportProvider,
    mode: ImportMode,
    format: ImportFormat,
    source_type: Option<&str>,
    notes_limit: usize,
    body: &[u8],
) -> Result<ImportReport, ApiError> {
    let mut report = ImportReport::base(provider, ImportKind::Suppressions, mode, format, body);
    let mut cursor = suppression_cursor(provider, format, body)?;
    let source_type = match source_type {
        Some(raw) => SuppressionType::parse(provider, raw)?,
        None => cursor.inferred_type(),
    };

    let mut counts = ImportCounts::default();
    let mut conflicts: Vec<RowNote> = Vec::new();
    let mut invalid: Vec<RowNote> = Vec::new();
    let mut failed: Vec<RowNote> = Vec::new();
    let mut by_reason: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut unparsed_timestamps = 0usize;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let source = provider.suppression_source();
    let now = Utc::now();

    // One chunk at a time: validate + dedupe in file order, filter against
    // what the database already holds (a chunked existence probe), then write
    // the survivors with the provider provenance.
    loop {
        let raw_chunk = cursor.next_chunk(IMPORT_CHUNK_SIZE)?;
        if raw_chunk.is_empty() {
            break;
        }
        counts.rows += raw_chunk.len();
        row_limit_reached(counts.rows)?;

        let mut chunk: Vec<FreshRow> = Vec::with_capacity(raw_chunk.len());
        for row in &raw_chunk {
            let email = row.email.trim().to_ascii_lowercase();
            if email.is_empty() || !apexmail_lib::validation::is_valid_email(&email) {
                counts.invalid += 1;
                push_note(
                    &mut invalid,
                    notes_limit,
                    row.row_number,
                    "invalid email address",
                );
                continue;
            }
            if !seen.insert(email.clone()) {
                counts.duplicates += 1;
                push_note(
                    &mut conflicts,
                    notes_limit,
                    row.row_number,
                    "duplicate email within the file, the first row is the one kept",
                );
                continue;
            }
            if row.timestamp_unparsed {
                unparsed_timestamps += 1;
            }
            let reason = derive_reason(provider, source_type, row);
            *by_reason.entry(reason.to_string()).or_default() += 1;
            chunk.push((row.row_number, email, reason, row.created_at));
        }
        if chunk.is_empty() {
            continue;
        }

        // Existing-row probe: the bulk_suppress conflict semantics. Rows
        // already present (any source) are duplicates, never overwritten.
        //
        // The probe is an equality JOIN against the unique `(tenant_id,
        // email)` index, NOT `LOWER(email) = ANY($2)`: a bound array
        // parameter gives the planner no element values, so `= ANY($param)`
        // cannot use a btree index and degrades to a sequential scan of the
        // tenant's rows per chunk (measured 52-90 ms per 500-row probe, i.e.
        // a 100k import could not finish inside the 30 s request timeout).
        // The join resolves each address through the index (measured ~1-2 ms
        // per chunk). Both sides compare the CANONICAL lowercase form the
        // unique index and the write itself use, so the probe is an exact
        // preview of the ON CONFLICT outcome.
        let emails: Vec<String> = chunk.iter().map(|(_, email, _, _)| email.clone()).collect();
        let existing: Vec<(String,)> = sqlx::query_as(
            "SELECT s.email FROM suppressions s
             JOIN UNNEST($2::text[]) AS e(email) ON s.email = e.email
             WHERE s.tenant_id = $1",
        )
        .bind(&auth.tenant_id)
        .bind(&emails)
        .fetch_all(&state.db)
        .await?;
        let existing: std::collections::HashSet<String> =
            existing.into_iter().map(|(email,)| email).collect();

        let mut fresh: Vec<FreshRow> = Vec::with_capacity(chunk.len());
        for candidate in chunk {
            if existing.contains(&candidate.1) {
                counts.duplicates += 1;
                push_note(
                    &mut conflicts,
                    notes_limit,
                    candidate.0,
                    "already suppressed, the existing row (and its source/reason) was kept",
                );
            } else {
                fresh.push(candidate);
            }
        }
        if fresh.is_empty() {
            continue;
        }

        if mode == ImportMode::Commit {
            let ids: Vec<String> = (0..fresh.len())
                .map(|_| apexmail_lib::id::generate_id("sup", 22))
                .collect();
            let emails: Vec<String> = fresh.iter().map(|(_, email, _, _)| email.clone()).collect();
            let reasons: Vec<String> = fresh
                .iter()
                .map(|(_, _, reason, _)| (*reason).to_string())
                .collect();
            let created: Vec<Option<DateTime<Utc>>> =
                fresh.iter().map(|(_, _, _, created)| *created).collect();

            let result = sqlx::query(
                r#"INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at)
                   SELECT id, $1, email, reason, $2, COALESCE(created_at, $3)
                   FROM UNNEST($4::text[], $5::text[], $6::text[], $7::timestamptz[])
                        AS t(id, email, reason, created_at)
                   ON CONFLICT (tenant_id, email) DO NOTHING"#,
            )
            .bind(&auth.tenant_id)
            .bind(&source)
            .bind(now)
            .bind(&ids)
            .bind(&emails)
            .bind(&reasons)
            .bind(&created)
            .execute(&state.db)
            .await;

            match result {
                Ok(result) => {
                    let inserted = result.rows_affected() as usize;
                    counts.imported += inserted;
                    if inserted < fresh.len() {
                        // Only reachable when a concurrent request inserted
                        // the same address between the probe and the write.
                        let raced = fresh.len() - inserted;
                        counts.duplicates += raced;
                        push_note(
                            &mut conflicts,
                            notes_limit,
                            fresh[0].0,
                            format!("{raced} row(s) were suppressed concurrently, kept"),
                        );
                    }
                }
                Err(error) => {
                    // Never report a failed chunk as created rows (the same
                    // contract bulk_suppress honours): log the detail, count
                    // the rows failed, keep going. One note per chunk keeps a
                    // database outage from turning the report into a row dump.
                    tracing::error!(
                        tenant_id = %auth.tenant_id,
                        rows = fresh.len(),
                        error = %error,
                        "provider suppression import chunk failed"
                    );
                    counts.failed += fresh.len();
                    push_note(
                        &mut failed,
                        notes_limit,
                        fresh[0].0,
                        format!(
                            "{} row(s) starting at this row failed to import (database error; \
                             the chunk was rolled back by the failed statement)",
                            fresh.len()
                        ),
                    );
                }
            }
        } else {
            // Dry run: report what a commit would write, write nothing.
            counts.imported += fresh.len();
        }
    }

    report.counts = counts;
    report.conflicts = conflicts;
    report.invalid = invalid;
    report.failed = failed;
    report.suppressions = Some(SuppressionReportSection {
        source_type: source_type.token().to_string(),
        by_reason: by_reason
            .into_iter()
            .map(|(reason, count)| ReasonCount { reason, count })
            .collect(),
        unparsed_timestamps,
    });
    if let Some(envelope) = cursor.envelope_key() {
        report.warnings.push(format!(
            "suppression records were read from the JSON key `{envelope}`"
        ));
    }
    if unparsed_timestamps > 0 {
        report.warnings.push(format!(
            "{unparsed_timestamps} row(s) carried an unparseable provider timestamp and were \
             imported with the import time instead (the raw value is not guessed)"
        ));
    }
    if source_type == SuppressionType::Bounces
        && matches!(provider, ImportProvider::SendGrid | ImportProvider::Mailgun)
    {
        report.warnings.push(
            "bounce permanence is classified from the export's status/reason text: transient \
             codes (4xx / soft) import as `temporary`, everything else as `hard_bounce`"
                .to_string(),
        );
    }
    Ok(report)
}
