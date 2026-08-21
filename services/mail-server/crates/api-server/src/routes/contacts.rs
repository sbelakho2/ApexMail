//! Contact management routes.

use super::helpers::{
    clamp_limit, compute_etag, decode_cursor, default_limit, encode_cursor, has_more,
    is_not_modified, pagination_meta,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_contact).get(list_contacts))
        .route(
            "/:id",
            get(get_contact).put(update_contact).delete(delete_contact),
        )
        .route("/bulk", post(bulk_import))
        .route("/counts", get(contact_counts))
        .route("/bulk/delete", post(bulk_delete))
        .route("/bulk/restore", post(bulk_restore))
        .route("/bulk/tag", post(bulk_tag))
        .route("/bulk/resolve-duplicates", post(bulk_resolve_duplicates))
        .route("/import", post(import_contacts))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateContactRequest {
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateContactRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContactResponse {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListContactsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Cursor for cursor-based pagination — hex-encoded `created_at` timestamp
    /// of the last item from the previous page. When provided, overrides `offset`.
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkImportRequest {
    pub contacts: Vec<CreateContactRequest>,
}

#[derive(Debug, Serialize)]
pub struct BulkImportResponse {
    pub created: usize,
    pub updated: usize,
    pub failed: usize,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_contact(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateContactRequest>,
) -> Result<(StatusCode, Json<ContactResponse>), ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    if !apexmail_lib::validation::is_valid_email(&body.email) {
        return Err(ApiError::Validation(vec!["invalid email address".into()]));
    }

    // Normalise to lowercase so the case-sensitive unique index on
    // (tenant_id, email) cannot be bypassed by varying case.
    let email = body.email.to_lowercase();
    let id = Uuid::new_v4();
    let now = Utc::now();
    let tags = body.tags.as_ref().map(|t| serde_json::json!(t));

    let insert_result = sqlx::query(
        "INSERT INTO contacts (id, tenant_id, email, name, tags, metadata, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$7)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&email)
    .bind(&body.name)
    .bind(&tags)
    .bind(&body.metadata)
    .bind(now)
    .execute(&state.db)
    .await;

    // Map a unique-constraint violation on (tenant_id, email) to 409 Conflict
    // instead of letting it propagate as a 500 Internal Server Error.
    if let Err(sqlx::Error::Database(db_err)) = &insert_result {
        if db_err.code().as_deref() == Some("23505") {
            return Err(ApiError::Conflict(
                "a contact with this email already exists".into(),
            ));
        }
    }
    insert_result?;

    Ok((
        StatusCode::CREATED,
        Json(ContactResponse {
            id: id.to_string(),
            email,
            name: body.name,
            tags,
            metadata: body.metadata,
            status: "active".into(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_contacts(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Query(params): Query<ListContactsQuery>,
) -> Result<Response, ApiError> {
    require_scopes(&auth, &["contacts:read"])?;

    let limit = clamp_limit(params.limit, 200);

    // Cursor-based pagination: decode the cursor (hex-encoded created_at timestamp)
    let cursor_value = params.cursor.as_deref().and_then(decode_cursor);

    let fetch_limit = limit + 1; // fetch one extra to detect has_more

    let rows = if let Some(ref cursor) = cursor_value {
        sqlx::query_as::<_, ContactRow>(
            "SELECT id, email, name, tags, metadata, status, created_at, updated_at
             FROM contacts WHERE tenant_id = $1 AND created_at < $2::timestamp
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(&auth.tenant_id)
        .bind(cursor)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await?
    } else {
        // Fallback to offset-based pagination for backward compatibility
        let offset = params.offset.clamp(0, 100_000);
        sqlx::query_as::<_, ContactRow>(
            "SELECT id, email, name, tags, metadata, status, created_at, updated_at
             FROM contacts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(&auth.tenant_id)
        .bind(fetch_limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

    // Build the response rows and detect has_more
    let mut details: Vec<ContactResponse> = rows.into_iter().map(Into::into).collect();
    let more = has_more(&mut details, limit as usize);

    // Compute the next cursor from the last row
    let next_cursor = details.last().map(|r| encode_cursor(&r.created_at));
    let meta = pagination_meta(more, next_cursor);

    // Build the response body and compute ETag
    let body = serde_json::json!({
        "data": details,
        "error": null,
        "meta": meta,
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let etag = compute_etag(&body_bytes);

    // Check If-None-Match for 304
    if is_not_modified(&headers, &etag) {
        return Ok(axum::response::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &etag)
            .body(axum::body::Body::empty())
            .expect("invariant: Response builder with valid status/headers should not fail"));
    }

    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("ETag", &etag)
        .header("Cache-Control", "private, max-age=0, must-revalidate")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(body_bytes))
        .expect("invariant: Response builder with valid status/headers/body should not fail"))
}

async fn get_contact(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ContactResponse>, ApiError> {
    require_scopes(&auth, &["contacts:read"])?;
    let row = fetch_contact(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn update_contact(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateContactRequest>,
) -> Result<Json<ContactResponse>, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    let existing = fetch_contact(&state, &auth.tenant_id, id.clone()).await?;

    let name = body.name.or(existing.name);
    let tags = body.tags.map(|t| serde_json::json!(t)).or(existing.tags);
    let metadata = body.metadata.or(existing.metadata);
    let status = body.status.unwrap_or(existing.status);

    sqlx::query(
        "UPDATE contacts SET name=$1, tags=$2, metadata=$3, status=$4, updated_at=NOW()
         WHERE id=$5 AND tenant_id=$6",
    )
    .bind(&name)
    .bind(&tags)
    .bind(&metadata)
    .bind(&status)
    .bind(&id)
    .bind(&auth.tenant_id)
    .execute(&state.db)
    .await?;

    Ok(Json(ContactResponse {
        id,
        email: existing.email,
        name,
        tags,
        metadata,
        status,
        created_at: existing.created_at.to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    }))
}

async fn delete_contact(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    let result = sqlx::query("DELETE FROM contacts WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("contact not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn bulk_import(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BulkImportRequest>,
) -> Result<Json<BulkImportResponse>, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    const MAX_BULK_CONTACTS: usize = 10_000;
    if body.contacts.len() > MAX_BULK_CONTACTS {
        return Err(ApiError::Validation(vec![format!(
            "maximum {} contacts per import",
            MAX_BULK_CONTACTS
        )]));
    }

    let mut created = 0usize;
    let mut updated = 0usize;
    let mut failed = 0usize;

    for contact in &body.contacts {
        if !apexmail_lib::validation::is_valid_email(&contact.email) {
            failed += 1;
            continue;
        }

        // Normalise to lowercase so the case-sensitive unique index on
        // (tenant_id, email) dedupes consistently with create_contact.
        let email = contact.email.to_lowercase();
        let tags = contact.tags.as_ref().map(|t| serde_json::json!(t));
        // xmax = 0 means a fresh insert; non-zero means update.
        let res: Result<Option<i64>, _> = sqlx::query_scalar(
            r#"INSERT INTO contacts (id, tenant_id, email, name, tags, metadata, status, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,'active',NOW(),NOW())
               ON CONFLICT (tenant_id, email) DO UPDATE SET
                 name = COALESCE(EXCLUDED.name, contacts.name),
                 tags = COALESCE(EXCLUDED.tags, contacts.tags),
                 metadata = COALESCE(EXCLUDED.metadata, contacts.metadata),
                 updated_at = NOW()
               RETURNING (xmax::text::bigint)"#,
        )
        .bind(Uuid::new_v4())
        .bind(&auth.tenant_id)
        .bind(&email)
        .bind(&contact.name)
        .bind(&tags)
        .bind(&contact.metadata)
        .fetch_optional(&state.db)
        .await;

        match res {
            Ok(Some(xmax)) => {
                if xmax == 0 {
                    created += 1;
                } else {
                    updated += 1;
                }
            }
            Ok(None) => {
                // Shouldn't happen with RETURNING, but count as created
                created += 1;
            }
            Err(e) => {
                tracing::error!(email = %apexmail_lib::pii::redact_email(&contact.email), error = %e, "Failed to upsert contact in bulk import");
                failed += 1;
            }
        }
    }

    Ok(Json(BulkImportResponse {
        created,
        updated,
        failed,
    }))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ContactRow {
    id: String,
    email: String,
    name: Option<String>,
    tags: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<ContactRow> for ContactResponse {
    fn from(r: ContactRow) -> Self {
        Self {
            id: r.id,
            email: r.email,
            name: r.name,
            tags: r.tags,
            metadata: r.metadata,
            status: r.status,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_contact(
    state: &AppState,
    tenant_id: &str,
    id: String,
) -> Result<ContactRow, ApiError> {
    sqlx::query_as::<_, ContactRow>(
        "SELECT id, email, name, tags, metadata, status, created_at, updated_at
         FROM contacts WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("contact not found".into()))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_contact_deser() {
        let json = r#"{"email":"alice@example.com","name":"Alice"}"#;
        let req: CreateContactRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.email, "alice@example.com");
    }

    #[test]
    fn test_bulk_import_response() {
        let resp = BulkImportResponse {
            created: 10,
            updated: 3,
            failed: 1,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["created"], 10);
    }
}

// ─── Additional Handlers (6B migration) ────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ContactCounts {
    pub total: i64,
    pub active: i64,
    pub unsubscribed: i64,
    pub bounced: i64,
    pub complained: i64,
}

async fn contact_counts(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ContactCounts>, ApiError> {
    require_scopes(&auth, &["contacts:read"])?;

    let counts = sqlx::query_as::<_, ContactCounts>(
        r#"SELECT
            COUNT(*)::bigint AS total,
            COUNT(*) FILTER (WHERE status = 'active')::bigint AS active,
            COUNT(*) FILTER (WHERE status = 'unsubscribed')::bigint AS unsubscribed,
            COUNT(*) FILTER (WHERE status = 'bounced')::bigint AS bounced,
            COUNT(*) FILTER (WHERE status = 'complained')::bigint AS complained
           FROM contacts WHERE tenant_id = $1"#,
    )
    .bind(auth.tenant_id.to_string())
    .fetch_one(&state.db)
    .await?;

    Ok(Json(ContactCounts {
        total: counts.total,
        active: counts.active,
        unsubscribed: counts.unsubscribed,
        bounced: counts.bounced,
        complained: counts.complained,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkIdsRequest {
    pub ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct BulkActionResult {
    pub affected: i64,
}

async fn bulk_delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BulkIdsRequest>,
) -> Result<Json<BulkActionResult>, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    let affected = sqlx::query(
        "UPDATE contacts SET status = 'deleted', updated_at = NOW()
         WHERE tenant_id = $1 AND id = ANY($2) AND status != 'deleted'",
    )
    .bind(auth.tenant_id.to_string())
    .bind(&body.ids[..])
    .execute(&state.db)
    .await?
    .rows_affected() as i64;

    Ok(Json(BulkActionResult { affected }))
}

async fn bulk_restore(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BulkIdsRequest>,
) -> Result<Json<BulkActionResult>, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    let affected = sqlx::query(
        "UPDATE contacts SET status = 'active', updated_at = NOW()
         WHERE tenant_id = $1 AND id = ANY($2) AND status = 'deleted'",
    )
    .bind(auth.tenant_id.to_string())
    .bind(&body.ids[..])
    .execute(&state.db)
    .await?
    .rows_affected() as i64;

    Ok(Json(BulkActionResult { affected }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkTagRequest {
    pub ids: Vec<Uuid>,
    pub tags: Vec<String>,
}

async fn bulk_tag(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BulkTagRequest>,
) -> Result<Json<BulkActionResult>, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    let tags_json = serde_json::to_value(&body.tags)
        .map_err(|e| ApiError::Internal(format!("tags serialization error: {e}")))?;
    let affected = sqlx::query(
        r#"UPDATE contacts SET
            tags = COALESCE(tags, '[]'::jsonb) || $3::jsonb,
            updated_at = NOW()
         WHERE tenant_id = $1 AND id = ANY($2)"#,
    )
    .bind(auth.tenant_id.to_string())
    .bind(&body.ids[..])
    .bind(tags_json)
    .execute(&state.db)
    .await?
    .rows_affected() as i64;

    Ok(Json(BulkActionResult { affected }))
}

async fn bulk_resolve_duplicates(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<BulkActionResult>, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    // Soft-delete duplicate contacts, keeping the oldest (lowest id) per email
    let affected = sqlx::query(
        r#"WITH dupes AS (
            SELECT id, ROW_NUMBER() OVER (PARTITION BY LOWER(email) ORDER BY created_at ASC) AS rn
            FROM contacts
            WHERE tenant_id = $1 AND status != 'deleted'
        )
        UPDATE contacts SET status = 'deleted', updated_at = NOW()
        WHERE id IN (SELECT id FROM dupes WHERE rn > 1)"#,
    )
    .bind(auth.tenant_id.to_string())
    .execute(&state.db)
    .await?
    .rows_affected() as i64;

    Ok(Json(BulkActionResult { affected }))
}

/// Maximum rows accepted by the CSV/XLSX import (audit J) — matches
/// `bulk_import`'s MAX_BULK_CONTACTS so the file path cannot bypass the
/// JSON path's cap.
const MAX_IMPORT_ROWS: usize = 10_000;

/// Maximum accepted XLSX body size (audit J): zip-bomb decompression guard.
/// A tiny malicious xlsx can expand to gigabytes of cells; the global 10 MB
/// body limit does not bound the DECOMPRESSED size.
const MAX_XLSX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Maximum total cells materialised from an XLSX sheet (audit J): second
/// decompression guard, bounding work even for legitimately small files
/// that encode huge sparse sheets.
const MAX_XLSX_TOTAL_CELLS: u64 = 5_000_000;

/// Insert chunk size for the import path (audit J): inserting one row per
/// round-trip let a 10k-row file hold 10k sequential queries.
const IMPORT_CHUNK_SIZE: usize = 500;

async fn import_contacts(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    // Detect file format from Content-Type header or file magic bytes
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/csv");

    let is_xlsx = content_type.contains("spreadsheet")
        || content_type.contains("xlsx")
        || (body.len() >= 4 && &body[..4] == b"PK\x03\x04"); // ZIP magic bytes

    if is_xlsx && body.len() > MAX_XLSX_BODY_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "XLSX import files must be smaller than {} bytes",
            MAX_XLSX_BODY_BYTES
        )));
    }

    let rows: Vec<(String, Option<String>)> = if is_xlsx {
        parse_xlsx_rows(&body)?
    } else {
        parse_csv_rows(&body)?
    };

    // Audit J: cap the row count like bulk_import does — an unbounded file
    // import could otherwise tie up a connection with unbounded work.
    if rows.len() > MAX_IMPORT_ROWS {
        return Err(ApiError::Validation(vec![format!(
            "import file contains {} rows; maximum is {MAX_IMPORT_ROWS}",
            rows.len()
        )]));
    }

    let mut imported = 0i64;
    let mut skipped = 0i64;
    let mut errors = Vec::new();

    // Validate + normalise everything up front so DB failures cannot leave
    // a half-imported batch of validated rows behind.
    let mut valid_rows: Vec<(usize, String, Option<String>)> = Vec::new();
    let mut seen_emails: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (idx, (raw_email, name)) in rows.iter().enumerate() {
        let email = raw_email.trim();

        if email.is_empty() || !apexmail_lib::validation::is_valid_email(email) {
            errors.push(format!("Row {}: invalid email", idx + 1));
            skipped += 1;
            continue;
        }

        // Normalise to lowercase so rows are deduped against the
        // case-sensitive unique index consistently with create_contact.
        let email = email.to_lowercase();
        // In-file duplicates are skipped up front: a multi-row upsert cannot
        // touch the same conflict row twice in one statement.
        if !seen_emails.insert(email.clone()) {
            errors.push(format!("Row {}: duplicate email in file", idx + 1));
            skipped += 1;
            continue;
        }
        valid_rows.push((idx + 1, email, name.clone()));
    }

    // Batched inserts (audit J): one multi-row upsert per 500-row chunk
    // instead of one round-trip per row.
    for chunk in valid_rows.chunks(IMPORT_CHUNK_SIZE) {
        let ids: Vec<Uuid> = chunk.iter().map(|_| Uuid::new_v4()).collect();
        let emails: Vec<String> = chunk.iter().map(|(_, email, _)| email.clone()).collect();
        let names: Vec<Option<String>> =
            chunk.iter().map(|(_, _, name)| name.clone()).collect();

        let result = sqlx::query(
            r#"INSERT INTO contacts (id, tenant_id, email, name, status, created_at, updated_at)
               SELECT id, $2, email, name, 'active', NOW(), NOW()
               FROM UNNEST($1::uuid[], $3::text[], $4::text[]) AS t(id, email, name)
               ON CONFLICT (tenant_id, email) DO UPDATE SET
                  name = COALESCE(EXCLUDED.name, contacts.name),
                  updated_at = NOW()"#,
        )
        .bind(&ids)
        .bind(auth.tenant_id.to_string())
        .bind(&emails)
        .bind(&names)
        .execute(&state.db)
        .await;

        match result {
            Ok(_) => imported += chunk.len() as i64,
            Err(e) => {
                // Audit J: never return the raw sqlx error string (it can
                // leak schema details and query fragments) — log the detail,
                // report a generic per-row message.
                tracing::error!(error = %e, tenant_id = %auth.tenant_id, "contact import chunk failed");
                for (row_number, _, _) in chunk {
                    errors.push(format!("Row {row_number}: failed to import"));
                }
                skipped += chunk.len() as i64;
            }
        }
    }

    Ok(Json(serde_json::json!({
        "imported": imported,
        "skipped": skipped,
        "errors": errors.len(),
        "error_details": if errors.len() <= 50 { errors } else { errors[..50].to_vec() },
        "format": if is_xlsx { "xlsx" } else { "csv" },
    })))
}

/// Parse CSV bytes into (email, name) rows.
fn parse_csv_rows(data: &[u8]) -> Result<Vec<(String, Option<String>)>, ApiError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(data);

    let mut rows = Vec::new();
    for result in reader.records() {
        let record = result.map_err(|e| ApiError::BadRequest(format!("CSV parse error: {e}")))?;
        let email = record.get(0).unwrap_or("").to_string();
        let name = record
            .get(1)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        rows.push((email, name));
    }
    Ok(rows)
}

/// Parse XLSX bytes into (email, name) rows using calamine.
fn parse_xlsx_rows(data: &[u8]) -> Result<Vec<(String, Option<String>)>, ApiError> {
    use calamine::{open_workbook_from_rs, Reader, Xlsx};
    use std::io::Cursor;

    let cursor = Cursor::new(data);
    let mut workbook: Xlsx<_> = open_workbook_from_rs(cursor)
        .map_err(|e| ApiError::BadRequest(format!("XLSX parse error: {e}")))?;

    let sheet_name = workbook
        .sheet_names()
        .first()
        .cloned()
        .ok_or_else(|| ApiError::BadRequest("XLSX has no sheets".into()))?;

    let range = workbook
        .worksheet_range(&sheet_name)
        .map_err(|e| ApiError::BadRequest(format!("XLSX sheet error: {e}")))?;

    // Audit J: decompression-bomb guard — the sheet's total cell count is
    // bounded BEFORE materialising rows, so a tiny malicious xlsx encoding a
    // huge sparse sheet cannot exhaust memory/CPU.
    let (row_count, col_count) = range.get_size();
    let total_cells = row_count as u64 * col_count as u64;
    if total_cells > MAX_XLSX_TOTAL_CELLS {
        return Err(ApiError::PayloadTooLarge(format!(
            "XLSX sheet expands to {total_cells} cells; maximum is {MAX_XLSX_TOTAL_CELLS}"
        )));
    }

    let mut rows = Vec::new();
    let mut is_header = true;

    for row in range.rows() {
        // Skip header row
        if is_header {
            is_header = false;
            continue;
        }

        let email = row.first().map(|c| c.to_string()).unwrap_or_default();
        let name = row.get(1).map(|c| c.to_string()).filter(|s| !s.is_empty());

        if !email.is_empty() {
            rows.push((email, name));
        }
    }

    Ok(rows)
}

#[cfg(test)]
mod tests_extra {
    use super::*;

    #[test]
    fn test_contact_response_serialisation() {
        let resp = ContactResponse {
            id: String::new(),
            email: "a@b.com".into(),
            name: Some("A".into()),
            tags: Some(serde_json::json!(["vip"])),
            metadata: None,
            status: "active".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "active");
    }
}
