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

// ─── Keyset cursor helpers ─────────────────────────────────────
//
// The list cursor encodes the `(created_at, id)` pair of the last row of the
// previous page. A timestamp alone skips or duplicates rows that share a
// `created_at` value; the tie-break `created_at = $ts AND id < $id` makes
// the ordering total.

/// Separator between the RFC3339 timestamp and the row id inside the
/// hex-encoded cursor payload (RFC3339 and contact ids never contain it).
const KEYSET_CURSOR_SEP: char = '\n';

/// Encode a `(created_at, id)` keyset cursor as an opaque hex string.
fn encode_keyset_cursor(created_at: &DateTime<Utc>, id: &str) -> String {
    encode_cursor(&format!("{created_at}{KEYSET_CURSOR_SEP}{id}"))
}

/// Decode and validate a `(created_at, id)` keyset cursor. Malformed
/// encodings, unparsable timestamps, or bogus ids are client errors (400) —
/// an unvalidated cursor used to reach the database and surface as a 500.
fn decode_keyset_cursor(encoded: &str) -> Result<(DateTime<Utc>, String), ApiError> {
    let Some(decoded) = decode_cursor(encoded) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed encoding".into(),
        ));
    };
    let Some((timestamp, id)) = decoded.split_once(KEYSET_CURSOR_SEP) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: must encode a created_at timestamp and row id".into(),
        ));
    };
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| {
            ApiError::BadRequest("invalid cursor: must be an encoded created_at timestamp".into())
        })?
        .with_timezone(&Utc);
    if id.is_empty() || id.len() > 64 || id.bytes().any(|b| b.is_ascii_control()) {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed row id".into(),
        ));
    }
    Ok((timestamp, id.to_string()))
}

// ─── Types ─────────────────────────────────────────────────────

/// Maximum number of tags stored on a contact. Matches the
/// `contacts_tags_shape_check` constraint added by migration 150.
const MAX_CONTACT_TAGS: usize = 50;

/// Maximum length of a single tag in characters. Matches the
/// `contacts_tags_shape_check` constraint added by migration 150.
const MAX_CONTACT_TAG_LEN: usize = 64;

/// Validate a tag list against the canonical `contacts.tags` shape
/// (migration 150): at most [`MAX_CONTACT_TAGS`] strings, each 1..
/// [`MAX_CONTACT_TAG_LEN`] characters. Shared by every write path
/// (create/update/bulk import/bulk tag) so an oversized payload is
/// rejected with 422 instead of tripping the database CHECK as a 500.
fn validate_tags(tags: &[String]) -> Result<(), ApiError> {
    if tags.len() > MAX_CONTACT_TAGS {
        return Err(ApiError::Validation(vec![format!(
            "a contact can have at most {MAX_CONTACT_TAGS} tags"
        )]));
    }
    for tag in tags {
        // chars(), not bytes: the database CHECK uses char_length, so a
        // multi-byte tag of 64 characters must be accepted.
        let len = tag.chars().count();
        if len == 0 || len > MAX_CONTACT_TAG_LEN {
            return Err(ApiError::Validation(vec![format!(
                "each tag must be between 1 and {MAX_CONTACT_TAG_LEN} characters"
            )]));
        }
    }
    Ok(())
}

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
    /// Tags in their ONE canonical representation (migration 150): a JSON
    /// array of bounded strings. Never null — reads coalesce a missing or
    /// unmigrated value to `[]`.
    pub tags: serde_json::Value,
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
    /// Cursor for cursor-based pagination — hex-encoded `created_at` + row id
    /// pair of the last item from the previous page. When provided, overrides
    /// `offset`.
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
    if let Some(tags) = &body.tags {
        validate_tags(tags)?;
    }
    // One representation: an absent tag list is stored as the empty array
    // (contacts.tags is NOT NULL DEFAULT '[]' since migration 150), never
    // as SQL NULL.
    let tags = serde_json::json!(body.tags.as_deref().unwrap_or_default());

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

    // Cursor-based pagination: decode and validate the hex-encoded
    // `created_at\nid` pair BEFORE binding — a bogus cursor used to reach
    // the `::timestamp` cast and surface as a database 500 instead of a
    // client 400.
    let cursor_value = match params.cursor.as_deref() {
        Some(encoded) => Some(decode_keyset_cursor(encoded)?),
        None => None,
    };

    let fetch_limit = limit + 1; // fetch one extra to detect has_more

    let rows = if let Some((ref cursor_ts, ref cursor_id)) = cursor_value {
        sqlx::query_as::<_, ContactRow>(
            "SELECT id, email, name, COALESCE(tags, '[]'::jsonb) AS tags, metadata, status, created_at, updated_at
             FROM contacts WHERE tenant_id = $1
               AND (created_at < $2::timestamp OR (created_at = $2::timestamp AND id < $3))
             ORDER BY created_at DESC, id DESC LIMIT $4",
        )
        .bind(&auth.tenant_id)
        .bind(cursor_ts)
        .bind(cursor_id)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await?
    } else {
        // Fallback to offset-based pagination for backward compatibility
        let offset = params.offset.clamp(0, 100_000);
        sqlx::query_as::<_, ContactRow>(
            "SELECT id, email, name, COALESCE(tags, '[]'::jsonb) AS tags, metadata, status, created_at, updated_at
             FROM contacts WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
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

    // Compute the next cursor from the last row's (created_at, id) pair.
    let next_cursor = details.last().and_then(|r| {
        chrono::DateTime::parse_from_rfc3339(&r.created_at)
            .ok()
            .map(|ts| encode_keyset_cursor(&ts.with_timezone(&Utc), &r.id))
    });
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
    // A provided tag list fully replaces the stored one (validated against
    // the canonical shape); an absent one keeps the existing array.
    let tags = match body.tags {
        Some(tags) => {
            validate_tags(&tags)?;
            serde_json::json!(tags)
        }
        None => existing.tags.clone(),
    };
    let metadata = body.metadata.or(existing.metadata);
    let status = body.status.unwrap_or(existing.status);

    // Status is stored verbatim — an unknown value would silently disappear
    // from every status-filtered view (counts, segments, sends).
    const VALID_CONTACT_STATUSES: &[&str] = &[
        "active",
        "subscribed",
        "unsubscribed",
        "bounced",
        "complained",
        "deleted",
    ];
    if !VALID_CONTACT_STATUSES.contains(&status.as_str()) {
        return Err(ApiError::Validation(vec![format!(
            "invalid status '{}'; expected one of: active, subscribed, unsubscribed, bounced, complained, deleted",
            status
        )]));
    }

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

/// Rows per chunked multi-row upsert in [`bulk_import`] — mirrors the CSV
/// import path's [`IMPORT_CHUNK_SIZE`] (one round-trip per 500 rows instead
/// of one per row, comfortably under the 65,535 bind-parameter limit).
const BULK_IMPORT_CHUNK_SIZE: usize = 500;

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

    // Validate, normalise, and dedupe up front so the database phase is a
    // clean all-or-nothing chunked upsert:
    // - invalid emails count as `failed` and never reach the database;
    // - emails are lowercased so the case-sensitive unique index on
    //   (tenant_id, email) dedupes consistently with create_contact;
    // - in-request duplicates collapse to their first occurrence (a
    //   multi-row upsert cannot touch the same conflict row twice in one
    //   statement) and count as `updated`, matching the per-row behaviour
    //   they used to produce.
    let mut failed = 0usize;
    let mut updated = 0usize;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut valid: Vec<&CreateContactRequest> = Vec::with_capacity(body.contacts.len());
    for contact in &body.contacts {
        if !apexmail_lib::validation::is_valid_email(&contact.email) {
            failed += 1;
            continue;
        }
        // Tag shape is structural: one malformed list rejects the batch
        // before any database work rather than failing mid-upsert.
        if let Some(tags) = &contact.tags {
            validate_tags(tags)?;
        }
        if !seen.insert(contact.email.to_lowercase()) {
            updated += 1;
            continue;
        }
        valid.push(contact);
    }

    // Chunked multi-row upsert inside ONE transaction (previously one query
    // per contact — 10,000 sequential round-trips for a max-size import).
    // `xmax = 0` means a fresh insert; non-zero means the conflict path
    // updated an existing row.
    let mut created = 0usize;
    if !valid.is_empty() {
        let mut tx = state.db.begin().await.map_err(|error| {
            tracing::error!(error = %error, tenant_id = %auth.tenant_id, "bulk import failed to begin transaction");
            ApiError::Internal("database error".into())
        })?;

        for chunk in valid.chunks(BULK_IMPORT_CHUNK_SIZE) {
            let mut query = String::from(
                "INSERT INTO contacts (id, tenant_id, email, name, tags, metadata, status, created_at, updated_at) VALUES ",
            );
            let mut param_idx = 1u32;
            for (i, _) in chunk.iter().enumerate() {
                if i > 0 {
                    query.push_str(", ");
                }
                query.push_str(&format!(
                    "(${}, ${}, ${}, ${}, ${}, ${}, 'active', NOW(), NOW())",
                    param_idx,
                    param_idx + 1,
                    param_idx + 2,
                    param_idx + 3,
                    param_idx + 4,
                    param_idx + 5,
                ));
                param_idx += 6;
            }
            query.push_str(
                " ON CONFLICT (tenant_id, email) DO UPDATE SET \
                   name = COALESCE(EXCLUDED.name, contacts.name), \
                   tags = COALESCE(EXCLUDED.tags, contacts.tags), \
                   metadata = COALESCE(EXCLUDED.metadata, contacts.metadata), \
                   updated_at = NOW() \
                 RETURNING (xmax::text::bigint)",
            );

            let mut q = sqlx::query_scalar::<_, i64>(&query);
            for contact in chunk {
                q = q
                    .bind(Uuid::new_v4())
                    .bind(&auth.tenant_id)
                    .bind(contact.email.to_lowercase())
                    .bind(&contact.name)
                    // Not NULL: an absent tag list inserts the canonical
                    // empty array (contacts.tags is NOT NULL, migration 150).
                    .bind(serde_json::json!(contact
                        .tags
                        .as_deref()
                        .unwrap_or_default()))
                    .bind(&contact.metadata);
            }

            let xmaxes = match q.fetch_all(&mut *tx).await {
                Ok(xmaxes) => xmaxes,
                Err(error) => {
                    let _ = tx.rollback().await;
                    tracing::error!(
                        error = %error,
                        tenant_id = %auth.tenant_id,
                        "bulk import chunk failed — transaction rolled back"
                    );
                    return Err(ApiError::Internal("database error".into()));
                }
            };
            for xmax in xmaxes {
                if xmax == 0 {
                    created += 1;
                } else {
                    updated += 1;
                }
            }
        }

        tx.commit().await.map_err(|error| {
            tracing::error!(error = %error, tenant_id = %auth.tenant_id, "bulk import commit failed");
            ApiError::Internal("database error".into())
        })?;
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
    /// Always a JSON array — every SELECT for this row type coalesces a
    /// missing/NULL tags value to '[]' (canonical shape, migration 150).
    tags: serde_json::Value,
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
        "SELECT id, email, name, COALESCE(tags, '[]'::jsonb) AS tags, metadata, status, created_at, updated_at
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
    /// `"add"` (default) unions the tags into each contact's set —
    /// duplicates collapse; `"remove"` subtracts them instead.
    #[serde(default)]
    pub action: Option<String>,
}

/// Bulk tag add: set-union semantics. `tags || $3::jsonb` concatenates the
/// arrays and the aggregation deduplicates and sorts the result, so adding
/// a tag a contact already has is a no-op instead of a duplicate entry.
/// A tenant predicate keeps the update inside the caller's tenant.
const BULK_TAG_ADD_SQL: &str = r#"
    UPDATE contacts SET
        tags = COALESCE((
            SELECT jsonb_agg(DISTINCT tag ORDER BY tag)
            FROM jsonb_array_elements(tags || $3::jsonb) AS tag
        ), '[]'::jsonb),
        updated_at = NOW()
    WHERE tenant_id = $1 AND id = ANY($2)"#;

/// Bulk tag remove: set-difference semantics. Keeps exactly the existing
/// tags that are not members of the removal list.
const BULK_TAG_REMOVE_SQL: &str = r#"
    UPDATE contacts SET
        tags = COALESCE((
            SELECT jsonb_agg(tag ORDER BY tag)
            FROM jsonb_array_elements(tags) AS tag
            WHERE NOT ($3::jsonb) ? (tag #>> '{}')
        ), '[]'::jsonb),
        updated_at = NOW()
    WHERE tenant_id = $1 AND id = ANY($2)"#;

/// Name of the shape constraint added by migration 150 — used to map a
/// check violation (SQLSTATE 23514) to a 422 instead of a 500.
const CONTACTS_TAGS_SHAPE_CHECK: &str = "contacts_tags_shape_check";

async fn bulk_tag(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BulkTagRequest>,
) -> Result<Json<BulkActionResult>, ApiError> {
    require_scopes(&auth, &["contacts:write"])?;

    let remove = match body.action.as_deref().unwrap_or("add") {
        "add" => false,
        "remove" => true,
        other => {
            return Err(ApiError::Validation(vec![format!(
                "invalid action '{other}'; expected 'add' or 'remove'"
            )]));
        }
    };
    // Same bounds the column enforces (migration 150): validated here so a
    // bad payload is a 422, not a database CHECK violation surfaced as 500.
    validate_tags(&body.tags)?;

    let tags_json = serde_json::to_value(&body.tags)
        .map_err(|e| ApiError::Internal(format!("tags serialization error: {e}")))?;
    let sql = if remove {
        BULK_TAG_REMOVE_SQL
    } else {
        BULK_TAG_ADD_SQL
    };

    let result = sqlx::query(sql)
        .bind(auth.tenant_id.to_string())
        .bind(&body.ids[..])
        .bind(&tags_json)
        .execute(&state.db)
        .await;

    let affected = match result {
        Ok(result) => result.rows_affected() as i64,
        // Adding tags to an already-full contact trips the shape CHECK.
        // Surface that as a client error instead of an internal one.
        Err(sqlx::Error::Database(db_err))
            if db_err.constraint() == Some(CONTACTS_TAGS_SHAPE_CHECK) =>
        {
            return Err(ApiError::Validation(vec![format!(
                "tagging would exceed the per-contact limit of {MAX_CONTACT_TAGS} tags"
            )]));
        }
        Err(e) => return Err(e.into()),
    };

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
        let names: Vec<Option<String>> = chunk.iter().map(|(_, _, name)| name.clone()).collect();

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
            tags: serde_json::json!(["vip"]),
            metadata: None,
            status: "active".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "active");
        // Canonical representation: an array, never null.
        assert_eq!(json["tags"], serde_json::json!(["vip"]));
    }

    #[test]
    fn test_validate_tags_bounds() {
        assert!(validate_tags(&[]).is_ok());
        assert!(validate_tags(&["vip".into(), "beta".into()]).is_ok());

        // More than MAX_CONTACT_TAGS entries.
        let too_many: Vec<String> = (0..=MAX_CONTACT_TAGS).map(|i| i.to_string()).collect();
        assert!(validate_tags(&too_many).is_err());

        // Empty and over-long individual tags.
        assert!(validate_tags(&["".into()]).is_err());
        let over_long = "x".repeat(MAX_CONTACT_TAG_LEN + 1);
        assert!(validate_tags(&[over_long]).is_err());

        // char_length semantics: 64 multi-byte characters are in bounds.
        let multi_byte = "ä".repeat(MAX_CONTACT_TAG_LEN);
        assert_eq!(multi_byte.len(), MAX_CONTACT_TAG_LEN * 2); // bytes > 64
        assert!(validate_tags(&[multi_byte]).is_ok());
    }

    #[test]
    fn test_bulk_tag_action_parsing() {
        let req: BulkTagRequest = serde_json::from_str(
            r#"{"ids":["00000000-0000-0000-0000-000000000001"],"tags":["vip"]}"#,
        )
        .unwrap();
        assert_eq!(req.action.as_deref(), None); // defaults to "add"

        let req: BulkTagRequest = serde_json::from_str(
            r#"{"ids":["00000000-0000-0000-0000-000000000001"],"tags":["vip"],"action":"remove"}"#,
        )
        .unwrap();
        assert_eq!(req.action.as_deref(), Some("remove"));
    }
}

// ─── F07 database tests ────────────────────────────────────────
//
// Exercise migration 150 (as shipped) and the bulk-tag SQL constants
// against a real PostgreSQL, following the audit_log.rs isolated-per-test
// database convention. Skipped unless TEST_DATABASE_URL is set.

#[cfg(test)]
mod tags_db_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;

    /// Migration 150 verbatim — these tests validate the real file, not a
    /// restatement of it.
    const MIGRATION_150: &str =
        include_str!("../../../../migrations/150_contacts_tags_canonical.sql");

    /// Dedicated per-test database (audit_log.rs pattern): skips unless
    /// TEST_DATABASE_URL is set (workspace convention).
    async fn isolated_pool(db_suffix: &str) -> Option<sqlx::PgPool> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api_contacts_f07_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;
        Some(pool)
    }

    async fn fetch_tags(pool: &sqlx::PgPool, tenant_id: &str, id: Uuid) -> serde_json::Value {
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT COALESCE(tags, '[]'::jsonb) FROM contacts WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("contact row must exist")
    }

    async fn run_bulk_tag(
        pool: &sqlx::PgPool,
        sql: &str,
        tenant_id: &str,
        ids: &[Uuid],
        tags: &[String],
    ) -> Result<u64, sqlx::Error> {
        let tags_json = serde_json::to_value(tags).expect("tags serialize");
        sqlx::query(sql)
            .bind(tenant_id.to_string())
            .bind(ids)
            .bind(tags_json)
            .execute(pool)
            .await
            .map(|r| r.rows_affected())
    }

    /// The 068 shape has NO tags column at all — the shape that made every
    /// `UPDATE contacts SET tags` fail with "column does not exist".
    /// Migration 150 must add the canonical column and enforce its bounds.
    #[tokio::test]
    async fn migration_150_establishes_tags_on_a_tags_less_shape() {
        let Some(pool) = isolated_pool("shape").await else {
            eprintln!("skipping migration_150_establishes_tags_on_a_tags_less_shape: TEST_DATABASE_URL not set");
            return;
        };

        sqlx::raw_sql(
            "CREATE TABLE contacts (
                id         UUID PRIMARY KEY,
                tenant_id  VARCHAR(26) NOT NULL,
                email      VARCHAR(320) NOT NULL,
                name       VARCHAR(512),
                status     VARCHAR(20) NOT NULL DEFAULT 'subscribed',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&pool)
        .await
        .expect("068-shape contacts table");

        // raw_sql: the migration file is a multi-statement script (the
        // prepared-statement protocol cannot carry it).
        sqlx::raw_sql(MIGRATION_150)
            .execute(&pool)
            .await
            .expect("migration 150 applies to the tags-less shape");

        let tenant = "test-f07-shape-tenant";
        let id = Uuid::new_v4();
        // Insert without tags -> canonical default '[]'.
        sqlx::query("INSERT INTO contacts (id, tenant_id, email) VALUES ($1, $2, 'a@x.ee')")
            .bind(id)
            .bind(tenant)
            .execute(&pool)
            .await
            .expect("insert without tags uses the '[]' default");
        assert_eq!(fetch_tags(&pool, tenant, id).await, serde_json::json!([]));

        // Explicit NULL is rejected (NOT NULL).
        let null_insert = sqlx::query(
            "INSERT INTO contacts (id, tenant_id, email, tags) VALUES ($1, $2, 'b@x.ee', NULL)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .execute(&pool)
        .await;
        assert!(null_insert.is_err(), "tags must be NOT NULL");

        // Non-array values are rejected by the CHECK.
        let bad_shapes = [
            serde_json::json!({"vip": true}),
            serde_json::json!("vip"),
            serde_json::json!(null),
        ];
        for bad in bad_shapes {
            let result = sqlx::query(
                "INSERT INTO contacts (id, tenant_id, email, tags) VALUES ($1, $2, 'c@x.ee', $3)",
            )
            .bind(Uuid::new_v4())
            .bind(tenant)
            .bind(bad)
            .execute(&pool)
            .await;
            assert!(result.is_err(), "non-array tags must violate the CHECK");
        }

        // >50 tags is rejected.
        let fifty_one: Vec<String> = (0..=50).map(|i| format!("t{i}")).collect();
        let result = sqlx::query(
            "INSERT INTO contacts (id, tenant_id, email, tags) VALUES ($1, $2, 'd@x.ee', $3)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(serde_json::json!(fifty_one))
        .execute(&pool)
        .await;
        assert!(result.is_err(), "more than 50 tags must violate the CHECK");

        // A 65-character tag is rejected; a 64-character one is accepted.
        for (len, expect_ok) in [(65usize, false), (64, true)] {
            let tag = "x".repeat(len);
            let result = sqlx::query(
                "INSERT INTO contacts (id, tenant_id, email, tags) VALUES ($1, $2, 'e@x.ee', $3)",
            )
            .bind(Uuid::new_v4())
            .bind(tenant)
            .bind(serde_json::json!([tag]))
            .execute(&pool)
            .await;
            assert_eq!(result.is_ok(), expect_ok, "tag of {len} chars");
        }

        // A JSON null element is rejected too.
        let result = sqlx::query(
            "INSERT INTO contacts (id, tenant_id, email, tags) VALUES ($1, $2, 'f@x.ee', $3)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(serde_json::json!([null, "vip"]))
        .execute(&pool)
        .await;
        assert!(result.is_err(), "null tag elements must violate the CHECK");

        pool.close().await;
    }

    /// Bulk tag add/remove against the canonical apexmail-db SCHEMA shape
    /// (nullable tags) with migration 150 applied on top: union dedupe,
    /// removal, round-trip through the coalescing read, tenant isolation,
    /// and the 50-tag ceiling.
    #[tokio::test]
    async fn bulk_tag_add_remove_round_trip_and_tenant_isolation() {
        let Some(pool) = isolated_pool("roundtrip").await else {
            eprintln!("skipping bulk_tag_add_remove_round_trip_and_tenant_isolation: TEST_DATABASE_URL not set");
            return;
        };

        // The 075/SCHEMA shape: contacts.tags exists but is nullable with
        // no shape constraint — migration 150 must normalise it. (The full
        // apexmail-db SCHEMA cannot be applied to a fresh database — its
        // campaigns/templates FK is uuid-to-varchar — so the subset is
        // spelled out here.)
        sqlx::raw_sql(
            "CREATE TABLE contacts (
                id         UUID PRIMARY KEY,
                tenant_id  VARCHAR(26) NOT NULL,
                email      TEXT NOT NULL,
                name       TEXT,
                tags       JSONB,
                metadata   JSONB,
                status     TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );",
        )
        .execute(&pool)
        .await
        .expect("075-shape contacts table");
        sqlx::raw_sql(MIGRATION_150)
            .execute(&pool)
            .await
            .expect("migration 150 applies on the SCHEMA shape");

        let tenant_a = "test-f07-round-a";
        let tenant_b = "test-f07-round-b";

        let contact_a = Uuid::new_v4();
        let contact_b = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, email, tags) VALUES ($1, $2, 'a@x.ee', $3)",
        )
        .bind(contact_a)
        .bind(tenant_a)
        .bind(serde_json::json!(["beta", "vip"]))
        .execute(&pool)
        .await
        .expect("contact A");
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, email, tags) VALUES ($1, $2, 'b@x.ee', $3)",
        )
        .bind(contact_b)
        .bind(tenant_b)
        .bind(serde_json::json!(["vip"]))
        .execute(&pool)
        .await
        .expect("contact B");

        // Add with an overlap: union dedupes and sorts.
        let affected = run_bulk_tag(
            &pool,
            BULK_TAG_ADD_SQL,
            tenant_a,
            &[contact_a],
            &["vip".into(), "new".into()],
        )
        .await
        .expect("bulk tag add");
        assert_eq!(affected, 1);
        assert_eq!(
            fetch_tags(&pool, tenant_a, contact_a).await,
            serde_json::json!(["beta", "new", "vip"])
        );

        // Re-adding the same tag is an idempotent no-op.
        run_bulk_tag(
            &pool,
            BULK_TAG_ADD_SQL,
            tenant_a,
            &[contact_a],
            &["vip".into()],
        )
        .await
        .expect("idempotent re-add");
        assert_eq!(
            fetch_tags(&pool, tenant_a, contact_a).await,
            serde_json::json!(["beta", "new", "vip"])
        );

        // Remove: absent tags in the removal list are harmless.
        let affected = run_bulk_tag(
            &pool,
            BULK_TAG_REMOVE_SQL,
            tenant_a,
            &[contact_a],
            &["vip".into(), "missing".into()],
        )
        .await
        .expect("bulk tag remove");
        assert_eq!(affected, 1);
        assert_eq!(
            fetch_tags(&pool, tenant_a, contact_a).await,
            serde_json::json!(["beta", "new"])
        );

        // Tenant isolation: tenant A cannot tag tenant B's contact.
        let affected = run_bulk_tag(
            &pool,
            BULK_TAG_ADD_SQL,
            tenant_a,
            &[contact_b],
            &["x".into()],
        )
        .await
        .expect("cross-tenant add is a query, not an error");
        assert_eq!(affected, 0, "cross-tenant bulk tag must affect nothing");
        assert_eq!(
            fetch_tags(&pool, tenant_b, contact_b).await,
            serde_json::json!(["vip"]),
            "tenant B's tags must be untouched"
        );

        // The union overflow trips the migration-150 CHECK instead of
        // silently truncating: 2 existing + 49 new = 51 > 50.
        let overflow: Vec<String> = (0..49).map(|i| format!("x{i}")).collect();
        let err = run_bulk_tag(&pool, BULK_TAG_ADD_SQL, tenant_a, &[contact_a], &overflow)
            .await
            .expect_err("union beyond 50 tags must violate the CHECK");
        match &err {
            sqlx::Error::Database(db_err) => {
                assert_eq!(db_err.code().as_deref(), Some("23514"));
                assert_eq!(db_err.constraint(), Some(CONTACTS_TAGS_SHAPE_CHECK));
            }
            other => panic!("expected a database check violation, got {other:?}"),
        }
        // The failed update left the contact's tags unchanged.
        assert_eq!(
            fetch_tags(&pool, tenant_a, contact_a).await,
            serde_json::json!(["beta", "new"])
        );

        pool.close().await;
    }
}
