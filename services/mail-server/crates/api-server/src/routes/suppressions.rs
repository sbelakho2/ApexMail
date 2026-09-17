//! Suppression list management routes.

use super::helpers::{clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_suppression).get(list_suppressions))
        .route("/:id", delete(delete_suppression))
        .route("/check/:email", get(check_suppression))
        .route("/bulk", post(bulk_suppress))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSuppressionRequest {
    pub email: String,
    pub reason: String,
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_source() -> String {
    "manual".into()
}

fn next_suppression_id() -> String {
    apexmail_lib::id::generate_id("sup", 22)
}

fn canonical_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

#[derive(Debug, Serialize)]
pub struct SuppressionResponse {
    pub id: String,
    pub email: String,
    pub reason: String,
    pub source: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListSuppressionsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckResponse {
    pub email: String,
    pub suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkSuppressRequest {
    pub entries: Vec<BulkEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkEntry {
    pub email: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct BulkSuppressResponse {
    pub created: usize,
    pub duplicates: usize,
    pub invalid: usize,
}

const MAX_BULK_ENTRIES: usize = 10_000;

/// Rows per chunked multi-row INSERT in [`bulk_suppress`] — one round-trip
/// per 500 rows (5 bind parameters each) instead of one per row.
const SUPPRESSION_BULK_CHUNK_SIZE: usize = 500;

/// Maximum length of the caller-supplied `reason` and `source` fields —
/// suppressions.reason is VARCHAR(50) and source VARCHAR(100) on the
/// canonical schema (runtime CREATE_SUPPRESSIONS), so over-long values
/// used to fail inside the INSERT with a database error instead of a 400.
const MAX_REASON_LEN: usize = 50;
const MAX_SOURCE_LEN: usize = 100;

/// Validate the caller-supplied `reason`/`source` lengths against the
/// VARCHAR columns they are stored in.
fn validate_reason_source(reason: &str, source: &str) -> Result<(), ApiError> {
    if reason.is_empty() || reason.len() > MAX_REASON_LEN {
        return Err(ApiError::Validation(vec![format!(
            "reason is required and must be {MAX_REASON_LEN} characters or fewer"
        )]));
    }
    if source.len() > MAX_SOURCE_LEN {
        return Err(ApiError::Validation(vec![format!(
            "source must be {MAX_SOURCE_LEN} characters or fewer"
        )]));
    }
    Ok(())
}

struct PreparedBulkEntry<'a> {
    email: String,
    reason: &'a str,
}

fn prepare_bulk_entries<'a>(
    entries: &'a [BulkEntry],
) -> (Vec<PreparedBulkEntry<'a>>, usize, usize) {
    let mut invalid = 0usize;
    let mut duplicates = 0usize;
    let mut seen = std::collections::HashSet::new();
    let mut prepared = Vec::with_capacity(entries.len());

    for entry in entries {
        let email = canonical_email(&entry.email);
        if !apexmail_lib::validation::is_valid_email(&email) {
            invalid += 1;
            continue;
        }
        // Over-long reasons would fail inside the chunked INSERT (the column
        // is VARCHAR(50)) — reject them up front as invalid entries.
        if entry.reason.is_empty() || entry.reason.len() > MAX_REASON_LEN {
            invalid += 1;
            continue;
        }
        if !seen.insert(email.clone()) {
            duplicates += 1;
            continue;
        }
        prepared.push(PreparedBulkEntry {
            email,
            reason: entry.reason.as_str(),
        });
    }

    (prepared, duplicates, invalid)
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_suppression(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateSuppressionRequest>,
) -> Result<(StatusCode, Json<SuppressionResponse>), ApiError> {
    require_scopes(&auth, &["suppressions:write"])?;

    let email = canonical_email(&body.email);

    if !apexmail_lib::validation::is_valid_email(&body.email) {
        return Err(ApiError::Validation(vec!["invalid email address".into()]));
    }
    validate_reason_source(&body.reason, &body.source)?;

    // Check duplicate
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND LOWER(email) = $2",
    )
    .bind(&auth.tenant_id)
    .bind(&email)
    .fetch_one(&state.db)
    .await?;

    if exists > 0 {
        return Err(ApiError::Conflict("email already suppressed".into()));
    }

    let id = next_suppression_id();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .bind(&email)
    .bind(&body.reason)
    .bind(&body.source)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(SuppressionResponse {
            id,
            email,
            reason: body.reason,
            source: body.source,
            created_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_suppressions(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListSuppressionsQuery>,
) -> Result<Json<Vec<SuppressionResponse>>, ApiError> {
    require_scopes(&auth, &["suppressions:read"])?;
    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);
    let rows = sqlx::query_as::<_, SuppressionRow>(
        "SELECT id, email, reason, source, created_at
         FROM suppressions WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&auth.tenant_id)
    .bind(clamp_limit(params.limit, 100))
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn delete_suppression(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["suppressions:write"])?;

    let result = sqlx::query("DELETE FROM suppressions WHERE id = $1 AND tenant_id = $2")
        .bind(&id)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("suppression not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn check_suppression(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(email): Path<String>,
) -> Result<Json<CheckResponse>, ApiError> {
    require_scopes(&auth, &["suppressions:read"])?;

    let email = canonical_email(&email);

    let row = sqlx::query_as::<_, SuppressionReasonRow>(
        "SELECT reason FROM suppressions WHERE tenant_id = $1 AND LOWER(email) = $2",
    )
    .bind(&auth.tenant_id)
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;

    Ok(Json(CheckResponse {
        email,
        suppressed: row.is_some(),
        reason: row.map(|r| r.reason),
    }))
}

async fn bulk_suppress(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<BulkSuppressRequest>,
) -> Result<Json<BulkSuppressResponse>, ApiError> {
    require_scopes(&auth, &["suppressions:write"])?;

    if body.entries.len() > MAX_BULK_ENTRIES {
        return Err(ApiError::BadRequest(format!(
            "bulk suppress limited to {} entries, got {}",
            MAX_BULK_ENTRIES,
            body.entries.len()
        )));
    }

    let mut created = 0usize;
    let (valid_entries, mut duplicates, invalid) = prepare_bulk_entries(&body.entries);

    // Batch query for existing emails to avoid N+1
    if !valid_entries.is_empty() {
        let emails: Vec<&str> = valid_entries.iter().map(|e| e.email.as_str()).collect();
        let existing: Vec<(String,)> = sqlx::query_as(
            "SELECT LOWER(email) FROM suppressions WHERE tenant_id = $1 AND LOWER(email) = ANY($2)",
        )
        .bind(&auth.tenant_id)
        .bind(&emails)
        .fetch_all(&state.db)
        .await?;

        let existing_set: std::collections::HashSet<&str> =
            existing.iter().map(|(e,)| e.as_str()).collect();

        // Chunked multi-row insert (previously one INSERT per entry — up to
        // 10,000 sequential round-trips for a max-size bulk request). Rows
        // already present are filtered first, so each chunk is a plain
        // multi-row INSERT with ON CONFLICT DO NOTHING as the race safety
        // net; a chunk hit by a concurrent insert simply counts those rows
        // as duplicates.
        let to_insert: Vec<&PreparedBulkEntry> = valid_entries
            .iter()
            .filter(|entry| !existing_set.contains(entry.email.as_str()))
            .collect();

        // Entries that already exist are duplicates too: the response
        // previously counted only in-file duplicates and chunk-insert races,
        // silently under-reporting the rows skipped because they were
        // already stored.
        duplicates += valid_entries.len() - to_insert.len();

        let now = Utc::now();
        for chunk in to_insert.chunks(SUPPRESSION_BULK_CHUNK_SIZE) {
            if chunk.is_empty() {
                continue;
            }

            let mut query = String::from(
                "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at) VALUES ",
            );
            let mut param_idx = 1u32;
            for (i, _) in chunk.iter().enumerate() {
                if i > 0 {
                    query.push_str(", ");
                }
                query.push_str(&format!(
                    "(${}, ${}, ${}, ${}, 'bulk', ${})",
                    param_idx,
                    param_idx + 1,
                    param_idx + 2,
                    param_idx + 3,
                    param_idx + 4,
                ));
                param_idx += 5;
            }
            query.push_str(" ON CONFLICT (tenant_id, email) DO NOTHING");

            let mut q = sqlx::query(&query);
            for entry in chunk {
                q = q
                    .bind(next_suppression_id())
                    .bind(&auth.tenant_id)
                    .bind(&entry.email)
                    .bind(entry.reason);
            }
            q = q.bind(now);

            match q.execute(&state.db).await {
                Ok(r) => {
                    created += r.rows_affected() as usize;
                    duplicates += chunk.len() - r.rows_affected() as usize;
                }
                Err(e) => {
                    tracing::error!(
                        tenant_id = %auth.tenant_id,
                        count = chunk.len(),
                        error = %e,
                        "bulk suppress chunk failed"
                    );
                }
            }
        }
    }

    Ok(Json(BulkSuppressResponse {
        created,
        duplicates,
        invalid,
    }))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct SuppressionRow {
    id: String,
    email: String,
    reason: String,
    source: String,
    created_at: DateTime<Utc>,
}

impl From<SuppressionRow> for SuppressionResponse {
    fn from(r: SuppressionRow) -> Self {
        Self {
            id: r.id,
            email: r.email,
            reason: r.reason,
            source: r.source,
            created_at: r.created_at.to_rfc3339(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct SuppressionReasonRow {
    reason: String,
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_response_suppressed() {
        let resp = CheckResponse {
            email: "bad@example.com".into(),
            suppressed: true,
            reason: Some("hard_bounce".into()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["suppressed"], true);
    }

    #[test]
    fn test_check_response_not_suppressed() {
        let resp = CheckResponse {
            email: "good@example.com".into(),
            suppressed: false,
            reason: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("reason").is_none()); // skip_serializing_if omits None
    }

    #[test]
    fn test_bulk_response_serialisation() {
        let resp = BulkSuppressResponse {
            created: 5,
            duplicates: 2,
            invalid: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["created"], 5);
    }

    #[test]
    fn test_canonical_email_trims_and_lowercases() {
        assert_eq!(
            canonical_email("  Jane.Doe+Tag@Example.COM  "),
            "jane.doe+tag@example.com"
        );
    }

    #[test]
    fn test_prepare_bulk_entries_counts_casefolded_duplicates() {
        let entries = vec![
            BulkEntry {
                email: "Alice@Example.com".into(),
                reason: "manual".into(),
            },
            BulkEntry {
                email: " alice@example.com ".into(),
                reason: "manual".into(),
            },
            BulkEntry {
                email: "not-an-email".into(),
                reason: "manual".into(),
            },
        ];

        let (prepared, duplicates, invalid) = prepare_bulk_entries(&entries);

        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].email, "alice@example.com");
        assert_eq!(duplicates, 1);
        assert_eq!(invalid, 1);
    }

    #[test]
    fn test_validate_reason_source_matches_column_widths() {
        assert!(validate_reason_source("hard_bounce", "manual").is_ok());
        assert!(validate_reason_source("hard_bounce", "").is_ok());

        // reason is VARCHAR(50): empty and over-long must 400, not fail
        // inside the INSERT.
        assert!(validate_reason_source("", "manual").is_err());
        assert!(validate_reason_source(&"r".repeat(51), "manual").is_err());
        assert!(validate_reason_source(&"r".repeat(50), "manual").is_ok());
        // source is VARCHAR(100).
        assert!(validate_reason_source("hard_bounce", &"s".repeat(101)).is_err());
        assert!(validate_reason_source("hard_bounce", &"s".repeat(100)).is_ok());
    }

    #[test]
    fn test_prepare_bulk_entries_rejects_overlong_reasons_as_invalid() {
        let entries = vec![BulkEntry {
            email: "ok@example.com".into(),
            reason: "r".repeat(51),
        }];

        let (prepared, _duplicates, invalid) = prepare_bulk_entries(&entries);

        assert!(prepared.is_empty());
        assert_eq!(invalid, 1);
    }
}

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    #[tokio::test]
    async fn suppression_lifecycle_create_check_list_delete() {
        let Some(pool) = crate::test_db::canonical_pool("supp_lifecycle").await else {
            return;
        };
        let (env, tenant) =
            AdvEnv::tenant(pool.clone(), &["suppressions:read", "suppressions:write"]).await;
        let (other_env, other_tenant) =
            AdvEnv::tenant(pool.clone(), &["suppressions:read", "suppressions:write"]).await;
        let _ = other_tenant;

        let email = format!(
            "victim-{}@example.com",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let (status, body) = env
            .post(
                "/v1/suppressions",
                &serde_json::json!({
                    "email": email.to_uppercase(),
                    "reason": "hard bounce",
                    "source": "api probe"
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(
            body["email"], email,
            "address is canonicalized to lowercase"
        );
        assert_eq!(body["reason"], "hard bounce");
        assert_eq!(body["source"], "api probe");
        let id = body["id"].as_str().expect("id").to_string();

        // Duplicate is a 409.
        let (status, body) = env
            .post(
                "/v1/suppressions",
                &serde_json::json!({ "email": email, "reason": "again" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // Check endpoint answers suppressed with the reason (case-insensitive).
        let (status, body) = env
            .get(&format!("/v1/suppressions/check/{}", email.to_uppercase()))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["suppressed"], true);
        assert_eq!(body["reason"], "hard bounce");

        // Another tenant sees the address as clean.
        let (status, body) = other_env
            .get(&format!("/v1/suppressions/check/{email}"))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["suppressed"], false);
        assert!(body["reason"].is_null());

        // List is tenant-scoped, newest first, paginated.
        let (status, body) = env.get("/v1/suppressions").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body.as_array().expect("array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], id);
        let other_email = format!(
            "other-{}@example.com",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        env.post(
            "/v1/suppressions",
            &serde_json::json!({ "email": other_email, "reason": "complaint" }).to_string(),
        )
        .await;
        let (status, body) = env.get("/v1/suppressions?limit=1").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().map(Vec::len), Some(1));
        let (status, body) = env
            .get("/v1/suppressions?limit=99&offset=-4&cursor=1")
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body.as_array().map(Vec::len),
            Some(1),
            "cursor wins over offset"
        );

        // Delete is tenant-bound; the neighbour's id is an opaque 404.
        let (status, body) = other_env.delete(&format!("/v1/suppressions/{id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        let (status, _body) = env.delete(&format!("/v1/suppressions/{id}")).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = env.get(&format!("/v1/suppressions/check/{email}")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["suppressed"], false,
            "deleted row no longer suppresses"
        );
        // Second delete is 404.
        let (status, _body) = env.delete(&format!("/v1/suppressions/{id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let _ = tenant;
    }

    #[tokio::test]
    async fn suppression_validation_refusals() {
        let Some(pool) = crate::test_db::canonical_pool("supp_refusals").await else {
            return;
        };
        let (env, _tenant) =
            AdvEnv::tenant(pool, &["suppressions:write", "suppressions:read"]).await;

        // Invalid emails.
        for email in ["", "no-at-sign", "@example.com", "a b@example.com"] {
            let (status, body) = env
                .post(
                    "/v1/suppressions",
                    &serde_json::json!({ "email": email, "reason": "probe" }).to_string(),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{email}: {body}");
        }

        // Reason/source length gates map to 400, never a VARCHAR overflow 500.
        let (status, body) = env
            .post(
                "/v1/suppressions",
                &serde_json::json!({ "email": "ok@example.com", "reason": "" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) = env
            .post(
                "/v1/suppressions",
                &serde_json::json!({ "email": "ok@example.com", "reason": "x".repeat(51) })
                    .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) = env
            .post(
                "/v1/suppressions",
                &serde_json::json!({ "email": "ok@example.com", "reason": "fine", "source": "s".repeat(101) }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // deny_unknown_fields.
        let (status, _body) = env
            .post(
                "/v1/suppressions",
                r#"{"email":"ok@example.com","reason":"fine","extra":1}"#,
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn bulk_suppress_counts_created_duplicates_and_invalid() {
        let Some(pool) = crate::test_db::canonical_pool("supp_bulk").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["suppressions:write"]).await;
        let unique = &uuid::Uuid::new_v4().simple().to_string()[..8];

        // Pre-existing row for the duplicate-in-database arm.
        let existing = format!("existing-{unique}@example.com");
        env.post(
            "/v1/suppressions",
            &serde_json::json!({ "email": existing, "reason": "already there" }).to_string(),
        )
        .await;

        let (status, body) = env
            .post(
                "/v1/suppressions/bulk",
                &serde_json::json!({
                    "entries": [
                        { "email": format!("a-{unique}@Example.COM "), "reason": "bounce" },
                        { "email": format!("A-{unique}@example.com"), "reason": "duplicate within file" },
                        { "email": "not-an-email", "reason": "invalid" },
                        { "email": format!("b-{unique}@example.com"), "reason": "" },
                        { "email": existing, "reason": "duplicate against db" }
                    ]
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["created"], 1, "one net-new row");
        assert_eq!(body["invalid"], 2, "bad email + empty reason");
        assert_eq!(body["duplicates"], 2, "in-file + in-database duplicates");

        // The created row landed with source='bulk' and the canonical email.
        let (stored_source,): (String,) =
            sqlx::query_as("SELECT source FROM suppressions WHERE tenant_id = $1 AND email = $2")
                .bind(&tenant)
                .bind(format!("a-{unique}@example.com"))
                .fetch_one(&pool)
                .await
                .expect("row");
        assert_eq!(stored_source, "bulk");

        // Re-running the identical bulk is all duplicates, nothing new.
        let (status, body) = env
            .post(
                "/v1/suppressions/bulk",
                &serde_json::json!({
                    "entries": [
                        { "email": format!("a-{unique}@example.com"), "reason": "bounce" },
                        { "email": existing, "reason": "again" }
                    ]
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["created"], 0);
        assert_eq!(body["duplicates"], 2);

        // Over the entry cap.
        let oversized: Vec<serde_json::Value> = (0..10_001)
            .map(|i| serde_json::json!({ "email": format!("x{i}@example.com"), "reason": "r" }))
            .collect();
        let (status, body) = env
            .post(
                "/v1/suppressions/bulk",
                &serde_json::json!({ "entries": oversized }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("10000")
                || body["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("10,000")
        );

        // deny_unknown_fields.
        let (status, _body) = env
            .post("/v1/suppressions/bulk", r#"{"entries":[],"nope":1}"#)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn suppressions_require_scopes() {
        let Some(pool) = crate::test_db::canonical_pool("supp_scopes").await else {
            return;
        };
        let (read_only, _t) = AdvEnv::tenant(pool.clone(), &["suppressions:read"]).await;
        let (status, body) = read_only
            .post(
                "/v1/suppressions",
                &serde_json::json!({ "email": "x@example.com", "reason": "r" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (write_only, _t2) = AdvEnv::tenant(pool, &["suppressions:write"]).await;
        let (status, body) = write_only.get("/v1/suppressions").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
}
