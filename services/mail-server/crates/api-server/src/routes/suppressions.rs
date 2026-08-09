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

    if !apexmail_lib::validation::is_valid_email(&email) {
        return Err(ApiError::Validation(vec!["invalid email address".into()]));
    }

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
        "SELECT id, email, type AS reason, source, created_at
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

        // Batch insert non-duplicates
        let now = Utc::now();
        for entry in &valid_entries {
            if existing_set.contains(entry.email.as_str()) {
                duplicates += 1;
                continue;
            }

            match sqlx::query(
                "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at)
                 VALUES ($1,$2,$3,$4,'bulk',$5)
                 ON CONFLICT (tenant_id, email) DO NOTHING",
            )
            .bind(next_suppression_id())
            .bind(&auth.tenant_id)
            .bind(&entry.email)
            .bind(entry.reason)
            .bind(now)
            .execute(&state.db)
            .await
            {
                Ok(r) if r.rows_affected() > 0 => created += 1,
                Ok(_) => duplicates += 1, // ON CONFLICT hit
                Err(e) => {
                    tracing::error!(email = %apexmail_lib::pii::redact_email(&entry.email), error = %e, "bulk suppress insert failed");
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
}
