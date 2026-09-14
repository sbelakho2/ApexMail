//! Campaign management routes.

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
        .route("/", post(create_campaign).get(list_campaigns))
        .route("/:id", get(get_campaign).delete(delete_campaign))
        .route("/:id/resume", post(resume_campaign))
        .route("/:id/pause", post(pause_campaign))
        .route("/:id/resend", post(resend_campaign))
}

// ─── Keyset cursor helpers ─────────────────────────────────────
//
// The list cursor encodes the `(created_at, id)` pair of the last row of the
// previous page. A timestamp alone skips or duplicates rows that share a
// `created_at` value; the tie-break `created_at = $ts AND id < $id` makes
// the ordering total.

/// Separator between the RFC3339 timestamp and the row id inside the
/// hex-encoded cursor payload (RFC3339 and UUID ids never contain it).
const KEYSET_CURSOR_SEP: char = '\n';

/// Encode a `(created_at, id)` keyset cursor as an opaque hex string.
fn encode_keyset_cursor(created_at: &DateTime<Utc>, id: &str) -> String {
    // RFC3339, not Display: decode parses with `parse_from_rfc3339`, so a
    // cursor rendered with Display("… UTC") could never be replayed (every
    // next-page request 400'd).
    encode_cursor(&format!(
        "{}{KEYSET_CURSOR_SEP}{id}",
        created_at.to_rfc3339()
    ))
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

/// Reject malformed campaign ids as 404 before any `::uuid` cast reaches the
/// database (an unvalidated cast used to surface as a 500).
fn parse_campaign_id(id: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id).map_err(|_| ApiError::NotFound("campaign not found".into()))
}

/// Duplicate campaign names are an honest 409 (unique
/// `idx_campaigns_tenant_name`), never a generic database 500.
fn map_campaign_write_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(ref db_error) = error {
        if db_error.code().as_deref() == Some("23505") {
            return ApiError::Conflict("a campaign with this name already exists".into());
        }
    }
    ApiError::from(error)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub subject: String,
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub scheduled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct CampaignResponse {
    pub id: String,
    pub name: String,
    pub subject: String,
    pub template_id: Option<String>,
    pub status: String,
    pub scheduled_at: Option<String>,
    pub sent_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListCampaignsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Cursor for cursor-based pagination — hex-encoded `created_at` + row id
    /// pair of the last item from the previous page. When provided, overrides
    /// `offset`.
    #[serde(default)]
    pub cursor: Option<String>,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn create_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateCampaignRequest>,
) -> Result<(StatusCode, Json<CampaignResponse>), ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

    if body.name.is_empty() || body.name.len() > 200 {
        return Err(ApiError::Validation(vec![
            "name is required and must be 200 characters or fewer".into(),
        ]));
    }
    if body.subject.is_empty() || body.subject.len() > 500 {
        return Err(ApiError::Validation(vec![
            "subject is required and must be 500 characters or fewer".into(),
        ]));
    }

    let id = Uuid::new_v4();
    let now = Utc::now();
    let status = if body.scheduled_at.is_some() {
        "scheduled"
    } else {
        "draft"
    };
    let template_id = body.template_id.clone();

    // Verify the referenced template exists and belongs to this tenant before
    // creating the campaign (prevents cross-tenant template_id references).
    if let Some(ref tid) = template_id {
        let exists: Option<bool> = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM templates WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(tid)
        .bind(&auth.tenant_id)
        .fetch_one(&state.db)
        .await?;
        if !exists.unwrap_or(false) {
            return Err(ApiError::NotFound("template not found".into()));
        }
    }

    sqlx::query(
        "INSERT INTO campaigns (id, tenant_id, name, subject, template_id, status, scheduled_at, sent_count, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5::uuid,$6,$7,0,$8,$8)",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.subject)
    .bind(&template_id)
    .bind(status)
    .bind(body.scheduled_at)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(map_campaign_write_error)?;

    Ok((
        StatusCode::CREATED,
        Json(CampaignResponse {
            id: id.to_string(),
            name: body.name,
            subject: body.subject,
            template_id,
            status: status.into(),
            scheduled_at: body.scheduled_at.map(|t| t.to_rfc3339()),
            sent_count: 0,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }),
    ))
}

async fn list_campaigns(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Query(params): Query<ListCampaignsQuery>,
) -> Result<Response, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;

    let limit = clamp_limit(params.limit, 100);

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
        // campaigns.id is UUID — the VALUE is cast once, never the column,
        // so the primary-key index remains usable for the tie-break.
        sqlx::query_as::<_, CampaignRow>(
            "SELECT id::text, name, subject, template_id::text, status, scheduled_at, sent_count, created_at, updated_at
             FROM campaigns WHERE tenant_id = $1
               AND (created_at < $2::timestamp OR (created_at = $2::timestamp AND id < $3::uuid))
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
        sqlx::query_as::<_, CampaignRow>(
            "SELECT id::text, name, subject, template_id::text, status, scheduled_at, sent_count, created_at, updated_at
             FROM campaigns WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
        )
        .bind(&auth.tenant_id)
        .bind(fetch_limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

    // Build the response rows and detect has_more
    let mut details: Vec<CampaignResponse> = rows.into_iter().map(Into::into).collect();
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

async fn get_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:read"])?;
    let row = fetch_campaign(&state, &auth.tenant_id, id).await?;
    Ok(Json(row.into()))
}

async fn delete_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

    let result = sqlx::query("DELETE FROM campaigns WHERE id = $1::uuid AND tenant_id = $2")
        .bind(parse_campaign_id(&id)?)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("campaign not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn resume_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    update_campaign_status_validated(&state, &auth.tenant_id, id, "sending", &["paused", "draft"])
        .await
}

async fn pause_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CampaignResponse>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;
    update_campaign_status_validated(
        &state,
        &auth.tenant_id,
        id,
        "paused",
        &["sending", "scheduled"],
    )
    .await
}

async fn update_campaign_status_validated(
    state: &AppState,
    tenant_id: &str,
    id: String,
    new_status: &str,
    valid_current_states: &[&str],
) -> Result<Json<CampaignResponse>, ApiError> {
    // Fetch current campaign to validate state transition.
    let current = fetch_campaign(state, tenant_id, id.clone()).await?;

    if !valid_current_states.contains(&current.status.as_str()) {
        return Err(ApiError::Validation(vec![format!(
            "cannot transition from '{}' to '{}'",
            current.status, new_status
        )]));
    }

    // Atomically guard the transition against TOCTOU races: the UPDATE only
    // fires if the status is still one of the allowed values. If 0 rows are
    // affected, the status changed between the SELECT and the UPDATE.
    let allowed: Vec<&str> = valid_current_states.to_vec();
    let result = sqlx::query(
        "UPDATE campaigns SET status = $1, updated_at = NOW()
         WHERE id = $2::uuid AND tenant_id = $3 AND status = ANY($4)",
    )
    .bind(new_status)
    .bind(&id)
    .bind(tenant_id)
    .bind(&allowed)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::Conflict(format!(
            "campaign '{}' status changed before update; cannot transition to '{}'",
            id, new_status
        )));
    }

    let row = fetch_campaign(state, tenant_id, id).await?;
    Ok(Json(row.into()))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct CampaignRow {
    id: String,
    name: String,
    subject: String,
    template_id: Option<String>,
    status: String,
    scheduled_at: Option<DateTime<Utc>>,
    // campaigns.sent_count is INT4 — sqlx refuses to decode INT4 into i64.
    sent_count: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<CampaignRow> for CampaignResponse {
    fn from(r: CampaignRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            subject: r.subject,
            template_id: r.template_id,
            status: r.status,
            scheduled_at: r.scheduled_at.map(|t| t.to_rfc3339()),
            sent_count: r.sent_count as i64,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn fetch_campaign(
    state: &AppState,
    tenant_id: &str,
    id: String,
) -> Result<CampaignRow, ApiError> {
    sqlx::query_as::<_, CampaignRow>(
        "SELECT id::text, name, subject, template_id::text, status, scheduled_at, sent_count, created_at, updated_at
         FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(parse_campaign_id(&id)?)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("campaign not found".into()))
}

// ─── Resend Handler ────────────────────────────────────────────

async fn resend_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["campaigns:write"])?;

    // Verify campaign exists and belongs to tenant, and is in a resendable state
    let campaign_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("campaign not found".into()))?;

    if campaign_status != "sent" && campaign_status != "partial" {
        return Err(ApiError::BadRequest(format!(
            "Campaign status '{}' is not resendable. Must be 'sent' or 'partial'.",
            campaign_status
        )));
    }

    // Create a new send job for failed/unsent recipients
    // job_type is NOT NULL with no default, so it must be supplied explicitly.
    let new_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO campaign_jobs (id, campaign_id, tenant_id, job_type, status, created_at)
         VALUES ($1, $2, $3, 'resend', 'queued', NOW())",
    )
    .bind(new_id)
    .bind(id)
    .bind(auth.tenant_id.to_string())
    .execute(&state.db)
    .await?;

    // Update campaign status
    sqlx::query("UPDATE campaigns SET status = 'resending', updated_at = NOW() WHERE id = $1::uuid AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id.to_string())
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({
        "job_id": new_id,
        "campaign_id": id,
        "status": "queued",
    })))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_campaign_deser() {
        let json = r#"{"name":"Summer Sale","subject":"50% Off!"}"#;
        let req: CreateCampaignRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "Summer Sale");
        assert!(req.template_id.is_none());
    }

    #[test]
    fn test_campaign_response_serialisation() {
        let resp = CampaignResponse {
            id: String::new(),
            name: "Test".into(),
            subject: "Sub".into(),
            template_id: None,
            status: "draft".into(),
            scheduled_at: None,
            sent_count: 0,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["sent_count"], 0);
    }
}

// ─── Adversarial CRUD / pagination / transition tests ──────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn auth_for(tenant: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: None,
            api_key_id: Some("key_adversarial".into()),
            session_id: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    async fn state_and_pool(name: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    async fn seed_tenant(pool: &sqlx::PgPool, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'campaigns adversarial', 'free', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_campaign(
        pool: &sqlx::PgPool,
        tenant: &str,
        name: &str,
        status: &str,
        created_at: DateTime<Utc>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO campaigns (id, tenant_id, name, subject, status, sent_count, created_at, updated_at)
             VALUES ($1, $2, $3, 'Subject', $4, 0, $5, $5)",
        )
        .bind(id)
        .bind(tenant)
        .bind(name)
        .bind(status)
        .bind(created_at)
        .execute(pool)
        .await
        .expect("seed campaign");
        id
    }

    async fn cleanup(pool: &sqlx::PgPool, tenants: &[&str]) {
        for tenant in tenants {
            sqlx::query("DELETE FROM campaigns WHERE tenant_id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup campaigns");
            sqlx::query("DELETE FROM campaign_jobs WHERE tenant_id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup jobs");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup tenants");
        }
    }

    #[test]
    fn keyset_cursor_rejects_every_malformed_shape() {
        let ts = Utc::now();
        let encoded = encode_keyset_cursor(&ts, "11111111-1111-1111-1111-111111111111");
        let (decoded_ts, decoded_id) = decode_keyset_cursor(&encoded).expect("roundtrip");
        assert_eq!(decoded_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(decoded_ts.timestamp(), ts.timestamp());

        assert!(matches!(
            decode_keyset_cursor("!!!not-hex!!!"),
            Err(ApiError::BadRequest(_))
        ));
        // Hex but no separator.
        let no_sep = encode_cursor("just-a-timestamp");
        assert!(matches!(
            decode_keyset_cursor(&no_sep),
            Err(ApiError::BadRequest(_))
        ));
        // Unparsable timestamp.
        let bad_ts = encode_cursor("yesterday\nsomeid");
        assert!(matches!(
            decode_keyset_cursor(&bad_ts),
            Err(ApiError::BadRequest(_))
        ));
        // Empty id / oversize id / control byte in id.
        for bad in [
            format!("{ts}\n"),
            format!("{ts}\n{}", "x".repeat(65)),
            format!("{ts}\nsome\u{7}id"),
        ] {
            let encoded = encode_cursor(&bad);
            assert!(
                matches!(decode_keyset_cursor(&encoded), Err(ApiError::BadRequest(_))),
                "cursor payload {bad:?} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn create_validates_bounds_and_references_before_insert() {
        let Some((state, pool)) = state_and_pool("adv_campaigns_create").await else {
            return;
        };
        let tenant = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant).await;
        let auth = auth_for(&tenant, &["campaigns:write"]);
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let campaign_name = format!("Launch {tag}");

        let empty_name = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: String::new(),
                subject: "s".into(),
                template_id: None,
                scheduled_at: None,
            }),
        )
        .await;
        assert!(matches!(empty_name, Err(ApiError::Validation(_))));

        let long_name = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "n".repeat(201),
                subject: "s".into(),
                template_id: None,
                scheduled_at: None,
            }),
        )
        .await;
        assert!(matches!(long_name, Err(ApiError::Validation(_))));

        let empty_subject = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "ok".into(),
                subject: String::new(),
                template_id: None,
                scheduled_at: None,
            }),
        )
        .await;
        assert!(matches!(empty_subject, Err(ApiError::Validation(_))));

        let long_subject = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "ok".into(),
                subject: "s".repeat(501),
                template_id: None,
                scheduled_at: None,
            }),
        )
        .await;
        assert!(matches!(long_subject, Err(ApiError::Validation(_))));

        // An unknown / cross-tenant template_id is a 404, never a silent FK.
        let missing_template = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: "ok".into(),
                subject: "s".into(),
                template_id: Some(Uuid::new_v4().to_string()),
                scheduled_at: None,
            }),
        )
        .await;
        assert!(matches!(missing_template, Err(ApiError::NotFound(_))));

        // A scheduled campaign is born in `scheduled`, a plain one is `draft`.
        let (status, Json(created)) = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: campaign_name.clone(),
                subject: "Hello".into(),
                template_id: None,
                scheduled_at: Some(Utc::now() + chrono::Duration::hours(1)),
            }),
        )
        .await
        .expect("create scheduled");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created.status, "scheduled");

        // Duplicate names within a tenant are an honest 409, not a 500.
        let duplicate = create_campaign(
            State(state.clone()),
            auth.clone(),
            Json(CreateCampaignRequest {
                name: campaign_name,
                subject: "Again".into(),
                template_id: None,
                scheduled_at: None,
            }),
        )
        .await;
        assert!(
            matches!(duplicate, Err(ApiError::Conflict(_))),
            "duplicate campaign name must conflict, got {duplicate:?}"
        );

        cleanup(&pool, &[&tenant]).await;
    }

    #[tokio::test]
    async fn list_paginates_by_offset_and_cursor_with_etag_revalidation() {
        let Some((state, pool)) = state_and_pool("adv_campaigns_list").await else {
            return;
        };
        let tenant_a = apexmail_lib::id::generate_id("", 26);
        let tenant_b = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant_a).await;
        seed_tenant(&pool, &tenant_b).await;
        let base = Utc::now();
        let tag_a = uuid::Uuid::new_v4().simple().to_string();
        let tag_b = uuid::Uuid::new_v4().simple().to_string();
        for i in 0..3 {
            seed_campaign(
                &pool,
                &tenant_a,
                &format!("A{i}-{tag_a}"),
                "draft",
                base - chrono::Duration::minutes(i),
            )
            .await;
        }
        // Tenant B's row must never leak.
        seed_campaign(
            &pool,
            &tenant_b,
            &format!("B-secret-{tag_b}"),
            "draft",
            base,
        )
        .await;

        let auth = auth_for(&tenant_a, &["campaigns:read"]);
        let page1 = list_campaigns(
            State(state.clone()),
            auth.clone(),
            HeaderMap::new(),
            Query(ListCampaignsQuery {
                limit: 2,
                offset: 0,
                cursor: None,
            }),
        )
        .await
        .expect("page 1");
        assert_eq!(page1.status(), StatusCode::OK);
        let etag = page1
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .expect("etag")
            .to_string();
        let bytes = axum::body::to_bytes(page1.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
        assert_eq!(body["meta"]["hasMore"], true);
        let all_text = body.to_string();
        assert!(!all_text.contains(&tag_b), "tenant isolation");

        // Conditional GET with the same ETag → 304 with no body.
        let mut headers = HeaderMap::new();
        headers.insert("if-none-match", etag.parse().unwrap());
        let not_modified = list_campaigns(
            State(state.clone()),
            auth.clone(),
            headers,
            Query(ListCampaignsQuery {
                limit: 2,
                offset: 0,
                cursor: None,
            }),
        )
        .await
        .expect("conditional get");
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

        // Cursor page walks the remaining row; the keyset cursor never
        // repeats the first page.
        let cursor = body["meta"]["nextCursor"]
            .as_str()
            .expect("next cursor")
            .to_string();
        let page2 = list_campaigns(
            State(state.clone()),
            auth.clone(),
            HeaderMap::new(),
            Query(ListCampaignsQuery {
                limit: 2,
                offset: 0,
                cursor: Some(cursor),
            }),
        )
        .await
        .expect("page 2");
        let bytes = axum::body::to_bytes(page2.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body2: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body2["data"].as_array().unwrap().len(), 1);
        assert_eq!(body2["meta"]["hasMore"], false);

        // Garbage cursors are 400s before touching SQL.
        for bad in ["zzzz", &encode_cursor("2026-01-01T00:00:00Z")] {
            let resp = list_campaigns(
                State(state.clone()),
                auth.clone(),
                HeaderMap::new(),
                Query(ListCampaignsQuery {
                    limit: 2,
                    offset: 0,
                    cursor: Some(bad.to_string()),
                }),
            )
            .await;
            assert!(
                matches!(resp, Err(ApiError::BadRequest(_))),
                "cursor {bad:?} must be refused"
            );
        }

        // Limit / offset clamps are honoured (limit 0 → 1, negative → 1).
        for (limit, offset) in [(0i64, 0i64), (-3, -10), (i64::MAX, 0)] {
            let resp = list_campaigns(
                State(state.clone()),
                auth.clone(),
                HeaderMap::new(),
                Query(ListCampaignsQuery {
                    limit,
                    offset,
                    cursor: None,
                }),
            )
            .await
            .expect("clamped list");
            assert_eq!(resp.status(), StatusCode::OK);
        }

        cleanup(&pool, &[&tenant_a, &tenant_b]).await;
    }

    #[tokio::test]
    async fn get_delete_and_transitions_are_tenant_scoped_with_honest_errors() {
        let Some((state, pool)) = state_and_pool("adv_campaigns_flow").await else {
            return;
        };
        let tenant_a = apexmail_lib::id::generate_id("", 26);
        let tenant_b = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant_a).await;
        seed_tenant(&pool, &tenant_b).await;
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let own = seed_campaign(&pool, &tenant_a, &format!("Own-{tag}"), "draft", Utc::now()).await;
        let foreign = seed_campaign(
            &pool,
            &tenant_b,
            &format!("Foreign-{tag}"),
            "draft",
            Utc::now(),
        )
        .await;

        let read = auth_for(&tenant_a, &["campaigns:read"]);
        let write = auth_for(&tenant_a, &["campaigns:write"]);

        let Json(fetched) = get_campaign(State(state.clone()), read.clone(), Path(own.to_string()))
            .await
            .expect("own read");
        assert_eq!(fetched.name, format!("Own-{tag}"));

        // Malformed ids are 404s, not database 500s.
        for bad in ["not-a-uuid", "", "123"] {
            let resp =
                get_campaign(State(state.clone()), read.clone(), Path(bad.to_string())).await;
            assert!(
                matches!(resp, Err(ApiError::NotFound(_))),
                "GET {bad:?} must be 404, got {resp:?}"
            );
            let resp =
                delete_campaign(State(state.clone()), write.clone(), Path(bad.to_string())).await;
            assert!(
                matches!(resp, Err(ApiError::NotFound(_))),
                "DELETE {bad:?} must be 404, got {resp:?}"
            );
        }

        let cross = get_campaign(
            State(state.clone()),
            read.clone(),
            Path(foreign.to_string()),
        )
        .await;
        assert!(matches!(cross, Err(ApiError::NotFound(_))));

        // Status transitions: draft→sending→paused, then illegal ones refused.
        let Json(resumed) =
            resume_campaign(State(state.clone()), write.clone(), Path(own.to_string()))
                .await
                .expect("resume draft");
        assert_eq!(resumed.status, "sending");
        let Json(paused) =
            pause_campaign(State(state.clone()), write.clone(), Path(own.to_string()))
                .await
                .expect("pause sending");
        assert_eq!(paused.status, "paused");
        let double_pause =
            pause_campaign(State(state.clone()), write.clone(), Path(own.to_string())).await;
        assert!(
            matches!(double_pause, Err(ApiError::Validation(_))),
            "pausing a paused campaign is invalid, got {double_pause:?}"
        );
        let cross_resume = resume_campaign(
            State(state.clone()),
            write.clone(),
            Path(foreign.to_string()),
        )
        .await;
        assert!(matches!(cross_resume, Err(ApiError::NotFound(_))));

        // Resend requires a sent/partial campaign.
        let draft_resend = resend_campaign(State(state.clone()), write.clone(), Path(own)).await;
        assert!(matches!(draft_resend, Err(ApiError::BadRequest(_))));
        sqlx::query("UPDATE campaigns SET status = 'sent' WHERE id = $1")
            .bind(own)
            .execute(&pool)
            .await
            .expect("mark sent");
        let Json(resend) = resend_campaign(State(state.clone()), write.clone(), Path(own))
            .await
            .expect("resend sent");
        assert_eq!(resend["status"], "queued");
        let (job_count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM campaign_jobs WHERE campaign_id = $1")
                .bind(own)
                .fetch_one(&pool)
                .await
                .expect("job count");
        assert_eq!(job_count, 1);
        let (status,): (String,) =
            sqlx::query_as("SELECT status FROM campaigns WHERE id = $1 AND tenant_id = $2")
                .bind(own)
                .bind(&tenant_a)
                .fetch_one(&pool)
                .await
                .expect("status");
        assert_eq!(status, "resending");

        let foreign_resend =
            resend_campaign(State(state.clone()), write.clone(), Path(foreign)).await;
        assert!(matches!(foreign_resend, Err(ApiError::NotFound(_))));

        // Cross-tenant delete is a 404 and leaves the row.
        let cross_delete = delete_campaign(
            State(state.clone()),
            write.clone(),
            Path(foreign.to_string()),
        )
        .await;
        assert!(matches!(cross_delete, Err(ApiError::NotFound(_))));
        let (still_there,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM campaigns WHERE id = $1 AND tenant_id = $2")
                .bind(foreign)
                .bind(&tenant_b)
                .fetch_one(&pool)
                .await
                .expect("foreign still exists");
        assert_eq!(still_there, 1);

        // Own delete → 204, second delete → 404.
        let deleted = delete_campaign(State(state.clone()), write.clone(), Path(own.to_string()))
            .await
            .expect("delete own");
        assert_eq!(deleted, StatusCode::NO_CONTENT);
        let deleted_again =
            delete_campaign(State(state.clone()), write.clone(), Path(own.to_string())).await;
        assert!(matches!(deleted_again, Err(ApiError::NotFound(_))));

        // Scope gates.
        assert!(matches!(
            get_campaign(
                State(state.clone()),
                auth_for(&tenant_a, &[]),
                Path(foreign.to_string())
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            resume_campaign(
                State(state.clone()),
                auth_for(&tenant_a, &["campaigns:read"]),
                Path(foreign.to_string())
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));

        cleanup(&pool, &[&tenant_a, &tenant_b]).await;
    }

    #[test]
    fn unknown_fields_are_refused_at_deserialization() {
        assert!(serde_json::from_str::<CreateCampaignRequest>(
            r#"{"name":"n","subject":"s","tenant_id":"other"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ListCampaignsQuery>(r#"{"limit":1,"evil":true}"#).is_err());
    }
}
