//! Sales suite endpoints.
//!
//! Migrated from:
//!   - apps/control-plane/src/app/api/sales/leads/route.ts
//!   - apps/control-plane/src/app/api/sales/leads/update/route.ts
//!   - apps/control-plane/src/app/api/sales/leads/enrich/route.ts
//!   - apps/control-plane/src/app/api/sales/campaigns/route.ts
//!   - apps/control-plane/src/app/api/sales/discovery/run/route.ts
//!   - apps/control-plane/src/app/api/sales/outreach/start/route.ts
//!   - apps/control-plane/src/app/api/sales/settings/route.ts

use axum::extract::{Query, State};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Instant;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/leads", get(list_leads))
        .route("/leads/update", patch(update_leads))
        .route("/leads/enrich", post(enrich_leads))
        .route("/campaigns", get(list_campaigns).patch(update_campaign))
        .route("/discovery/run", post(run_discovery))
        .route("/outreach/start", post(start_outreach))
        .route("/settings", get(get_settings).put(save_settings))
}

// ──────────────────────────────────────────
// Leads
// ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LeadsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub status: Option<String>,
    pub source: Option<String>,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeadEntry {
    pub id: String,
    pub company_name: String,
    pub domain: String,
    pub contact_email: Option<String>,
    pub contact_name: Option<String>,
    pub status: String,
    pub source: String,
    pub score: Option<i32>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub deal_value: Option<f64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeadsResponse {
    pub leads: Vec<LeadEntry>,
    pub total: i64,
    pub stats_by_provider: serde_json::Value,
    pub stats_by_source: serde_json::Value,
}

async fn list_leads(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<LeadsQuery>,
) -> Result<Json<LeadsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    // Count total
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sales_leads")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    // Fetch leads
    let rows: Vec<(
        String, String, String, Option<String>, Option<String>,
        String, String, Option<i32>, Option<String>,
        Option<Vec<String>>, Option<f64>,
        chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT id, company_name, domain, contact_email, contact_name,
                status, source, score, notes, tags, deal_value,
                created_at, updated_at
         FROM sales_leads
         ORDER BY created_at DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    ?;

    let leads: Vec<LeadEntry> = rows
        .into_iter()
        .map(|(id, company, domain, email, name, status, source, score, notes, tags, deal, ca, ua)| {
            LeadEntry {
                id,
                company_name: company,
                domain,
                contact_email: email,
                contact_name: name,
                status,
                source,
                score,
                notes,
                tags: tags.unwrap_or_default(),
                deal_value: deal,
                created_at: ca.to_rfc3339(),
                updated_at: ua.to_rfc3339(),
            }
        })
        .collect();

    // Aggregate stats
    let provider_stats: Vec<(String, String)> = sqlx::query_as(
        "SELECT COALESCE(source, 'unknown'), COUNT(*)::text FROM sales_leads GROUP BY source",
    )
    .fetch_all(&state.db)
    .await
    ?;

    let source_stats: Vec<(String, String)> = sqlx::query_as(
        "SELECT status, COUNT(*)::text FROM sales_leads GROUP BY status",
    )
    .fetch_all(&state.db)
    .await
    ?;

    let stats_by_provider: serde_json::Value = provider_stats
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v.parse::<i64>().unwrap_or(0))))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();

    let stats_by_source: serde_json::Value = source_stats
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v.parse::<i64>().unwrap_or(0))))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();

    Ok(Json(LeadsResponse { leads, total, stats_by_provider, stats_by_source }))
}

// ──────────────────────────────────────────
// Lead updates (single + bulk)
// ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeadUpdate {
    pub id: Option<String>,
    pub ids: Option<Vec<String>>,
    pub status: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub contact_email: Option<String>,
    pub contact_name: Option<String>,
    pub deal_value: Option<f64>,
}

async fn update_leads(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<LeadUpdate>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let ids: Vec<String> = if let Some(ref single) = body.id {
        vec![single.clone()]
    } else if let Some(ref bulk) = body.ids {
        bulk.clone()
    } else {
        return Err(ApiError::Validation(vec!["id or ids required".into()]));
    };

    if ids.is_empty() || ids.len() > 100 {
        return Err(ApiError::Validation(vec!["1-100 IDs allowed".into()]));
    }

    if let Some(ref status) = body.status {
        let allowed = [
            "new", "prospect", "contacted", "qualified", "engaged",
            "demo_scheduled", "converted", "lost", "unqualified",
        ];
        if !allowed.contains(&status.as_str()) {
            return Err(ApiError::Validation(vec!["Invalid status".into()]));
        }
    }

    // Build dynamic SET clause
    let mut sets: Vec<String> = Vec::new();
    let mut bind_idx = 2u32; // $1 = ids array

    if body.status.is_some() {
        sets.push(format!("status = ${bind_idx}"));
        bind_idx += 1;
    }
    if body.notes.is_some() {
        sets.push(format!("notes = ${bind_idx}"));
        bind_idx += 1;
    }
    if body.tags.is_some() {
        sets.push(format!("tags = ${bind_idx}"));
        bind_idx += 1;
    }
    if body.contact_email.is_some() {
        sets.push(format!("contact_email = ${bind_idx}"));
        bind_idx += 1;
    }
    if body.contact_name.is_some() {
        sets.push(format!("contact_name = ${bind_idx}"));
        bind_idx += 1;
    }
    if body.deal_value.is_some() {
        sets.push(format!("deal_value = ${bind_idx}"));
        bind_idx += 1;
    }
    let _ = bind_idx;

    if sets.is_empty() {
        return Err(ApiError::Validation(vec!["No fields to update".into()]));
    }

    sets.push("updated_at = NOW()".into());
    let sql = format!(
        "UPDATE sales_leads SET {} WHERE id = ANY($1)",
        sets.join(", ")
    );

    let mut query = sqlx::query(&sql).bind(&ids);

    if let Some(ref status) = body.status { query = query.bind(status); }
    if let Some(ref notes) = body.notes { query = query.bind(notes); }
    if let Some(ref tags) = body.tags { query = query.bind(tags); }
    if let Some(ref email) = body.contact_email { query = query.bind(email); }
    if let Some(ref name) = body.contact_name { query = query.bind(name); }
    if let Some(deal) = body.deal_value { query = query.bind(deal); }

    let result = query.execute(&state.db).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "updated": result.rows_affected()
    })))
}

// ──────────────────────────────────────────
// Lead enrichment
// ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrichRequest {
    pub lead_ids: Vec<String>,
}

async fn enrich_leads(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<EnrichRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    if body.lead_ids.is_empty() || body.lead_ids.len() > 50 {
        return Err(ApiError::Validation(vec!["1-50 lead IDs allowed".into()]));
    }

    // Proxy to autopilot backend
    let url = "http://localhost:3010/api/v1/operator/enrich";
    let response = state
        .http_client
        .post(url)
        .json(&serde_json::json!({ "leadIds": body.lead_ids }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Enrich request failed: {e}");
            ApiError::Internal("Enrichment service unavailable".into())
        })?;

    let result: serde_json::Value = response.json().await
        .map_err(|e| ApiError::Internal(format!("failed to parse enrichment response: {e}")))?;
    Ok(Json(result))
}

// ──────────────────────────────────────────
// Campaigns
// ──────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Campaign {
    pub id: String,
    pub name: String,
    pub status: String,
    pub campaign_type: String,
    pub total_recipients: i64,
    pub sent: i64,
    pub opened: i64,
    pub clicked: i64,
    pub replied: i64,
    pub created_at: String,
    pub updated_at: String,
}

async fn list_campaigns(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<Campaign>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let rows: Vec<(
        String, String, String, String,
        String, String, String, String, String,
        chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT c.id, c.name, c.status, COALESCE(c.campaign_type, 'email'),
                COUNT(cr.id)::text,
                COUNT(cr.id) FILTER (WHERE cr.status IN ('sent', 'delivered'))::text,
                COUNT(cr.id) FILTER (WHERE cr.opened_at IS NOT NULL)::text,
                COUNT(cr.id) FILTER (WHERE cr.clicked_at IS NOT NULL)::text,
                COUNT(cr.id) FILTER (WHERE cr.replied_at IS NOT NULL)::text,
                c.created_at, c.updated_at
         FROM drip_campaigns c
         LEFT JOIN campaign_recipients cr ON cr.campaign_id = c.id
         GROUP BY c.id, c.name, c.status, c.campaign_type, c.created_at, c.updated_at
         ORDER BY c.created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    ?;

    let campaigns: Vec<Campaign> = rows
        .into_iter()
        .map(|(id, name, status, ctype, total, sent, opened, clicked, replied, ca, ua)| {
            Campaign {
                id, name, status,
                campaign_type: ctype,
                total_recipients: total.parse().unwrap_or(0),
                sent: sent.parse().unwrap_or(0),
                opened: opened.parse().unwrap_or(0),
                clicked: clicked.parse().unwrap_or(0),
                replied: replied.parse().unwrap_or(0),
                created_at: ca.to_rfc3339(),
                updated_at: ua.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(campaigns))
}

#[derive(Debug, Deserialize)]
pub struct CampaignUpdate {
    pub id: String,
    pub action: String,
}

async fn update_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CampaignUpdate>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let new_status = match body.action.as_str() {
        "pause" => "paused",
        "resume" => "active",
        "archive" => "archived",
        "cancel" => "cancelled",
        _ => return Err(ApiError::Validation(vec!["Invalid action".into()])),
    };

    sqlx::query("UPDATE drip_campaigns SET status = $1, updated_at = NOW() WHERE id = $2")
        .bind(new_status)
        .bind(&body.id)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "status": new_status
    })))
}

// ──────────────────────────────────────────
// Discovery
// ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryRequest {
    pub sources: Vec<String>,
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    #[serde(default = "default_max_pages")]
    pub max_pages: i32,
}

fn default_max_pages() -> i32 {
    3
}

async fn run_discovery(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DiscoveryRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    if body.sources.is_empty() {
        return Err(ApiError::Validation(vec!["At least one source required".into()]));
    }

    let url = "http://localhost:3010/api/v1/operator/discovery";
    let response = state
        .http_client
        .post(url)
        .json(&serde_json::json!({
            "sources": body.sources,
            "categories": body.categories,
            "maxPages": body.max_pages,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Discovery request failed: {e}");
            ApiError::Internal("Discovery service unavailable".into())
        })?;

    let result: serde_json::Value = response.json().await
        .map_err(|e| ApiError::Internal(format!("failed to parse discovery response: {e}")))?;
    Ok(Json(result))
}

// ──────────────────────────────────────────
// Outreach
// ──────────────────────────────────────────

static OUTREACH_LIMITER: Mutex<Option<(Instant, u32)>> = Mutex::new(None);
const OUTREACH_RATE_LIMIT: u32 = 5;
const OUTREACH_RATE_WINDOW_SECS: u64 = 600;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutreachRequest {
    pub lead_ids: Vec<String>,
    pub offer_id: Option<String>,
    pub template_name: Option<String>,
    pub subject: Option<String>,
}

async fn start_outreach(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<OutreachRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    if body.lead_ids.is_empty() || body.lead_ids.len() > 100 {
        return Err(ApiError::Validation(vec!["1-100 lead IDs allowed".into()]));
    }

    // In-memory rate limiter
    {
        if let Ok(mut guard) = OUTREACH_LIMITER.lock() {
            let now = Instant::now();
            match guard.as_mut() {
                Some((ref ts, ref mut count)) if now.duration_since(*ts).as_secs() < OUTREACH_RATE_WINDOW_SECS => {
                    if *count >= OUTREACH_RATE_LIMIT {
                        return Err(ApiError::RateLimited);
                    }
                    *count += 1;
                }
                _ => {
                    *guard = Some((now, 1));
                }
            }
        }
    }

    let template = body.template_name.unwrap_or_else(|| "default".into());

    let url = "http://localhost:3010/api/v1/operator/outreach";
    let response = state
        .http_client
        .post(url)
        .json(&serde_json::json!({
            "leadIds": body.lead_ids,
            "offerId": body.offer_id,
            "templateName": template,
            "subject": body.subject,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Outreach request failed: {e}");
            ApiError::Internal("Outreach service unavailable".into())
        })?;

    let result: serde_json::Value = response.json().await
        .map_err(|e| ApiError::Internal(format!("failed to parse outreach response: {e}")))?;
    Ok(Json(result))
}

// ──────────────────────────────────────────
// Settings
// ──────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SalesSettings {
    #[serde(default)]
    pub scoring_weights: serde_json::Value,
    #[serde(default)]
    pub schedule: serde_json::Value,
    #[serde(default)]
    pub notifications: serde_json::Value,
}

async fn get_settings(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SalesSettings>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let row: Option<(serde_json::Value, serde_json::Value, serde_json::Value)> = sqlx::query_as(
        "SELECT scoring_weights, schedule, notifications FROM sales_settings LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let settings = match row {
        Some((sw, sc, nf)) => SalesSettings {
            scoring_weights: sw,
            schedule: sc,
            notifications: nf,
        },
        None => SalesSettings {
            scoring_weights: serde_json::json!({}),
            schedule: serde_json::json!({}),
            notifications: serde_json::json!({}),
        },
    };

    Ok(Json(settings))
}

async fn save_settings(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<SalesSettings>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    // Ensure table exists
    if let Err(e) = sqlx::query(
        "CREATE TABLE IF NOT EXISTS sales_settings (
            id SERIAL PRIMARY KEY,
            scoring_weights JSONB NOT NULL DEFAULT '{}'::jsonb,
            schedule JSONB NOT NULL DEFAULT '{}'::jsonb,
            notifications JSONB NOT NULL DEFAULT '{}'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
         )",
    )
    .execute(&state.db)
    .await
    {
        tracing::warn!(error = %e, "Failed to ensure sales_settings table exists");
    }

    // Upsert settings (single row)
    sqlx::query(
        "INSERT INTO sales_settings (id, scoring_weights, schedule, notifications, updated_at)
         VALUES (1, $1, $2, $3, NOW())
         ON CONFLICT (id) DO UPDATE SET
            scoring_weights = EXCLUDED.scoring_weights,
            schedule = EXCLUDED.schedule,
            notifications = EXCLUDED.notifications,
            updated_at = NOW()",
    )
    .bind(&body.scoring_weights)
    .bind(&body.schedule)
    .bind(&body.notifications)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "success": true })))
}
