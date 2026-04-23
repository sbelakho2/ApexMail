//! Sales suite endpoints.
//!
//! Migrated from://! - apps/control-plane/src/app/api/sales/leads/route.ts
//! - apps/control-plane/src/app/api/sales/leads/update/route.ts
//! - apps/control-plane/src/app/api/sales/leads/enrich/route.ts
//! - apps/control-plane/src/app/api/sales/campaigns/route.ts
//! - apps/control-plane/src/app/api/sales/discovery/run/route.ts
//! - apps/control-plane/src/app/api/sales/outreach/start/route.ts
//! - apps/control-plane/src/app/api/sales/settings/route.ts

use super::super::helpers::{column_exists, table_exists};
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

fn sales_autopilot_base_url(state: &AppState) -> String {
    state
        .config
        .sales_autopilot_base_url
        .trim_end_matches('/')
        .to_string()
}

fn with_internal_service_auth(
    request: reqwest::RequestBuilder,
    state: &AppState,
) -> reqwest::RequestBuilder {
    if let Some(token) = state.config.internal_service_token.as_deref() {
        request.header("x-api-key", token)
    } else {
        request
    }
}

fn empty_leads_response() -> LeadsResponse {
    LeadsResponse {
        leads: Vec::new(),
        total: 0,
        stats_by_provider: serde_json::json!({}),
        stats_by_source: serde_json::json!({}),
    }
}

async fn ensure_campaign_tables(db: &sqlx::PgPool) -> Result<(), ApiError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS drip_campaigns (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            campaign_type TEXT,
            description TEXT,
            from_email TEXT,
            from_name TEXT,
            sequence JSONB NOT NULL DEFAULT '[]'::jsonb,
            stats JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            started_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(db)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS campaign_recipients (
            id BIGSERIAL PRIMARY KEY,
            campaign_id TEXT NOT NULL REFERENCES drip_campaigns(id) ON DELETE CASCADE,
            lead_id TEXT,
            email TEXT,
            status TEXT NOT NULL DEFAULT 'queued',
            opened_at TIMESTAMPTZ,
            clicked_at TIMESTAMPTZ,
            replied_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(db)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_campaign_recipients_campaign_id
         ON campaign_recipients(campaign_id)",
    )
    .execute(db)
    .await?;

    Ok(())
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

    if !table_exists(&state.db, "sales_leads").await {
        return Ok(Json(empty_leads_response()));
    }

    let has_deal_value = column_exists(&state.db, "sales_leads", "deal_value").await;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    let mut count_builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT COUNT(*)::bigint FROM sales_leads WHERE 1=1",
    );
    if let Some(status) = params.status.as_deref() {
        count_builder.push(" AND status = ").push_bind(status);
    }
    if let Some(source) = params.source.as_deref() {
        count_builder.push(" AND source = ").push_bind(source);
    }
    let total: i64 = count_builder
        .build_query_scalar()
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let mut leads_builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT id, company_name, domain, contact_email, contact_name,
                status, source, score, notes, COALESCE(to_jsonb(tags), '[]'::jsonb), ",
    );
    if has_deal_value {
        leads_builder.push("deal_value");
    } else {
        leads_builder.push("NULL::double precision");
    }
    leads_builder.push(
        ", created_at, updated_at
         FROM sales_leads WHERE 1=1",
    );
    if let Some(status) = params.status.as_deref() {
        leads_builder.push(" AND status = ").push_bind(status);
    }
    if let Some(source) = params.source.as_deref() {
        leads_builder.push(" AND source = ").push_bind(source);
    }
    leads_builder
        .push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);

    let rows: Vec<(
        String, String, String, Option<String>, Option<String>,
        String, String, Option<i32>, Option<String>,
        serde_json::Value, Option<f64>,
        chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>,
    )> = leads_builder.build_query_as().fetch_all(&state.db).await?;

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
                tags: serde_json::from_value(tags).unwrap_or_default(),
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
    if let Some(ref tags) = body.tags { query = query.bind(serde_json::json!(tags)); }
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

    if !table_exists(&state.db, "sales_leads").await {
        return Ok(Json(serde_json::json!({
            "success": true,
            "enriched": 0,
            "results": [],
            "skipped": body.lead_ids.into_iter().map(|lead_id| {
                serde_json::json!({ "leadId": lead_id, "reason": "sales leads table unavailable" })
            }).collect::<Vec<_>>()
        })));
    }

    let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, contact_email, domain FROM sales_leads WHERE id = ANY($1)",
    )
    .bind(&body.lead_ids)
    .fetch_all(&state.db)
    .await?;

    let mut results = Vec::new();
    let mut skipped = Vec::new();
    let base_url = sales_autopilot_base_url(&state);

    for requested_id in &body.lead_ids {
        if rows.iter().all(|(id, _, _)| id != requested_id) {
            skipped.push(serde_json::json!({
                "leadId": requested_id,
                "reason": "lead not found"
            }));
        }
    }

    for (lead_id, contact_email, domain) in rows {
        let payload = if let Some(email) = contact_email {
            serde_json::json!({ "email": email })
        } else if let Some(domain) = domain {
            serde_json::json!({ "domain": domain })
        } else {
            skipped.push(serde_json::json!({
                "leadId": lead_id,
                "reason": "lead is missing both contact email and domain"
            }));
            continue;
        };

        let response = with_internal_service_auth(
            state.http_client.post(format!("{base_url}/enrich")).json(&payload),
            &state,
        )
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Enrich request failed: {e}");
            ApiError::Internal("Enrichment service unavailable".into())
        })?;

        if !response.status().is_success() {
            skipped.push(serde_json::json!({
                "leadId": lead_id,
                "reason": format!("enrichment backend returned {}", response.status())
            }));
            continue;
        }

        let company: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ApiError::Internal(format!("failed to parse enrichment response: {e}")))?;

        results.push(serde_json::json!({
            "leadId": lead_id,
            "company": company
        }));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "enriched": results.len(),
        "results": results,
        "skipped": skipped,
    })))
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

    if !table_exists(&state.db, "drip_campaigns").await {
        return Ok(Json(vec![]));
    }

    let has_recipients = table_exists(&state.db, "campaign_recipients").await;

    let rows: Vec<(
        String, String, String, String,
        String, String, String, String, String,
        chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>,
    )> = if has_recipients {
        sqlx::query_as(
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
        .await?
    } else {
        sqlx::query_as(
            "SELECT id, name, status, COALESCE(campaign_type, 'email'),
                    '0', '0', '0', '0', '0', created_at, updated_at
             FROM drip_campaigns
             ORDER BY created_at DESC",
        )
        .fetch_all(&state.db)
        .await?
    };

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

    if !table_exists(&state.db, "drip_campaigns").await {
        return Err(ApiError::NotFound("campaign not found".into()));
    }

    let new_status = match body.action.as_str() {
        "pause" => "paused",
        "resume" => "active",
        "archive" => "archived",
        "cancel" => "cancelled",
        _ => return Err(ApiError::Validation(vec!["Invalid action".into()])),
    };

    let result = sqlx::query("UPDATE drip_campaigns SET status = $1, updated_at = NOW() WHERE id = $2")
        .bind(new_status)
        .bind(&body.id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("campaign not found".into()));
    }

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

    let job_id = apexmail_lib::id::generate_id("disc", 22);
    if !table_exists(&state.db, "sales_leads").await || !table_exists(&state.db, "enriched_companies").await {
        return Ok(Json(serde_json::json!({
            "jobId": job_id,
            "status": "unavailable",
            "discovered": 0,
            "imported": 0,
            "message": "discovery requires both sales_leads and enriched_companies tables"
        })));
    }

    let limit = i64::from(body.max_pages.clamp(1, 10)) * 25;
    let rows: Vec<(String, String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT tenant_id, domain, company_name, industry, description
         FROM enriched_companies
         WHERE tenant_id = $2
         ORDER BY last_enriched_at DESC
         LIMIT $1",
    )
    .bind(limit)
    .bind(&auth.tenant_id)
    .fetch_all(&state.db)
    .await?;

    let categories = body.categories.unwrap_or_default();
    let normalized_categories: Vec<String> = categories
        .into_iter()
        .map(|category| category.to_ascii_lowercase())
        .collect();
    let primary_source = body
        .sources
        .first()
        .cloned()
        .unwrap_or_else(|| "discovery".into());

    let mut discovered = 0i64;
    let mut imported = 0i64;

    for (tenant_id, domain, company_name, industry, description) in rows {
        if !normalized_categories.is_empty() {
            let Some(ref industry_name) = industry else {
                continue;
            };
            let normalized_industry = industry_name.to_ascii_lowercase();
            if normalized_categories
                .iter()
                .all(|category| !normalized_industry.contains(category))
            {
                continue;
            }
        }

        discovered += 1;

        let existing: Option<String> = sqlx::query_scalar(
            "SELECT id FROM sales_leads WHERE domain = $1 AND tenant_id = $2 LIMIT 1",
        )
        .bind(&domain)
        .bind(&tenant_id)
        .fetch_optional(&state.db)
        .await?;

        if existing.is_some() {
            continue;
        }

        let lead_id = apexmail_lib::id::generate_id("", 26);
        sqlx::query(
            "INSERT INTO sales_leads (
                tenant_id, id, company_name, domain, status, source, notes, created_at, updated_at
             ) VALUES ($1, $2, $3, $4, 'new', $5, $6, NOW(), NOW())",
        )
        .bind(&tenant_id)
        .bind(&lead_id)
        .bind(company_name.unwrap_or_else(|| domain.clone()))
        .bind(&domain)
        .bind(&primary_source)
        .bind(description.or(industry.clone()))
        .execute(&state.db)
        .await?;
        imported += 1;
    }

    Ok(Json(serde_json::json!({
        "jobId": job_id,
        "status": "completed",
        "discovered": discovered,
        "imported": imported,
        "source": primary_source,
    })))
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

    if !table_exists(&state.db, "sales_leads").await {
        return Err(ApiError::ServiceUnavailable("sales leads unavailable".into()));
    }

    ensure_campaign_tables(&state.db).await?;

    let lead_rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, contact_email FROM sales_leads WHERE id = ANY($1)",
    )
    .bind(&body.lead_ids)
    .fetch_all(&state.db)
    .await?;

    let mut valid_recipients = Vec::new();
    let mut skipped = Vec::new();
    for requested_id in &body.lead_ids {
        match lead_rows.iter().find(|(id, _)| id == requested_id) {
            Some((lead_id, Some(contact_email))) => {
                valid_recipients.push((lead_id.clone(), contact_email.clone()));
            }
            Some((lead_id, None)) => skipped.push(serde_json::json!({
                "leadId": lead_id,
                "reason": "lead is missing a contact email"
            })),
            None => skipped.push(serde_json::json!({
                "leadId": requested_id,
                "reason": "lead not found"
            })),
        }
    }

    if valid_recipients.is_empty() {
        return Err(ApiError::Validation(vec![
            "No selected leads are ready for outreach".into(),
        ]));
    }

    let template = body.template_name.unwrap_or_else(|| "default".into());
    let campaign_id = apexmail_lib::id::generate_id("cmp", 22);
    let campaign_name = if let Some(ref offer_id) = body.offer_id {
        format!("{} - {}", offer_id.replace('_', " "), chrono::Utc::now().date_naive())
    } else {
        format!("{} - {}", template, chrono::Utc::now().date_naive())
    };
    let sequence = serde_json::json!([
        {
            "templateName": template,
            "subject": body.subject,
            "offerId": body.offer_id,
        }
    ]);
    let stats = serde_json::json!({
        "queued": valid_recipients.len(),
        "sent": 0,
        "opened": 0,
        "clicked": 0,
        "replied": 0,
    });

    sqlx::query(
        "INSERT INTO drip_campaigns (
            id, name, status, campaign_type, sequence, stats, created_at, started_at, updated_at
         ) VALUES ($1, $2, 'active', 'email', $3, $4, NOW(), NOW(), NOW())",
    )
    .bind(&campaign_id)
    .bind(&campaign_name)
    .bind(&sequence)
    .bind(&stats)
    .execute(&state.db)
    .await?;

    for (lead_id, email) in &valid_recipients {
        sqlx::query(
            "INSERT INTO campaign_recipients (campaign_id, lead_id, email, status, created_at)
             VALUES ($1, $2, $3, 'queued', NOW())",
        )
        .bind(&campaign_id)
        .bind(lead_id)
        .bind(email)
        .execute(&state.db)
        .await?;
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "campaignId": campaign_id,
        "status": "active",
        "leadsEnrolled": valid_recipients.len(),
        "offer": body.offer_id,
        "template": template,
        "skipped": skipped,
    })))
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
