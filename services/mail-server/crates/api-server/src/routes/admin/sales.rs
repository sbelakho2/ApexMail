//! Sales suite endpoints.
//!
//! The control plane is a command/read surface here, not a sales engine: it
//! never creates campaigns or recipients and never runs runtime DDL. Outreach
//! is an enrollment command forwarded to the canonical sales-autopilot
//! service; campaign listings proxy its enrollment read model (falling back to
//! the canonical `sales_enrollments` rows when the service is unconfigured).

use std::time::Duration;

use super::super::helpers::table_exists;
use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use deadpool_redis::redis;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

/// Outbound calls to the sales-autopilot service are bounded.
const SALES_PROXY_TIMEOUT_SECS: u64 = 30;

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

async fn log_sales_audit(
    db: &sqlx::PgPool,
    auth: &AuthUser,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort(
        db,
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        resource_type,
        resource_id,
        metadata,
        None,
        None,
    )
    .await;
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
        stats_by_source: serde_json::json!({}),
        stats_by_status: serde_json::json!({}),
    }
}

/// The sales-autopilot base URL, or a fail-closed error when unconfigured.
/// An empty value is "not configured" — there is no local fallback engine.
fn configured_sales_autopilot_base_url(state: &AppState) -> Result<String, ApiError> {
    let base = sales_autopilot_base_url(state);
    if base.is_empty() {
        return Err(ApiError::ServiceUnavailable(
            "sales-autopilot is not configured (SALES_AUTOPILOT_BASE_URL is empty)".into(),
        ));
    }
    Ok(base)
}

/// A buffered upstream response forwarded to the caller verbatim (status,
/// content type and body) — the CP never rewrites the engine's answer.
struct UpstreamResponse {
    status: StatusCode,
    content_type: Option<HeaderValue>,
    body: Bytes,
}

impl UpstreamResponse {
    fn status_u16(&self) -> u16 {
        self.status.as_u16()
    }

    /// The body parsed as JSON, when it is JSON — used only for audit
    /// metadata/ids, never to alter what the caller receives.
    fn body_json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }

    fn into_axum_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        if let Some(content_type) = self.content_type {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, content_type);
        }
        response
    }
}

async fn proxy_to_sales_service(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<UpstreamResponse, ApiError> {
    let base = configured_sales_autopilot_base_url(state)?;
    let mut request = state
        .http_client
        .request(method, format!("{base}{path}"))
        .header("x-tenant-id", "system")
        .timeout(Duration::from_secs(SALES_PROXY_TIMEOUT_SECS));
    request = with_internal_service_auth(request, state);
    if let Some(payload) = body {
        request = request.json(&payload);
    }

    let response = request.send().await.map_err(|error| {
        tracing::error!(error = %error, path, "sales-autopilot proxy request failed");
        ApiError::ServiceUnavailable(format!("sales-autopilot is unreachable at {base}"))
    })?;

    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| HeaderValue::from_bytes(value.as_bytes()).ok());
    let body = response.bytes().await.map_err(|error| {
        tracing::error!(error = %error, path, "failed to read the sales-autopilot response");
        ApiError::ServiceUnavailable("sales-autopilot returned an unreadable response".into())
    })?;

    Ok(UpstreamResponse {
        status,
        content_type,
        body,
    })
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
    pub stats_by_source: serde_json::Value,
    pub stats_by_status: serde_json::Value,
}

async fn list_leads(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<LeadsQuery>,
) -> Result<Json<LeadsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    if !table_exists(&state.db, "sales_leads").await {
        return Ok(Json(empty_leads_response()));
    }

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    // Scope reads to the caller's tenant so listing matches the tenant-scoped
    // writes in update_leads/start_outreach (require_system_tenant guarantees
    // the system tenant here).
    let mut count_builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT COUNT(*)::bigint FROM sales_leads WHERE tenant_id = ",
    );
    count_builder.push_bind(auth.tenant_id.clone());
    count_builder.push(" AND 1=1");
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

    // deal_value is canonical (migration 200) — selected directly.
    let mut leads_builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT id, company_name, domain, contact_email, contact_name,
                status, source, score, notes, COALESCE(to_jsonb(tags), '[]'::jsonb),
                deal_value, created_at, updated_at
         FROM sales_leads WHERE tenant_id = ",
    );
    leads_builder.push_bind(auth.tenant_id.clone());
    leads_builder.push(" AND 1=1");
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
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        Option<i32>,
        Option<String>,
        serde_json::Value,
        Option<f64>,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = leads_builder.build_query_as().fetch_all(&state.db).await?;

    let leads: Vec<LeadEntry> = rows
        .into_iter()
        .map(
            |(
                id,
                company,
                domain,
                email,
                name,
                status,
                source,
                score,
                notes,
                tags,
                deal,
                ca,
                ua,
            )| {
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
            },
        )
        .collect();

    // Aggregate stats (scoped to the same tenant as the rows above)
    let source_stats: Vec<(String, String)> = sqlx::query_as(
        "SELECT COALESCE(source, 'unknown'), COUNT(*)::text FROM sales_leads WHERE tenant_id = $1 GROUP BY source",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&state.db)
    .await?;

    let status_stats: Vec<(String, String)> = sqlx::query_as(
        "SELECT status, COUNT(*)::text FROM sales_leads WHERE tenant_id = $1 GROUP BY status",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&state.db)
    .await?;

    let stats_by_source: serde_json::Value = source_stats
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v.parse::<i64>().unwrap_or(0))))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();

    let stats_by_status: serde_json::Value = status_stats
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v.parse::<i64>().unwrap_or(0))))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();

    Ok(Json(LeadsResponse {
        leads,
        total,
        stats_by_source,
        stats_by_status,
    }))
}

// ──────────────────────────────────────────
// Lead updates (single + bulk)
// ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

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
            "new",
            "prospect",
            "contacted",
            "qualified",
            "engaged",
            "demo_scheduled",
            "converted",
            "lost",
            "unqualified",
        ];
        if !allowed.contains(&status.as_str()) {
            return Err(ApiError::Validation(vec!["Invalid status".into()]));
        }
    }

    // Build dynamic SET clause (deal_value is canonical since migration 200).
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
    // Add tenant_id filter to WHERE clause to prevent cross-tenant lead modification.
    let tenant_param_idx = bind_idx;
    let sql = format!(
        "UPDATE sales_leads SET {} WHERE id = ANY($1) AND tenant_id = ${tenant_param_idx}",
        sets.join(", ")
    );

    let mut query = sqlx::query(&sql).bind(&ids);

    if let Some(ref status) = body.status {
        query = query.bind(status);
    }
    if let Some(ref notes) = body.notes {
        query = query.bind(notes);
    }
    if let Some(ref tags) = body.tags {
        query = query.bind(serde_json::json!(tags));
    }
    if let Some(ref email) = body.contact_email {
        query = query.bind(email);
    }
    if let Some(ref name) = body.contact_name {
        query = query.bind(name);
    }
    if let Some(deal) = body.deal_value {
        query = query.bind(deal);
    }
    // Bind tenant_id for WHERE clause scoping
    query = query.bind(&auth.tenant_id);

    let result = query.execute(&state.db).await?;

    log_sales_audit(
        &state.db,
        &auth,
        "control_plane.sales.leads_updated",
        "sales_lead",
        if ids.len() == 1 {
            Some(ids[0].as_str())
        } else {
            None
        },
        json!({
            "ids": ids,
            "updated": result.rows_affected(),
            "status": body.status,
            "notes": body.notes,
            "tags": body.tags,
            "contactEmail": body.contact_email,
            "contactName": body.contact_name,
            "dealValue": body.deal_value,
        }),
    )
    .await;

    crate::routes::admin::dashboard::invalidate_dashboard_cache().await;

    Ok(Json(serde_json::json!({
        "success": true,
        "updated": result.rows_affected()
    })))
}

// ──────────────────────────────────────────
// Lead enrichment
// ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    if body.lead_ids.is_empty() || body.lead_ids.len() > 50 {
        return Err(ApiError::Validation(vec!["1-50 lead IDs allowed".into()]));
    }

    if !table_exists(&state.db, "sales_leads").await {
        log_sales_audit(
            &state.db,
            &auth,
            "control_plane.sales.leads_enriched",
            "sales_lead",
            None,
            json!({
                "leadIds": body.lead_ids,
                "enriched": 0,
                "status": "unavailable",
            }),
        )
        .await;

        return Ok(Json(serde_json::json!({
            "success": true,
            "enriched": 0,
            "results": [],
            "skipped": body.lead_ids.into_iter().map(|lead_id| {
                serde_json::json!({ "leadId": lead_id, "reason": "sales leads table unavailable" })
            }).collect::<Vec<_>>()
        })));
    }

    let rows: Vec<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT id, contact_email, domain FROM sales_leads WHERE id = ANY($1)")
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

        // sales-autopilot requires both the service token (x-api-key, added
        // by with_internal_service_auth when configured) and a tenant header.
        let response = with_internal_service_auth(
            state
                .http_client
                .post(format!("{base_url}/enrich"))
                .header("x-tenant-id", "system")
                .json(&payload),
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

    log_sales_audit(
        &state.db,
        &auth,
        "control_plane.sales.leads_enriched",
        "sales_lead",
        None,
        json!({
            "leadIds": body.lead_ids,
            "enriched": results.len(),
            "skipped": skipped.len(),
        }),
    )
    .await;

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

/// List outreach campaigns.
///
/// Primary path: proxy the canonical enrollment read model
/// (`GET {base}/enrollments`) so the CP reports exactly what the engine
/// scheduled. When the service is unconfigured, fall back to the canonical
/// `sales_enrollments` rows joined to `sales_sequences` — never the retired
/// CP-local campaign tables.
async fn list_campaigns(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    if configured_sales_autopilot_base_url(&state).is_ok() {
        let upstream =
            proxy_to_sales_service(&state, reqwest::Method::GET, "/enrollments", None).await?;
        return Ok(upstream.into_axum_response());
    }

    Ok(Json(canonical_enrollment_campaigns(&state).await?).into_response())
}

/// Canonical read-model fallback: one row per enrollment, labelled by its
/// sequence. Used only when the sales service is unconfigured.
async fn canonical_enrollment_campaigns(state: &AppState) -> Result<Vec<Campaign>, ApiError> {
    if !table_exists(&state.db, "sales_enrollments").await
        || !table_exists(&state.db, "sales_sequences").await
    {
        return Ok(Vec::new());
    }

    let rows: Vec<(
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT e.id::text,
                COALESCE(s.name, 'sequence') AS name,
                e.state,
                e.enrolled_at,
                e.updated_at
         FROM sales_enrollments e
         LEFT JOIN sales_sequence_versions v ON v.id = e.sequence_version_id
         LEFT JOIN sales_sequences s ON s.id = v.sequence_id
         ORDER BY e.enrolled_at DESC",
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, name, status, enrolled_at, updated_at)| Campaign {
            id,
            name,
            status,
            campaign_type: "sequence".into(),
            total_recipients: 1,
            sent: 0,
            opened: 0,
            clicked: 0,
            replied: 0,
            created_at: enrolled_at.to_rfc3339(),
            updated_at: updated_at.to_rfc3339(),
        })
        .collect())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignUpdate {
    pub id: String,
    pub action: String,
}

/// Pause/resume/cancel an enrollment batch on the canonical sales service.
/// The CP does not own enrollment state and never writes it locally.
async fn update_campaign(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CampaignUpdate>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let downstream_action = match body.action.as_str() {
        "pause" => "pause",
        "resume" => "resume",
        "archive" | "cancel" => "cancel",
        _ => return Err(ApiError::Validation(vec!["Invalid action".into()])),
    };

    let enrollment_id = urlencoding::encode(&body.id);
    let result = proxy_to_sales_service(
        &state,
        reqwest::Method::POST,
        &format!("/enrollments/{enrollment_id}/{downstream_action}"),
        None,
    )
    .await;
    let upstream_status = result.as_ref().ok().map(UpstreamResponse::status_u16);

    log_sales_audit(
        &state.db,
        &auth,
        "control_plane.sales.campaign_updated",
        "sales_enrollment",
        Some(&body.id),
        json!({
            "action": body.action,
            "downstreamAction": downstream_action,
            "upstreamStatus": upstream_status,
        }),
    )
    .await;

    if result.is_ok() {
        crate::routes::admin::dashboard::invalidate_dashboard_cache().await;
    }

    result.map(UpstreamResponse::into_axum_response)
}

// ──────────────────────────────────────────
// Discovery
// ──────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Run sales discovery.
///
/// The control plane does **not** discover markets: it only imports rows that
/// were already enriched into `enriched_companies`. Real discovery (provider
/// fan-out, candidate provenance, budget control) lives in the sales-autopilot
/// service at `POST {base}/discovery/jobs`; when that service is configured
/// this handler proxies the command there and returns its answer verbatim.
/// Without the service the CP degrades to `import_only` mode over
/// `enriched_companies`.
async fn run_discovery(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DiscoveryRequest>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    if body.sources.is_empty() {
        return Err(ApiError::Validation(vec![
            "At least one source required".into()
        ]));
    }

    if configured_sales_autopilot_base_url(&state).is_ok() {
        let payload = serde_json::to_value(&body)
            .map_err(|error| ApiError::Internal(format!("invalid discovery payload: {error}")))?;
        let result = proxy_to_sales_service(
            &state,
            reqwest::Method::POST,
            "/discovery/jobs",
            Some(payload),
        )
        .await;
        let upstream_status = result.as_ref().ok().map(UpstreamResponse::status_u16);
        let job_id = result
            .as_ref()
            .ok()
            .and_then(UpstreamResponse::body_json)
            .and_then(|value| {
                value
                    .get("jobId")
                    .or_else(|| value.get("id"))
                    .and_then(|id| id.as_str())
                    .map(str::to_string)
            });

        log_sales_audit(
            &state.db,
            &auth,
            "control_plane.sales.discovery_run",
            "sales_discovery_job",
            job_id.as_deref(),
            json!({
                "sources": body.sources,
                "categories": body.categories,
                "upstreamStatus": upstream_status,
            }),
        )
        .await;

        return result.map(UpstreamResponse::into_axum_response);
    }

    let job_id = apexmail_lib::id::generate_id("disc", 22);
    if !table_exists(&state.db, "sales_leads").await
        || !table_exists(&state.db, "enriched_companies").await
    {
        log_sales_audit(
            &state.db,
            &auth,
            "control_plane.sales.discovery_run",
            "sales_discovery_job",
            Some(&job_id),
            json!({
                "sources": body.sources,
                "categories": body.categories,
                "status": "unavailable",
            }),
        )
        .await;

        return Ok(Json(serde_json::json!({
            "jobId": job_id,
            "status": "unavailable",
            "mode": "import_only",
            "discovered": 0,
            "imported": 0,
            "message": "discovery requires both sales_leads and enriched_companies tables"
        }))
        .into_response());
    }

    let limit = i64::from(body.max_pages.clamp(1, 10)) * 25;
    // CP admins see every enriched company regardless of which tenant it was
    // enriched for; imported leads are attributed to the system tenant so
    // they show up in the tenant-scoped leads list.
    let rows: Vec<(String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT domain, company_name, industry, description
         FROM enriched_companies
         ORDER BY last_enriched_at DESC
         LIMIT $1",
    )
    .bind(limit)
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

    for (domain, company_name, industry, description) in rows {
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
        .bind(&auth.tenant_id)
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
        .bind(&auth.tenant_id)
        .bind(&lead_id)
        .bind(company_name.unwrap_or_else(|| domain.clone()))
        .bind(&domain)
        .bind(&primary_source)
        .bind(description.or(industry.clone()))
        .execute(&state.db)
        .await?;
        imported += 1;
    }

    log_sales_audit(
        &state.db,
        &auth,
        "control_plane.sales.discovery_run",
        "sales_discovery_job",
        Some(&job_id),
        json!({
            "sources": body.sources,
            "categories": normalized_categories,
            "source": primary_source,
            "discovered": discovered,
            "imported": imported,
        }),
    )
    .await;

    crate::routes::admin::dashboard::invalidate_dashboard_cache().await;

    Ok(Json(serde_json::json!({
        "jobId": job_id,
        "status": "completed",
        "mode": "import_only",
        "discovered": discovered,
        "imported": imported,
        "source": primary_source,
    }))
    .into_response())
}

// ──────────────────────────────────────────
// Outreach
// ──────────────────────────────────────────

const OUTREACH_RATE_LIMIT: u32 = 5;
const OUTREACH_RATE_WINDOW_SECS: u64 = 600;

fn build_outreach_rate_limit_key(tenant_id: &str) -> String {
    format!("apexmail:admin:sales:outreach_rate_limit:{tenant_id}")
}

async fn check_outreach_rate_limit(state: &AppState, tenant_id: &str) -> Result<(), ApiError> {
    let mut conn = state.redis.get().await?;
    let ttl_secs = OUTREACH_RATE_WINDOW_SECS.max(1) as i64;
    let key = build_outreach_rate_limit_key(tenant_id);
    let script = redis::Script::new(
        r#"
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then
            redis.call('EXPIRE', KEYS[1], ARGV[1])
        end
        return count
        "#,
    );
    let count: u32 = script
        .key(key)
        .arg(ttl_secs)
        .invoke_async(&mut *conn)
        .await?;

    if count > OUTREACH_RATE_LIMIT {
        return Err(ApiError::RateLimited);
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct OutreachRequest {
    /// UUID of a `sales_sequences` row.
    pub sequence_id: String,
    /// UUIDs of `sales_contacts` rows (1..=100).
    pub contact_ids: Vec<String>,
    /// UUID of a `sales_jurisdiction_policies` row.
    pub autonomy_policy_id: String,
    #[serde(default)]
    pub experiment_id: Option<String>,
}

/// Start outreach by enrolling contacts in a sequence.
///
/// This is an enrollment command, not a local campaign writer: the CP creates
/// no campaign and no recipient rows. It forwards `{"sequenceId",
/// "contactIds","autonomyPolicyId","experimentId"}` to
/// `POST {base}/enrollments` and returns the service's response verbatim.
/// Without a configured service the call fails closed — there is no local
/// fallback.
async fn start_outreach(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<OutreachRequest>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    if body.contact_ids.is_empty() || body.contact_ids.len() > 100 {
        return Err(ApiError::Validation(vec![
            "1-100 contact IDs allowed".into()
        ]));
    }

    // Keep the existing Redis burst guard on operator-initiated outreach.
    check_outreach_rate_limit(&state, &auth.tenant_id).await?;

    let payload = serde_json::to_value(&body)
        .map_err(|error| ApiError::Internal(format!("invalid outreach payload: {error}")))?;
    let result =
        proxy_to_sales_service(&state, reqwest::Method::POST, "/enrollments", Some(payload)).await;
    let upstream_status = result.as_ref().ok().map(UpstreamResponse::status_u16);
    let batch_id = result
        .as_ref()
        .ok()
        .and_then(UpstreamResponse::body_json)
        .and_then(|value| {
            value
                .get("enrollmentBatchId")
                .and_then(|id| id.as_str())
                .map(str::to_string)
        });

    log_sales_audit(
        &state.db,
        &auth,
        "control_plane.sales.outreach_started",
        "sales_enrollment_batch",
        batch_id.as_deref(),
        json!({
            "sequenceId": body.sequence_id,
            "contactCount": body.contact_ids.len(),
            "autonomyPolicyId": body.autonomy_policy_id,
            "experimentId": body.experiment_id,
            "upstreamStatus": upstream_status,
        }),
    )
    .await;

    if result.is_ok() {
        crate::routes::admin::dashboard::invalidate_dashboard_cache().await;
    }

    result.map(UpstreamResponse::into_axum_response)
}

// ──────────────────────────────────────────
// Settings
// ──────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    // Real database errors propagate — settings are never silently faked.
    let row: Option<(serde_json::Value, serde_json::Value, serde_json::Value)> = sqlx::query_as(
        "SELECT scoring_weights, schedule, notifications
         FROM sales_settings
         WHERE tenant_id = 'system'",
    )
    .fetch_optional(&state.db)
    .await?;

    let settings = match row {
        Some((sw, sc, nf)) => SalesSettings {
            scoring_weights: sw,
            schedule: sc,
            notifications: nf,
        },
        // Explicit defaults only when the system tenant genuinely has no row
        // yet (first run); the first save creates it via the upsert below.
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
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    // Upsert the system tenant's settings row. No runtime DDL: the table and
    // its scoring_weights/schedule/notifications columns are canonical
    // (migrations 069/093/200) and a missing row is created here.
    sqlx::query(
        "INSERT INTO sales_settings (tenant_id, scoring_weights, schedule, notifications, updated_at)
         VALUES ('system', $1, $2, $3, NOW())
         ON CONFLICT (tenant_id) DO UPDATE SET
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

    log_sales_audit(
        &state.db,
        &auth,
        "control_plane.sales.settings_saved",
        "sales_settings",
        Some("1"),
        json!({
            "scoringWeightKeys": body.scoring_weights.as_object().map(|value| value.len()).unwrap_or(0),
            "scheduleKeys": body.schedule.as_object().map(|value| value.len()).unwrap_or(0),
            "notificationKeys": body.notifications.as_object().map(|value| value.len()).unwrap_or(0),
        }),
    )
    .await;

    Ok(Json(serde_json::json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::{test_config, test_state_over_with_config};
    use axum::body::Body;
    use axum::http::Request;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    /// A router exposing the outreach handler at its production path over a
    /// real (lazily connected) AppState. Routes are registered directly rather
    /// than with `nest` because nesting strips the URI prefix, and the
    /// control-plane static API key path guard inspects the full path.
    async fn test_app() -> Router {
        let mut config = test_config();
        config.control_plane_api_key = Some("test-cp-key".into());
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
            .expect("lazy test pool");
        let state = test_state_over_with_config(db, config).await;
        Router::new()
            .route("/v1/admin/sales/outreach/start", post(start_outreach))
            .with_state(state)
    }

    fn outreach_post(contact_ids: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/admin/sales/outreach/start")
            .header("host", "localhost")
            .header("x-api-key", "test-cp-key")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "sequenceId": "11111111-1111-1111-1111-111111111111",
                    "contactIds": contact_ids,
                    "autonomyPolicyId": "33333333-3333-3333-3333-333333333333",
                })
                .to_string(),
            ))
            .unwrap()
    }

    #[test]
    fn build_outreach_rate_limit_key_scopes_by_tenant() {
        assert_eq!(
            build_outreach_rate_limit_key("tenant_123"),
            "apexmail:admin:sales:outreach_rate_limit:tenant_123"
        );
    }

    #[test]
    fn outreach_request_deserializes_the_canonical_camel_case_contract() {
        let request: OutreachRequest = serde_json::from_value(json!({
            "sequenceId": "11111111-1111-1111-1111-111111111111",
            "contactIds": ["22222222-2222-2222-2222-222222222222"],
            "autonomyPolicyId": "33333333-3333-3333-3333-333333333333",
            "experimentId": "44444444-4444-4444-4444-444444444444"
        }))
        .expect("canonical outreach request must deserialize");
        assert_eq!(request.contact_ids.len(), 1);

        // The retired lead/campaign contract must no longer deserialize.
        assert!(serde_json::from_value::<OutreachRequest>(json!({
            "leadIds": ["old_lead_id"],
            "offerId": "legacy_offer"
        }))
        .is_err());
    }

    #[tokio::test]
    async fn outreach_rejects_empty_contact_ids() {
        let app = test_app().await;

        let response = app.oneshot(outreach_post(json!([]))).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn outreach_rejects_more_than_100_contact_ids() {
        let app = test_app().await;
        let too_many: Vec<String> = (0..101).map(|index| format!("contact_{index}")).collect();

        let response = app.oneshot(outreach_post(json!(too_many))).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Fragments are assembled at runtime so the test source itself does not
    /// contain the forbidden strings it scans for.
    #[test]
    fn sales_module_has_no_runtime_ddl_or_retired_tables() {
        let source = include_str!("sales.rs");
        let forbidden = [
            ["CREATE", "TABLE"].join(" "),
            ["ALTER", "TABLE"].join(" "),
            ["drip", "campaigns"].join("_"),
            ["campaign", "recipients"].join("_"),
            ["ensure", "campaign", "tables"].join("_"),
            ["SALES", "SETTINGS", "ENSURE"].join("_"),
        ];
        for fragment in forbidden {
            assert!(
                !source.contains(&fragment),
                "sales.rs must not contain the retired artifact `{fragment}`"
            );
        }
    }
}
