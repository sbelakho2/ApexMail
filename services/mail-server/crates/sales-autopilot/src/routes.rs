use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tower_http::timeout::TimeoutLayer;
use tracing::warn;
use uuid::Uuid;

use crate::{
    calendar::CalendarService,
    campaigns::CampaignManager,
    crm::CrmService,
    enrichment::EnrichmentService,
    inbox::InboxManager,
    types::{LeadStatus, SalesError},
};

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub crm: CrmService,
    pub enrichment: EnrichmentService,
    pub campaigns: CampaignManager,
    pub calendar: CalendarService,
    pub inbox: InboxManager,
    pub service_token: String,
}

/// Build the axum `Router` with all sales-autopilot routes.
pub fn router(state: AppState) -> Router {
    let shared = Arc::new(state);
    Router::new()
// Health (unauthenticated for k8s probes)
        .route("/health", get(health))
// Authenticated routes
        .route("/leads", get(list_leads).post(create_lead))
        .route("/leads/{id}", get(get_lead))
        .route("/companies", get(list_companies))
        .route("/enrich", post(enrich))
        .route("/campaigns", get(list_campaigns).post(create_campaign))
        .route("/campaigns/:id/recipients", post(add_campaign_recipients))
        .route("/campaigns/:id/start", post(start_campaign))
        .route("/campaigns/:id/pause", post(pause_campaign))
        .route("/calendar", get(list_calendar))
        .route("/inbox", get(list_inbox))
        .with_state(shared.clone())
        .layer(DefaultBodyLimit::max(256 * 1024)) // 256 KB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(middleware::from_fn_with_state(shared, require_service_token))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "healthy", "service": "sales-autopilot" }))
}

async fn require_service_token(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
// Skip auth for health checks
    if req.uri().path() == "/health" {
        return Ok(next.run(req).await);
    }
    if state.service_token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let provided = req.headers().get("x-api-key")
        .and_then(|v| v.to_str().ok().map(String::from))
        .or_else(|| {
            req.headers().get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|raw| raw.trim().strip_prefix("Bearer ").map(String::from))
        });
    if provided.as_deref().map_or(false, |p| apexmail_lib::timing_safe_compare(p, &state.service_token)) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

// -- Leads ------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateLeadBody {
    email: String,
    name: String,
    company: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    source: String,
}

#[derive(Deserialize)]
struct LeadQuery {
    status: Option<String>,
    source: Option<String>,
    q: Option<String>,
}

async fn create_lead(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateLeadBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let lead = state.crm.create_lead(
        body.email,
        body.name,
        body.company,
        body.title,
        if body.source.is_empty() { "api".into() } else { body.source },
    );
    json_response(&lead)
}

async fn list_leads(
    State(state): State<Arc<AppState>>,
    Query(q): Query<LeadQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    if let Some(ref search) = q.q {
        let results = state.crm.search_leads(search);
        return json_response(&results);
    }
    let status = q.status.and_then(|s| match s.as_str() {
        "new" => Some(LeadStatus::New),
        "contacted" => Some(LeadStatus::Contacted),
        "qualified" => Some(LeadStatus::Qualified),
        "converted" => Some(LeadStatus::Converted),
        "lost" => Some(LeadStatus::Lost),
        _ => None,
    });
    let leads = state.crm.list_leads(status, q.source.as_deref());
    json_response(&leads)
}

async fn get_lead(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let lead = state.crm.get_lead(id)?;
    json_response(&lead)
}

// -- Companies / Enrichment -------------------------------------------------

#[derive(Debug, Deserialize)]
struct CompanyQuery {
    #[serde(default)]
    industry: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

#[derive(sqlx::FromRow, serde::Serialize)]
struct EnrichedCompanyRow {
    id: Uuid,
    domain: String,
    company_name: Option<String>,
    industry: Option<String>,
    employee_count: Option<String>,
    annual_revenue: Option<String>,
    funding_stage: Option<String>,
    headquarters: Option<String>,
    founded_year: Option<i32>,
    description: Option<String>,
    linkedin_url: Option<String>,
    email_provider: Option<String>,
    confidence_score: f64,
    last_enriched_at: chrono::DateTime<chrono::Utc>,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn list_companies(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CompanyQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).clamp(0, 100_000);

    let rows = if let Some(ref industry) = q.industry {
        let escaped = escape_like_pattern(industry);
        sqlx::query_as::<_, EnrichedCompanyRow>(
            "SELECT id, domain, company_name, industry, employee_count, annual_revenue,
                    funding_stage, headquarters, founded_year, description, linkedin_url,
                    email_provider, confidence_score, last_enriched_at, created_at
             FROM enriched_companies
             WHERE industry ILIKE $1 ESCAPE '\\'
             ORDER BY last_enriched_at DESC
             LIMIT $2 OFFSET $3",
        )
        .bind(format!("%{}%", escaped))
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
        .map_err(|e| SalesError::Internal(anyhow::anyhow!(e)))?
    } else {
        sqlx::query_as::<_, EnrichedCompanyRow>(
            "SELECT id, domain, company_name, industry, employee_count, annual_revenue,
                    funding_stage, headquarters, founded_year, description, linkedin_url,
                    email_provider, confidence_score, last_enriched_at, created_at
             FROM enriched_companies
             ORDER BY last_enriched_at DESC
             LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
        .map_err(|e| SalesError::Internal(anyhow::anyhow!(e)))?
    };

    json_response(&rows)
}

#[derive(Deserialize)]
struct EnrichBody {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
}

async fn enrich(
    State(state): State<Arc<AppState>>,
    Json(body): Json<EnrichBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let company = if let Some(email) = body.email.as_deref() {
        state.enrichment.enrich_lead(email)?
    } else if let Some(domain) = body.domain.as_deref() {
        state.enrichment.enrich_company(domain)?
    } else {
        return Err(SalesError::InvalidInput("email or domain is required".into()));
    };
    let tenant_id = body.tenant_id.unwrap_or_else(|| "default".to_string());

// Persist to enriched_companies table
    if let Err(error) = sqlx::query(
        "INSERT INTO enriched_companies (
            id, tenant_id, domain, company_name, industry, employee_count,
            annual_revenue, confidence_score, last_enriched_at, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $9)
         ON CONFLICT (tenant_id, domain) DO UPDATE SET
            company_name = EXCLUDED.company_name,
            industry = EXCLUDED.industry,
            employee_count = EXCLUDED.employee_count,
            annual_revenue = EXCLUDED.annual_revenue,
            confidence_score = EXCLUDED.confidence_score,
            last_enriched_at = EXCLUDED.last_enriched_at,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(company.id)
    .bind(&tenant_id)
    .bind(&company.domain)
    .bind(&company.name)
    .bind(&company.industry)
    .bind(&company.size)
    .bind(&company.revenue_range)
    .bind(0.85f64) // Default confidence score
    .bind(company.enriched_at)
    .execute(&state.db)
    .await
    {
        warn!(email = ?body.email, domain = ?body.domain, tenant_id = %tenant_id, error = %error, "Failed to persist enriched company cache entry");
    }

    json_response(&company)
}

// -- Campaigns --------------------------------------------------------------

#[derive(Deserialize)]
struct CreateCampaignBody {
    name: String,
    template_id: String,
    #[serde(default)]
    audience: String,
}

async fn create_campaign(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateCampaignBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let c = state
        .campaigns
        .create_campaign(body.name, body.template_id, body.audience)?;
    json_response(&c)
}

async fn list_campaigns(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let campaigns = state.campaigns.list_campaigns();
    json_response(&campaigns)
}

#[derive(Deserialize)]
struct RecipientBody {
    emails: Vec<String>,
}

async fn add_campaign_recipients(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(body): Json<RecipientBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    if body.emails.is_empty() {
        return Err(SalesError::InvalidInput("at least one recipient email is required".into()));
    }

    let added = state.campaigns.add_recipients(id, body.emails)?;
    json_response(&serde_json::json!({ "campaignId": id, "added": added }))
}

async fn start_campaign(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let campaign = state.campaigns.start_campaign(id)?;
    json_response(&campaign)
}

async fn pause_campaign(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let campaign = state.campaigns.pause_campaign(id)?;
    json_response(&campaign)
}

// -- Calendar ---------------------------------------------------------------

#[derive(Deserialize)]
struct CalendarQuery {
    from: Option<String>,
    to: Option<String>,
}

async fn list_calendar(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CalendarQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    use chrono::{DateTime, Utc};
    let from: DateTime<Utc> = q
        .from
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(Utc::now);
    let to: DateTime<Utc> = q
        .to
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| from + chrono::Duration::days(7));
    let events = state.calendar.list_events(from, to);
    json_response(&events)
}

// -- Inbox ------------------------------------------------------------------

#[derive(Deserialize)]
struct InboxQuery {
    category: Option<String>,
}

async fn list_inbox(
    State(state): State<Arc<AppState>>,
    Query(q): Query<InboxQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    use crate::types::MessageCategory;
    let cat = q.category.and_then(|c| match c.as_str() {
        "lead" => Some(MessageCategory::Lead),
        "customer" => Some(MessageCategory::Customer),
        "support" => Some(MessageCategory::Support),
        "spam" => Some(MessageCategory::Spam),
        _ => Some(MessageCategory::Other),
    });
    let msgs = if let Some(c) = cat {
        state.inbox.list_by_category(c)
    } else {
        state.inbox.list_all()
    };
    json_response(&msgs)
}

fn json_response<T: Serialize>(value: &T) -> Result<Json<serde_json::Value>, SalesError> {
    serde_json::to_value(value)
        .map(Json)
        .map_err(|err| SalesError::Internal(anyhow::anyhow!(err)))
}

fn escape_like_pattern(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let state = AppState {
            db,
            crm: CrmService::new(),
            enrichment: EnrichmentService::new("http://mock"),
            campaigns: CampaignManager::new(10),
            calendar: CalendarService::new(),
            inbox: InboxManager::new(),
            service_token: "test-key".into(),
        };
        router(state)
    }

    #[tokio::test]
    async fn test_health() {
        let app = test_app();
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_and_list_leads() {
        let app = test_app();
        let body = serde_json::json!({
            "email": "alice@acme.com",
            "name": "Alice",
            "company": "Acme",
        });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/leads")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

// list
        let resp2 = app
            .oneshot(
                Request::get("/leads")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_enrich_endpoint() {
        let app = test_app();
        let body = serde_json::json!({ "email": "bob@beta.io" });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let domain_body = serde_json::json!({ "domain": "acme.com" });
        let domain_resp = app
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&domain_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(domain_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_campaign_lifecycle_endpoints() {
        let app = test_app();
        let create_body = serde_json::json!({
            "name": "Migration wave",
            "template_id": "tmpl_competitor_migration",
            "audience": "selected-leads"
        });

        let create_resp = app
            .clone()
            .oneshot(
                Request::post("/campaigns")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);

        let created: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(create_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let campaign_id = created["id"].as_str().unwrap();

        let recipients_body = serde_json::json!({
            "emails": ["alice@acme.com", "bob@beta.io"]
        });
        let recipients_resp = app
            .clone()
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/recipients"))
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&recipients_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recipients_resp.status(), StatusCode::OK);

        let start_resp = app
            .clone()
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/start"))
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start_resp.status(), StatusCode::OK);

        let started: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(start_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(started["status"], "active");

        let pause_resp = app
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/pause"))
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pause_resp.status(), StatusCode::OK);

        let paused: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(pause_resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(paused["status"], "paused");
    }
}
