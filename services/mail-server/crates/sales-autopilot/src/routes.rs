use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use sqlx::PgPool;
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
}

/// Build the axum `Router` with all sales-autopilot routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        // Health
        .route("/health", get(health))
        // Leads
        .route("/leads", get(list_leads).post(create_lead))
        .route("/leads/{id}", get(get_lead))
        // Companies (enrichment)
        .route("/companies", get(list_companies))
        .route("/enrich", post(enrich))
        // Campaigns
        .route("/campaigns", get(list_campaigns).post(create_campaign))
        // Calendar
        .route("/calendar", get(list_calendar))
        // Inbox
        .route("/inbox", get(list_inbox))
        .with_state(Arc::new(state))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "healthy", "service": "sales-autopilot" }))
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
    Ok(Json(serde_json::to_value(&lead).unwrap()))
}

async fn list_leads(
    State(state): State<Arc<AppState>>,
    Query(q): Query<LeadQuery>,
) -> Json<serde_json::Value> {
    if let Some(ref search) = q.q {
        let results = state.crm.search_leads(search);
        return Json(serde_json::to_value(&results).unwrap());
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
    Json(serde_json::to_value(&leads).unwrap())
}

async fn get_lead(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let lead = state.crm.get_lead(id)?;
    Ok(Json(serde_json::to_value(&lead).unwrap()))
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
    confidence_score: sqlx::types::BigDecimal,
    last_enriched_at: chrono::DateTime<chrono::Utc>,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn list_companies(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CompanyQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let limit = q.limit.unwrap_or(100).min(500);
    let offset = q.offset.unwrap_or(0);

    let rows = if let Some(ref industry) = q.industry {
        sqlx::query_as::<_, EnrichedCompanyRow>(
            "SELECT id, domain, company_name, industry, employee_count, annual_revenue,
                    funding_stage, headquarters, founded_year, description, linkedin_url,
                    email_provider, confidence_score, last_enriched_at, created_at
             FROM enriched_companies
             WHERE industry ILIKE $1
             ORDER BY last_enriched_at DESC
             LIMIT $2 OFFSET $3",
        )
        .bind(format!("%{}%", industry))
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
        .map_err(|e| SalesError::Internal(e.to_string()))?
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
        .map_err(|e| SalesError::Internal(e.to_string()))?
    };

    Ok(Json(serde_json::to_value(&rows).unwrap()))
}

#[derive(Deserialize)]
struct EnrichBody {
    email: String,
    #[serde(default)]
    tenant_id: Option<String>,
}

async fn enrich(
    State(state): State<Arc<AppState>>,
    Json(body): Json<EnrichBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let company = state.enrichment.enrich_lead(&body.email)?;
    let tenant_id = body.tenant_id.unwrap_or_else(|| "default".to_string());

    // Persist to enriched_companies table
    sqlx::query(
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
    .map_err(|e| SalesError::Internal(e.to_string()))?;

    Ok(Json(serde_json::to_value(&company).unwrap()))
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
    Ok(Json(serde_json::to_value(&c).unwrap()))
}

async fn list_campaigns(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let campaigns = state.campaigns.list_campaigns();
    Json(serde_json::to_value(&campaigns).unwrap())
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
) -> Json<serde_json::Value> {
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
    Json(serde_json::to_value(&events).unwrap())
}

// -- Inbox ------------------------------------------------------------------

#[derive(Deserialize)]
struct InboxQuery {
    category: Option<String>,
}

async fn list_inbox(
    State(state): State<Arc<AppState>>,
    Query(q): Query<InboxQuery>,
) -> Json<serde_json::Value> {
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
        // return all
        state.inbox.list_by_category(MessageCategory::Lead)
    };
    Json(serde_json::to_value(&msgs).unwrap())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_app() -> Router {
        let state = AppState {
            crm: CrmService::new(),
            enrichment: EnrichmentService::new("http://mock"),
            campaigns: CampaignManager::new(10),
            calendar: CalendarService::new(),
            inbox: InboxManager::new(),
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
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // list
        let resp2 = app
            .oneshot(Request::get("/leads").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_enrich_endpoint() {
        let app = test_app();
        let body = serde_json::json!({ "email": "bob@beta.io" });
        let resp = app
            .oneshot(
                Request::post("/enrich")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
