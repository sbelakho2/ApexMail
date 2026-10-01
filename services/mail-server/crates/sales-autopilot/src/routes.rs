use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use axum::{
    extract::{DefaultBodyLimit, FromRequestParts, Path, Query, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
    Json, Router,
};
use metrics::{counter, gauge};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::Instrument;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    calendar::CalendarService,
    campaigns::CampaignManager,
    config,
    config::SalesConfig,
    control,
    crm::CrmBackend,
    discovery::{default_sources, DiscoveryJobRunner, DiscoveryQuery},
    dispatcher::ProductionCampaignDispatcher,
    enrichment::EnrichmentService,
    inbox::InboxManager,
    intelligence::SalesIntelligence,
    personalization::MessageStrategist,
    types::{CreateConversionBody, LeadStatus, SalesError},
};

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: deadpool_redis::Pool,
    pub crm: CrmBackend,
    pub enrichment: EnrichmentService,
    pub campaigns: CampaignManager,
    /// The production campaign dispatcher, when configured
    /// (SALES_CAMPAIGN_FROM_EMAIL + SALES_UNSUBSCRIBE_SECRET). `None` ⇒
    /// campaign start refuses with 503 (fix I-1 semantics preserved).
    pub dispatcher: Option<Arc<ProductionCampaignDispatcher>>,
    pub calendar: CalendarService,
    pub inbox: InboxManager,
    pub service_token: String,
    /// Sales autopilot configuration.
    pub config: SalesConfig,
    /// In-memory rate limit fallback used when Redis is unavailable.
    pub rate_limit_fallback: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
    /// §12 — the configured evidence-grounded intelligence provider (or the
    /// deterministic offline implementation when no AI service is configured).
    pub intelligence: Arc<dyn SalesIntelligence>,
    /// §13/§14 — the structured message strategist, bound to the canonical
    /// verified knowledge base.
    pub strategist: Arc<MessageStrategist>,
}

/// An in-memory rate-limit window entry (count + window start).
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub count: u64,
    pub window_start: Instant,
}

const ENRICH_RATE_LIMIT_MAX_REQUESTS: usize = 30;
const ENRICH_RATE_LIMIT_WINDOW_SECS: u64 = 60;

const RATE_LIMITER_REDIS_PREFIX: &str = "apexmail:enrichment_rate:";

// ---------------------------------------------------------------------------
// Tenant-ID extractor — reads `x-tenant-id` from request headers.
// ---------------------------------------------------------------------------

/// A validated tenant ID extracted from the `x-tenant-id` request header.
#[derive(Debug, Clone)]
pub struct TenantId(pub String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for TenantId
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let tenant_id = parts
            .headers
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or(StatusCode::BAD_REQUEST)?;
        Ok(TenantId(tenant_id.to_string()))
    }
}

/// Verify the database schema this service requires.
///
/// Retained under its historical name so existing callers keep compiling, but
/// the behaviour is now a **verification**, not a bootstrap. This function
/// used to create every sales table at runtime with `CREATE TABLE IF NOT
/// EXISTS` / `ALTER TABLE IF NOT EXISTS`, which made the effective schema
/// depend on which service started first and meant a deployment could serve
/// traffic against a schema no migration described. Schema ownership is now
/// deterministic: the canonical migration chain owns it, and this function
/// refuses to run against anything else.
///
/// See [`crate::schema::verify`] for the required/retired manifest.
pub async fn initialize_schema(db: &PgPool) -> Result<(), SalesError> {
    crate::schema::verify(db).await
}

/// Build the axum `Router` with all sales-autopilot routes.
///
/// Note: this workspace resolves to axum 0.7 (matchit 0.7), whose path
/// parameter syntax is `:param`. Curly-brace segments (`{param}`) would be
/// treated as literals and never match.
pub fn router(state: AppState) -> Router {
    let shared = Arc::new(state);
    Router::new()
        // Health (unauthenticated for k8s probes)
        .route("/health", get(health))
        // Authenticated routes
        .route("/leads", get(list_leads).post(create_lead))
        .route("/leads/:id", get(get_lead))
        .route("/companies", get(list_companies))
        .route("/enrich", post(enrich))
        .route("/campaigns", get(list_campaigns).post(create_campaign))
        .route("/campaigns/:id/recipients", post(add_campaign_recipients))
        .route("/campaigns/:id/start", post(start_campaign))
        .route("/campaigns/:id/pause", post(pause_campaign))
        .route("/campaigns/:id/dry-run", post(dry_run_campaign))
        // Public unsubscribe endpoints (CAN-SPAM / RFC 8058). Auth is by
        // HMAC-signed token, not the shared service token — see
        // `require_service_token`'s path exemption and the handlers below.
        .route("/u/:token", get(unsubscribe_get).post(unsubscribe_post))
        // F39 (batch 2): the manual unsubscribe is a two-step, no-JS flow —
        // GET /u/:token renders the side-effect-free confirmation form whose
        // submit POSTs here. Kept a separate route so the RFC 8058 one-click
        // POST contract on /u/:token stays untouched.
        .route("/u/:token/confirm", post(unsubscribe_confirm_post))
        .route("/calendar", get(list_calendar))
        .route("/calendar/events", post(create_calendar_event))
        .route("/calendar/events/:id", delete(cancel_calendar_event))
        .route("/calendar/slots", get(find_calendar_slots))
        .route("/inbox", get(list_inbox))
        .route("/inbox/:id/reply", post(reply_inbox_message))
        // Conversion tracking (SALES-03)
        .route(
            "/conversions",
            get(list_conversions).post(create_conversion),
        )
        // ── Discovery (provider-backed; the CP proxies POST /discovery/jobs) ─
        .route("/discovery/jobs", post(create_discovery_job))
        .route("/discovery/jobs/:id", get(get_discovery_job))
        .route("/discovery/jobs/:id/run", post(run_discovery_job))
        // ── Control surface ────────────────────────────────────────────────
        // The authenticated read/steer API the ApexMail control plane proxies
        // to. This is the ONLY sales brain; the CP holds no decision logic of
        // its own.
        .route("/control/overview", get(control::overview))
        .route("/control/decisions", get(control::decisions))
        .route("/control/exceptions", get(control::exceptions))
        .route("/control/actions", get(control::actions))
        .route("/control/mode", post(control::set_mode))
        .route("/control/pause", post(control::pause))
        .route("/control/resume", post(control::resume))
        .route("/control/kill-switch", post(control::kill_switch))
        .route(
            "/control/decisions/:id/review",
            post(control::review_decision),
        )
        .route("/control/actions/:id/replay", post(control::replay_action))
        // ── Enrollments (canonical outreach command + read model) ──────────
        .route(
            "/enrollments",
            get(control::list_enrollments).post(control::start_outreach),
        )
        .route(
            "/enrollments/:id/:action",
            post(control::set_enrollment_state),
        )
        .with_state(shared.clone())
        .layer(DefaultBodyLimit::max(256 * 1024)) // 256 KB
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(middleware::from_fn_with_state(
            shared,
            require_service_token,
        ))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health(State(state): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    let db_healthy = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();

    let status = if db_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(serde_json::json!({
            "status": if db_healthy { "healthy" } else { "degraded" },
            "service": "sales-autopilot",
            "database": if db_healthy { "up" } else { "down" },
        })),
    )
}

async fn require_service_token(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for health checks and the PUBLIC unsubscribe endpoints
    // (`/u/:token` and, batch 2, its `/u/:token/confirm` confirmation
    // submit) — recipient clicks arrive from mail clients with no service
    // token; authenticity comes from the HMAC token signature. The
    // `/u/` prefix match covers BOTH routes.
    let path = req.uri().path();
    if path == "/health" || path.starts_with("/u/") {
        return Ok(next.run(req).await);
    }
    if state.service_token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok().map(String::from))
        .or_else(|| {
            req.headers()
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|raw| raw.trim().strip_prefix("Bearer ").map(String::from))
        });
    if provided
        .as_deref()
        .is_some_and(|p| apexmail_lib::timing_safe_compare(p, &state.service_token))
    {
        // System-tenant hard restriction: this service is the platform
        // OWNER's sales brain. The single shared internal token authenticates
        // the CALLER; the tenant claim in `x-tenant-id` is then hard-checked
        // against the system tenant. Customer automation execution lives in
        // `worker-processors`, so there is no customer surface left to serve
        // — a non-system tenant claim cannot be honoured and is refused
        // outright. Boot enforces the same restriction for the deployment
        // configuration (`config::require_system_tenant_scope`).
        if let Some(tenant) = req
            .headers()
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            if tenant != config::SYSTEM_TENANT_ID {
                warn!(
                    tenant_id = %tenant,
                    "tenant rejected: sales-autopilot serves the system tenant only"
                );
                return Err(StatusCode::FORBIDDEN);
            }
        }
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn normalize_pagination(
    limit: Option<i64>,
    offset: Option<i64>,
    default_limit: i64,
    max_limit: i64,
) -> (i64, i64) {
    (
        limit.unwrap_or(default_limit).clamp(1, max_limit),
        offset.unwrap_or(0).clamp(0, 100_000),
    )
}

/// Redis-backed enrichment rate limiter: 30 req / 60 s per tenant.
/// Uses a Lua script so the INCR and the window EXPIRE happen atomically —
/// a crash between separate INCR and EXPIRE calls would otherwise leave a
/// key with no TTL that permanently rate-limits the tenant.
/// When Redis is unavailable, falls back to an in-memory rate limiter
/// (provided via `fallback`) so that rate limiting is not completely
/// degraded on Redis outage.
async fn enforce_enrichment_rate_limit(
    redis: &deadpool_redis::Pool,
    tenant_id: &str,
    fallback: Option<&Arc<Mutex<HashMap<String, RateLimitEntry>>>>,
) -> Result<(), SalesError> {
    let mut conn = match redis.get().await {
        Ok(conn) => conn,
        Err(e) => {
            warn!(
                error = %e,
                "redis pool unavailable — using in-memory fallback rate limiter"
            );
            return enforce_in_memory_rate_limit(fallback, tenant_id);
        }
    };

    let key = format!("{RATE_LIMITER_REDIS_PREFIX}{tenant_id}");

    // Atomically increment the counter and set the TTL on the first request
    // of each window, in a single Redis round trip. (redis-rs's Script API
    // places the key into KEYS[1] with the correct numkeys argument.)
    let rate_limit_script = redis::Script::new(
        r"local c = redis.call('INCR', KEYS[1]) if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end return c",
    );
    let count: u64 = rate_limit_script
        .key(&key)
        .arg(ENRICH_RATE_LIMIT_WINDOW_SECS)
        .invoke_async(&mut *conn)
        .await
        .map_err(|e| SalesError::Internal(anyhow::anyhow!("redis rate-limit EVAL error: {e}")))?;

    // Emit aggregate metrics for observability. The raw tenant_id is
    // deliberately NOT used as a label: unbounded label cardinality would
    // explode the Prometheus time series count.
    counter!("sales_autopilot_rate_limit_hits_total").increment(1);
    let remaining = (ENRICH_RATE_LIMIT_MAX_REQUESTS as u64).saturating_sub(count);
    gauge!("sales_autopilot_rate_limit_remaining").set(remaining as f64);

    if count > ENRICH_RATE_LIMIT_MAX_REQUESTS as u64 {
        warn!(
            tenant_id = %tenant_id,
            current_count = count,
            max_requests = ENRICH_RATE_LIMIT_MAX_REQUESTS,
            window_secs = ENRICH_RATE_LIMIT_WINDOW_SECS,
            "enrichment rate limit exceeded for tenant"
        );
        return Err(SalesError::RateLimited(
            "enrichment rate limit exceeded".into(),
        ));
    }

    info!(
        tenant_id = %tenant_id,
        current_count = count,
        max_requests = ENRICH_RATE_LIMIT_MAX_REQUESTS,
        window_secs = ENRICH_RATE_LIMIT_WINDOW_SECS,
        "enrichment request allowed"
    );

    Ok(())
}

/// In-memory fallback rate limiter used when Redis is unavailable.
/// Tracks per-tenant request counts with sliding windows.
fn enforce_in_memory_rate_limit(
    fallback: Option<&Arc<Mutex<HashMap<String, RateLimitEntry>>>>,
    tenant_id: &str,
) -> Result<(), SalesError> {
    let guard = match fallback {
        Some(g) => g,
        None => {
            // No fallback available — allow the request (fully degraded).
            warn!("rate limit fallback not configured — allowing enrichment request");
            return Ok(());
        }
    };

    let mut map = guard.lock();

    let now = Instant::now();
    let window = Duration::from_secs(ENRICH_RATE_LIMIT_WINDOW_SECS);

    let entry = map.entry(tenant_id.to_string()).or_insert(RateLimitEntry {
        count: 0,
        window_start: now,
    });

    // Reset window if expired
    if now.duration_since(entry.window_start) > window {
        entry.count = 0;
        entry.window_start = now;
    }

    entry.count += 1;

    if entry.count > ENRICH_RATE_LIMIT_MAX_REQUESTS as u64 {
        warn!(
            tenant_id = %tenant_id,
            current_count = entry.count,
            max_requests = ENRICH_RATE_LIMIT_MAX_REQUESTS,
            window_secs = ENRICH_RATE_LIMIT_WINDOW_SECS,
            "enrichment rate limit exceeded for tenant (in-memory fallback)"
        );
        return Err(SalesError::RateLimited(
            "enrichment rate limit exceeded".into(),
        ));
    }

    info!(
        tenant_id = %tenant_id,
        current_count = entry.count,
        max_requests = ENRICH_RATE_LIMIT_MAX_REQUESTS,
        window_secs = ENRICH_RATE_LIMIT_WINDOW_SECS,
        "enrichment request allowed (in-memory fallback)"
    );

    Ok(())
}

// -- Leads ------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateLeadBody {
    email: String,
    name: String,
    company: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    tenant_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeadQuery {
    status: Option<String>,
    source: Option<String>,
    q: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    tenant_id: Option<String>,
}

#[axum::debug_handler]
async fn create_lead(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<CreateLeadBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = required_tenant_id(&tenant_id.0, body.tenant_id.as_deref())?;
    let span =
        tracing::info_span!("create_lead", tenant_id = %tenant_id, operation = "create_lead");
    async move {
        let lead = state
            .crm
            .create_lead(
                &tenant_id,
                body.email,
                body.name,
                body.company,
                body.title,
                if body.source.is_empty() {
                    "api".into()
                } else {
                    body.source
                },
            )
            .await?;

        // SA-1: Wire lead scoring into the creation pipeline.
        // Previously, `score_lead()` existed as dead code — it was defined
        // in `crm.rs` and re-exported by `crm_pg.rs` but never called from
        // any route handler, so all leads were created with score: 0.
        //
        // We now attempt to enrich the lead's company domain and compute a
        // score from the enrichment data. If enrichment fails (e.g. no API
        // configured), we compute a minimal default score of 10 so the
        // scoring pipeline is live and observable.
        let score =
            compute_lead_score(&state.enrichment, &lead.email, &lead.company, &state.config).await;
        if let Err(e) = state.crm.set_lead_score(&lead.id, score, &tenant_id).await {
            tracing::warn!(error = %e, lead_id = %lead.id, "failed to set lead score (non-fatal)");
        }
        let mut enriched_lead = lead;
        enriched_lead.score = score;

        json_response(&enriched_lead)
    }
    .instrument(span)
    .await
}

/// Compute a lead score (0–100) from enrichment data.
///
/// Uses the `CrmService::score_lead(engagement, company_size, recency)`
/// function. At lead creation time, engagement data is unavailable, so we
/// derive the score from company firmographics (industry + employee count).
///
/// Scoring dimensions:
/// - If enrichment provides a known industry → 30 base points
/// - If enrichment provides employee size → 20 base points
/// - If enrichment succeeds at all → 10 base points
///   Combined with a default recency score of 30 (new lead).
///
/// When enrichment is unavailable (mock disabled, no API), returns a
/// baseline score of 10 so the pipeline is visibly active.
/// Compute a lead score (0–100) from enrichment data.
///
/// Uses the `CrmService::score_lead(engagement, company_size, recency)`
/// function. At lead creation time, engagement data is unavailable, so we
/// derive the score from company firmographics (industry + employee count).
///
/// Scoring dimensions:
/// - If enrichment provides a known industry → 30 base points
/// - If enrichment provides employee size → 20 base points
/// - If enrichment succeeds at all → 10 base points
///   Combined with a default recency score of 30 (new lead).
///
/// When enrichment is unavailable (mock disabled, no API), returns a
/// baseline score of 10 so the pipeline is visibly active.
///
/// Uses configurable weights from `SalesConfig::lead_scoring` (SALES-01).
async fn compute_lead_score(
    enrichment: &EnrichmentService,
    email: &str,
    _company_name: &str,
    config: &SalesConfig,
) -> u8 {
    // Extract configurable scoring weights (SALES-01).
    let ew = config.lead_scoring.engagement_weight;
    let csw = config.lead_scoring.company_size_weight;
    let rw = config.lead_scoring.recency_weight;

    // Attempt enrichment. This is best-effort — failure is non-fatal.
    let company = enrichment.enrich_lead(email).await.ok();

    if let Some(ref c) = company {
        // We have enrichment data: compute a meaningful score.
        // engagement: unknown at creation → 0.3 (placeholder)
        // company_size: derived from employee count band
        let company_size = match c.size.as_str() {
            "1-10" => 0.2,
            "10-50" => 0.4,
            "50-200" => 0.6,
            "200-1000" => 0.8,
            "1000+" => 1.0,
            _ => 0.3, // unknown → conservative 0.3
        };
        // recency: newly created lead → maximum
        let recency = 1.0;
        // engagement: if we have a known industry, assume moderate engagement
        let engagement = if c.industry != "Unknown" { 0.5 } else { 0.3 };

        crate::crm::CrmService::score_lead_with_weights(
            engagement,
            company_size,
            recency,
            ew,
            csw,
            rw,
        )
    } else {
        // No enrichment data available. Return a baseline score of 10
        // so the scoring pipeline is visibly live (SA-1).
        10
    }
}

async fn list_leads(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(q): Query<LeadQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = required_tenant_id(&tenant_id.0, q.tenant_id.as_deref())?;
    let span = tracing::info_span!("list_leads", tenant_id = %tenant_id, operation = "list_leads");
    async move {
        let (limit, offset) = normalize_pagination(q.limit, q.offset, 100, 500);

        if let Some(ref search) = q.q {
            let results = state
                .crm
                .search_leads(&tenant_id, search, limit, offset)
                .await?;
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
        let leads = state
            .crm
            .list_leads(&tenant_id, status, q.source.as_deref(), limit, offset)
            .await?;
        json_response(&leads)
    }
    .instrument(span)
    .await
}

async fn get_lead(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    // `sales_leads.id` is TEXT and lead ids are not necessarily UUIDs
    // (api-server uses "lead_<timestamp>", other services nanoid/ULID),
    // so the path parameter is taken as a raw string.
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = tenant_id.0;
    let span = tracing::info_span!("get_lead", tenant_id = %tenant_id, lead_id = %id, operation = "get_lead");
    async move {
        let lead = state.crm.get_lead(&id, &tenant_id).await?;
        json_response(&lead)
    }
    .instrument(span)
    .await
}

// -- Companies / Enrichment -------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompanyQuery {
    #[serde(default)]
    industry: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    tenant_id: Option<String>,
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
    tenant_id: TenantId,
    Query(q): Query<CompanyQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let (limit, offset) = normalize_pagination(q.limit, q.offset, 100, 500);
    let tenant_id = required_tenant_id(&tenant_id.0, q.tenant_id.as_deref())?;
    let span =
        tracing::info_span!("list_companies", tenant_id = %tenant_id, operation = "list_companies");
    async move {
        let rows = if let Some(ref industry) = q.industry {
            let escaped = escape_like_pattern(industry);
            sqlx::query_as::<_, EnrichedCompanyRow>(
                "SELECT id, domain, company_name, industry, employee_count, annual_revenue,
                        funding_stage, headquarters, founded_year, description, linkedin_url,
                        email_provider, confidence_score, last_enriched_at, created_at
                 FROM enriched_companies
                 WHERE tenant_id = $1
                   AND industry ILIKE $2 ESCAPE '\\'
                 ORDER BY last_enriched_at DESC
                 LIMIT $3 OFFSET $4",
            )
            .bind(&tenant_id)
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
                   WHERE tenant_id = $1
                 ORDER BY last_enriched_at DESC
                   LIMIT $2 OFFSET $3",
            )
            .bind(&tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.db)
            .await
            .map_err(|e| SalesError::Internal(anyhow::anyhow!(e)))?
        };

        json_response(&rows)
    }
    .instrument(span)
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    tenant_id: TenantId,
    Json(body): Json<EnrichBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = required_tenant_id(&tenant_id.0, body.tenant_id.as_deref())?;
    let span = tracing::info_span!("enrich", tenant_id = %tenant_id, operation = "enrich");
    async move {
        enforce_enrichment_rate_limit(&state.redis, &tenant_id, Some(&state.rate_limit_fallback))
            .await?;

        // Resolve the company domain and keep the email (when present) so the
        // waterfall can also target people/deliverability fields.
        let (domain, email) = if let Some(email) = body.email.as_deref() {
            let domain = EnrichmentService::extract_domain(email)
                .ok_or_else(|| SalesError::InvalidInput(format!("bad email: {email}")))?;
            (domain, Some(email))
        } else if let Some(domain) = body.domain.as_deref() {
            (domain.trim().to_ascii_lowercase(), None)
        } else {
            return Err(SalesError::InvalidInput(
                "email or domain is required".into(),
            ));
        };

        // Durable path: routed waterfall → sales_evidence + provenance-
        // carrying `sales_enrichment_facts` → `enriched_companies` projection.
        //
        // When the database is unavailable the enrichment answer is still
        // returned (matching the historical non-fatal cache-write semantics),
        // but it is explicitly unpersisted and logged — never silent.
        let company = match state
            .enrichment
            .enrich_persisted(&state.db, &tenant_id, &domain, email, None)
            .await
        {
            Ok(persisted) => persisted.company,
            Err(SalesError::Database(error)) => {
                warn!(
                    tenant_id = %tenant_id,
                    domain = %domain,
                    error = %error,
                    "enrichment persistence unavailable — returning unpersisted company"
                );
                state.enrichment.enrich_company(&domain).await?
            }
            Err(other) => return Err(other),
        };

        json_response(&company)
    }
    .instrument(span)
    .await
}

// -- Discovery --------------------------------------------------------------

/// Body accepted from the control plane's `POST /v1/admin/sales/discovery/run`
/// proxy (`DiscoveryRequest` in api-server's `routes/admin/sales.rs`, which
/// serializes camelCase: `sources`, `categories`, `maxPages`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateDiscoveryJobBody {
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    categories: Option<Vec<String>>,
    #[serde(default)]
    keywords: Option<Vec<String>>,
    #[serde(default)]
    industries: Option<Vec<String>>,
    #[serde(default)]
    countries: Option<Vec<String>>,
    /// The CP sends `maxPages`; `max_pages` is accepted for direct callers.
    #[serde(default, alias = "maxPages")]
    max_pages: Option<i32>,
    #[serde(default)]
    tenant_id: Option<String>,
}

fn discovery_runner(state: &AppState, tenant_id: &str) -> DiscoveryJobRunner {
    DiscoveryJobRunner::new(
        state.db.clone(),
        default_sources(&state.db, &state.config, tenant_id),
    )
}

fn trimmed_terms(values: Option<Vec<String>>, max_terms: usize) -> Vec<String> {
    values
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .take(max_terms)
        .collect()
}

/// `POST /discovery/jobs` — create a queued discovery job.
async fn create_discovery_job(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<CreateDiscoveryJobBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = required_tenant_id(&tenant_id.0, body.tenant_id.as_deref())?;
    let span = tracing::info_span!(
        "create_discovery_job",
        tenant_id = %tenant_id,
        operation = "create_discovery_job"
    );
    async move {
        // Accepted values come from either the CP form (categories) or a
        // direct caller (industries); cap every term list so a hostile body
        // cannot build an unbounded job payload.
        let mut industries = trimmed_terms(body.industries, 32);
        if industries.is_empty() {
            industries = trimmed_terms(body.categories.clone(), 32);
        }
        let query = DiscoveryQuery {
            keywords: trimmed_terms(body.keywords, 32),
            industries,
            countries: trimmed_terms(body.countries, 32),
            max_results: body.max_pages.unwrap_or(3).clamp(1, 10) as usize * 25,
            categories: trimmed_terms(body.categories, 32),
        };

        let runner = discovery_runner(&state, &tenant_id);
        // Unknown source names are recorded as requested but do not disable
        // discovery: the runner falls back to every configured source.
        let job = runner.create_job(&tenant_id, &query, &body.sources).await?;

        Ok(Json(serde_json::json!({
            "jobId": job.id,
            "id": job.id,
            "status": job.status,
            "sources": job.sources,
            "discovered": job.discovered,
            "imported": job.imported,
            "costEur": job.cost_eur,
            "cursor": job.cursor,
        })))
    }
    .instrument(span)
    .await
}

/// `GET /discovery/jobs/:id` — tenant-scoped job status.
async fn get_discovery_job(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = tenant_id.0;
    let span = tracing::info_span!(
        "get_discovery_job",
        tenant_id = %tenant_id,
        job_id = %id,
        operation = "get_discovery_job"
    );
    async move {
        let runner = discovery_runner(&state, &tenant_id);
        let job = runner.get_job(&tenant_id, id).await?;
        Ok(Json(serde_json::json!({
            "jobId": job.id,
            "id": job.id,
            "status": job.status,
            "query": job.query,
            "sources": job.sources,
            "cursor": job.cursor,
            "discovered": job.discovered,
            "imported": job.imported,
            "costEur": job.cost_eur,
            "error": job.error,
            "createdAt": job.created_at,
            "startedAt": job.started_at,
            "completedAt": job.completed_at,
        })))
    }
    .instrument(span)
    .await
}

/// `POST /discovery/jobs/:id/run` — execute one bounded batch (resumes from
/// the persisted cursor; a batch may complete the job).
async fn run_discovery_job(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = tenant_id.0;
    let span = tracing::info_span!(
        "run_discovery_job",
        tenant_id = %tenant_id,
        job_id = %id,
        operation = "run_discovery_job"
    );
    async move {
        let runner = discovery_runner(&state, &tenant_id);
        let job = runner
            .run_job(&tenant_id, id, crate::discovery::MAX_PAGES_PER_RUN)
            .await?;
        Ok(Json(serde_json::json!({
            "jobId": job.id,
            "id": job.id,
            "status": job.status,
            "sources": job.sources,
            "cursor": job.cursor,
            "discovered": job.discovered,
            "imported": job.imported,
            "costEur": job.cost_eur,
            "error": job.error,
        })))
    }
    .instrument(span)
    .await
}

// -- Conversions (SALES-03) -------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConversionQuery {
    #[serde(default)]
    campaign_id: Option<Uuid>,
    #[serde(default)]
    lead_id: Option<Uuid>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    tenant_id: Option<String>,
}

#[derive(sqlx::FromRow, Serialize)]
struct ConversionRow {
    id: Uuid,
    tenant_id: String,
    campaign_id: Uuid,
    lead_id: Uuid,
    revenue: f64,
    description: String,
    converted_at: chrono::DateTime<chrono::Utc>,
}

impl From<ConversionRow> for Conversion {
    fn from(row: ConversionRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            campaign_id: row.campaign_id,
            lead_id: row.lead_id,
            revenue: row.revenue,
            description: row.description,
            converted_at: row.converted_at,
        }
    }
}

use crate::types::Conversion;

async fn create_conversion(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<CreateConversionBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    // Fix I-3: header/payload tenant consistency is enforced on EVERY
    // mutation — this handler previously missed the check.
    let tenant_id = required_tenant_id(&tenant_id.0, body.tenant_id.as_deref())?;
    let span = tracing::info_span!("create_conversion", tenant_id = %tenant_id, operation = "create_conversion");
    async move {
        // Verify the campaign exists and belongs to this tenant
        let campaign_exists: bool = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sales_campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(body.campaign_id)
        .bind(&tenant_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
            > 0;
        if !campaign_exists {
            return Err(SalesError::CampaignNotFound(body.campaign_id));
        }

        // Verify the lead exists and belongs to this tenant. `sales_leads` is
        // the derived view and `id` is TEXT (lead ids use several formats),
        // so the Uuid must be bound as its string form — binding the raw Uuid
        // produced `operator does not exist: text = uuid` (HTTP 500).
        let lead_exists: bool = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sales_leads WHERE id = $1 AND tenant_id = $2",
        )
        .bind(body.lead_id.to_string())
        .bind(&tenant_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
            > 0;
        if !lead_exists {
            return Err(SalesError::LeadNotFound(body.lead_id.to_string()));
        }

        // `lead_id` is TEXT since migration 223 and FK-references
        // sales_contacts.legacy_lead_id, so the id is stored as its string
        // form (the API keeps exposing a Uuid; see ConversionRow).
        let conversion_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_conversions (id, tenant_id, campaign_id, lead_id, revenue, description, converted_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(conversion_id)
        .bind(&tenant_id)
        .bind(body.campaign_id)
        .bind(body.lead_id.to_string())
        .bind(body.revenue)
        .bind(&body.description)
        .bind(chrono::Utc::now())
        .execute(&state.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        // Update the lead status to Converted. This is best-effort: the lead
        // lifecycle state machine only allows Qualified → Converted, so a lead
        // that was never qualified keeps its current status (the conversion
        // record itself is unaffected).
        let _ = state
            .crm
            .update_lead_status(&body.lead_id.to_string(), LeadStatus::Converted, &tenant_id)
            .await;

        let conversion = Conversion {
            id: conversion_id,
            tenant_id,
            campaign_id: body.campaign_id,
            lead_id: body.lead_id,
            revenue: body.revenue,
            description: body.description,
            converted_at: chrono::Utc::now(),
        };
        json_response(&conversion)
    }
    .instrument(span)
    .await
}

async fn list_conversions(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(q): Query<ConversionQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = required_tenant_id(&tenant_id.0, q.tenant_id.as_deref())?;
    let (limit, offset) = normalize_pagination(q.limit, q.offset, 100, 500);
    let span = tracing::info_span!("list_conversions", tenant_id = %tenant_id, operation = "list_conversions");
    async move {
        // `sales_conversions.lead_id` is TEXT since migration 223 (a real
        // reference to sales_contacts.legacy_lead_id). Conversion API lead
        // ids are UUIDs, so the read casts back to the API's Uuid type; the
        // cast is safe because only this API ever inserted the column and it
        // always bound a Uuid string.
        let rows: Vec<ConversionRow> = if let Some(cid) = q.campaign_id {
            sqlx::query_as::<_, ConversionRow>(
                "SELECT id, tenant_id, campaign_id, lead_id::uuid AS lead_id, revenue, \
                        description, converted_at \
                 FROM sales_conversions \
                 WHERE tenant_id = $1 AND campaign_id = $2 \
                 ORDER BY converted_at DESC LIMIT $3 OFFSET $4",
            )
            .bind(&tenant_id)
            .bind(cid)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?
        } else if let Some(lid) = q.lead_id {
            sqlx::query_as::<_, ConversionRow>(
                "SELECT id, tenant_id, campaign_id, lead_id::uuid AS lead_id, revenue, \
                        description, converted_at \
                 FROM sales_conversions \
                 WHERE tenant_id = $1 AND lead_id = $2 \
                 ORDER BY converted_at DESC LIMIT $3 OFFSET $4",
            )
            .bind(&tenant_id)
            .bind(lid.to_string())
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?
        } else {
            sqlx::query_as::<_, ConversionRow>(
                "SELECT id, tenant_id, campaign_id, lead_id::uuid AS lead_id, revenue, \
                        description, converted_at \
                 FROM sales_conversions \
                 WHERE tenant_id = $1 \
                 ORDER BY converted_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(&tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?
        };

        let conversions: Vec<Conversion> = rows.into_iter().map(Conversion::from).collect();
        json_response(&conversions)
    }
    .instrument(span)
    .await
}

// -- Campaigns --------------------------------------------------------------

fn required_tenant_id(
    header_tenant_id: &str,
    explicit_tenant_id: Option<&str>,
) -> Result<String, SalesError> {
    let explicit = explicit_tenant_id.map(str::trim).filter(|v| !v.is_empty());

    match explicit {
        Some(explicit) if explicit != header_tenant_id => Err(SalesError::InvalidInput(
            "tenant_id mismatch between header and request payload".into(),
        )),
        _ => Ok(header_tenant_id.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateCampaignBody {
    name: String,
    template_id: String,
    #[serde(default)]
    audience: String,
    tenant_id: Option<String>,
}

async fn create_campaign(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<CreateCampaignBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = required_tenant_id(&tenant_id.0, body.tenant_id.as_deref())?;
    let span = tracing::info_span!("create_campaign", tenant_id = %tenant_id, operation = "create_campaign");
    async move {
        let c = state
            .campaigns
            .create_campaign(tenant_id, body.name, body.template_id, body.audience)
            .await?;
        json_response(&c)
    }
    .instrument(span)
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignQuery {
    tenant_id: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

async fn list_campaigns(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(q): Query<CampaignQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = required_tenant_id(&tenant_id.0, q.tenant_id.as_deref())?;
    let span =
        tracing::info_span!("list_campaigns", tenant_id = %tenant_id, operation = "list_campaigns");
    async move {
        let (limit, offset) = normalize_pagination(q.limit, q.offset, 100, 500);
        let campaigns = state
            .campaigns
            .list_campaigns(&tenant_id, limit, offset)
            .await?;
        json_response(&campaigns)
    }
    .instrument(span)
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientBody {
    emails: Vec<String>,
}

async fn add_campaign_recipients(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(id): Path<Uuid>,
    Json(body): Json<RecipientBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    if body.emails.is_empty() {
        return Err(SalesError::InvalidInput(
            "at least one recipient email is required".into(),
        ));
    }

    let tenant_id = tenant_id.0;
    let span = tracing::info_span!("add_campaign_recipients", tenant_id = %tenant_id, campaign_id = %id, operation = "add_campaign_recipients");
    async move {
        let added = state
            .campaigns
            .add_recipients(&tenant_id, id, body.emails)
            .await?;
        json_response(&serde_json::json!({ "campaignId": id, "added": added }))
    }
    .instrument(span)
    .await
}

async fn start_campaign(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = tenant_id.0;
    let span = tracing::info_span!("start_campaign", tenant_id = %tenant_id, campaign_id = %id, operation = "start_campaign");
    async move {
        // A legacy campaign no longer dispatches mail itself: starting it
        // materializes canonical enrollments, which the durable action worker
        // then executes through the Decision Packet. There is therefore no
        // dispatcher requirement here any more — the old 503 guard existed only
        // because this route used to flip the campaign to 'active' and send
        // from its own loop.
        //
        // The start is a durable operation with an idempotent retry. An
        // operator must be able to see that: when the campaign was NOT
        // activated (mid-materialization failure resumed later, or enrollment
        // accepted zero contacts), the response carries the durable
        // start-operation phase and its operator message in addition to the
        // per-recipient enrollment outcome.
        let (campaign, report) = state
            .campaigns
            .start_campaign_operation(&tenant_id, id)
            .await?;
        let mut body = serde_json::to_value(&campaign)
            .map_err(|e| SalesError::Internal(anyhow::anyhow!("serialize campaign: {e}")))?;
        if let Some(object) = body.as_object_mut() {
            // Surfacing the enrollment outcome is the point: an operator must
            // see which recipients could not be enrolled and why, rather than a
            // bare status hiding a partial start.
            if let Some(outreach) = &report.outreach {
                object.insert(
                    "enrollment".to_string(),
                    serde_json::to_value(outreach).map_err(|e| {
                        SalesError::Internal(anyhow::anyhow!("serialize enrollment: {e}"))
                    })?,
                );
            }
            object.insert(
                "start".to_string(),
                serde_json::json!({
                    "operationId": report.operation_id,
                    "state": report.phase.as_str(),
                    "message": report.message,
                }),
            );
        }
        if !matches!(report.phase, crate::campaigns::CampaignStartPhase::Active) {
            tracing::warn!(
                campaign_id = %id,
                operation_id = %report.operation_id,
                start_state = report.phase.as_str(),
                message = report.message.as_deref().unwrap_or_default(),
                "campaign start did not activate the campaign"
            );
        }
        json_response(&body)
    }
    .instrument(span)
    .await
}

async fn pause_campaign(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = tenant_id.0;
    let span = tracing::info_span!("pause_campaign", tenant_id = %tenant_id, campaign_id = %id, operation = "pause_campaign");
    async move {
        let campaign = state.campaigns.pause_campaign(&tenant_id, id).await?;
        json_response(&campaign)
    }
    .instrument(span)
    .await
}

/// Dry-run a campaign: render templates and evaluate every dispatch filter
/// (suppression, frequency cap, sender-domain readiness) WITHOUT enqueueing
/// anything or stamping the send ledger. Operator safety net + test seam.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DryRunQuery {
    /// How many due recipients to render in the preview (default 3, max 25).
    #[serde(default)]
    sample: Option<usize>,
}

async fn dry_run_campaign(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(id): Path<Uuid>,
    Query(q): Query<DryRunQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = tenant_id.0;
    let span = tracing::info_span!(
        "dry_run_campaign",
        tenant_id = %tenant_id,
        campaign_id = %id,
        operation = "dry_run_campaign"
    );
    async move {
        let sample = q.sample.unwrap_or(3).clamp(1, 25);
        let report = state
            .campaigns
            .dry_run(&tenant_id, id, sample, state.dispatcher.as_deref())
            .await?;
        Ok(Json(report))
    }
    .instrument(span)
    .await
}

// -- Public unsubscribe endpoints (CAN-SPAM / RFC 8058) ----------------------

/// Token resolution only (v2 → legacy v1). Shared by the side-effect-free
/// GET (which must verify without suppressing) and the suppression path.
///
/// 1. **v2 opaque token** — decoded (strict 43-char URL-safe base64, no
///    database use for malformed shapes), SHA-256'd, looked up in
///    `sales_unsubscribe_tokens` (only the hash is stored).
/// 2. **v1 legacy token** — read-only compatibility for links already
///    delivered in email (see `apply_unsubscribe` for the retirement plan).
///
/// Neither the raw token nor the decoded PII is logged; the only log line
/// carries the tenant id.
async fn resolve_unsubscribe(
    state: &AppState,
    token: &str,
) -> Result<crate::dispatcher::UnsubscribeTokenData, SalesError> {
    // v2 first: a malformed/unknown v2 token is `Ok(None)`, a DB failure is
    // an `Err` (never silently fall through to the legacy verifier on a
    // transient outage — that could reject a valid v2 link).
    match crate::dispatcher::resolve_unsubscribe_token(&state.db, token).await? {
        Some(data) => Ok(data),
        None => {
            // Legacy v1 fallback (old emails in inboxes). Without a secret
            // the v1 verifier cannot run, but that must not turn an invalid
            // token into a 5xx: v2 is secret-independent, so an unresolvable
            // token is a client error in every deployment.
            let secret = &state.config.dispatch.unsubscribe_secret;
            let legacy = if secret.trim().is_empty() {
                tracing::warn!(
                    "unsubscribe request rejected: no legacy v1 secret configured (v2 tokens \
                     remain valid)"
                );
                None
            } else {
                crate::dispatcher::verify_unsubscribe_token(secret, token)
            };
            match legacy {
                Some(data) => Ok(data),
                None => {
                    // The log line intentionally omits the token.
                    tracing::warn!("unsubscribe request with invalid or expired token");
                    Err(SalesError::InvalidInput(
                        "invalid or expired unsubscribe token".into(),
                    ))
                }
            }
        }
    }
}

/// Verify the token AND perform the suppression (the consent-changing step).
/// Idempotent by construction (`ON CONFLICT DO NOTHING` in both suppression
/// stores) — a second click succeeds without duplicating rows.
async fn apply_unsubscribe(
    state: &AppState,
    token: &str,
) -> Result<crate::dispatcher::UnsubscribeTokenData, SalesError> {
    let data = resolve_unsubscribe(state, token).await?;

    ProductionCampaignDispatcher::suppress(
        &state.db,
        &data.tenant_id,
        &data.email,
        "unsubscribe-link",
    )
    .await?;

    metrics::counter!("sales_campaign_unsubscribes_total").increment(1);
    tracing::info!(
        tenant_id = %data.tenant_id,
        "recipient unsubscribed from sales campaigns"
    );
    Ok(data)
}

/// Minimal HTML escaping for values interpolated into the unsubscribe pages
/// (token, email) — no template-engine dependency.
fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The safe path back every terminal unsubscribe page offers (batch 2): the
/// site home these pages are served from.
const BACK_LINK: &str = r#"<p class="back-link"><a href="/">Return to ApexMail</a></p>"#;

/// Shared card shell for the public unsubscribe pages (confirmation,
/// completion, error) — identical styling on every browser-facing surface.
fn unsubscribe_page_shell(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{title} — ApexMail</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f7f7f9;color:#222}}.card{{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);padding:48px;text-align:center;max-width:420px}}h1{{font-size:20px;margin:0 0 12px}}p{{color:#666;font-size:14px;line-height:1.6;margin:0 0 16px}}.btn{{display:inline-block;background:#dc2626;color:#fff;border:none;border-radius:8px;padding:12px 24px;font-size:14px;font-weight:700;cursor:pointer}}.back-link{{margin-top:8px}}.back-link a{{color:#666}}</style>
</head>
<body><div class="card">{body}</div></body></html>"#,
    )
}

/// Branded completion page shown after a confirmed unsubscribe when no
/// explicit redirect URL is configured.
fn unsubscribed_page() -> axum::response::Html<String> {
    axum::response::Html(unsubscribe_page_shell(
        "Unsubscribed",
        &format!(
            "<h1>You're unsubscribed</h1>\n<p>You will not receive any further campaign emails from us. Sorry to see you go!</p>\n{BACK_LINK}"
        ),
    ))
}

/// F39 (batch 2): the GET render — a plain no-JS HTML form whose submit
/// POSTs to `/u/:token/confirm`. GET itself changes NOTHING, so prefetching
/// mail clients and link scanners can no longer unsubscribe anyone by
/// fetching a URL.
fn unsubscribe_confirm_page(token: &str, email: &str) -> axum::response::Html<String> {
    let token = html_escape(token);
    let email = html_escape(email);
    axum::response::Html(unsubscribe_page_shell(
        "Confirm Unsubscribe",
        &format!(
            r#"<h1>Confirm unsubscribe</h1>
<p>Are you sure you want to stop receiving sales campaign emails at <strong>{email}</strong>?</p>
<form method="POST" action="/u/{token}/confirm">
  <input type="hidden" name="confirm" value="true">
  <button type="submit" class="btn">Yes, unsubscribe</button>
</form>
<p class="back-link"><a href="/">No, take me back</a></p>"#
        ),
    ))
}

/// Branded error page for the BROWSER-facing unsubscribe routes (batch 2):
/// mail recipients never see raw JSON. Callers pass fixed human copy —
/// raw error chains are logged, never rendered.
fn unsubscribe_error_page(message: &str) -> axum::response::Html<String> {
    let message = html_escape(message);
    axum::response::Html(unsubscribe_page_shell(
        "Error",
        &format!("<h1>Something went wrong</h1>\n<p>{message}</p>\n{BACK_LINK}"),
    ))
}

/// GET /u/:token — manual (link click) unsubscribe, step 1. F39 (batch 2):
/// SIDE-EFFECT FREE — verifies the token and renders the confirmation form;
/// consent changes only on the confirmed POST (`/u/:token/confirm`).
async fn unsubscribe_get(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    match resolve_unsubscribe(&state, &token).await {
        Ok(data) => unsubscribe_confirm_page(&token, &data.email).into_response(),
        Err(SalesError::InvalidInput(_)) => (
            StatusCode::BAD_REQUEST,
            unsubscribe_error_page(
                "This unsubscribe link is invalid or has expired. Please request a new one.",
            ),
        )
            .into_response(),
        Err(e) => {
            // Full detail stays in the log; the page carries fixed copy only.
            tracing::error!(error = %e, "unsubscribe GET failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                unsubscribe_error_page("Something went wrong. Please try again."),
            )
                .into_response()
        }
    }
}

/// The hidden field of the confirmation form (F39): a POST to
/// `/u/:token/confirm` only proceeds when the form actually confirmed.
#[derive(Deserialize)]
struct UnsubscribeConfirmForm {
    #[serde(default)]
    confirm: Option<String>,
}

/// POST /u/:token/confirm — manual unsubscribe, step 2 (batch 2, F39): the
/// ONLY browser-driven path that suppresses the recipient. Distinct from the
/// RFC 8058 one-click POST (which requires the exact
/// `List-Unsubscribe=One-Click` body) so both contracts stay separate.
async fn unsubscribe_confirm_post(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    axum::Form(form): axum::Form<UnsubscribeConfirmForm>,
) -> Response {
    if form.confirm.as_deref() != Some("true") && form.confirm.as_deref() != Some("1") {
        return (
            StatusCode::BAD_REQUEST,
            unsubscribe_error_page("Invalid confirmation request."),
        )
            .into_response();
    }

    match apply_unsubscribe(&state, &token).await {
        Ok(_) => match &state.config.dispatch.unsubscribe_redirect_url {
            // The operator-configured post-unsubscribe target replaces the
            // branded completion page (now on the CONFIRM step, never the
            // prefetchable GET).
            Some(url) => Redirect::to(url).into_response(),
            None => unsubscribed_page().into_response(),
        },
        Err(SalesError::InvalidInput(_)) => (
            StatusCode::BAD_REQUEST,
            unsubscribe_error_page(
                "This unsubscribe link is invalid or has expired. Please request a new one.",
            ),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "unsubscribe confirmation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                unsubscribe_error_page("Something went wrong. Please try again."),
            )
                .into_response()
        }
    }
}

/// POST /u/:token — RFC 8058 one-click unsubscribe (mail clients). The body
/// MUST be exactly `List-Unsubscribe=One-Click` (CRLF-tolerant).
async fn unsubscribe_post(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    body: String,
) -> Response {
    if body.trim() != "List-Unsubscribe=One-Click" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid request body" })),
        )
            .into_response();
    }
    match apply_unsubscribe(&state, &token).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response(),
        Err(SalesError::InvalidInput(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// -- Calendar ---------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalendarQuery {
    from: Option<String>,
    to: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

async fn list_calendar(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(q): Query<CalendarQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = tenant_id.0;
    let span =
        tracing::info_span!("list_calendar", tenant_id = %tenant_id, operation = "list_calendar");
    async move {
        use chrono::{DateTime, Utc};
        let (limit, offset) = normalize_pagination(q.limit, q.offset, 100, 500);
        let from: DateTime<Utc> = q.from.and_then(|s| s.parse().ok()).unwrap_or_else(Utc::now);
        let to: DateTime<Utc> =
            q.to.and_then(|s| s.parse().ok())
                .unwrap_or_else(|| from + chrono::Duration::days(7));
        let events = state
            .calendar
            .list_events(&tenant_id, from, to, limit, offset)
            .await?;
        json_response(&events)
    }
    .instrument(span)
    .await
}

// -- Inbox ------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InboxQuery {
    category: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

async fn list_inbox(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(q): Query<InboxQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = tenant_id.0;
    let span = tracing::info_span!("list_inbox", tenant_id = %tenant_id, operation = "list_inbox");
    async move {
        use crate::types::MessageCategory;
        let (limit, offset) = normalize_pagination(q.limit, q.offset, 100, 500);
        let cat = q.category.map(|c| match c.as_str() {
            "lead" => MessageCategory::Lead,
            "customer" => MessageCategory::Customer,
            "support" => MessageCategory::Support,
            "spam" => MessageCategory::Spam,
            "unsubscribe" => MessageCategory::Unsubscribe,
            // Fix #19: the review bucket must be listable — this is the one
            // consumer that READS low-confidence classifications (humans
            // resolving them); it never drives an action.
            "needs_review" => MessageCategory::NeedsReview,
            _ => MessageCategory::Other,
        });
        let msgs = if let Some(c) = cat {
            state
                .inbox
                .list_by_category(&tenant_id, c, limit, offset)
                .await?
        } else {
            state.inbox.list_all(&tenant_id, limit, offset).await?
        };
        json_response(&msgs)
    }
    .instrument(span)
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateCalendarEventBody {
    title: String,
    #[serde(default)]
    attendees: Vec<String>,
    start_at: chrono::DateTime<chrono::Utc>,
    end_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    meeting_link: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
}

async fn create_calendar_event(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Json(body): Json<CreateCalendarEventBody>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = required_tenant_id(&tenant_id.0, body.tenant_id.as_deref())?;
    let span = tracing::info_span!(
        "create_calendar_event",
        tenant_id = %tenant_id,
        operation = "create_calendar_event"
    );
    async move {
        let event = state
            .calendar
            .create_event(
                tenant_id,
                body.title,
                body.attendees,
                body.start_at,
                body.end_at,
                body.meeting_link,
            )
            .await?;
        json_response(&event)
    }
    .instrument(span)
    .await
}

async fn cancel_calendar_event(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = tenant_id.0;
    let span = tracing::info_span!(
        "cancel_calendar_event",
        tenant_id = %tenant_id,
        event_id = %id,
        operation = "cancel_calendar_event"
    );
    async move {
        state.calendar.cancel_event(id, &tenant_id).await?;
        json_response(&serde_json::json!({ "id": id, "cancelled": true }))
    }
    .instrument(span)
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotQuery {
    date: Option<String>,
    /// Optional IANA timezone (audit §29). When present the handler returns
    /// DST-correct local slots honouring the configured working hours,
    /// buffers, minimum notice, weekday allowlist, per-day cap and
    /// round-robin salesperson selection. When absent the historical
    /// 09:00–17:00 UTC behaviour is preserved for existing callers.
    timezone: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
}

async fn find_calendar_slots(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Query(q): Query<SlotQuery>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = required_tenant_id(&tenant_id.0, q.tenant_id.as_deref())?;
    let span = tracing::info_span!(
        "find_calendar_slots",
        tenant_id = %tenant_id,
        operation = "find_calendar_slots"
    );
    async move {
        // An unparseable date is rejected instead of silently falling back
        // to "today".
        let date = match q.date {
            Some(raw) => raw.parse::<chrono::DateTime<chrono::Utc>>().map_err(|_| {
                SalesError::InvalidInput("date must be an RFC 3339 timestamp".into())
            })?,
            None => chrono::Utc::now(),
        };

        // IANA-timezone mode: the date is interpreted as a local calendar
        // date in the requested zone and every policy dimension is applied.
        if let Some(raw_timezone) = q.timezone.as_deref() {
            let timezone = crate::calendar::parse_iana_zone(raw_timezone).ok_or_else(|| {
                SalesError::InvalidInput(format!(
                    "timezone must be a valid IANA zone name (e.g. Europe/Tallinn), got {raw_timezone:?}"
                ))
            })?;
            let mut request =
                state
                    .calendar
                    .config()
                    .availability_request(&tenant_id, date.date_naive(), chrono::Utc::now());
            request.timezone = timezone;
            let slots = state.calendar.availability(&request).await?;
            let slots: Vec<serde_json::Value> = slots
                .iter()
                .map(|slot| {
                    serde_json::json!({
                        "start": slot.start,
                        "end": slot.end,
                        "local_start": slot.local_start,
                        "timezone": slot.timezone.name(),
                        "salesperson": slot.salesperson,
                    })
                })
                .collect();
            return json_response(&slots);
        }

        // Legacy UTC mode (unchanged contract).
        let slots = state
            .calendar
            .find_available_slots(&tenant_id, date)
            .await?;
        let slots: Vec<serde_json::Value> = slots
            .into_iter()
            .map(|(start, end)| serde_json::json!({ "start": start, "end": end }))
            .collect();
        json_response(&slots)
    }
    .instrument(span)
    .await
}

/// Request body for replying to an inbox message.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyBody {
    /// The reply text (plain text; the HTML part is composed with escaping).
    body: String,
    #[serde(default)]
    tenant_id: Option<String>,
}

/// Maximum accepted reply length in characters (the router-level body limit
/// is 256 KB; this keeps individual replies civil).
const REPLY_BODY_MAX_CHARS: usize = 100_000;

/// POST /inbox/:id/reply — compose a reply to an inbound message and enqueue
/// it through the platform pipeline (`messages` + `email_queue`), exactly
/// like the REST send path.
///
/// # Fix I-4 history / decision
///
/// The handler previously flipped the `replied` flag and answered
/// `{replied: true}` without sending anything (honest 501 followed). Now
/// that the crate owns a real enqueue pipeline, the sender identity IS
/// resolvable whenever the production dispatcher is configured
/// (`SALES_CAMPAIGN_FROM_EMAIL` + verified/DKIM-ready sender domain): the
/// reply is composed ("Re: {subject}", HTML-escaped body) and enqueued with
/// quota reservation, platform-suppression check and a deterministic
/// idempotency key (`sareply:{inbox_message_id}` — one enqueued reply per
/// message; the `replied` flag commits atomically with the enqueue).
///
/// When NO sender identity is resolvable (dispatcher unconfigured) the
/// endpoint keeps failing honestly with 501 BEFORE mutating anything.
async fn reply_inbox_message(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(id): Path<Uuid>,
    Json(body): Json<ReplyBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), SalesError> {
    let tenant_id = required_tenant_id(&tenant_id.0, body.tenant_id.as_deref())?;
    let span = tracing::info_span!(
        "reply_inbox_message",
        tenant_id = %tenant_id,
        message_id = %id,
        operation = "reply_inbox_message"
    );
    async move {
        let text = body.body.trim();
        if text.is_empty() {
            return Err(SalesError::InvalidInput(
                "reply body must not be empty".into(),
            ));
        }
        if text.chars().count() > REPLY_BODY_MAX_CHARS {
            return Err(SalesError::InvalidInput(format!(
                "reply body exceeds the maximum of {REPLY_BODY_MAX_CHARS} characters"
            )));
        }

        // Sender identity resolution: the production dispatcher carries the
        // configured From address and resolves the verified sender domain
        // per tenant at enqueue time. Without it there is no honest email
        // path — 501 before mutating anything.
        let Some(dispatcher) = state.dispatcher.clone() else {
            return Err(SalesError::NotImplemented(
                "reply delivery not available: no sender identity is configured \
                 (set SALES_CAMPAIGN_FROM_EMAIL and SALES_UNSUBSCRIBE_SECRET to enable replies)"
                    .into(),
            ));
        };

        // The message being replied to (tenant-scoped).
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT sender, subject, category FROM sales_inbox_messages \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(&tenant_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        let (sender, original_subject, category) = row.ok_or(SalesError::MessageNotFound(id))?;

        // Fix #19 — irreversible-action guard: the reply enqueue is an
        // outbound send. A message whose classifier confidence fell below
        // the automation threshold (or a legacy non-concrete row) MUST NOT
        // drive it: it goes to human review instead. `is_concrete` is the
        // structural gate — NeedsReview and Other can never pass it, so a
        // low-confidence classification can never fire this action no
        // matter how the consumer matches.
        let category = crate::types::MessageCategory::from_str(&category);
        if !category.is_concrete() {
            return Err(SalesError::PolicyDenied(format!(
                "inbox message is categorized `{category}` (below automation confidence): \
                 resolve its classification by human review before a reply can be sent (Fix #19)"
            )));
        }

        // The correspondent's address is the reply recipient — validate it
        // syntactically before spending a quota reservation.
        if !apexmail_lib::validation::is_valid_email(sender.trim()) {
            return Err(SalesError::InvalidInput(format!(
                "inbox message sender is not a valid email address: {sender}"
            )));
        }

        let subject = crate::dispatcher::compose_reply_subject(&original_subject);
        let html = crate::dispatcher::compose_reply_html(text);

        let outcome = dispatcher
            .enqueue_reply(&tenant_id, id, sender.trim(), &subject, Some(&html), text)
            .await?;

        Ok(match outcome {
            crate::dispatcher::ReplyOutcome::Enqueued { message_id } => (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "messageId": message_id,
                    "queued": true,
                    "replied": true,
                    "to": sender.trim(),
                })),
            ),
            crate::dispatcher::ReplyOutcome::AlreadyReplied { message_id } => (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "messageId": message_id,
                    "queued": false,
                    "duplicate": true,
                    "replied": true,
                    "to": sender.trim(),
                })),
            ),
        })
    }
    .instrument(span)
    .await
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

    /// App harness on the canonical provisioned test database. Async so it can
    /// be awaited directly inside `#[tokio::test]` — the previous
    /// `Runtime::new().block_on(..)` inside the test runtime panicked with
    /// "Cannot start a runtime from within a runtime". `None` means the
    /// environment is unconfigured → the test soft-skips.
    pub(super) async fn test_app(test_name: &str) -> Option<Router> {
        test_app_impl(test_name, "test-key", false).await
    }

    /// App harness for campaign-start flows.
    ///
    /// Previously this attached a test dispatcher to get past the Fix I-1 503
    /// short-circuit. Campaign start no longer dispatches mail — it
    /// materializes enrollments — so no dispatcher is involved and this is now
    /// the same harness as [`test_app`].
    async fn test_app_with_dispatcher(test_name: &str) -> Option<Router> {
        test_app_impl(test_name, "test-key", false).await
    }

    async fn test_app_with_service_token(test_name: &str, service_token: &str) -> Option<Router> {
        test_app_impl(test_name, service_token, false).await
    }

    pub(super) async fn test_app_impl(
        test_name: &str,
        service_token: &str,
        _with_dispatcher: bool,
    ) -> Option<Router> {
        let db = crate::test_db::canonical_test_pool(test_name).await?;
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");
        let campaigns = CampaignManager::new(10, db.clone());
        let state = AppState {
            db: db.clone(),
            redis,
            config: Default::default(),
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            campaigns,
            dispatcher: None,
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            service_token: service_token.into(),
            rate_limit_fallback: Arc::new(Mutex::new(HashMap::new())),
            intelligence: Arc::new(crate::intelligence::OfflineIntelligence::new()),
            strategist: Arc::new(MessageStrategist::new(
                db,
                crate::knowledge::SalesKnowledgeBase::canonical(),
            )),
        };
        Some(router(state))
    }

    /// A per-run unique mailbox under the example zone.
    ///
    /// batch: system-tenant restriction — every API test now runs as the ONE
    /// system tenant on the SHARED, reused canonical database, so the
    /// per-tenant unique email index (`sales_leads`,
    /// `sales_contact_points`) needs a run-unique local part where
    /// `unique_test_tenant` used to provide isolation via a unique tenant id.
    fn unique_email(local: &str) -> String {
        format!(
            "{local}-{}@acme.example",
            &Uuid::new_v4().simple().to_string()[..10]
        )
    }

    // ── Fix I tests: honest failures + tenant scoping ────────────────────

    /// Async-test-safe app builder: a LAZY pool (never connects) so the
    /// router can be driven inside `#[tokio::test]` without nesting
    /// runtimes. Handlers that reach the database fail; the tests below
    /// assert on the pre-database behavior (auth, scoping, 501/503).
    pub(super) fn lazy_test_app_with_config(config: crate::config::SalesConfig) -> Router {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool");
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");
        let state = AppState {
            db: db.clone(),
            redis,
            config,
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            campaigns: CampaignManager::new(10, db.clone()),
            dispatcher: None,
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            service_token: "test-key".into(),
            rate_limit_fallback: Arc::new(Mutex::new(HashMap::new())),
            intelligence: Arc::new(crate::intelligence::OfflineIntelligence::new()),
            strategist: Arc::new(MessageStrategist::new(
                db,
                crate::knowledge::SalesKnowledgeBase::canonical(),
            )),
        };
        router(state)
    }

    pub(super) fn lazy_test_app() -> Router {
        lazy_test_app_with_config(crate::config::SalesConfig::default())
    }

    /// Campaign start no longer requires a dispatcher.
    ///
    /// Fix I-1 guarded a route that used to flip the campaign to 'active' and
    /// send from its own loop, so an unwired dispatcher meant a campaign that
    /// silently sent nothing. Campaign start now materializes canonical
    /// enrollments and the durable action worker performs the sending, so the
    /// correct behaviour on an unwired deployment is a normal error from the
    /// enrollment path — never the old blanket 503, which would refuse a start
    /// that can legitimately succeed.
    #[tokio::test]
    async fn test_campaign_start_no_longer_requires_a_dispatcher() {
        let app = lazy_test_app();
        let resp = app
            .oneshot(
                Request::post(format!("/campaigns/{}/start", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an unwired dispatcher must no longer refuse a campaign start"
        );
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            !body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("dispatcher"),
            "the response must not blame a dispatcher that is no longer involved: {body}"
        );
    }

    /// Fix I-4: inbox reply without a resolvable sender identity (dispatcher
    /// unconfigured) must stay an HONEST 501 — never `{replied:true}` with
    /// nothing sent, and not a silent fallback either.
    #[tokio::test]
    async fn test_inbox_reply_returns_501_when_sender_identity_unresolvable() {
        let app = lazy_test_app(); // dispatcher: None in this harness
        let resp = app
            .oneshot(
                Request::post(format!("/inbox/{}/reply", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "body": "Thanks for reaching out!"
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("no sender identity is configured"),
            "501 message must explain WHY replies are unavailable: {body}"
        );
    }

    /// Reply validation: an empty body is rejected with 400 before any
    /// sender-identity lookup or quota reservation.
    #[tokio::test]
    async fn test_inbox_reply_rejects_empty_body() {
        let app = lazy_test_app();
        let resp = app
            .oneshot(
                Request::post(format!("/inbox/{}/reply", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "body": "   "
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Fix I-3: header/payload tenant consistency is enforced on
    /// create_conversion (the previously-missed mutation).
    #[tokio::test]
    async fn test_create_conversion_rejects_tenant_mismatch() {
        let app = lazy_test_app();
        let body = serde_json::json!({
            "campaign_id": Uuid::new_v4(),
            "lead_id": Uuid::new_v4(),
            "tenant_id": "tenant-b"
        });
        let resp = app
            .oneshot(
                Request::post("/conversions")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "header/payload tenant mismatch must be rejected"
        );
    }

    /// System-tenant hard restriction: the shared token can only ever act on
    /// the system tenant. The middleware refuses any other tenant claim
    /// outright, regardless of the deployment allowlist (which boot requires
    /// to be exactly the system tenant — `config::require_system_tenant_scope`).
    #[tokio::test]
    async fn test_system_tenant_only_scoping() {
        let app = lazy_test_app();

        // The system tenant passes the middleware (then fails on the dead DB
        // with 500 — proving it got PAST the scope check).
        let allowed = app
            .clone()
            .oneshot(
                Request::post(format!("/campaigns/{}/start", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(allowed.status(), StatusCode::FORBIDDEN);

        // Any non-system tenant claim is rejected outright.
        let denied = app
            .oneshot(
                Request::post(format!("/campaigns/{}/start", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-b")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[tokio::test]
    async fn test_health() {
        let Some(app) = test_app("routes::tests::test_health").await else {
            return;
        };
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // Canonical truth (health handler, routes.rs:198): with the
        // provisioned database reachable, /health reports 200 healthy/"up".
        // The previous SERVICE_UNAVAILABLE assertion only held because the
        // fixture pointed at a dead `unused` DSN.
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["database"], "up");
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[tokio::test]
    async fn test_create_and_list_leads() {
        let Some(app) = test_app("routes::tests::test_create_and_list_leads").await else {
            return;
        };
        // batch: system-tenant restriction — the router middleware refuses
        // every tenant but `config::SYSTEM_TENANT_ID`, so the create/list
        // pair runs as the system tenant; `unique_email` replaces the unique
        // tenant id as the collision guard on the shared database.
        let tenant = config::SYSTEM_TENANT_ID;
        let email = unique_email("alice");
        let body = serde_json::json!({
            "email": email,
            "name": "Alice",
            "company": "Acme",
        });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
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
                    .header("x-tenant-id", tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);

        // batch: scoped cleanup — the system tenant is SHARED by every test
        // in the suite, so cleanup must key on this test's unique email and
        // never on tenant_id.
        if let Some(db) = crate::test_db::canonical_test_pool(
            "routes::tests::test_create_and_list_leads::cleanup",
        )
        .await
        {
            let _ = sqlx::query("DELETE FROM sales_leads WHERE tenant_id = $1 AND email = $2")
                .bind(tenant)
                .bind(&email)
                .execute(&db)
                .await;
        }
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[tokio::test]
    async fn test_enrich_endpoint() {
        let Some(app) = test_app("routes::tests::test_enrich_endpoint").await else {
            return;
        };
        // batch: system-tenant restriction — the gate only admits
        // `config::SYSTEM_TENANT_ID`; the fixed domains are safe because
        // enrichment persistence upserts on (tenant_id, domain).
        let tenant = config::SYSTEM_TENANT_ID;
        let body = serde_json::json!({ "email": "bob@beta.io" });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "enrich by email should succeed with mock backend"
        );

        let domain_body = serde_json::json!({ "domain": "acme.com" });
        let domain_resp = app
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&domain_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            domain_resp.status(),
            StatusCode::OK,
            "enrich by domain should succeed with mock backend"
        );
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[tokio::test]
    async fn test_campaign_lifecycle_endpoints() {
        // A working test dispatcher is attached so start exercises the REAL
        // transition (the no-dispatcher 503 path is asserted separately by
        // the non-ignored `test_campaign_start_returns_503_without_dispatcher`).
        let Some(app) =
            test_app_with_dispatcher("routes::tests::test_campaign_lifecycle_endpoints").await
        else {
            return;
        };
        // batch: system-tenant restriction — the whole lifecycle runs as
        // `config::SYSTEM_TENANT_ID`; the seeded contact points get
        // run-unique addresses because `sales_contact_points` is UNIQUE on
        // (tenant_id, channel, normalized_value) and the tenant is now fixed.
        let tenant = config::SYSTEM_TENANT_ID;

        // Campaign start activates only when at least one recipient can be
        // sent to, so seed canonical verified email points for the recipients
        // used below (the route harness exposes only the Router, so this test
        // takes its own pool on the same shared database).
        let Some(seed_pool) = crate::test_db::canonical_test_pool(
            "routes::tests::test_campaign_lifecycle_endpoints::seed",
        )
        .await
        else {
            return;
        };
        let recipient_emails = [unique_email("alice"), unique_email("bob")];
        let mut contact_ids = Vec::new();
        for email in recipient_emails.clone() {
            let contact_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO sales_contacts (id, tenant_id, full_name) VALUES ($1, $2, '')",
            )
            .bind(contact_id)
            .bind(&tenant)
            .execute(&seed_pool)
            .await
            .expect("seed contact");
            sqlx::query(
                "INSERT INTO sales_contact_points \
                     (id, tenant_id, contact_id, channel, value, normalized_value, \
                      verification, confidence) \
                 VALUES ($1, $2, $3, 'email', $4, LOWER($4), 'valid', 0.9)",
            )
            .bind(Uuid::new_v4())
            .bind(&tenant)
            .bind(contact_id)
            .bind(&email)
            .execute(&seed_pool)
            .await
            .expect("seed verified point");
            contact_ids.push(contact_id);
        }

        let create_body = serde_json::json!({
            "name": "Migration wave",
            "template_id": "tmpl_competitor_migration",
            "audience": "selected-leads",
            "tenant_id": tenant
        });

        let create_resp = app
            .clone()
            .oneshot(
                Request::post("/campaigns")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
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
            "emails": recipient_emails
        });
        let recipients_resp = app
            .clone()
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/recipients"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&recipients_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recipients_resp.status(), StatusCode::OK);

        // With the test dispatcher wired, start performs the real transition
        // and reports the campaign active.
        let start_resp = app
            .clone()
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/start"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
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
        // The response exposes the durable start operation that activated it.
        assert_eq!(started["start"]["state"], "active");
        assert!(
            started["start"]["operationId"].as_str().is_some(),
            "the activation must report its durable operation id: {started}"
        );
        assert!(started["start"]["message"].is_null());

        let pause_resp = app
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/pause"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
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

        // batch: scoped cleanup — the system tenant is shared, so remove only
        // this campaign's rows (by id) and this run's contact fixtures (by
        // id), never by tenant_id.
        let campaign_uuid = Uuid::parse_str(campaign_id).expect("campaign id is a uuid");
        let _ = sqlx::query("DELETE FROM sales_campaign_recipients WHERE campaign_id = $1")
            .bind(campaign_uuid)
            .execute(&seed_pool)
            .await;
        let _ = sqlx::query("DELETE FROM sales_campaigns WHERE id = $1")
            .bind(campaign_uuid)
            .execute(&seed_pool)
            .await;
        for contact_id in contact_ids {
            let _ = sqlx::query("DELETE FROM sales_contact_points WHERE contact_id = $1")
                .bind(contact_id)
                .execute(&seed_pool)
                .await;
            let _ = sqlx::query("DELETE FROM sales_contacts WHERE id = $1")
                .bind(contact_id)
                .execute(&seed_pool)
                .await;
        }
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[tokio::test]
    async fn test_campaign_routes_reject_cross_tenant_mutation() {
        // The dispatcher must be wired, otherwise the unconditional Fix I-1
        // 503 short-circuit would mask the tenant-scoped 404 under test.
        let Some(app) = test_app_with_dispatcher(
            "routes::tests::test_campaign_routes_reject_cross_tenant_mutation",
        )
        .await
        else {
            return;
        };
        // batch: system-tenant restriction — the campaign is created as the
        // system tenant (the only one the gate admits); the foreign claim is
        // kept as a `unique_test_tenant` string precisely because the gate
        // must refuse it.
        let tenant = config::SYSTEM_TENANT_ID;
        let other_tenant = crate::test_db::unique_test_tenant("routes-campaign-other");
        let create_body = serde_json::json!({
            "name": "Tenant scoped",
            "template_id": "tmpl_scoped",
            "audience": "selected-leads",
            "tenant_id": tenant
        });

        let create_resp = app
            .clone()
            .oneshot(
                Request::post("/campaigns")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
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

        let cross_tenant_resp = app
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/start"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", other_tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // batch: system-tenant restriction — the gate refuses foreign tenants
        // with 403 (the security property is enforced earlier than the old
        // data-layer tenant-scoped 404).
        assert_eq!(cross_tenant_resp.status(), StatusCode::FORBIDDEN);

        // batch: scoped cleanup — only this run's campaign, never by
        // tenant_id on the shared system tenant.
        if let Some(db) = crate::test_db::canonical_test_pool(
            "routes::tests::test_campaign_routes_reject_cross_tenant_mutation::cleanup",
        )
        .await
        {
            let _ = sqlx::query("DELETE FROM sales_campaigns WHERE id = $1")
                .bind(Uuid::parse_str(campaign_id).expect("campaign id is a uuid"))
                .execute(&db)
                .await;
        }
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[tokio::test]
    async fn test_list_leads_respects_pagination() {
        let Some(app) = test_app("routes::tests::test_list_leads_respects_pagination").await else {
            return;
        };
        // batch: system-tenant restriction — the pagination run happens as
        // the system tenant; `unique_email` keeps the three seeds colliding
        // with neither concurrent tests nor previous runs (the shared
        // database reuses the per-tenant unique email index).
        let tenant = config::SYSTEM_TENANT_ID;
        let emails: Vec<String> = (0..3)
            .map(|index| unique_email(&format!("lead{index}")))
            .collect();

        for email in &emails {
            let body = serde_json::json!({
                "email": email,
                "name": "Lead",
                "company": "Acme"
            });
            let response = app
                .clone()
                .oneshot(
                    Request::post("/leads")
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let response = app
            .oneshot(
                Request::get("/leads?limit=1&offset=1")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let leads: Vec<serde_json::Value> = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(leads.len(), 1);

        // batch: scoped cleanup — delete this run's three leads by their
        // unique emails; tenant_id deletes would race concurrent tests on
        // the shared system tenant.
        if let Some(db) = crate::test_db::canonical_test_pool(
            "routes::tests::test_list_leads_respects_pagination::cleanup",
        )
        .await
        {
            let _ = sqlx::query("DELETE FROM sales_leads WHERE tenant_id = $1 AND email = ANY($2)")
                .bind(tenant)
                .bind(&emails)
                .execute(&db)
                .await;
        }
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[tokio::test]
    async fn test_protected_routes_reject_requests_when_service_token_missing() {
        let Some(app) = test_app_with_service_token(
            "routes::tests::test_protected_routes_reject_requests_when_service_token_missing",
            "",
        )
        .await
        else {
            return;
        };
        let response = app
            .oneshot(Request::get("/leads").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[tokio::test]
    async fn test_enrich_requires_tenant_scope() {
        let Some(app) = test_app("routes::tests::test_enrich_requires_tenant_scope").await else {
            return;
        };
        let body = serde_json::json!({ "domain": "acme.com" });
        let response = app
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Synchronous test exercising the Redis-backed rate limiter logic
    /// using the in-memory fallback path (Redis unavailable).
    #[test]
    fn test_enrichment_rate_limit_fallback_on_redis_down() {
        // When Redis is unavailable, the rate limiter uses the in-memory fallback.
        // With no fallback provided (None), it still degrades open without panicking.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:16379") // wrong port
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .expect("failed to create redis pool");

            // Degrade open when no fallback configured
            let result = enforce_enrichment_rate_limit(&redis, "tenant-a", None).await;
            assert!(
                result.is_ok(),
                "rate limiter should degrade open when Redis is down and no fallback configured"
            );
        });
    }

    /// Test that the in-memory fallback rate limiter actually enforces limits.
    #[test]
    fn test_enrichment_rate_limit_in_memory_fallback_enforces_limits() {
        let fallback: Arc<Mutex<HashMap<String, RateLimitEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:16379") // wrong port
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .expect("failed to create redis pool");

            // First 30 requests should be allowed
            for _ in 0..ENRICH_RATE_LIMIT_MAX_REQUESTS {
                let result =
                    enforce_enrichment_rate_limit(&redis, "tenant-b", Some(&fallback)).await;
                assert!(result.is_ok(), "request within limit should be allowed");
            }

            // 31st should be rate-limited
            let result = enforce_enrichment_rate_limit(&redis, "tenant-b", Some(&fallback)).await;
            assert!(
                result.is_err(),
                "request exceeding limit should be rejected"
            );
        });
    }

    // ── Discovery routes ─────────────────────────────────────────────────

    /// The CP proxies to `POST {base}/discovery/jobs`; the path must exist
    /// and stay behind the shared service-token middleware.
    #[tokio::test]
    async fn test_discovery_routes_require_auth_and_exist() {
        let app = lazy_test_app();

        // No token → 401, before any routing to the handler matters.
        let unauthorized = app
            .clone()
            .oneshot(
                Request::post("/discovery/jobs")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"sources":["provider_api"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        // Token but no tenant header → the handler rejects with 400 (the
        // route exists; a missing route would be 404).
        let no_tenant = app
            .clone()
            .oneshot(
                Request::post("/discovery/jobs")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"sources":["provider_api"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_tenant.status(), StatusCode::BAD_REQUEST);
        assert_ne!(no_tenant.status(), StatusCode::NOT_FOUND);

        // Authenticated and tenant-scoped: the lazy test pool cannot serve
        // the insert, so a 5xx proves the handler was reached (not 404).
        let reached = app
            .clone()
            .oneshot(
                Request::post("/discovery/jobs")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"sources":["provider_api"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(reached.status(), StatusCode::NOT_FOUND);

        // GET /discovery/jobs/:id must exist too.
        let get_reached = app
            .oneshot(
                Request::get(format!("/discovery/jobs/{}", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(get_reached.status(), StatusCode::NOT_FOUND);
    }

    /// `POST /discovery/jobs/:id/run` exists and validates the tenant before
    /// touching the database.
    #[tokio::test]
    async fn test_run_discovery_job_route_exists() {
        let app = lazy_test_app();
        let run_reached = app
            .oneshot(
                Request::post(format!("/discovery/jobs/{}/run", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(run_reached.status(), StatusCode::NOT_FOUND);
    }

    /// The CP payload uses camelCase and `maxPages`; it must be accepted.
    #[tokio::test]
    async fn test_create_discovery_job_accepts_cp_payload_shape() {
        let app = lazy_test_app();
        let body = serde_json::json!({
            "sources": ["provider_api"],
            "categories": ["SaaS"],
            "maxPages": 3
        });
        let response = app
            .oneshot(
                Request::post("/discovery/jobs")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Reached the handler (DB down in this harness) rather than a 4xx
        // payload rejection.
        assert!(
            response.status().is_server_error(),
            "CP payload must parse, got {}",
            response.status()
        );
    }

    /// A payload tenant_id that disagrees with the header is rejected before
    /// any database work.
    #[tokio::test]
    async fn test_create_discovery_job_rejects_tenant_mismatch() {
        let app = lazy_test_app();
        let body = serde_json::json!({
            "sources": ["provider_api"],
            "tenant_id": "tenant-b"
        });
        let response = app
            .oneshot(
                Request::post("/discovery/jobs")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── Item 25: v2 opaque tokens through the public handler ────────────

    /// A NEW send's opaque token (no tenant, no email, no hex payload in the
    /// URL) redeems through the PUBLIC `/u/:token` handler: both suppression
    /// stores get the canonical lowercased address, `used_at` is stamped,
    /// and a replay stays idempotent.
    ///
    /// FIXED (batch 2, F39): the redemption happens on the CONFIRMED POST
    /// (`/u/:token/confirm`); the prefetchable GET is side-effect free and
    /// only renders the confirmation form.
    #[tokio::test]
    async fn v2_opaque_token_redeems_through_the_public_handler() {
        let Some(db) = crate::test_db::canonical_test_pool("unsub_v2_http").await else {
            return;
        };
        let tenant_id = crate::test_db::unique_test_tenant("unsubv2");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) \
             VALUES ($1, 'Unsub V2 Test', $2, 'free', 'active')",
        )
        .bind(&tenant_id)
        .bind(format!("unsub-v2-{tenant_id}"))
        .execute(&db)
        .await
        .expect("insert test tenant");

        let app = test_app_impl("unsub_v2_http", "test-key", false)
            .await
            .expect("canonical test app");

        let email = "V2.Click@Example.COM";
        let token = crate::dispatcher::create_unsubscribe_token(&db, &tenant_id, email)
            .await
            .expect("v2 token creation");

        // The URL that goes into the email carries no tenant/email material.
        let url = format!("/u/{token}");
        assert!(!url.contains(&tenant_id));
        assert!(!url.contains("v2.click"));
        assert!(!url.contains("example.com"));
        assert!(
            !url.contains('.'),
            "v2 tokens are not v1 dot-separated payloads"
        );

        // FIXED (batch 2, F39): GET renders the confirmation form and must
        // suppress NOTHING (a prefetcher fetching the URL changes no state).
        let resp = app
            .clone()
            .oneshot(Request::get(&url).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "confirmation page renders");
        let confirmation = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let confirmation = String::from_utf8_lossy(&confirmation).to_string();
        assert!(
            confirmation.contains(r#"form method="POST""#) && confirmation.contains("/confirm"),
            "GET must render the POST confirmation form, got: {confirmation}"
        );
        let pre_get_sup: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1 AND email = $2",
        )
        .bind(&tenant_id)
        .bind("v2.click@example.com")
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(pre_get_sup, 0, "F39: a plain GET must not change consent");

        // The confirmed POST suppresses (both stores, canonical address).
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("{url}/confirm"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("confirm=true"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "branded page renders");

        // Both suppression stores carry the canonical lowercased address.
        let sales_sup: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1 AND email = $2",
        )
        .bind(&tenant_id)
        .bind("v2.click@example.com")
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(sales_sup, 1, "sales-side suppression recorded");
        let platform_sup: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2",
        )
        .bind(&tenant_id)
        .bind("v2.click@example.com")
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(platform_sup, 1, "platform suppression mirrored");

        // First redemption stamps `used_at` (documented semantics).
        let used_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT used_at FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
                .bind(&tenant_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(used_at.is_some(), "redemption stamps used_at");

        // Replay (RFC 8058 POST) succeeds and duplicates nothing.
        let resp = app
            .clone()
            .oneshot(
                Request::post(&url)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("List-Unsubscribe=One-Click"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let sales_sup2: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1")
                .bind(&tenant_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(sales_sup2, 1, "no duplicate suppression row");

        // Cleanup (tenant delete cascades the platform suppression mirror).
        let _ = sqlx::query("DELETE FROM sales_unsubscribes WHERE tenant_id = $1")
            .bind(&tenant_id)
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
            .bind(&tenant_id)
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant_id)
            .execute(&db)
            .await;
    }

    /// A tampered v2 token is rejected by the handler (400) and suppresses
    /// nothing — the v2 path is checked BEFORE the legacy v1 fallback.
    #[tokio::test]
    async fn tampered_v2_token_is_rejected_by_the_public_handler() {
        let Some(db) = crate::test_db::canonical_test_pool("unsub_v2_http_bad").await else {
            return;
        };
        let app = test_app_impl("unsub_v2_http_bad", "test-key", false)
            .await
            .expect("canonical test app");

        let tenant_id = crate::test_db::unique_test_tenant("unsubv2bad");
        let token = crate::dispatcher::create_unsubscribe_token(&db, &tenant_id, "bad@example.com")
            .await
            .expect("v2 token creation");
        let mut chars: Vec<char> = token.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();

        let resp = app
            .oneshot(
                Request::get(format!("/u/{tampered}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let sup: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1")
                .bind(&tenant_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(sup, 0, "a tampered token must suppress nothing");

        let _ = sqlx::query("DELETE FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
            .bind(&tenant_id)
            .execute(&db)
            .await;
    }

    // -----------------------------------------------------------------------
    // Adversarial router proofs (run by default; soft-skip only when the
    // canonical test database is unconfigured).
    // -----------------------------------------------------------------------

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    /// `/health` is public; every other route demands the service token, and
    /// a caller presenting no credential never reaches a handler.
    #[tokio::test]
    async fn health_is_public_and_protected_routes_require_the_service_token() {
        // Health must answer on the REAL provisioned pool (the auth-behaviour
        // checks below deliberately use the lazy pool so they never touch a
        // database).
        let Some(canonical) = test_app("routes_health_public").await else {
            return;
        };
        let health = canonical
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK, "health is public");
        let health_body = json_body(health).await;
        assert_eq!(health_body["database"], "up");
        assert_eq!(health_body["service"], "sales-autopilot");

        let app = lazy_test_app();

        let no_token = app
            .clone()
            .oneshot(
                Request::get("/leads")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_token.status(), StatusCode::UNAUTHORIZED);

        let wrong_token = app
            .clone()
            .oneshot(
                Request::get("/leads")
                    .header("x-api-key", "not-the-token")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_token.status(), StatusCode::UNAUTHORIZED);

        let wrong_bearer = app
            .clone()
            .oneshot(
                Request::get("/leads")
                    .header(axum::http::header::AUTHORIZATION, "Bearer not-the-token")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_bearer.status(), StatusCode::UNAUTHORIZED);

        // The public unsubscribe route is NOT behind the token (it answers on
        // its own terms — a malformed token is a 400/404, never a 401).
        let public_unsubscribe = app
            .clone()
            .oneshot(
                Request::get("/u/not-a-real-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            public_unsubscribe.status(),
            StatusCode::UNAUTHORIZED,
            "recipient clicks arrive without a service token"
        );

        // A valid credential passes the middleware (then fails on the dead
        // lazy database with a 500 — proving it got past auth).
        let authed = app
            .oneshot(
                Request::get("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(authed.status(), StatusCode::UNAUTHORIZED);
        assert_ne!(authed.status(), StatusCode::FORBIDDEN);
    }

    /// The lead lifecycle through the real router: create scores the lead,
    /// listing is paged/searched/filtered, reads are tenant-scoped, and
    /// malformed or cross-tenant payloads are refused before any write.
    #[tokio::test]
    async fn lead_lifecycle_is_scored_paged_and_tenant_scoped() {
        let Some(app) = test_app("routes_lead_lifecycle").await else {
            return;
        };
        // batch: system-tenant restriction — the whole lifecycle runs as the
        // system tenant; `other` stays a unique foreign claim because the
        // gate must refuse it (header/payload mismatch and cross-tenant
        // reads below).
        let tenant = config::SYSTEM_TENANT_ID;
        let other = crate::test_db::unique_test_tenant("routes-lead-other");
        let email = format!(
            "alice-{}@acme.example",
            &Uuid::new_v4().simple().to_string()[..10]
        );

        let create = |app: Router, email: String, tenant: String| async move {
            app.oneshot(
                Request::post("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "email": email,
                            "name": "Alice",
                            "company": "Acme",
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        };

        let resp = create(app.clone(), email.clone(), tenant.to_string()).await;
        assert_eq!(resp.status(), StatusCode::OK, "create lead");
        let created = json_body(resp).await;
        let lead_id = created["id"].as_str().expect("a lead id").to_string();
        assert!(
            created["score"].as_u64().unwrap_or(0) >= 10,
            "the scoring pipeline is live: {created}"
        );
        assert_eq!(created["email"], email);

        // A replay of the same address is a conflict, not a second lead
        // (the per-tenant unique email index of the now-fixed system tenant).
        let duplicate = create(app.clone(), email.clone(), tenant.to_string()).await;
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);

        // Malformed JSON and a missing required field are rejections.
        let malformed = app
            .clone()
            .oneshot(
                Request::post("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from("{not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        let missing = app
            .clone()
            .oneshot(
                Request::post("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({ "email": "x@y.z" })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Header/payload tenant mismatch is refused.
        let mismatch = app
            .clone()
            .oneshot(
                Request::post("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "email": format!("bob-{}@acme.example", &Uuid::new_v4().simple().to_string()[..10]),
                            "name": "Bob",
                            "company": "Acme",
                            "tenant_id": other,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);

        // Read back: own tenant sees it, another tenant gets a 404.
        let own = app
            .clone()
            .oneshot(
                Request::get(format!("/leads/{lead_id}"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(own.status(), StatusCode::OK);
        let foreign = app
            .clone()
            .oneshot(
                Request::get(format!("/leads/{lead_id}"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", other.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // batch: system-tenant restriction — the gate refuses foreign tenants
        // with 403 (previously the data layer answered a tenant-scoped 404;
        // the isolation property is now enforced at the router).
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
        let unknown = app
            .clone()
            .oneshot(
                Request::get("/leads/lead_does_not_exist")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        // Pagination is clamped and the search/status filters are real
        // queries, not 500s.
        for url in [
            "/leads?limit=1&offset=0",
            "/leads?limit=99999&offset=-5",
            "/leads?status=new&limit=10",
            "/leads?status=nonsense&limit=10",
            "/leads?source=api&limit=10",
            "/leads?q=alice&limit=10",
            "/leads?limit=0",
        ] {
            let resp = app
                .clone()
                .oneshot(
                    Request::get(url)
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{url}");
            let body = json_body(resp).await;
            assert!(body.is_array(), "{url}: {body}");
            if url.starts_with("/leads?limit=1&") {
                assert_eq!(body.as_array().unwrap().len(), 1, "limit=1");
            }
        }

        // Companies is tenant-scoped and paged.
        let companies = app
            .clone()
            .oneshot(
                Request::get("/companies?limit=5&industry=saas")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(companies.status(), StatusCode::OK);

        // Cleanup: the system tenant is SHARED by every test in the suite, so
        // delete only this run's lead (by its unique email), never by
        // tenant_id. batch: system-tenant restriction.
        if let Some(db) = crate::test_db::canonical_test_pool("routes_lead_lifecycle_cleanup").await
        {
            let _ = sqlx::query("DELETE FROM sales_leads WHERE tenant_id = $1 AND email = $2")
                .bind(tenant)
                .bind(&email)
                .execute(&db)
                .await;
        }
    }

    /// Enrichment validates its input and always lands on the tenant-scoped
    /// persisted path (or an explicit unpersisted warning), never a panic.
    #[tokio::test]
    async fn enrich_validates_input_and_answers_by_email_or_domain() {
        let Some(app) = test_app("routes_enrich_input").await else {
            return;
        };
        // batch: system-tenant restriction — enrichment runs as the system
        // tenant (the fixed domains are upsert-idempotent on
        // (tenant_id, domain)).
        let tenant = config::SYSTEM_TENANT_ID;

        let no_input = app
            .clone()
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_input.status(), StatusCode::BAD_REQUEST);

        let bad_email = app
            .clone()
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({ "email": "not-an-email" }))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_email.status(), StatusCode::BAD_REQUEST);

        let by_domain = app
            .clone()
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({ "domain": "acme.example" }))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(by_domain.status(), StatusCode::OK);
        let company = json_body(by_domain).await;
        assert!(company.is_object(), "{company}");

        let by_email = app
            .clone()
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({ "email": "bob@beta.example" }))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(by_email.status(), StatusCode::OK);

        // Missing tenant scope is refused before any work.
        let no_tenant = app
            .clone()
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({ "domain": "acme.example" }))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_tenant.status(), StatusCode::BAD_REQUEST);

        // batch: scoped cleanup — the system tenant is shared, so delete only
        // the facts/evidence/projection produced for THIS test's domains (the
        // sales_accounts rows are intentionally left: they are upsert targets
        // that other tenants of the suite never read).
        if let Some(db) = crate::test_db::canonical_test_pool("routes_enrich_input_cleanup").await {
            let domains = ["acme.example", "beta.example"];
            let account_ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT id FROM sales_accounts WHERE tenant_id = $1 AND domain = ANY($2)",
            )
            .bind(tenant)
            .bind(&domains)
            .fetch_all(&db)
            .await
            .unwrap_or_default();
            if !account_ids.is_empty() {
                let _ =
                    sqlx::query("DELETE FROM sales_enrichment_facts WHERE subject_id = ANY($1)")
                        .bind(&account_ids)
                        .execute(&db)
                        .await;
                let _ = sqlx::query("DELETE FROM sales_evidence WHERE account_id = ANY($1)")
                    .bind(&account_ids)
                    .execute(&db)
                    .await;
            }
            let _ = sqlx::query(
                "DELETE FROM enriched_companies WHERE tenant_id = $1 AND domain = ANY($2)",
            )
            .bind(tenant)
            .bind(&domains)
            .execute(&db)
            .await;
        }
    }

    /// Conversions can only be created against a campaign AND a lead that both
    /// belong to the calling tenant, and the read model filters by either
    /// relation without leaking across tenants.
    #[tokio::test]
    async fn conversions_require_same_tenant_campaign_and_lead() {
        let Some(app) = test_app("routes_conversions").await else {
            return;
        };
        // batch: system-tenant restriction — lead, campaign and conversion
        // are all created as the system tenant; `other` stays a unique
        // foreign claim for the gate refusal below.
        let tenant = config::SYSTEM_TENANT_ID;
        let other = crate::test_db::unique_test_tenant("routes-conv-other");
        let auth = |builder: axum::http::request::Builder| {
            builder
                .header("x-api-key", "test-key")
                .header("x-tenant-id", tenant)
                .header("content-type", "application/json")
        };

        // A lead and a campaign for this tenant.
        let lead_request = auth(Request::post("/leads"))
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "email": format!(
                        "conv-{}@acme.example",
                        &Uuid::new_v4().simple().to_string()[..10]
                    ),
                    "name": "Convertible",
                    "company": "Acme",
                }))
                .unwrap(),
            ))
            .unwrap();
        let lead_resp = app.clone().oneshot(lead_request).await.unwrap();
        assert_eq!(lead_resp.status(), StatusCode::OK);
        let lead = json_body(lead_resp).await;
        let lead_id = Uuid::parse_str(lead["id"].as_str().expect("lead id")).unwrap();

        let campaign_request = auth(Request::post("/campaigns"))
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "name": "Conversion source",
                    "template_id": "tmpl_conv",
                    "audience": "all",
                }))
                .unwrap(),
            ))
            .unwrap();
        let campaign_resp = app.clone().oneshot(campaign_request).await.unwrap();
        assert_eq!(campaign_resp.status(), StatusCode::OK);
        let campaign = json_body(campaign_resp).await;
        let campaign_id = Uuid::parse_str(campaign["id"].as_str().expect("campaign id")).unwrap();

        // A missing campaign or lead is a 404, never a dangling row.
        let missing_campaign_request = auth(Request::post("/conversions"))
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "campaign_id": Uuid::new_v4(),
                    "lead_id": lead_id,
                    "revenue": 1.0,
                }))
                .unwrap(),
            ))
            .unwrap();
        let missing_campaign = app.clone().oneshot(missing_campaign_request).await.unwrap();
        assert_eq!(missing_campaign.status(), StatusCode::NOT_FOUND);
        let missing_lead_request = auth(Request::post("/conversions"))
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "campaign_id": campaign_id,
                    "lead_id": Uuid::new_v4(),
                    "revenue": 1.0,
                }))
                .unwrap(),
            ))
            .unwrap();
        let missing_lead = app.clone().oneshot(missing_lead_request).await.unwrap();
        assert_eq!(missing_lead.status(), StatusCode::NOT_FOUND);

        // The real conversion records and is listed by tenant, campaign and
        // lead.
        let created_request = auth(Request::post("/conversions"))
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "campaign_id": campaign_id,
                    "lead_id": lead_id,
                    "revenue": 1234.5,
                    "description": "closed won",
                }))
                .unwrap(),
            ))
            .unwrap();
        let created = app.clone().oneshot(created_request).await.unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let created = json_body(created).await;
        assert_eq!(created["revenue"], 1234.5);
        assert_eq!(created["campaign_id"], campaign_id.to_string());

        // batch: system-tenant restriction — the system tenant is shared by
        // the whole suite, so the unfiltered listing is only asserted to
        // CONTAIN this conversion (concurrent tests may own others); the
        // campaign/lead/limit-scoped listings stay exact.
        let unfiltered_request = auth(Request::get("/conversions"))
            .body(Body::empty())
            .unwrap();
        let unfiltered = app.clone().oneshot(unfiltered_request).await.unwrap();
        assert_eq!(unfiltered.status(), StatusCode::OK);
        let unfiltered_rows = json_body(unfiltered).await;
        assert!(
            unfiltered_rows
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == created["id"]),
            "the conversion must be listed unfiltered: {unfiltered_rows}"
        );
        for url in [
            format!("/conversions?campaign_id={campaign_id}"),
            format!("/conversions?lead_id={lead_id}"),
            "/conversions?limit=1&offset=0".to_string(),
        ] {
            let request = auth(Request::get(url.clone())).body(Body::empty()).unwrap();
            let resp = app.clone().oneshot(request).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{url}");
            let rows = json_body(resp).await;
            assert_eq!(rows.as_array().unwrap().len(), 1, "{url}: {rows}");
        }

        // batch: system-tenant restriction — the gate refuses foreign tenants
        // with 403 (previously another tenant simply saw an empty list at the
        // data layer; the isolation property is enforced at the router now).
        let foreign = app
            .clone()
            .oneshot(
                Request::get("/conversions")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", other.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);

        // batch: scoped cleanup — the system tenant is shared, so delete by
        // this test's ids/emails, never by tenant_id.
        if let Some(db) = crate::test_db::canonical_test_pool("routes_conversions_cleanup").await {
            let _ =
                sqlx::query("DELETE FROM sales_conversions WHERE campaign_id = $1 OR lead_id = $2")
                    .bind(campaign_id)
                    .bind(lead_id)
                    .execute(&db)
                    .await;
            let _ = sqlx::query("DELETE FROM sales_campaigns WHERE id = $1")
                .bind(campaign_id)
                .execute(&db)
                .await;
            let _ = sqlx::query("DELETE FROM sales_leads WHERE id = $1")
                .bind(lead_id.to_string())
                .execute(&db)
                .await;
        }
    }
}

#[cfg(test)]
mod gate_and_validation_tests {
    //! Middleware gates (every token shape + tenant allowlist + public
    //! exemptions) and validation refusals, driven through the real router
    //! with tower oneshot.

    use super::tests::{test_app, test_app_impl};
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn missing_or_wrong_tokens_are_unauthorized_on_every_protected_route() {
        let Some(app) = test_app("routes_gates_tokens").await else {
            return;
        };
        // No token at all.
        let resp = app
            .clone()
            .oneshot(
                Request::get("/campaigns")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // A wrong token is indistinguishable from none.
        let resp = app
            .clone()
            .oneshot(
                Request::get("/campaigns")
                    .header("x-api-key", "wrong-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // A malformed Authorization header is not a Bearer token.
        let resp = app
            .clone()
            .oneshot(
                Request::get("/campaigns")
                    .header("authorization", "Basic dXNlcjpwd2Q=")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_bearer_token_authorizes_like_the_api_key() {
        let Some(app) = test_app("routes_gates_bearer").await else {
            return;
        };
        let resp = app
            .oneshot(
                Request::get("/campaigns")
                    .header("authorization", "Bearer test-key")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED, "Bearer accepted");
    }

    #[tokio::test]
    async fn an_empty_configured_service_token_rejects_every_protected_route() {
        let Some(app) = test_app_impl("routes_gates_empty_token", "", false).await else {
            return;
        };
        let resp = app
            .oneshot(
                Request::get("/campaigns")
                    .header("x-api-key", "")
                    .header("x-tenant-id", config::SYSTEM_TENANT_ID)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_and_unsubscribe_paths_are_public() {
        let Some(app) = test_app("routes_gates_public").await else {
            return;
        };
        // No token: /health still answers.
        let resp = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // No token: the unsubscribe path is routed (auth is not the gate;
        // the HMAC token is). Any non-401 answer proves the exemption.
        let resp = app
            .oneshot(
                Request::get("/u/not-a-valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn adding_an_empty_recipient_list_is_refused_with_400() {
        let Some(app) = test_app("routes_validation_campaign").await else {
            return;
        };
        // batch: system-tenant restriction — the campaign draft is created as
        // the system tenant (the only tenant the gate admits).
        let tenant = config::SYSTEM_TENANT_ID;
        // A campaign draft first (create succeeds — recipients gate only the
        // send path).
        let create_body = serde_json::json!({
            "name": "No recipients",
            "template_id": "tmpl_competitor_migration",
            "audience": "selected-leads",
        });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/campaigns")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let created: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let id = created["id"].as_str().unwrap();

        // Adding an EMPTY recipient list is a validation refusal that names
        // the missing input.
        let body = serde_json::json!({ "emails": [] });
        let resp = app
            .oneshot(
                Request::post(format!("/campaigns/{id}/recipients"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap_or_default();
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
            "validation refusal, got {status}: {text}"
        );
        assert!(
            text.contains("recipient"),
            "the refusal names the missing input: {text}"
        );
    }

    #[tokio::test]
    async fn campaign_list_is_tenant_scoped_and_paginates() {
        let Some(app) = test_app("routes_list_campaigns").await else {
            return;
        };
        // batch: system-tenant restriction — the listing runs as the system
        // tenant.
        let tenant = config::SYSTEM_TENANT_ID;
        let resp = app
            .clone()
            .oneshot(
                Request::get("/campaigns?limit=5&offset=0")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(body.get("campaigns").is_some() || body.is_array(), "{body}");

        // batch: system-tenant restriction — a DIFFERENT tenant claim is
        // refused by the gate with 403 (previously it saw its own disjoint
        // list at the data layer; the isolation property is enforced at the
        // router now).
        let other = crate::test_db::unique_test_tenant("routes-listother");
        let resp = app
            .oneshot(
                Request::get("/campaigns")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", other)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn discovery_job_status_for_an_unknown_job_is_404() {
        let Some(app) = test_app("routes_discovery_404").await else {
            return;
        };
        // batch: system-tenant restriction — the request must reach the
        // handler (the gate only admits the system tenant), so the unknown
        // job's client error below is the runner's contract, not the 403.
        let tenant = config::SYSTEM_TENANT_ID;
        let resp = app
            .oneshot(
                Request::get(format!("/discovery/jobs/{}", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // The unknown job is refused with a 4xx (not a success, and the
        // auth gate has already passed); the exact code is the runner's
        // contract (404 when the runner reports NotFound, 400 when the
        // provider contract treats the tenant+job pair as invalid).
        assert!(
            resp.status().is_client_error(),
            "unknown job refused: {}",
            resp.status()
        );
    }
}

// ---------------------------------------------------------------------------
// Coverage-wave adversarial proofs: the arms the earlier waves never drove —
// the public unsubscribe contract variants, the Redis rate-limit path, the
// inbox/calendar/discovery surfaces end to end, and LIKE-injection in the
// companies filter. Run by default; soft-skip only when the canonical test
// database is unconfigured.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod coverage_wave_routes {
    use super::tests::{lazy_test_app, test_app};
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use billing_service::send_admission::SendAdmissionBackend;
    use tower::ServiceExt;

    /// Unlimited, suppression-free admission backend so route tests can drive
    /// the REAL dispatcher without live billing storage (mirrors the fake in
    /// `dispatcher::tests`).
    #[derive(Debug, Default)]
    struct UnlimitedAdmission;

    #[async_trait::async_trait]
    impl SendAdmissionBackend for UnlimitedAdmission {
        async fn record_send_usage(
            &self,
            _tenant_id: &str,
            _quantity: i64,
            _event_id: Uuid,
        ) -> Result<billing_service::usage::QuotaRecordResult, billing_service::usage::UsageError>
        {
            Ok(billing_service::usage::QuotaRecordResult {
                allowed: true,
                current: 0,
                duplicate: false,
            })
        }

        async fn rollback_send_usage(
            &self,
            _tenant_id: &str,
            _quantity: i64,
            _event_id: Uuid,
            _recorded_at: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), billing_service::usage::UsageError> {
            Ok(())
        }

        async fn suppressed_recipients(
            &self,
            _tenant_id: &str,
            _canonical_recipients: &[String],
        ) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }
    }

    fn route_dispatch_config() -> crate::config::DispatchConfig {
        crate::config::DispatchConfig {
            from_email: "sales@routes-wave.example".into(),
            from_name: "Coverage Wave".into(),
            unsubscribe_secret: "route-wave-unsubscribe-secret-0123456789abcdef".into(),
            public_base_url: "http://127.0.0.1:3010".into(),
            unsubscribe_redirect_url: None,
            dispatch_interval_secs: 30,
            dispatch_batch_size: 100,
            dispatch_concurrency: 1,
        }
    }

    /// Canonical-pool app with a custom `SalesConfig` (the existing harnesses
    /// hardcode the default config).
    async fn canonical_app_with_config(
        test_name: &str,
        config: crate::config::SalesConfig,
    ) -> Option<Router> {
        canonical_app_with_redis_url(test_name, config, "redis://127.0.0.1:6379").await
    }

    /// Canonical-pool app with explicit `SalesConfig` AND Redis URL.
    ///
    /// The extra seam exists for the enrichment rate-limit proof: the
    /// limiter keys on the tenant id, and every route test now shares the ONE
    /// system tenant — pointing this harness at a dedicated logical Redis db
    /// keeps the 30-request window exact against concurrent `/enrich` tests
    /// on the default db.
    async fn canonical_app_with_redis_url(
        test_name: &str,
        config: crate::config::SalesConfig,
        redis_url: &str,
    ) -> Option<Router> {
        let db = crate::test_db::canonical_test_pool(test_name).await?;
        let redis = deadpool_redis::Config::from_url(redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");
        let state = AppState {
            db: db.clone(),
            redis,
            config,
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            campaigns: CampaignManager::new(10, db.clone()),
            dispatcher: None,
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            service_token: "test-key".into(),
            rate_limit_fallback: Arc::new(Mutex::new(HashMap::new())),
            intelligence: Arc::new(crate::intelligence::OfflineIntelligence::new()),
            strategist: Arc::new(MessageStrategist::new(
                db,
                crate::knowledge::SalesKnowledgeBase::canonical(),
            )),
        };
        Some(router(state))
    }

    /// Canonical-pool app with the production dispatcher wired (the real
    /// enqueue pipeline; unlimited test admission).
    async fn canonical_app_with_dispatcher(test_name: &str) -> Option<Router> {
        let db = crate::test_db::canonical_test_pool(test_name).await?;
        let dispatcher = ProductionCampaignDispatcher::new(
            route_dispatch_config(),
            db.clone(),
            Arc::new(UnlimitedAdmission),
        )
        .expect("the route-wave dispatch config is configured");
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");
        let state = AppState {
            db: db.clone(),
            redis,
            config: Default::default(),
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            campaigns: CampaignManager::new(10, db.clone()),
            dispatcher: Some(Arc::new(dispatcher)),
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            service_token: "test-key".into(),
            rate_limit_fallback: Arc::new(Mutex::new(HashMap::new())),
            intelligence: Arc::new(crate::intelligence::OfflineIntelligence::new()),
            strategist: Arc::new(MessageStrategist::new(
                db,
                crate::knowledge::SalesKnowledgeBase::canonical(),
            )),
        };
        Some(router(state))
    }

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    /// The next weekday (`Weekday::Mon`) at least `min_days_out` days ahead,
    /// so calendar fixtures never depend on today's position in the week.
    fn next_weekday_at(
        weekday: chrono::Weekday,
        min_days_out: i64,
        hour: u32,
        minute: u32,
    ) -> chrono::DateTime<chrono::Utc> {
        use chrono::Datelike;
        let mut day = chrono::Utc::now().date_naive() + chrono::Duration::days(min_days_out);
        while day.weekday() != weekday {
            day += chrono::Duration::days(1);
        }
        day.and_hms_opt(hour, minute, 0)
            .expect("valid wall clock")
            .and_utc()
    }

    /// RFC 3339 with a `Z` designator (never `+00:00`): a raw `+` in a query
    /// string decodes as a space and would corrupt the timestamp.
    fn query_ts(t: chrono::DateTime<chrono::Utc>) -> String {
        t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    /// Insert the platform `tenants` row a platform-table FK (suppressions,
    /// messages, domains) requires for a raw `unique_test_tenant` id.
    async fn seed_platform_tenant(db: &PgPool, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) \
             VALUES ($1, $2, $3, 'starter', 'active') ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(format!("test {tenant}"))
        .bind(format!("slug-{tenant}"))
        .execute(db)
        .await
        .expect("insert platform tenant row");
    }

    // ── Public unsubscribe contract ──────────────────────────────────────

    /// RFC 8058: the POST body MUST be exactly `List-Unsubscribe=One-Click`
    /// (CRLF-tolerant). Anything else is a 400 that must NOT redeem a token —
    /// and an invalid token on the correct body is a 400 naming the token, not
    /// a 5xx and never a silent success.
    #[tokio::test]
    async fn unsubscribe_post_guards_the_one_click_body_and_invalid_tokens() {
        // Wrong body shapes are refused before anything is redeemed. (A
        // CRLF/whitespace-padded correct body is deliberately ACCEPTED —
        // the handler trims — so it is not in the hostile list.)
        for hostile in ["", "List-Unsubscribe=Two-Click", "GET"] {
            let Some(app) = test_app("routes_wave_unsub_body").await else {
                return;
            };
            let resp = app
                .oneshot(
                    Request::post("/u/not-a-real-token")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(hostile.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "hostile one-click body {hostile:?} must be refused"
            );
            let body = json_body(resp).await;
            assert_eq!(body["error"], "Invalid request body", "{body}");
        }

        // The correct body with an invalid token is an honest 400 that names
        // the problem — with no legacy secret configured the v1 verifier is
        // skipped, but that must not become a 5xx.
        let Some(app) = test_app("routes_wave_unsub_invalid").await else {
            return;
        };
        let resp = app
            .oneshot(
                Request::post("/u/not-a-real-token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("List-Unsubscribe=One-Click"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("invalid or expired unsubscribe token"),
            "{body}"
        );
    }

    /// FIXED (batch 2, F39): GET /u/:token no longer suppresses — it renders
    /// the side-effect-free confirmation form. A configured
    /// `SALES_UNSUBSCRIBE_REDIRECT_URL` is honoured by the CONFIRM POST (the
    /// consent-changing step): confirm → suppress → redirect to the
    /// operator's target.
    #[tokio::test]
    async fn unsubscribe_get_redirects_to_the_configured_target_after_suppressing() {
        let Some(db) = crate::test_db::canonical_test_pool("routes_wave_unsub_redirect_db").await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("routes-unsub-red");
        seed_platform_tenant(&db, &tenant).await;
        let mut config = crate::config::SalesConfig::default();
        config.dispatch.unsubscribe_redirect_url = Some("https://brand.example/goodbye".into());
        let Some(app) = canonical_app_with_config("routes_wave_unsub_redirect", config).await
        else {
            return;
        };

        let token =
            crate::dispatcher::create_unsubscribe_token(&db, &tenant, "clicker@example.com")
                .await
                .expect("v2 token");

        // GET: the confirmation form (200 HTML), never a redirect, never a
        // suppression.
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/u/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "F39: the prefetchable GET must render the confirmation form"
        );
        let pre_confirm: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1 AND email = $2",
        )
        .bind(&tenant)
        .bind("clicker@example.com")
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(pre_confirm, 0, "F39: GET must not suppress");

        // POST confirm: suppression FIRST, then the redirect to the
        // configured operator target.
        let resp = app
            .oneshot(
                Request::post(format!("/u/{token}/confirm"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("confirm=true"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status().is_redirection(),
            "a configured redirect target must be honoured, got {}",
            resp.status()
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("https://brand.example/goodbye"),
            "the redirect must go to the configured target"
        );

        // The redirect happened AFTER the suppression, not instead of it.
        let suppressed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1 AND email = $2",
        )
        .bind(&tenant)
        .bind("clicker@example.com")
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(suppressed, 1, "redirect must not skip the suppression");

        for statement in [
            "DELETE FROM sales_unsubscribes WHERE tenant_id = $1",
            "DELETE FROM sales_unsubscribe_tokens WHERE tenant_id = $1",
            "DELETE FROM suppressions WHERE tenant_id = $1",
            "DELETE FROM tenants WHERE id = $1",
        ] {
            let _ = sqlx::query(statement).bind(&tenant).execute(&db).await;
        }
    }

    // ── Redis-backed enrichment rate limit through the real router ──────

    /// 30 enrichment calls per tenant per minute — enforced through the REAL
    /// Redis Lua path (the in-memory fallback is covered elsewhere). Request
    /// 31 is a 429; the limiter counts BEFORE input validation, so the cheap
    /// bad-email body proves the window without 31 persisted enrichments.
    ///
    /// batch: system-tenant restriction — every `/enrich` caller shares the
    /// ONE system tenant, so the limiter key would be shared with concurrent
    /// enrich tests; this proof therefore runs on a dedicated logical Redis
    /// db (db 1), keeping the exact 30/31 window deterministic.
    #[tokio::test]
    async fn enrichment_rate_limit_429s_the_thirty_first_request_via_redis() {
        const ISOLATED_REDIS_URL: &str = "redis://127.0.0.1:6379/1";
        let config = crate::config::SalesConfig::default();
        let Some(app) =
            canonical_app_with_redis_url("routes_wave_rate_limit", config, ISOLATED_REDIS_URL)
                .await
        else {
            return;
        };
        // Determinism hygiene: back-to-back suite runs must start from an
        // empty 60-second window on the shared logical db.
        let purge_pool = deadpool_redis::Config::from_url(ISOLATED_REDIS_URL)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("isolated redis pool");
        let mut purge_conn = purge_pool
            .get()
            .await
            .expect("connect to the isolated redis db");
        let _: i64 = deadpool_redis::redis::cmd("DEL")
            .arg(format!(
                "{RATE_LIMITER_REDIS_PREFIX}{}",
                config::SYSTEM_TENANT_ID
            ))
            .query_async(&mut purge_conn)
            .await
            .expect("purge the rate-limit window");

        let tenant = config::SYSTEM_TENANT_ID;
        let mut saw_429_early = false;
        for index in 0..31u32 {
            let resp = app
                .clone()
                .oneshot(
                    Request::post("/enrich")
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&serde_json::json!({ "email": "bad" })).unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            if index < 30 {
                assert_eq!(
                    status,
                    StatusCode::BAD_REQUEST,
                    "request {index} is inside the window (bad email is the 400)"
                );
                assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
            } else {
                assert_eq!(
                    status,
                    StatusCode::TOO_MANY_REQUESTS,
                    "request 31 must hit the Redis-backed rate limit"
                );
                saw_429_early = true;
            }
        }
        assert!(saw_429_early, "the 31st request must be the 429");

        // batch: system-tenant restriction — the per-tenant window can no
        // longer be probed with a second tenant through the router: the gate
        // refuses any non-system tenant with 403 before the limiter runs.
        let other = crate::test_db::unique_test_tenant("routes-ratelimit-b");
        let resp = app
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", other)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({ "email": "bad" })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "the gate refuses foreign tenants before the rate limiter"
        );
    }

    // ── Inbox read model ─────────────────────────────────────────────────

    /// GET /inbox filters by category (the unknown category lands in
    /// `other`), is tenant-scoped, and paginates with clamping.
    ///
    /// batch: system-tenant restriction — the listing runs as the system
    /// tenant on the SHARED database, so the fixture clears its own fixed
    /// senders first (determinism across runs) and asserts with
    /// concurrency-tolerant shapes where sibling tests may add system-tenant
    /// rows; the foreign claim is gate-refused with 403.
    #[tokio::test]
    async fn inbox_listing_is_category_filtered_tenant_scoped_and_paged() {
        let Some(db) = crate::test_db::canonical_test_pool("routes_wave_inbox_db").await else {
            return;
        };
        let Some(app) = test_app("routes_wave_inbox").await else {
            return;
        };
        let tenant = config::SYSTEM_TENANT_ID;
        let senders = [
            "lead1@example.com",
            "spam1@example.com",
            "optout1@example.com",
            "misc1@example.com",
        ];
        // Clear this fixture's rows from previous runs (the canonical
        // database is reused); never delete the shared tenant's other rows.
        sqlx::query("DELETE FROM sales_inbox_messages WHERE tenant_id = $1 AND sender = ANY($2)")
            .bind(tenant)
            .bind(&senders)
            .execute(&db)
            .await
            .expect("clear stale fixture inbox messages");
        for (sender, category) in [
            ("lead1@example.com", "lead"),
            ("spam1@example.com", "spam"),
            ("optout1@example.com", "unsubscribe"),
            ("misc1@example.com", "other"),
        ] {
            sqlx::query(
                "INSERT INTO sales_inbox_messages (id, tenant_id, sender, subject, category) \
                 VALUES ($1, $2, $3, 'seeded', $4)",
            )
            .bind(Uuid::new_v4())
            .bind(tenant)
            .bind(sender)
            .bind(category)
            .execute(&db)
            .await
            .expect("seed inbox message");
        }

        let get = |url: &'static str, tenant: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::get(url)
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        // Sibling tests (inbox replies) may add system-tenant rows while this
        // runs, so the unfiltered shape is asserted to contain THIS fixture's
        // four senders — all under the system tenant.
        let all = json_body(get("/inbox", tenant.to_string()).await).await;
        let all_rows = all.as_array().unwrap();
        assert!(all_rows.len() >= 4, "{all}");
        for sender in senders {
            assert!(
                all_rows.iter().any(|row| row["from"] == sender),
                "fixture sender {sender} must be listed: {all}"
            );
        }
        assert!(
            all_rows.iter().all(|row| row["tenant_id"] == tenant),
            "every row belongs to the calling tenant: {all}"
        );

        let spam = json_body(get("/inbox?category=spam", tenant.to_string()).await).await;
        assert_eq!(spam.as_array().unwrap().len(), 1, "{spam}");
        assert_eq!(spam[0]["category"], "spam");

        let optout = json_body(get("/inbox?category=unsubscribe", tenant.to_string()).await).await;
        assert_eq!(optout.as_array().unwrap().len(), 1, "{optout}");

        // An unknown category string maps to the `other` bucket, not an error
        // and not "everything". (Reply tests may add system-tenant `other`
        // rows concurrently, so assert the bucketing, not an exact count.)
        let nonsense = json_body(get("/inbox?category=telepathy", tenant.to_string()).await).await;
        let nonsense_rows = nonsense.as_array().unwrap();
        assert!(!nonsense_rows.is_empty(), "{nonsense}");
        assert!(
            nonsense_rows.iter().all(|row| row["category"] == "other"),
            "unknown categories land in `other`: {nonsense}"
        );
        assert!(
            nonsense_rows
                .iter()
                .any(|row| row["from"] == "misc1@example.com"),
            "{nonsense}"
        );

        // Hostile pagination clamps instead of erroring.
        let paged = json_body(get("/inbox?limit=2&offset=0", tenant.to_string()).await).await;
        assert_eq!(paged.as_array().unwrap().len(), 2, "{paged}");
        let clamped =
            json_body(get("/inbox?limit=-5&offset=99999", tenant.to_string()).await).await;
        assert!(clamped.as_array().unwrap().is_empty(), "{clamped}");

        // batch: system-tenant restriction — the gate refuses foreign tenants
        // with 403 (previously the foreign tenant simply saw its own
        // data-layer-isolated list).
        let other = crate::test_db::unique_test_tenant("routes-inbox-other");
        let foreign = get("/inbox", other).await;
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);

        let _ = sqlx::query(
            "DELETE FROM sales_inbox_messages WHERE tenant_id = $1 AND sender = ANY($2)",
        )
        .bind(tenant)
        .bind(&senders)
        .execute(&db)
        .await;
    }

    // ── Inbox reply through the real dispatcher ──────────────────────────

    /// POST /inbox/:id/reply with the production dispatcher wired: the reply
    /// is enqueued through the platform pipeline exactly once, the `replied`
    /// flag commits with it, and a replay is an idempotent duplicate.
    #[tokio::test]
    async fn inbox_reply_enqueues_exactly_once_through_the_platform_pipeline() {
        let Some(db) = crate::test_db::canonical_test_pool("routes_wave_reply_db").await else {
            return;
        };
        let Some(app) = canonical_app_with_dispatcher("routes_wave_reply").await else {
            return;
        };
        // batch: system-tenant restriction — the fixture and the reply both
        // run as the system tenant on the shared database, so every write and
        // cleanup below is keyed by ids/emails, never by tenant_id alone.
        let tenant = config::SYSTEM_TENANT_ID;
        seed_platform_tenant(&db, tenant).await;
        // The reply's legacy sender is the deployment-wide
        // `SALES_CAMPAIGN_FROM_EMAIL`; its domain must be verified+DKIM-ready
        // for the fixture tenant or the enqueue honestly refuses. The name is
        // globally unique in `domains`, so clear any stale row first (the
        // canonical database is reused across runs).
        sqlx::query("DELETE FROM domains WHERE name = 'routes-wave.example'")
            .execute(&db)
            .await
            .expect("clear stale fixture sender domain");
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, \
             ses_verified, dkim_selector, dkim_public_key, dkim_private_key) \
             VALUES ($1, $2, 'routes-wave.example', 'verified', true, true, true, \
                     'wave-selector', 'wave-public', 'dkim:v1:wave-test')",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .execute(&db)
        .await
        .expect("seed verified sender domain");
        let inbox_id = Uuid::new_v4();
        let sender = format!(
            "prospect-{}@example.com",
            &inbox_id.simple().to_string()[..8]
        );
        // Fix #19: the fixture previously seeded the legacy category
        // 'positive' (which parses to the non-concrete `Other`) — the new
        // irreversible-action guard refuses replies to non-concrete rows,
        // so the fixture uses a concrete, classifier-emitted category
        // (`lead`). All assertions below are unchanged.
        sqlx::query(
            "INSERT INTO sales_inbox_messages (id, tenant_id, sender, subject, category) \
             VALUES ($1, $2, $3, 'Re: demo', 'lead')",
        )
        .bind(inbox_id)
        .bind(tenant)
        .bind(&sender)
        .execute(&db)
        .await
        .expect("seed inbox message");

        let post_reply = |app: Router, body: serde_json::Value| {
            let tenant = tenant;
            async move {
                app.oneshot(
                    Request::post(format!("/inbox/{inbox_id}/reply"))
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        let first = post_reply(
            app.clone(),
            serde_json::json!({ "body": "Thanks for the demo!" }),
        )
        .await;
        assert_eq!(
            first.status(),
            StatusCode::ACCEPTED,
            "reply enqueues: {}",
            serde_json::to_string(&json_body(first).await).unwrap_or_default()
        );
        let body = json_body(first).await;
        assert_eq!(body["queued"], true, "{body}");
        assert_eq!(body["replied"], true);
        assert_eq!(body["to"], sender);
        let message_id = body["messageId"].as_str().expect("messageId").to_string();

        // The platform rows exist and the flag committed with the enqueue.
        // (batch: scoped counts — the platform tables are shared under the
        // system tenant, so count only THIS inbox message's reply.)
        let replied: bool =
            sqlx::query_scalar("SELECT replied FROM sales_inbox_messages WHERE id = $1")
                .bind(inbox_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(replied, "the flag commits atomically with the enqueue");
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM email_queue WHERE metadata->>'inbox_message_id' = $1",
        )
        .bind(inbox_id.to_string())
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(queued, 1);

        // A replay does NOT send a second reply.
        let replay = post_reply(
            app.clone(),
            serde_json::json!({ "body": "duplicate attempt" }),
        )
        .await;
        assert_eq!(replay.status(), StatusCode::ACCEPTED);
        let body = json_body(replay).await;
        assert_eq!(body["duplicate"], true, "{body}");
        assert_eq!(body["queued"], false);
        assert_eq!(
            body["messageId"].as_str().unwrap(),
            message_id,
            "the replay reports the original message"
        );
        let messages: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM messages WHERE metadata->>'inbox_message_id' = $1",
        )
        .bind(inbox_id.to_string())
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(messages, 1, "exactly one reply per inbox message");

        // batch: system-tenant restriction — the gate refuses foreign tenants
        // with 403 (previously the data layer answered a tenant-scoped 404).
        let foreign = app
            .oneshot(
                Request::post(format!("/inbox/{inbox_id}/reply"))
                    .header("x-api-key", "test-key")
                    .header(
                        "x-tenant-id",
                        crate::test_db::unique_test_tenant("routes-reply-o"),
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({ "body": "steal" })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN, "gate-refused");

        // batch: scoped cleanup — delete only this fixture's rows; the shared
        // system tenants row (and the other tests' rows) must survive.
        let _ = sqlx::query("DELETE FROM email_queue WHERE message_id = $1")
            .bind(message_id.parse::<Uuid>().unwrap())
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM messages WHERE metadata->>'inbox_message_id' = $1")
            .bind(inbox_id.to_string())
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM sales_inbox_messages WHERE id = $1")
            .bind(inbox_id)
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM domains WHERE name = 'routes-wave.example'")
            .execute(&db)
            .await;
    }

    /// The reply route's honest refusals: a platform-suppressed correspondent
    /// and a syntactically invalid sender are 400s that leave the message
    /// unanswered, an unknown message is a 404, and an oversized body is
    /// refused before any enqueue work.
    #[tokio::test]
    async fn inbox_reply_refuses_suppressed_invalid_and_oversized_requests() {
        let Some(db) = crate::test_db::canonical_test_pool("routes_wave_reply_bad_db").await else {
            return;
        };
        let Some(app) = canonical_app_with_dispatcher("routes_wave_reply_bad").await else {
            return;
        };
        // batch: system-tenant restriction — the fixture runs as the system
        // tenant on the shared database; writes and cleanups are keyed by
        // ids/emails, never by tenant_id alone.
        let tenant = config::SYSTEM_TENANT_ID;
        seed_platform_tenant(&db, tenant).await;

        let suppressed_inbox = Uuid::new_v4();
        let invalid_inbox = Uuid::new_v4();
        // Fix #19: the fixtures previously seeded the legacy category
        // 'other' (non-concrete); the new irreversible-action guard refuses
        // replies to non-concrete rows BEFORE the suppression/sender checks
        // these cases exercise, so the fixtures use a concrete
        // classifier-emitted category (`support`). Assertions unchanged.
        for (id, sender) in [
            (suppressed_inbox, "bounced@example.com"),
            (invalid_inbox, "no-at-sign"),
        ] {
            sqlx::query(
                "INSERT INTO sales_inbox_messages (id, tenant_id, sender, subject, category) \
                 VALUES ($1, $2, $3, 'hi', 'support')",
            )
            .bind(id)
            .bind(tenant)
            .bind(sender)
            .execute(&db)
            .await
            .expect("seed inbox message");
        }
        // Fix #19 fixture: a low-confidence classification (NeedsReview) is
        // the row the guard exists for.
        let needs_review_inbox = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_inbox_messages (id, tenant_id, sender, subject, category) \
             VALUES ($1, $2, 'review-me@example.com', 'hello?', 'needs_review')",
        )
        .bind(needs_review_inbox)
        .bind(tenant)
        .execute(&db)
        .await
        .expect("seed needs-review inbox message");
        // Platform-level hard bounce for the suppressed correspondent. The
        // reply is 1:1 correspondence, so only THIS list blocks it.
        let suppression_id = apexmail_lib::id::generate_id("sup", 22);
        sqlx::query(
            "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at) \
             VALUES ($1, $2, 'bounced@example.com', 'hard_bounce', 'platform', NOW())",
        )
        .bind(&suppression_id)
        .bind(tenant)
        .execute(&db)
        .await
        .expect("platform-suppress the correspondent");

        let reply = |inbox: Uuid, body: serde_json::Value, tenant: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::post(format!("/inbox/{inbox}/reply"))
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        // (a) Suppressed correspondent: 400, nothing enqueued, flag untouched.
        let resp = reply(
            suppressed_inbox,
            serde_json::json!({ "body": "hello?" }),
            tenant.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("suppressed"),
            "{body}"
        );
        let replied: bool =
            sqlx::query_scalar("SELECT replied FROM sales_inbox_messages WHERE id = $1")
                .bind(suppressed_inbox)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(!replied, "a refused reply leaves the message unanswered");
        // batch: scoped count — the messages table is shared under the system
        // tenant, so assert on THIS inbox message's (non-)reply only.
        let messages: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM messages WHERE metadata->>'inbox_message_id' = $1",
        )
        .bind(suppressed_inbox.to_string())
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(messages, 0, "no message for a suppressed correspondent");

        // (b) A sender that is not a valid email is refused before any quota.
        let resp = reply(
            invalid_inbox,
            serde_json::json!({ "body": "hello?" }),
            tenant.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("not a valid email"),
            "{body}"
        );

        // (c) Unknown message id: tenant-scoped 404, never a 500.
        let resp = reply(
            Uuid::new_v4(),
            serde_json::json!({ "body": "hello?" }),
            tenant.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // (d) An oversized reply is refused by length before any work.
        let oversized = "x".repeat(100_001);
        let resp = reply(
            suppressed_inbox,
            serde_json::json!({ "body": oversized }),
            tenant.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("exceeds the maximum"),
            "{body}"
        );

        // (e) Fix #19: a NeedsReview (below automation confidence) message
        // is refused BEFORE any enqueue work — no irreversible outbound send
        // may fire from a low-confidence classification. The refusal names
        // the review requirement and leaves the row unanswered.
        let resp = reply(
            needs_review_inbox,
            serde_json::json!({ "body": "hello?" }),
            tenant.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = json_body(resp).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("needs_review"),
            "the refusal must name the non-concrete category: {body}"
        );
        let replied: bool =
            sqlx::query_scalar("SELECT replied FROM sales_inbox_messages WHERE id = $1")
                .bind(needs_review_inbox)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            !replied,
            "a guard-refused reply leaves the message unanswered"
        );
        let messages: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM messages WHERE metadata->>'inbox_message_id' = $1",
        )
        .bind(needs_review_inbox.to_string())
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(messages, 0, "no reply is enqueued for a review-bucket row");

        // batch: scoped cleanup — only this fixture's rows; the shared system
        // tenants row (and the other tests' rows) must survive.
        for id in [suppressed_inbox, invalid_inbox, needs_review_inbox] {
            let _ = sqlx::query("DELETE FROM sales_inbox_messages WHERE id = $1")
                .bind(id)
                .execute(&db)
                .await;
        }
        let _ = sqlx::query("DELETE FROM suppressions WHERE id = $1")
            .bind(&suppression_id)
            .execute(&db)
            .await;
    }

    // ── Calendar surface ─────────────────────────────────────────────────

    /// The calendar event lifecycle through the router: creation validates
    /// ordering, recency and legacy working hours; listing is tenant-scoped
    /// and clamps hostile pagination; cancellation is tenant-scoped.
    #[tokio::test]
    async fn calendar_event_lifecycle_is_validated_tenant_scoped_and_cancellable() {
        let Some(db) = crate::test_db::canonical_test_pool("routes_wave_calendar_db").await else {
            return;
        };
        let Some(app) = test_app("routes_wave_calendar").await else {
            return;
        };
        // batch: system-tenant restriction — the booking runs as the system
        // tenant on the shared database. The title and the start time are
        // run-unique because `create_event` refuses OVERLAPPING events for
        // the tenant regardless of title/status, and the canonical database
        // is reused across runs.
        let tenant = config::SYSTEM_TENANT_ID;
        let other = crate::test_db::unique_test_tenant("routes-cal-other");
        let title = format!(
            "Discovery call-{}",
            &Uuid::new_v4().simple().to_string()[..8]
        );
        let start = next_weekday_at(chrono::Weekday::Mon, 14, 9, 0)
            + chrono::Duration::minutes(
                1 + (Uuid::new_v4().as_u128() % 360) as i64, // 09:01–15:01, end ≤ 15:31
            );
        let end = start + chrono::Duration::minutes(30);

        let post_event = |body: serde_json::Value, tenant: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::post("/calendar/events")
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        let created = post_event(
            serde_json::json!({
                "title": title,
                "attendees": ["prospect@example.com"],
                "start_at": start.to_rfc3339(),
                "end_at": end.to_rfc3339(),
            }),
            tenant.to_string(),
        )
        .await;
        assert_eq!(created.status(), StatusCode::OK, "valid event books");
        let event = json_body(created).await;
        let event_id = event["id"].as_str().expect("event id").to_string();
        assert_eq!(event["title"], title);
        assert!(
            event["meeting_link"].as_str().unwrap_or_default().len() > 0,
            "a conferencing link is generated: {event}"
        );

        // end_at <= start_at is a 400 naming the rule.
        let resp = post_event(
            serde_json::json!({
                "title": "Backwards",
                "start_at": start.to_rfc3339(),
                "end_at": start.to_rfc3339(),
            }),
            tenant.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(json_body(resp).await["error"]
            .as_str()
            .unwrap_or_default()
            .contains("end_at must be after start_at"));

        // A past start is refused.
        let resp = post_event(
            serde_json::json!({
                "title": "Time travel",
                "start_at": (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339(),
                "end_at": chrono::Utc::now().to_rfc3339(),
            }),
            tenant.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Outside the legacy working hours (default 09:00–17:00) is refused.
        let late = next_weekday_at(chrono::Weekday::Mon, 14, 20, 0);
        let resp = post_event(
            serde_json::json!({
                "title": "Midnight oil",
                "start_at": late.to_rfc3339(),
                "end_at": (late + chrono::Duration::minutes(30)).to_rfc3339(),
            }),
            tenant.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "outside hours");

        // Header/payload tenant mismatch is refused before any write.
        let resp = post_event(
            serde_json::json!({
                "title": "Smuggled",
                "start_at": start.to_rfc3339(),
                "end_at": end.to_rfc3339(),
                "tenant_id": other,
            }),
            tenant.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Listing: owner sees this run's event (the default window is
        // now..+7d, so query an explicit range covering the fixture), hostile
        // pagination clamps.
        let window = format!(
            "from={}&to={}",
            (chrono::Utc::now() - chrono::Duration::days(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            (chrono::Utc::now() + chrono::Duration::days(60))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        let listed = app
            .clone()
            .oneshot(
                Request::get(format!("/calendar?{window}"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let events = json_body(listed).await;
        // batch: system-tenant restriction — the system tenant is shared, so
        // scope the listing assertion to THIS run's uniquely titled event
        // instead of the whole window's array.
        let own_events = events
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["title"] == title)
            .count();
        assert_eq!(own_events, 1, "{events}");
        let paged = json_body(
            app.clone()
                .oneshot(
                    Request::get(format!("/calendar?{window}&limit=-3&offset=5"))
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert!(paged.as_array().unwrap().is_empty(), "{paged}");

        // batch: system-tenant restriction — the gate refuses foreign tenants
        // with 403 (previously the foreign tenant saw an empty data-layer
        // list; the isolation property is enforced at the router now).
        let foreign = app
            .clone()
            .oneshot(
                Request::get("/calendar")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", &other)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);

        // Cancellation is tenant-scoped: the owner can cancel; the foreign
        // tenant is gate-refused and an unknown id is a 404.
        let cancel = |id: Uuid, tenant: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::delete(format!("/calendar/events/{id}"))
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };
        // batch: system-tenant restriction — the gate refuses foreign tenants
        // with 403 (previously a data-layer tenant-scoped 404).
        let foreign_cancel = cancel(event_id.parse().unwrap(), other.clone()).await;
        assert_eq!(foreign_cancel.status(), StatusCode::FORBIDDEN);
        let unknown_cancel = cancel(Uuid::new_v4(), tenant.to_string()).await;
        assert_eq!(unknown_cancel.status(), StatusCode::NOT_FOUND);
        let own_cancel = cancel(event_id.parse().unwrap(), tenant.to_string()).await;
        assert_eq!(own_cancel.status(), StatusCode::OK);
        let body = json_body(own_cancel).await;
        assert_eq!(body["cancelled"], true);
        assert_eq!(body["id"], event_id);

        // batch: scoped cleanup — the system tenant is shared, so delete only
        // this run's event (by unique title / id), never by tenant_id.
        let _ = sqlx::query("DELETE FROM sales_calendar_events WHERE id = $1")
            .bind(event_id.parse::<Uuid>().unwrap())
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM sales_meetings WHERE id = $1")
            .bind(event_id.parse::<Uuid>().unwrap())
            .execute(&db)
            .await;
        let _ =
            sqlx::query("DELETE FROM sales_calendar_events WHERE tenant_id = $1 AND title = $2")
                .bind(tenant)
                .bind(&title)
                .execute(&db)
                .await;
    }

    /// Slot discovery: garbage dates and timezones are 400s, legacy UTC mode
    /// offers the 09:00–17:00 half-hour grid on a weekday, IANA mode offers
    /// nothing on a weekend and DST-correct local slots on a weekday.
    #[tokio::test]
    async fn calendar_slots_validate_input_and_honour_timezone_policy() {
        let Some(app) = test_app("routes_wave_slots").await else {
            return;
        };
        // batch: system-tenant restriction — slot discovery runs as the
        // system tenant (slot computation reads no cross-test data on the
        // queried weekday).
        let tenant = config::SYSTEM_TENANT_ID;
        let monday = next_weekday_at(chrono::Weekday::Mon, 21, 12, 0);
        let sunday = next_weekday_at(chrono::Weekday::Sun, 21, 12, 0);

        let get_slots = |query: String| {
            let app = app.clone();
            let tenant = tenant;
            async move {
                app.oneshot(
                    Request::get(format!("/calendar/slots?{query}"))
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };

        // An unparseable date is a 400, never a silent "today".
        let resp = get_slots("date=not-a-timestamp".to_string()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(json_body(resp).await["error"]
            .as_str()
            .unwrap_or_default()
            .contains("RFC 3339"));

        // An unparseable IANA zone is a 400 naming the input.
        let resp = get_slots(format!("date={}&timezone=Mars/Olympus", query_ts(monday))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(json_body(resp).await["error"]
            .as_str()
            .unwrap_or_default()
            .contains("IANA"));

        // Header/payload tenant mismatch is refused.
        let resp = get_slots(format!(
            "date={}&tenant_id=smuggled-tenant",
            query_ts(monday)
        ))
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Legacy UTC mode: the 09:00–17:00 half-hour grid on a weekday.
        let resp = get_slots(format!("date={}", query_ts(monday))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let slots = json_body(resp).await;
        let slots = slots.as_array().expect("legacy slots array");
        assert_eq!(slots.len(), 16, "8 working hours of 30-minute slots");
        let first_start: chrono::DateTime<chrono::Utc> =
            serde_json::from_value(slots[0]["start"].clone()).unwrap();
        assert_eq!(first_start.format("%H:%M").to_string(), "09:00");
        let last_end: chrono::DateTime<chrono::Utc> =
            serde_json::from_value(slots[15]["end"].clone()).unwrap();
        assert_eq!(last_end.format("%H:%M").to_string(), "17:00");

        // IANA mode: a Sunday is outside the Mon–Fri working week — empty,
        // not an error; a weekday yields DST-correct local slots labelled
        // with the requested zone.
        let resp = get_slots(format!("date={}&timezone=Europe/Tallinn", query_ts(sunday))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let sunday_slots = json_body(resp).await;
        assert!(
            sunday_slots.as_array().unwrap().is_empty(),
            "a Sunday has no slots: {sunday_slots}"
        );

        let resp = get_slots(format!("date={}&timezone=Europe/Tallinn", query_ts(monday))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let tallinn = json_body(resp).await;
        let tallinn = tallinn.as_array().expect("tallinn slots array");
        assert!(!tallinn.is_empty(), "a Monday has slots in Europe/Tallinn");
        for slot in tallinn {
            assert_eq!(slot["timezone"], "Europe/Tallinn");
            assert!(slot["local_start"].is_string(), "{slot}");
            assert!(slot["start"].is_string(), "{slot}");
        }
    }

    // ── Discovery surface ────────────────────────────────────────────────

    /// The full offline discovery job: a first-party job is created queued,
    /// runs to completed importing the tenant's own accounts, is readable
    /// tenant-scoped, and refuses a second run once terminal.
    #[tokio::test]
    async fn discovery_first_party_job_creates_runs_and_completes_offline() {
        let Some(db) = crate::test_db::canonical_test_pool("routes_wave_disc_db").await else {
            return;
        };
        let Some(app) = test_app("routes_wave_disc").await else {
            return;
        };
        // batch: system-tenant restriction — the job runs as the system
        // tenant on the shared database; the seeded account gets a run-unique
        // domain (enrichment tests create other system-tenant accounts
        // concurrently) and every count/cleanup below is scoped to it.
        let tenant = config::SYSTEM_TENANT_ID;
        let other = crate::test_db::unique_test_tenant("routes-disc-other");
        let account_domain = format!(
            "disc-{}.example",
            &Uuid::new_v4().simple().to_string()[..12]
        );
        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain) \
             VALUES ($1, $2, 'Acme Disc Co', $3)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(&account_domain)
        .execute(&db)
        .await
        .expect("seed account");

        let auth = |builder: axum::http::request::Builder, tenant: String| {
            builder
                .header("x-api-key", "test-key")
                .header("x-tenant-id", tenant)
                .header("content-type", "application/json")
        };

        let create = app
            .clone()
            .oneshot(
                auth(Request::post("/discovery/jobs"), tenant.to_string())
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "sources": ["first_party"],
                            "keywords": ["Acme"],
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK, "job is created queued");
        let job = json_body(create).await;
        let job_id = job["jobId"].as_str().expect("jobId").to_string();
        assert_eq!(job["status"], "queued", "{job}");

        // The tenant-scoped status endpoint shows the queued job; the foreign
        // tenant is gate-refused.
        let status = app
            .clone()
            .oneshot(
                auth(
                    Request::get(format!("/discovery/jobs/{job_id}")),
                    tenant.to_string(),
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(status.status(), StatusCode::OK);
        assert_eq!(json_body(status).await["status"], "queued");
        // batch: system-tenant restriction — the gate refuses foreign tenants
        // with 403 (previously the data layer answered a tenant-scoped miss).
        let foreign = app
            .clone()
            .oneshot(
                auth(
                    Request::get(format!("/discovery/jobs/{job_id}")),
                    other.clone(),
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            foreign.status(),
            StatusCode::FORBIDDEN,
            "a foreign tenant cannot read the job"
        );

        // One bounded batch completes the first-party job and surfaces the
        // tenant's own account as a candidate. `imported` counts only
        // PROMOTIONS (candidates turned into NEW accounts) — a first-party
        // candidate already IS the account, so it must be discovered without
        // being re-imported.
        let run = app
            .clone()
            .oneshot(
                auth(
                    Request::post(format!("/discovery/jobs/{job_id}/run")),
                    tenant.to_string(),
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(run.status(), StatusCode::OK, "the batch runs");
        let ran = json_body(run).await;
        assert_eq!(ran["status"], "completed", "{ran}");
        assert!(
            ran["discovered"].as_i64().unwrap_or(0) >= 1,
            "the tenant's own account is discovered: {ran}"
        );
        assert_eq!(
            ran["imported"], 0,
            "a first-party candidate must not be re-imported over the live account: {ran}"
        );
        // batch: scoped count — the system tenant is shared, so assert on
        // THIS run's uniquely-domained account only.
        let accounts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_accounts WHERE tenant_id = $1 AND domain = $2",
        )
        .bind(tenant)
        .bind(&account_domain)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(accounts, 1, "discovery must not duplicate the account");

        // A terminal job refuses a second run.
        let rerun = app
            .oneshot(
                auth(
                    Request::post(format!("/discovery/jobs/{job_id}/run")),
                    tenant.to_string(),
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            rerun.status().is_client_error(),
            "a completed job must not run again: {}",
            rerun.status()
        );

        // batch: scoped cleanup — only this suite writes discovery rows under
        // the system tenant; the seeded account is removed by its run-unique
        // domain (never by tenant_id).
        for statement in [
            "DELETE FROM sales_discovery_candidates WHERE tenant_id = $1",
            "DELETE FROM sales_source_runs WHERE tenant_id = $1",
            "DELETE FROM sales_discovery_jobs WHERE tenant_id = $1",
        ] {
            let _ = sqlx::query(statement).bind(tenant).execute(&db).await;
        }
        let _ = sqlx::query("DELETE FROM sales_accounts WHERE tenant_id = $1 AND domain = $2")
            .bind(tenant)
            .bind(&account_domain)
            .execute(&db)
            .await;
    }

    /// An unknown source name is refused with a 400 that NAMES it: the old
    /// fallback-to-every-configured-source would run a paid provider because
    /// of a typo.
    #[tokio::test]
    async fn discovery_job_creation_refuses_unknown_source_names() {
        let Some(app) = test_app("routes_wave_disc_unknown").await else {
            return;
        };
        // batch: system-tenant restriction — the request must reach the
        // handler (the gate only admits the system tenant) so the 400 below
        // is the source-name validation, not the gate.
        let tenant = config::SYSTEM_TENANT_ID;
        let resp = app
            .oneshot(
                Request::post("/discovery/jobs")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "sources": ["totally_bogus_source"]
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("totally_bogus_source"),
            "the refusal must name the unknown source: {body}"
        );
    }

    // ── Companies LIKE-injection ─────────────────────────────────────────

    /// The industry filter escapes LIKE metacharacters: a `%`/`_` filter
    /// matches its literal self (nothing), not every company.
    #[tokio::test]
    async fn companies_industry_filter_escapes_like_wildcards() {
        let Some(db) = crate::test_db::canonical_test_pool("routes_wave_companies_db").await else {
            return;
        };
        let Some(app) = test_app("routes_wave_companies").await else {
            return;
        };
        // batch: system-tenant restriction — the fixture runs as the system
        // tenant on the shared database, so the row gets a run-unique domain
        // (enrichment tests create other system-tenant rows concurrently)
        // and every assertion is scoped to it.
        let tenant = config::SYSTEM_TENANT_ID;
        let other = crate::test_db::unique_test_tenant("routes-companies-o");
        let domain = format!(
            "wildcard-{}.example",
            &Uuid::new_v4().simple().to_string()[..12]
        );
        sqlx::query(
            "INSERT INTO enriched_companies (id, tenant_id, domain, company_name, industry, confidence_score) \
             VALUES ($1, $2, $3, 'Wildcard Co', 'saas', 0.9)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(&domain)
        .execute(&db)
        .await
        .expect("seed enriched company");

        let get = |query: String, tenant: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::get(format!("/companies?{query}"))
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };
        // batch: scoped assertion — filter every listing to THIS run's
        // uniquely-domained row instead of counting the shared tenant's
        // whole result set.
        let ours = |resp: serde_json::Value| {
            resp.as_array()
                .unwrap()
                .iter()
                .filter(|row| row["domain"] == domain)
                .count()
        };

        let plain = json_body(get(String::new(), tenant.to_string()).await).await;
        assert_eq!(ours(plain.clone()), 1, "{plain}");
        assert_eq!(plain[0]["industry"], "saas");

        // A bare `%` filter would match every industry unescaped.
        let percent = json_body(get("industry=%25".to_string(), tenant.to_string()).await).await;
        assert_eq!(
            ours(percent.clone()),
            0,
            "a % filter must match the literal %, not everything: {percent}"
        );
        let underscore = json_body(get("industry=_".to_string(), tenant.to_string()).await).await;
        assert_eq!(
            ours(underscore.clone()),
            0,
            "a _ filter must match the literal _, not any character: {underscore}"
        );
        // A real substring still matches.
        let substring = json_body(get("industry=sa".to_string(), tenant.to_string()).await).await;
        assert_eq!(ours(substring.clone()), 1, "{substring}");

        // batch: system-tenant restriction — the gate refuses foreign tenants
        // with 403 (previously the foreign tenant saw an empty data-layer
        // list).
        let foreign = get(String::new(), other.clone()).await;
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);

        let _ = sqlx::query("DELETE FROM enriched_companies WHERE tenant_id = $1 AND domain = $2")
            .bind(tenant)
            .bind(&domain)
            .execute(&db)
            .await;
    }

    // ── Honest health + tenant-header shapes ─────────────────────────────

    /// With an unreachable database `/health` reports 503 degraded — the
    /// k8s probe must see the degradation, not a green 200.
    #[tokio::test]
    async fn health_reports_degraded_when_the_database_is_unreachable() {
        // `lazy_test_app` never connects: the health probe must answer 503
        // with database "down" instead of hanging or lying.
        let app = lazy_test_app();
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(resp).await;
        assert_eq!(body["status"], "degraded", "{body}");
        assert_eq!(body["database"], "down", "{body}");
    }

    /// The tenant header contract after the system-tenant restriction
    /// (batch): a whitespace-only header passes the auth gate (the gate only
    /// filters non-blank claims) and is rejected by the handler's `TenantId`
    /// extractor with 400; a padded NON-system tenant is trimmed and then
    /// gate-refused with 403; a padded SYSTEM tenant is trimmed and admitted
    /// past auth (failing on the dead lazy database — proving the padding
    /// did not leak into the tenant id).
    #[tokio::test]
    async fn tenant_header_whitespace_is_trimmed_and_blank_is_rejected() {
        let app = lazy_test_app();
        // batch: system-tenant restriction — the middleware no longer filters
        // the blank header out; the 400 now comes from the handler layer
        // (`TenantId` extractor: trim → empty → BAD_REQUEST).
        let blank = app
            .clone()
            .oneshot(
                Request::get("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "   ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blank.status(), StatusCode::BAD_REQUEST);

        // batch: system-tenant restriction — "  tenant-a  " trims to
        // `tenant-a`, which the gate refuses with 403 before any handler runs
        // (previously it fell through to the dead-database 500).
        let padded_foreign = app
            .clone()
            .oneshot(
                Request::get("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "  tenant-a  ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            padded_foreign.status(),
            StatusCode::FORBIDDEN,
            "a padded foreign tenant must be trimmed and then gate-refused"
        );

        // Trimming is what lets the padded SYSTEM tenant through the gate:
        // taken literally, "  system  " would be a 403 like the foreign
        // claim above. Past auth it fails on the dead lazy database — a 4xx
        // would mean the padding leaked into the tenant id.
        let padded_system = app
            .oneshot(
                Request::get("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "  system  ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            padded_system.status().is_server_error(),
            "padded system tenant must be trimmed and admitted, got {}",
            padded_system.status()
        );
    }

    // ── Campaign start: the honest non-active report through the router ──

    /// A start whose every recipient is rejected reports the durable
    /// verification_pending phase AND the per-recipient enrollment outcome in
    /// the HTTP response — an operator must see a partial start, not a bare
    /// status. A retry resumes the SAME durable operation id.
    #[tokio::test]
    async fn campaign_start_reports_verification_pending_and_enrollment_outcome() {
        let Some(db) = crate::test_db::canonical_test_pool("routes_wave_start_db").await else {
            return;
        };
        let Some(app) = test_app("routes_wave_start").await else {
            return;
        };
        // batch: system-tenant restriction — the start flow runs as the
        // system tenant; the campaign/recipients cleanup at the end is
        // already scoped by campaign id, so the shared tenant stays intact.
        let tenant = config::SYSTEM_TENANT_ID;
        let create = app
            .clone()
            .oneshot(
                Request::post("/campaigns")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "name": "Honest start",
                            "template_id": "tmpl_wave",
                            "audience": "all",
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let campaign = json_body(create).await;
        let campaign_id = campaign["id"].as_str().unwrap().to_string();

        // The recipient has NO verified contact point: enrollment must reject
        // it (unverified_contact) and the start must NOT activate.
        let recipients = app
            .clone()
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/recipients"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "emails": ["unverified-recipient@example.com"]
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recipients.status(), StatusCode::OK);

        let start = app
            .clone()
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/start"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start.status(), StatusCode::OK);
        let started = json_body(start).await;
        assert_eq!(started["status"], "draft", "not active: {started}");
        assert_eq!(
            started["start"]["state"], "verification_pending",
            "the durable phase is reported, not hidden: {started}"
        );
        assert!(
            started["start"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("verification_pending"),
            "{started}"
        );
        assert_eq!(
            started["enrollment"]["rejected"], 1,
            "the per-recipient outcome is surfaced: {started}"
        );
        assert_eq!(
            started["enrollment"]["rejectionReasons"]["unverified_contact"], 1,
            "{started}"
        );
        let operation_id = started["start"]["operationId"]
            .as_str()
            .expect("durable operation id")
            .to_string();

        // A retry resumes the SAME durable operation.
        let retry = app
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/start"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        let retried = json_body(retry).await;
        assert_eq!(retried["start"]["state"], "verification_pending");
        assert_eq!(
            retried["start"]["operationId"].as_str().unwrap(),
            operation_id,
            "the retry resumes the same durable operation"
        );

        let _ = sqlx::query("DELETE FROM sales_campaign_recipients WHERE campaign_id = $1")
            .bind(campaign_id.parse::<Uuid>().unwrap())
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM sales_campaigns WHERE id = $1")
            .bind(campaign_id.parse::<Uuid>().unwrap())
            .execute(&db)
            .await;
    }

    // ── Batch 1 (W2): browser-facing unsubscribe page contracts ──────────

    /// Router over the CALLER'S pool so the contract tests can seed tokens
    /// and assert side effects on the SAME database the app uses (mirrors
    /// [`test_app_impl`]'s state construction).
    async fn contract_app(pool: sqlx::PgPool) -> Router {
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");
        let state = AppState {
            db: pool.clone(),
            redis,
            config: Default::default(),
            crm: CrmBackend::postgres(pool.clone()),
            enrichment: EnrichmentService::mock(),
            campaigns: CampaignManager::new(10, pool.clone()),
            dispatcher: None,
            calendar: CalendarService::new(pool.clone()),
            inbox: InboxManager::new(pool.clone()),
            service_token: "test-key".into(),
            rate_limit_fallback: Arc::new(Mutex::new(HashMap::new())),
            intelligence: Arc::new(crate::intelligence::OfflineIntelligence::new()),
            strategist: Arc::new(MessageStrategist::new(
                pool,
                crate::knowledge::SalesKnowledgeBase::canonical(),
            )),
        };
        router(state)
    }

    /// GATE G same-crate coverage: `unsubscribed_page()` is a private fn,
    /// so the integration-tests error-page gate cannot render it. These
    /// assertions mirror
    /// integration-tests/tests/ui_error_page_consistency.rs for the sales
    /// surface (shell + leak markers + sentence copy; the doctype is
    /// accepted case-insensitively per HTML5).
    #[test]
    fn sales_unsubscribed_page_matches_the_error_page_shell_contract() {
        let html = unsubscribed_page().0;
        assert!(
            html.trim_start()
                .to_ascii_lowercase()
                .starts_with("<!doctype html>"),
            "must start with an HTML5 doctype, got: {html}"
        );
        assert!(html.contains("lang=\"en\""), "must declare lang=\"en\"");
        let title_start = html.find("<title>").expect("must carry a <title>") + "<title>".len();
        let title_end = html[title_start..].find("</title>").expect("closed title");
        assert!(
            !html[title_start..title_start + title_end].trim().is_empty(),
            "<title> must not be empty"
        );
        for marker in [
            "panic",
            "unwrap(",
            "Backtrace",
            "sqlx",
            "postgres://",
            "INTERNAL",
            "serde_json",
        ] {
            assert!(!html.contains(marker), "leaks internal detail {marker:?}");
        }
        assert!(
            !html.contains("<script"),
            "the page must be script-free (CSP `script-src 'none'` elsewhere)"
        );
        assert!(
            html.contains("Sorry to see you go!"),
            "the closing copy must remain a complete sentence"
        );
    }

    /// BATCH-2 FIX TARGET: the completion page renders no link back to a
    /// safe path (`/` or `/login`) — the recipient hits a dead end.
    #[test]
    fn contract_sales_unsubscribed_page_offers_a_safe_path_back() {
        let html = unsubscribed_page().0;
        assert!(
            html.contains("href=\"/\"") || html.contains("href=\"/login\""),
            "BATCH-2 FIX TARGET: the sales unsubscribed page renders no link back \
             to a safe path (/ or /login); add a back-link to `unsubscribed_page`."
        );
    }

    /// BATCH-2 FIX TARGET: a browser hitting `GET /u/:token` with a bad or
    /// expired token receives raw JSON (`{"error": ...}`), not an HTML page.
    /// The contract: browser-facing unsubscribe errors render the HTML error
    /// page. (The RFC 8058 one-click POST keeps its JSON contract — that is
    /// a mail-client surface, not a browser.) RED until batch 2.
    #[tokio::test]
    async fn contract_sales_unsubscribe_errors_render_html_not_json() {
        // Shape-invalid token: rejected BEFORE any database use, so the lazy
        // (never-connecting) pool keeps this deterministic and offline.
        let app = lazy_test_app();
        let resp = app
            .oneshot(
                Request::get("/u/definitely-not-a-v2-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "an invalid token must stay a client error"
        );
        let content_type = resp
            .headers()
            .get("content-type")
            .map(|value| value.to_str().unwrap_or_default().to_string())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("text/html"),
            "BATCH-2 FIX TARGET: a browser unsubscribe FAILURE rendered content-type \
             {content_type:?} — it must render the HTML error page (text/html), not raw JSON"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            body.starts_with(b"<!DOCTYPE html>") || body.starts_with(b"<!doctype html>"),
            "the failure page must be an HTML document, got: {}",
            String::from_utf8_lossy(&body)
        );
    }

    /// BATCH-2 FIX TARGET: `GET /u/:token` with a VALID token suppresses the
    /// recipient immediately and renders the completion page. The contract
    /// (mirroring the tracking-service F39 flow): GET is side-effect free
    /// and renders a plain-HTML POST confirmation form; only the confirmed
    /// POST performs the suppression. RED until batch 2.
    #[tokio::test]
    async fn contract_sales_unsubscribe_get_is_side_effect_free_and_offers_confirmation() {
        let Some(db) = crate::test_db::canonical_test_pool("contract_sales_unsub_get").await else {
            return;
        };
        let app = contract_app(db.clone()).await;
        let tenant = "ten_b1salesget";
        let email = "sales.get@example.com";
        // Determinism hygiene (batch 2, F39 fix): the old GET-suppressing
        // handler (and this test's own confirmed POST) leave rows on the
        // SHARED scratch database for this fixed tenant — clear them so the
        // assertions below hold on every run, not just the first. No
        // contract assertion is changed.
        let _ = sqlx::query("DELETE FROM sales_unsubscribes WHERE tenant_id = $1 AND email = $2")
            .bind(tenant)
            .bind(email)
            .execute(&db)
            .await;
        let token = crate::dispatcher::create_unsubscribe_token(&db, tenant, email)
            .await
            .expect("v2 unsubscribe token");

        // GET must render a confirmation form and change nothing.
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/u/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .map(|value| value.to_str().unwrap_or_default().to_string())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("text/html"),
            "GET must render HTML, got content-type {content_type:?}"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body).to_string();
        assert!(
            body.contains("form method=\"POST\"") && body.contains("/confirm"),
            "BATCH-2 FIX TARGET: GET /u/:token performed the unsubscribe immediately \
             and rendered the completion page; it must render a side-effect-free HTML \
             confirmation form (POST to a confirm path). Body: {body}"
        );

        let suppression_count = |db: &sqlx::PgPool| {
            let db = db.clone();
            async move {
                let (count,): (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1 AND email = $2",
                )
                .bind(tenant)
                .bind(email)
                .fetch_one(&db)
                .await
                .expect("suppression lookup");
                count
            }
        };

        assert_eq!(
            suppression_count(&db).await,
            0,
            "BATCH-2 FIX TARGET: GET /u/:token created a suppression row — a plain link \
             click (or prefetcher) must never change consent; only a confirmed POST may"
        );

        // POST with the confirmation performs the unsubscribe.
        let resp = app
            .oneshot(
                Request::post(format!("/u/{token}/confirm"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("confirm=true"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "BATCH-2 FIX TARGET: the confirmed POST (POST /u/:token/confirm with \
             confirm=true) must perform the unsubscribe and render the completion page"
        );
        assert_eq!(
            suppression_count(&db).await,
            1,
            "the confirmed POST must persist the suppression"
        );

        // Determinism hygiene (batch 2): leave no rows for the next run on
        // the shared scratch database.
        let _ = sqlx::query("DELETE FROM sales_unsubscribes WHERE tenant_id = $1 AND email = $2")
            .bind(tenant)
            .bind(email)
            .execute(&db)
            .await;
        let _ = sqlx::query("DELETE FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
            .bind(tenant)
            .execute(&db)
            .await;
    }
}
