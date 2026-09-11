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
    config::SalesConfig,
    control,
    crm::CrmBackend,
    discovery::{default_sources, DiscoveryJobRunner, DiscoveryQuery},
    dispatcher::ProductionCampaignDispatcher,
    enrichment::EnrichmentService,
    inbox::InboxManager,
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
    // (`/u/:token`) — recipient clicks arrive from mail clients with no
    // service token; authenticity comes from the HMAC token signature.
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
        // Fix I-3 (tenant scoping): this service uses a single shared
        // internal token; the tenant is then taken from the (fully trusted)
        // `x-tenant-id` header — the token holder can address any tenant by
        // design. Authenticity of the tenant claim cannot be established at
        // this layer, so the blast radius is reduced by an explicit
        // deployment allowlist (`SALES_ALLOWED_TENANTS`). When unset, all
        // tenants are allowed and a warning is logged once.
        if let Some(tenant) = req
            .headers()
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            static WARNED_UNSCOPED: std::sync::Once = std::sync::Once::new();
            match &state.config.allowed_tenants {
                Some(allowed) if !allowed.iter().any(|a| a == tenant) => {
                    warn!(tenant_id = %tenant, "tenant rejected: not in SALES_ALLOWED_TENANTS");
                    return Err(StatusCode::FORBIDDEN);
                }
                Some(_) => {}
                None => WARNED_UNSCOPED.call_once(|| {
                    warn!(
                        "SALES_ALLOWED_TENANTS is not set — the shared service token can address every tenant"
                    );
                }),
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

        // Verify the lead exists and belongs to this tenant
        // `sales_leads.id` is TEXT (lead ids use several formats), so the
        // Uuid must be bound as its string form — binding the raw Uuid
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

        let conversion_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_conversions (id, tenant_id, campaign_id, lead_id, revenue, description, converted_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(conversion_id)
        .bind(&tenant_id)
        .bind(body.campaign_id)
        .bind(body.lead_id)
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
        let rows: Vec<ConversionRow> = if let Some(cid) = q.campaign_id {
            sqlx::query_as::<_, ConversionRow>(
                "SELECT id, tenant_id, campaign_id, lead_id, revenue, description, converted_at \
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
                "SELECT id, tenant_id, campaign_id, lead_id, revenue, description, converted_at \
                 FROM sales_conversions \
                 WHERE tenant_id = $1 AND lead_id = $2 \
                 ORDER BY converted_at DESC LIMIT $3 OFFSET $4",
            )
            .bind(&tenant_id)
            .bind(lid)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?
        } else {
            sqlx::query_as::<_, ConversionRow>(
                "SELECT id, tenant_id, campaign_id, lead_id, revenue, description, converted_at \
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
        // Fix I-1: without a dispatcher the campaign would flip to 'active'
        // and silently send nothing. Fail loudly with 503 instead.
        if !state.campaigns.has_email_dispatcher() {
            return Err(SalesError::ServiceUnavailable(
                "email dispatcher not configured — campaign start refused (no emails would be sent)"
                    .into(),
            ));
        }
        let campaign = state.campaigns.start_campaign(&tenant_id, id).await?;
        json_response(&campaign)
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

/// Shared suppression logic for GET and POST. Idempotent by construction
/// (`ON CONFLICT DO NOTHING` in both suppression stores) — a second click
/// succeeds without duplicating rows.
async fn apply_unsubscribe(
    state: &AppState,
    token: &str,
) -> Result<crate::dispatcher::UnsubscribeTokenData, SalesError> {
    let secret = &state.config.dispatch.unsubscribe_secret;
    if secret.trim().is_empty() {
        // No secret configured ⇒ tokens cannot be validated ⇒ refuse.
        return Err(SalesError::ServiceUnavailable(
            "unsubscribe tokens are not configured".into(),
        ));
    }
    let data = crate::dispatcher::verify_unsubscribe_token(secret, token).ok_or_else(|| {
        tracing::warn!("unsubscribe request with invalid or expired token");
        SalesError::InvalidInput("invalid or expired unsubscribe token".into())
    })?;

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

/// Branded confirmation page shown after a GET unsubscribe when no explicit
/// redirect URL is configured.
fn unsubscribed_page() -> axum::response::Html<&'static str> {
    axum::response::Html(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Unsubscribed — ApexMail</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f7f7f9;color:#222}.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);padding:48px;text-align:center;max-width:420px}h1{font-size:20px;margin:0 0 12px}p{color:#666;font-size:14px;line-height:1.6;margin:0}</style>
</head>
<body><div class="card"><h1>You're unsubscribed</h1>
<p>You will not receive any further campaign emails from us. Sorry to see you go!</p>
</div></body></html>"#,
    )
}

/// GET /u/:token — manual (link click) unsubscribe: suppress + redirect to a
/// branded page.
async fn unsubscribe_get(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    match apply_unsubscribe(&state, &token).await {
        Ok(_) => match &state.config.dispatch.unsubscribe_redirect_url {
            Some(url) => Redirect::to(url).into_response(),
            None => unsubscribed_page().into_response(),
        },
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
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT sender, subject FROM sales_inbox_messages \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(&tenant_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        let (sender, original_subject) = row.ok_or(SalesError::MessageNotFound(id))?;

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

    /// Test dispatcher reporting every requested recipient as enqueued, so
    /// `CampaignManager::start_campaign` completes the Active transition.
    /// Production wiring uses `ProductionCampaignDispatcher`; this double
    /// never sends anything.
    #[derive(Debug)]
    struct TestCampaignDispatcher;

    impl crate::campaigns::CampaignEmailDispatcher for TestCampaignDispatcher {
        fn dispatch(
            &self,
            _tenant_id: &str,
            _campaign_id: Uuid,
            _template_id: &str,
            recipients: &[crate::campaigns::DispatchRecipient],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, SalesError>> + Send>>
        {
            let enqueued = recipients.len();
            Box::pin(async move { Ok(enqueued) })
        }

        fn unsubscribe_link(
            &self,
            tenant_id: &str,
            campaign_id: Uuid,
            recipient_email: &str,
        ) -> String {
            format!(
                "https://sales.apexmail.ee/unsubscribe/{tenant_id}/{campaign_id}/{recipient_email}"
            )
        }
    }

    /// App harness on the canonical provisioned test database. Async so it can
    /// be awaited directly inside `#[tokio::test]` — the previous
    /// `Runtime::new().block_on(..)` inside the test runtime panicked with
    /// "Cannot start a runtime from within a runtime". `None` means the
    /// environment is unconfigured → the test soft-skips.
    async fn test_app(test_name: &str) -> Option<Router> {
        test_app_impl(test_name, "test-key", false).await
    }

    /// App harness with a working test dispatcher attached, so campaign start
    /// reaches the state machine instead of the Fix I-1 503 short-circuit.
    async fn test_app_with_dispatcher(test_name: &str) -> Option<Router> {
        test_app_impl(test_name, "test-key", true).await
    }

    async fn test_app_with_service_token(test_name: &str, service_token: &str) -> Option<Router> {
        test_app_impl(test_name, service_token, false).await
    }

    async fn test_app_impl(
        test_name: &str,
        service_token: &str,
        with_dispatcher: bool,
    ) -> Option<Router> {
        let db = crate::test_db::canonical_test_pool(test_name).await?;
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");
        let mut campaigns = CampaignManager::new(10, db.clone());
        if with_dispatcher {
            campaigns = campaigns.with_email_dispatcher(Arc::new(TestCampaignDispatcher));
        }
        let state = AppState {
            db: db.clone(),
            redis,
            config: Default::default(),
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            campaigns,
            dispatcher: None,
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db),
            service_token: service_token.into(),
            rate_limit_fallback: Arc::new(Mutex::new(HashMap::new())),
        };
        Some(router(state))
    }

    // ── Fix I tests: honest failures + tenant scoping ────────────────────

    /// Async-test-safe app builder: a LAZY pool (never connects) so the
    /// router can be driven inside `#[tokio::test]` without nesting
    /// runtimes. Handlers that reach the database fail; the tests below
    /// assert on the pre-database behavior (auth, scoping, 501/503).
    fn lazy_test_app_with_config(config: crate::config::SalesConfig) -> Router {
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
            inbox: InboxManager::new(db),
            service_token: "test-key".into(),
            rate_limit_fallback: Arc::new(Mutex::new(HashMap::new())),
        };
        router(state)
    }

    fn lazy_test_app() -> Router {
        lazy_test_app_with_config(crate::config::SalesConfig::default())
    }

    /// Fix I-1: without a dispatcher wired, campaign start must fail loudly
    /// with 503 instead of returning 200 'active' while sending nothing.
    #[tokio::test]
    async fn test_campaign_start_returns_503_without_dispatcher() {
        let app = lazy_test_app();
        let resp = app
            .oneshot(
                Request::post(format!("/campaigns/{}/start", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            body["error"].as_str().unwrap().contains("dispatcher"),
            "error must name the missing dispatcher: {body}"
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
                    .header("x-tenant-id", "tenant-a")
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
                    .header("x-tenant-id", "tenant-a")
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
                    .header("x-tenant-id", "tenant-a")
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

    /// Fix I-3: SALES_ALLOWED_TENANTS scopes the shared-token blast radius.
    #[tokio::test]
    async fn test_allowed_tenants_scoping() {
        let config = crate::config::SalesConfig {
            allowed_tenants: Some(vec!["tenant-a".into()]),
            ..Default::default()
        };
        let app = lazy_test_app_with_config(config);

        // Allowed tenant passes the middleware (then fails on the dead DB
        // with 500 — proving it got PAST the scope check).
        let allowed = app
            .clone()
            .oneshot(
                Request::post(format!("/campaigns/{}/start", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(allowed.status(), StatusCode::FORBIDDEN);

        // Tenant outside the allowlist is rejected outright.
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
    #[ignore]
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
    #[ignore]
    #[tokio::test]
    async fn test_create_and_list_leads() {
        let Some(app) = test_app("routes::tests::test_create_and_list_leads").await else {
            return;
        };
        // Unique tenant per run: `sales_leads` has a per-tenant unique email
        // index, so a fixed name would fail on the second run against the
        // reused canonical database.
        let tenant = crate::test_db::unique_test_tenant("routes-leads");
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
                    .header("x-tenant-id", tenant.clone())
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
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_enrich_endpoint() {
        let Some(app) = test_app("routes::tests::test_enrich_endpoint").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("routes-enrich");
        let body = serde_json::json!({ "email": "bob@beta.io" });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", tenant.clone())
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
    #[ignore]
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
        let tenant = crate::test_db::unique_test_tenant("routes-campaign");
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
                    .header("x-tenant-id", tenant.clone())
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
                    .header("x-tenant-id", tenant.clone())
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
                    .header("x-tenant-id", tenant.clone())
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
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[ignore]
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
        let tenant = crate::test_db::unique_test_tenant("routes-campaign-owner");
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
                    .header("x-tenant-id", tenant.clone())
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
        assert_eq!(cross_tenant_resp.status(), StatusCode::NOT_FOUND);
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[ignore]
    #[tokio::test]
    async fn test_list_leads_respects_pagination() {
        let Some(app) = test_app("routes::tests::test_list_leads_respects_pagination").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("routes-pagination");

        for index in 0..3 {
            let body = serde_json::json!({
                "email": format!("lead{index}@acme.com"),
                "name": format!("Lead {index}"),
                "company": "Acme"
            });
            let response = app
                .clone()
                .oneshot(
                    Request::post("/leads")
                        .header("x-api-key", "test-key")
                        .header("x-tenant-id", tenant.clone())
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
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[ignore]
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
    #[ignore]
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
                    .header("x-tenant-id", "tenant-a")
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
                    .header("x-tenant-id", "tenant-a")
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
                    .header("x-tenant-id", "tenant-a")
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
                    .header("x-tenant-id", "tenant-a")
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
                    .header("x-tenant-id", "tenant-a")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
