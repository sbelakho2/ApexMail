use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use axum::{
    extract::{DefaultBodyLimit, FromRequestParts, Path, Query, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::{self, Next},
    response::Response,
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
    crm::CrmBackend,
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

pub async fn initialize_schema(db: &PgPool) -> Result<(), SalesError> {
    // PostgreSQL DDL (CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS)
    // is **not** safe to run concurrently against the same target — racing
    // catalog inserts produce
    // `duplicate key value violates unique constraint "pg_class_relname_nsp_index"`.
    // Tests in functional-tests and integration-tests call this concurrently,
    // so guard the whole bootstrap with a session-level advisory lock keyed on
    // a stable hash of "sales-autopilot:initialize_schema". The lock is
    // released automatically on connection drop.
    // Pin the advisory lock to a SINGLE dedicated connection so that the
    // CREATE TABLE / CREATE INDEX statements that follow run while the same
    // connection still holds the lock. (deadpool/sqlx may otherwise run
    // subsequent statements on a different pooled connection that does not
    // hold the session-scoped lock.)
    let mut lock_conn = db
        .acquire()
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    sqlx::query("SELECT pg_advisory_lock(7723691501421983234)")
        .execute(&mut *lock_conn)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

    let result = initialize_schema_inner(db).await;

    let _ = sqlx::query("SELECT pg_advisory_unlock(7723691501421983234)")
        .execute(&mut *lock_conn)
        .await;
    drop(lock_conn);

    result
}

async fn initialize_schema_inner(db: &PgPool) -> Result<(), SalesError> {
    sqlx::query(
        r#"
            CREATE TABLE IF NOT EXISTS enriched_companies (
                id UUID PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                company_name TEXT,
                industry TEXT,
                employee_count TEXT,
                annual_revenue TEXT,
                funding_stage TEXT,
                headquarters TEXT,
                founded_year INTEGER,
                description TEXT,
                linkedin_url TEXT,
                email_provider TEXT,
                confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0,
                last_enriched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (tenant_id, domain)
            )
        "#,
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_enriched_companies_last_enriched_at ON enriched_companies(last_enriched_at DESC)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_enriched_companies_industry ON enriched_companies(industry)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    // ── Campaigns ──────────────────────────────────────────────────────
    sqlx::query(
        r#"
            CREATE TABLE IF NOT EXISTS sales_campaigns (
                id UUID PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                template_id TEXT NOT NULL,
                audience TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'draft',
                sent BIGINT NOT NULL DEFAULT 0,
                opened BIGINT NOT NULL DEFAULT 0,
                clicked BIGINT NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        "#,
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sales_campaigns_tenant_id ON sales_campaigns(tenant_id)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sales_campaigns_status ON sales_campaigns(status)")
        .execute(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

    // ── Campaign recipients ────────────────────────────────────────────
    sqlx::query(
        r#"
            CREATE TABLE IF NOT EXISTS sales_campaign_recipients (
                campaign_id UUID NOT NULL REFERENCES sales_campaigns(id) ON DELETE CASCADE,
                email TEXT NOT NULL,
                PRIMARY KEY (campaign_id, email)
            )
        "#,
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    // Send ledger for campaign recipients (see CampaignManager::get_recipients):
    // `sent_at` is stamped after a successful dispatch so that pausing and
    // re-starting a campaign does not re-dispatch the entire recipient list.
    sqlx::query(
        "ALTER TABLE sales_campaign_recipients ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    // ── Suppression list (fix I-2, CAN-SPAM) ──────────────────────────
    // Recipients on this list are excluded from every campaign send; the
    // dispatch path also enforces a per-recipient frequency cap (see
    // CampaignManager::get_recipients).
    sqlx::query(
        r#"
            CREATE TABLE IF NOT EXISTS sales_unsubscribes (
                tenant_id TEXT NOT NULL,
                email TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (tenant_id, email)
            )
        "#,
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sales_unsubscribes_tenant ON sales_unsubscribes(tenant_id)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    // ── Calendar events ────────────────────────────────────────────────
    sqlx::query(
        r#"
            CREATE TABLE IF NOT EXISTS sales_calendar_events (
                id UUID PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL,
                attendees TEXT[] NOT NULL DEFAULT '{}',
                start_at TIMESTAMPTZ NOT NULL,
                end_at TIMESTAMPTZ NOT NULL,
                meeting_link TEXT
            )
        "#,
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sales_calendar_events_tenant_id_start_at ON sales_calendar_events(tenant_id, start_at)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sales_calendar_events_start_at ON sales_calendar_events(start_at)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    // Race-free double-booking prevention: a GiST exclusion constraint on
    // (tenant_id, [start_at, end_at)) makes overlapping inserts impossible
    // even when two concurrent requests both pass the COUNT pre-check in
    // CalendarService::create_event (the pre-check remains as a friendly
    // fast path; violations surface as SalesError::SlotUnavailable).
    // btree_gist provides the `=` operator for the scalar tenant_id column
    // inside a GiST index. The DO block drops any existing constraint first
    // so re-running this migration is idempotent.
    sqlx::query("CREATE EXTENSION IF NOT EXISTS btree_gist")
        .execute(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        r#"
            DO $$
            BEGIN
                ALTER TABLE sales_calendar_events DROP CONSTRAINT IF EXISTS no_overlapping_events;
                ALTER TABLE sales_calendar_events ADD CONSTRAINT no_overlapping_events
                    EXCLUDE USING gist (tenant_id WITH =, tsrange(start_at, end_at) WITH &&);
            END $$;
        "#,
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    // ── Inbox messages ─────────────────────────────────────────────────
    sqlx::query(
        r#"
            CREATE TABLE IF NOT EXISTS sales_inbox_messages (
                id UUID PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                category TEXT NOT NULL DEFAULT 'other',
                replied BOOLEAN NOT NULL DEFAULT false
            )
        "#,
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sales_inbox_messages_tenant_id ON sales_inbox_messages(tenant_id)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sales_inbox_messages_category ON sales_inbox_messages(category)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sales_inbox_messages_received_at ON sales_inbox_messages(received_at)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    // ── Conversion tracking (SALES-03) ───────────────────────────────────
    sqlx::query(
        r#"
            CREATE TABLE IF NOT EXISTS sales_conversions (
                id UUID PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                campaign_id UUID NOT NULL,
                lead_id UUID NOT NULL,
                revenue DOUBLE PRECISION NOT NULL DEFAULT 0,
                description TEXT NOT NULL DEFAULT '',
                converted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        "#,
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sales_conversions_tenant_id ON sales_conversions(tenant_id)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sales_conversions_campaign_id ON sales_conversions(campaign_id)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sales_conversions_lead_id ON sales_conversions(lead_id)",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(())
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
    // Skip auth for health checks
    if req.uri().path() == "/health" {
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
        enforce_enrichment_rate_limit(
            &state.redis,
            &tenant_id,
            Some(&state.rate_limit_fallback),
        )
        .await?;

        let company = if let Some(email) = body.email.as_deref() {
            state.enrichment.enrich_lead(email).await?
        } else if let Some(domain) = body.domain.as_deref() {
            state.enrichment.enrich_company(domain).await?
        } else {
            return Err(SalesError::InvalidInput(
                "email or domain is required".into(),
            ));
        };

        // Persist to enriched_companies table (non-fatal on failure — enrichment
        // data is still returned to the caller even if the cache write fails).
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
    }.instrument(span).await
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

async fn reply_inbox_message(
    State(state): State<Arc<AppState>>,
    tenant_id: TenantId,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SalesError> {
    let tenant_id = tenant_id.0;
    let span = tracing::info_span!(
        "reply_inbox_message",
        tenant_id = %tenant_id,
        message_id = %id,
        operation = "reply_inbox_message"
    );
    async move {
        // Fix I-4: there is no email delivery path for inbox replies in this
        // crate — the handler previously flipped the `replied` flag and
        // answered `{replied: true}` without sending anything. Fail honestly
        // with 501 (before mutating anything) until compose+queue is wired.
        let _ = &state;
        Err(SalesError::NotImplemented(
            "reply delivery not implemented — no outbound email path is wired for inbox replies"
                .into(),
        ))
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

    fn test_app() -> Router {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let db = rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), async {
                PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(Duration::from_millis(100))
                    .connect("postgres://localhost/unused")
                    .await
            })
            .await
            .unwrap_or_else(|_| panic!("DB connection timed out after 2s"))
            .unwrap_or_else(|_| panic!("DB connection failed"))
        });
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
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db),
            service_token: "test-key".into(),
            rate_limit_fallback: Arc::new(Mutex::new(HashMap::new())),
        };
        router(state)
    }

    fn test_app_with_service_token(service_token: &str) -> Router {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let db = rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), async {
                PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(Duration::from_millis(100))
                    .connect("postgres://localhost/unused")
                    .await
            })
            .await
            .unwrap_or_else(|_| panic!("DB connection timed out after 2s"))
            .unwrap_or_else(|_| panic!("DB connection failed"))
        });
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
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db),
            service_token: service_token.into(),
            rate_limit_fallback: Arc::new(Mutex::new(HashMap::new())),
        };
        router(state)
    }


    // ── Fix I tests: honest failures + tenant scoping ────────────────────

    /// Async-test-safe app builder: a LAZY pool (never connects) so the
    /// router can be driven inside `#[tokio::test]` without nesting
    /// runtimes. Handlers that reach the database fail; the tests below
    /// assert on the pre-database behavior (auth, scoping, 501/503).
    fn lazy_test_app_with_config(
        config: crate::config::SalesConfig,
    ) -> Router {
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

    /// Fix I-4: inbox reply has no delivery path — 501, not {replied:true}.
    #[tokio::test]
    async fn test_inbox_reply_returns_501_not_implemented() {
        let app = lazy_test_app();
        let resp = app
            .oneshot(
                Request::post(format!("/inbox/{}/reply", Uuid::new_v4()))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
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
        let mut config = crate::config::SalesConfig::default();
        config.allowed_tenants = Some(vec!["tenant-a".into()]);
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
        let app = test_app();
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Integration test requiring local Postgres and Redis. Run with infrastructure.
    #[ignore]
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
                    .header("x-tenant-id", "tenant-a")
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
                    .header("x-tenant-id", "tenant-a")
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
        let app = test_app();
        let body = serde_json::json!({ "email": "bob@beta.io" });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/enrich")
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
            StatusCode::OK,
            "enrich by email should succeed with mock backend"
        );

        let domain_body = serde_json::json!({ "domain": "acme.com" });
        let domain_resp = app
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-a")
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
        let app = test_app();
        let create_body = serde_json::json!({
            "name": "Migration wave",
            "template_id": "tmpl_competitor_migration",
            "audience": "selected-leads",
            "tenant_id": "tenant-a"
        });

        let create_resp = app
            .clone()
            .oneshot(
                Request::post("/campaigns")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-a")
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
                    .header("x-tenant-id", "tenant-a")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&recipients_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recipients_resp.status(), StatusCode::OK);

        // Fix I-1 note: this test harness wires no CampaignEmailDispatcher,
        // so start must now fail loudly with 503 (previously it returned
        // 200 'active' while sending nothing). Updated from the old
        // `assert_eq!(start_resp.status(), StatusCode::OK)` which asserted
        // the vulnerable silent-no-send behavior.
        let start_resp = app
            .clone()
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/start"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start_resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let pause_resp = app
            .oneshot(
                Request::post(format!("/campaigns/{campaign_id}/pause"))
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-a")
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
        let app = test_app();
        let create_body = serde_json::json!({
            "name": "Tenant scoped",
            "template_id": "tmpl_scoped",
            "audience": "selected-leads",
            "tenant_id": "tenant-a"
        });

        let create_resp = app
            .clone()
            .oneshot(
                Request::post("/campaigns")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "tenant-a")
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
                    .header("x-tenant-id", "tenant-b")
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
        let app = test_app();

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
                        .header("x-tenant-id", "tenant-a")
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
                    .header("x-tenant-id", "tenant-a")
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
        let app = test_app_with_service_token("");
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
        let app = test_app();
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
}
