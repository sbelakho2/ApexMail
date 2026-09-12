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

/// The CP's rendered lead row. Identity and [`LeadEntry::status`] are
/// canonical (see [`CANONICAL_LEAD_CTE`]); the remaining fields are the
/// **bounded legacy projection** that still lives on the `sales_leads`
/// bridge row because the canonical model has no home for them yet:
///
/// | field | bridge column (migration 200) | readers | retirement condition |
/// |---|---|---|---|
/// | `source` | `sales_leads.source` (200:69) | this response; `sales-autopilot` `/leads`; `admin::leads_discovery` source breakdown | retired when discovery/campaign provenance moves onto a canonical account source |
/// | `score` | `sales_leads.score` (200:68) | this response; `admin::crm_leads` (sort/read); `sales-autopilot` `/leads` | retired when the CP renders the explainable `sales_scores` model (migration 200:403) instead of the single legacy integer |
/// | `notes` | `sales_leads.notes` (200:79) | this response only | retired when a canonical CRM-notes model exists (or the CP stops rendering notes) |
/// | `tags` | `sales_leads.tags` (200:80) | this response only | retired when a canonical tag model exists (or the CP stops rendering tags) |
/// | `deal_value` | `sales_leads.deal_value` (200:81) | this response only | retired when deal value moves onto the canonical account/opportunity model (or the CP stops rendering it) |
///
/// These are the ONLY fields the CP update path still writes to
/// `sales_leads` (see [`LeadUpdate`]); identity (`contact_email`,
/// `contact_name`, `company_name`, `domain`) and status are written to the
/// canonical tables, never to the legacy bridge columns.
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

/// Canonical CP lead read (audit item 17): identity and status come from the
/// canonical account/contact model, `sales_leads` is only the bridge for
/// lead-only concepts.
///
/// Column mapping, preserved so the CP UI keeps rendering the same
/// [`LeadEntry`] shape:
///
/// | `LeadEntry` field | canonical source | fallback |
/// |---|---|---|
/// | `id` | `sales_leads.id` (the API row key; lead-only) | — |
/// | `contact_email` | newest unsuppressed `sales_contact_points.value` (migration 200:279) | legacy `sales_leads.contact_email` when the row predates the bridge |
/// | `contact_name` | `sales_contacts.full_name` | legacy `sales_leads.contact_name` |
/// | `company_name` | `sales_accounts.company` | legacy `sales_leads.company_name` |
/// | `domain` | `sales_accounts.domain` | legacy `sales_leads.domain` |
/// | `status` | `CASE` over canonical contact/account/enrollment lifecycle (below) | `'new'` when no canonical state exists |
/// | `source`, `score`, `notes`, `tags`, `deal_value`, timestamps | `sales_leads` (lead-only fields with no canonical home yet) | — |
///
/// The legacy `sales_leads.status` column is deliberately NOT selected: it is
/// never written by any runtime path any more (see [`CanonicalLeadStatus`] —
/// the CP admin update, the SSR form and the reply worker all write canonical
/// lifecycle state), so selecting it would surface a frozen column as truth.
/// The remaining readers of that column (`admin::dashboard` KPIs,
/// `admin::crm_leads` and `admin::leads_discovery` list shapes) are legacy
/// read surfaces that predate this change; they are listed in the item-17
/// report as the precondition for making `sales_leads` a pure view.
/// Rows without a canonical `contact_id` (pre-upgrade data, plus
/// discovery-imported rows that deliberately have no reachable address) are
/// not listed until the bridge transition backfills them.
///
/// The CTE projects `tenant_id`; callers scope with
/// `WHERE tenant_id = $n` in the outer query (the positional binds are
/// emitted by `QueryBuilder` at the call site, so a `$1` inside this raw
/// string would not line up with them).
pub(crate) const CANONICAL_LEAD_CTE: &str = r#"
    WITH canonical_leads AS (
        SELECT
            c.tenant_id AS tenant_id,
            l.id,
            l.source,
            l.score,
            l.notes,
            COALESCE(to_jsonb(l.tags), '[]'::jsonb) AS tags,
            l.deal_value,
            l.created_at,
            l.updated_at,
            COALESCE(NULLIF(cp.value, ''), NULLIF(l.contact_email, '')) AS contact_email,
            COALESCE(NULLIF(c.full_name, ''), NULLIF(l.contact_name, '')) AS contact_name,
            COALESCE(NULLIF(a.company, ''), NULLIF(l.company_name, '')) AS company_name,
            COALESCE(NULLIF(a.domain, ''), NULLIF(l.domain, '')) AS domain,
            CASE
                WHEN c.lifecycle = 'customer' OR a.lifecycle = 'customer' THEN 'converted'
                WHEN c.lifecycle = 'meeting_booked' OR e.state = 'meeting_booked' THEN 'demo_scheduled'
                WHEN c.lifecycle = 'replied' OR e.state = 'replied' THEN 'engaged'
                WHEN c.lifecycle = 'do_not_contact'
                     OR e.state IN ('suppressed', 'failed') THEN 'lost'
                WHEN c.lifecycle = 'left_company'
                     OR a.lifecycle = 'disqualified' THEN 'unqualified'
                WHEN a.lifecycle = 'qualified' THEN 'qualified'
                WHEN a.lifecycle = 'nurturing' THEN 'prospect'
                WHEN e.state IN ('active', 'waiting', 'pending', 'completed')
                     OR c.lifecycle = 'snoozed' THEN 'contacted'
                ELSE 'new'
            END AS status
        FROM sales_contacts c
        LEFT JOIN sales_accounts a
               ON a.id = c.account_id AND a.tenant_id = c.tenant_id
        LEFT JOIN LATERAL (
            SELECT cp.value
            FROM sales_contact_points cp
            WHERE cp.contact_id = c.id
              AND cp.tenant_id = c.tenant_id
              AND cp.channel = 'email'
            ORDER BY (cp.suppressed_at IS NULL) DESC,
                     cp.confidence DESC,
                     cp.created_at DESC
            LIMIT 1
        ) cp ON TRUE
        LEFT JOIN LATERAL (
            SELECT e.state
            FROM sales_enrollments e
            WHERE e.contact_id = c.id AND e.tenant_id = c.tenant_id
            ORDER BY CASE
                         WHEN e.state IN ('completed', 'failed', 'suppressed') THEN 1
                         ELSE 0
                     END,
                     e.updated_at DESC, e.id
            LIMIT 1
        ) e ON TRUE
        JOIN LATERAL (
            SELECT l.id, l.source, l.score, l.notes, l.tags, l.deal_value,
                   l.contact_email, l.contact_name, l.company_name, l.domain,
                   l.created_at, l.updated_at
            FROM sales_leads l
            WHERE l.contact_id = c.id AND l.tenant_id = c.tenant_id
            ORDER BY l.created_at DESC, l.id DESC
            LIMIT 1
        ) l ON TRUE
    )
"#;

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
    let mut count_builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(CANONICAL_LEAD_CTE);
    count_builder.push(" SELECT COUNT(*)::bigint FROM canonical_leads WHERE tenant_id = ");
    count_builder.push_bind(auth.tenant_id.clone());
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

    // LeadEntry shape preserved; identity/status are canonical (see
    // CANONICAL_LEAD_CTE), lead-only fields still come from the bridge row.
    let leads = load_lead_entries(
        &state.db,
        &auth.tenant_id,
        params.status.as_deref(),
        params.source.as_deref(),
        limit,
        offset,
    )
    .await?;

    // Aggregate stats over the SAME canonical row set (tenant-scoped the same
    // way), so the list and its KPIs cannot disagree. `source` is a lead-only
    // concept (bridge), `status` is the canonical derivation.
    let source_stats: Vec<(String, String)> = sqlx::query_as(&format!(
        "{CANONICAL_LEAD_CTE} SELECT COALESCE(source, 'unknown'), COUNT(*)::text \
         FROM canonical_leads WHERE tenant_id = $1 GROUP BY source"
    ))
    .bind(&auth.tenant_id)
    .fetch_all(&state.db)
    .await?;

    let status_stats: Vec<(String, String)> = sqlx::query_as(&format!(
        "{CANONICAL_LEAD_CTE} SELECT status, COUNT(*)::text \
         FROM canonical_leads WHERE tenant_id = $1 GROUP BY status"
    ))
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

/// Run the canonical lead list query with the CP's filters and pagination.
/// Extracted from [`list_leads`] so DB-backed tests exercise the production
/// SQL directly (no handler/auth scaffolding).
async fn load_lead_entries(
    db: &sqlx::PgPool,
    tenant_id: &str,
    status: Option<&str>,
    source: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<LeadEntry>, sqlx::Error> {
    let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(CANONICAL_LEAD_CTE);
    builder.push(
        " SELECT id, company_name, domain, contact_email, contact_name,
                 status, source, score, notes, tags,
                 deal_value, created_at, updated_at
          FROM canonical_leads WHERE tenant_id = ",
    );
    builder.push_bind(tenant_id);
    if let Some(status) = status {
        builder.push(" AND status = ").push_bind(status);
    }
    if let Some(source) = source {
        builder.push(" AND source = ").push_bind(source);
    }
    builder
        .push(" ORDER BY created_at DESC, id DESC LIMIT ")
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
    )> = builder.build_query_as().fetch_all(db).await?;

    Ok(rows
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
        .collect())
}

// ──────────────────────────────────────────
// Canonical operator status decisions
// ──────────────────────────────────────────

/// Where an operator status decision is canonically written.
///
/// `sales_leads.status` is never written (audit item 17): the CP reads
/// ([`CANONICAL_LEAD_CTE`] and `web::data::CP_LEADS_CANONICAL_CTE`) derive
/// status from canonical lifecycle state, so a write to the legacy column
/// would be invisible. The operator vocabulary is mapped onto the canonical
/// fields the read actually consults:
///
/// | request `status` | canonical write | CP renders |
/// |---|---|---|
/// | `qualified` | `sales_accounts.lifecycle = 'qualified'` | `qualified` |
/// | `prospect` | `sales_accounts.lifecycle = 'nurturing'` | `prospect` |
/// | `converted` | `sales_contacts.lifecycle = 'customer'` | `converted` |
/// | `unqualified` | `sales_contacts.lifecycle = 'do_not_contact'` | `lost` |
/// | `lost` | `sales_contacts.lifecycle = 'do_not_contact'` | `lost` |
///
/// `new`, `contacted`, `engaged` and `demo_scheduled` are deliberately NOT
/// accepted: the canonical read derives them from live enrollment/contact
/// activity, and the canonical model exposes no operator-settable field for
/// them — accepting them would fabricate outreach history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonicalLeadStatus {
    /// Write `sales_accounts.lifecycle` for the lead's linked account.
    AccountLifecycle(&'static str),
    /// Write `sales_contacts.lifecycle` for the lead's linked contact.
    ContactLifecycle(&'static str),
}

impl CanonicalLeadStatus {
    /// The lifecycle value this decision writes.
    pub(crate) fn lifecycle(self) -> &'static str {
        match self {
            Self::AccountLifecycle(value) | Self::ContactLifecycle(value) => value,
        }
    }

    fn writes_account(self) -> bool {
        matches!(self, Self::AccountLifecycle(_))
    }

    /// The status label [`CANONICAL_LEAD_CTE`] renders once the write lands.
    pub(crate) fn rendered_status(self) -> &'static str {
        match self {
            Self::AccountLifecycle("qualified") => "qualified",
            Self::AccountLifecycle("nurturing") => "prospect",
            Self::ContactLifecycle("customer") => "converted",
            Self::ContactLifecycle("do_not_contact") => "lost",
            // Unreachable for the mapped vocabulary; a future value must not
            // panic, it simply reports no known label.
            _ => "unknown",
        }
    }
}

/// Map the CP's operator `status` vocabulary onto canonical lifecycle fields.
pub(crate) fn canonical_lead_status(requested: &str) -> Option<CanonicalLeadStatus> {
    match requested {
        "qualified" => Some(CanonicalLeadStatus::AccountLifecycle("qualified")),
        "prospect" => Some(CanonicalLeadStatus::AccountLifecycle("nurturing")),
        "converted" => Some(CanonicalLeadStatus::ContactLifecycle("customer")),
        "unqualified" | "lost" => Some(CanonicalLeadStatus::ContactLifecycle("do_not_contact")),
        _ => None,
    }
}

/// The rejection message for a status with no canonical equivalent. It names
/// the supported values and the canonical effect of each, so an API caller
/// can correct the request without reading the source.
fn unsupported_status_message(requested: &str) -> String {
    format!(
        "unsupported lead status `{requested}`: it has no canonical equivalent. Supported \
         statuses: `qualified` (sales_accounts.lifecycle = 'qualified'), `prospect` \
         (sales_accounts.lifecycle = 'nurturing'), `converted` (sales_contacts.lifecycle = \
         'customer'), `unqualified` / `lost` (sales_contacts.lifecycle = 'do_not_contact', \
         shown as 'lost'). `new`, `contacted`, `engaged` and `demo_scheduled` are derived \
         from live enrollment activity and cannot be set by an operator."
    )
}

/// Failure of an operator status decision. `Display` is safe for operators:
/// it never embeds raw database error text.
#[derive(Debug)]
pub(crate) enum LeadStatusWriteError {
    /// The requested status has no canonical destination.
    Unsupported(String),
    /// A requested lead id does not exist for the tenant.
    LeadNotFound(String),
    /// The lead exists but its canonical account/contact is missing (or was
    /// deleted), so the lifecycle write has no target.
    MissingCanonicalLink { lead_id: String, link: &'static str },
    /// The database rejected the write. The caller logs this and reports the
    /// generic message to the operator.
    Database(sqlx::Error),
}

impl std::fmt::Display for LeadStatusWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(status) => formatter.write_str(&unsupported_status_message(status)),
            Self::LeadNotFound(id) => {
                write!(formatter, "lead `{id}` was not found for this tenant")
            }
            Self::MissingCanonicalLink { lead_id, link } => write!(
                formatter,
                "lead `{lead_id}` has no live canonical {link}; its status cannot be set"
            ),
            Self::Database(_) => formatter.write_str("the lead status change could not be applied"),
        }
    }
}

impl From<sqlx::Error> for LeadStatusWriteError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// Apply one canonical operator status decision to `ids` inside `tx`.
///
/// All validation runs before the first write, and the caller's transaction
/// makes the id set all-or-nothing: an unknown id, or a lead whose canonical
/// link was deleted, aborts the whole request with nothing written. Returns
/// the number of leads whose canonical state was set and the label the CP
/// read will render.
pub(crate) async fn apply_lead_status_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    ids: &[String],
    requested: &str,
) -> Result<(u64, &'static str), LeadStatusWriteError> {
    let target = canonical_lead_status(requested)
        .ok_or_else(|| LeadStatusWriteError::Unsupported(requested.to_string()))?;

    // Dedupe while preserving order so a repeated id is one lead, not a
    // phantom "missing row".
    let mut unique: Vec<String> = Vec::with_capacity(ids.len());
    for id in ids {
        if !unique.iter().any(|existing| existing == id) {
            unique.push(id.clone());
        }
    }

    let rows: Vec<(String, Option<uuid::Uuid>, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT id, account_id, contact_id FROM sales_leads \
         WHERE tenant_id = $1 AND id = ANY($2) FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(&unique)
    .fetch_all(&mut **tx)
    .await?;

    if rows.len() != unique.len() {
        let missing = unique
            .iter()
            .find(|id| !rows.iter().any(|(row_id, _, _)| row_id == *id))
            .cloned()
            .unwrap_or_default();
        return Err(LeadStatusWriteError::LeadNotFound(missing));
    }

    let link_field = if target.writes_account() {
        "account"
    } else {
        "contact"
    };
    let linked: Vec<uuid::Uuid> = rows
        .iter()
        .filter_map(|(_, account_id, contact_id)| {
            if target.writes_account() {
                *account_id
            } else {
                *contact_id
            }
        })
        .collect();
    if linked.len() != rows.len() {
        let lead_id = rows
            .iter()
            .find(|(_, account_id, contact_id)| {
                if target.writes_account() {
                    account_id.is_none()
                } else {
                    contact_id.is_none()
                }
            })
            .map(|(id, _, _)| id.clone())
            .unwrap_or_default();
        return Err(LeadStatusWriteError::MissingCanonicalLink {
            lead_id,
            link: link_field,
        });
    }

    let mut distinct: Vec<uuid::Uuid> = Vec::with_capacity(linked.len());
    for id in linked {
        if !distinct.contains(&id) {
            distinct.push(id);
        }
    }

    let table = if target.writes_account() {
        "sales_accounts"
    } else {
        "sales_contacts"
    };
    let live: Vec<uuid::Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM {table} WHERE tenant_id = $1 AND id = ANY($2)"
    ))
    .bind(tenant_id)
    .bind(&distinct)
    .fetch_all(&mut **tx)
    .await?;
    if live.len() != distinct.len() {
        let dead = distinct
            .iter()
            .find(|id| !live.contains(id))
            .copied()
            .unwrap_or_default();
        let lead_id = rows
            .iter()
            .find(|(_, account_id, contact_id)| {
                let link = if target.writes_account() {
                    account_id
                } else {
                    contact_id
                };
                *link == Some(dead)
            })
            .map(|(id, _, _)| id.clone())
            .unwrap_or_default();
        return Err(LeadStatusWriteError::MissingCanonicalLink {
            lead_id,
            link: link_field,
        });
    }

    sqlx::query(&format!(
        "UPDATE {table} SET lifecycle = $1, updated_at = NOW() \
         WHERE tenant_id = $2 AND id = ANY($3)"
    ))
    .bind(target.lifecycle())
    .bind(tenant_id)
    .bind(&distinct)
    .execute(&mut **tx)
    .await?;

    Ok((
        u64::try_from(unique.len()).unwrap_or(u64::MAX),
        target.rendered_status(),
    ))
}

/// Pool-level wrapper for the SSR form path: one transaction, canonical-only.
pub(crate) async fn apply_lead_status_decision(
    db: &sqlx::PgPool,
    tenant_id: &str,
    ids: &[String],
    requested: &str,
) -> Result<(u64, &'static str), LeadStatusWriteError> {
    let mut tx = db.begin().await?;
    let outcome = apply_lead_status_in_tx(&mut tx, tenant_id, ids, requested).await?;
    tx.commit().await?;
    Ok(outcome)
}

fn lead_status_write_error(error: LeadStatusWriteError) -> ApiError {
    match error {
        LeadStatusWriteError::Database(sqlx_error) => ApiError::from(sqlx_error),
        message => ApiError::Validation(vec![message.to_string()]),
    }
}

/// Rewrite `contactEmail` onto the canonical contact point of the lead's
/// linked contact. The legacy `sales_leads.contact_email` column is left
/// untouched: after the bridge transition it is only a fallback for rows that
/// predate the canonical link, and writing it would make the bridge a second
/// identity authority.
async fn update_canonical_contact_email(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    lead_id: &str,
    email: &str,
) -> Result<(), ApiError> {
    let contact_id = lead_contact_id(tx, tenant_id, lead_id).await?;
    let trimmed = email.trim();
    let normalized = trimmed.to_ascii_lowercase();
    if normalized.is_empty()
        || !normalized.contains('@')
        || normalized.contains(char::is_whitespace)
    {
        return Err(ApiError::Validation(vec![format!(
            "`contactEmail` must be a single email address, got `{email}`"
        )]));
    }

    let existing_point: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT id FROM sales_contact_points \
         WHERE tenant_id = $1 AND contact_id = $2 AND channel = 'email' \
         ORDER BY (suppressed_at IS NULL) DESC, confidence DESC, created_at DESC \
         LIMIT 1",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_optional(&mut **tx)
    .await?;

    let result = match existing_point {
        Some(point_id) => {
            sqlx::query(
                "UPDATE sales_contact_points \
                 SET value = $1, normalized_value = $2, updated_at = NOW() \
                 WHERE id = $3 AND tenant_id = $4",
            )
            .bind(trimmed)
            .bind(&normalized)
            .bind(point_id)
            .bind(tenant_id)
            .execute(&mut **tx)
            .await
        }
        None => {
            sqlx::query(
                "INSERT INTO sales_contact_points \
                     (id, tenant_id, contact_id, channel, value, normalized_value, \
                      verification, confidence, source, created_at, updated_at) \
                 VALUES ($1, $2, $3, 'email', $4, $5, 'unverified', 0, 'operator', NOW(), NOW())",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(tenant_id)
            .bind(contact_id)
            .bind(trimmed)
            .bind(&normalized)
            .execute(&mut **tx)
            .await
        }
    };

    result.map(|_| ()).map_err(|error| match &error {
        sqlx::Error::Database(database_error)
            if database_error.code().as_deref() == Some("23505") =>
        {
            ApiError::Validation(vec![format!(
                "`{trimmed}` is already the canonical email of another contact in this tenant"
            )])
        }
        _ => ApiError::from(error),
    })
}

/// Rewrite `contactName` onto `sales_contacts.full_name`.
async fn update_canonical_contact_name(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    lead_id: &str,
    name: &str,
) -> Result<(), ApiError> {
    let contact_id = lead_contact_id(tx, tenant_id, lead_id).await?;
    sqlx::query(
        "UPDATE sales_contacts SET full_name = $1, updated_at = NOW() \
         WHERE id = $2 AND tenant_id = $3",
    )
    .bind(name.trim())
    .bind(contact_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The lead's LIVE canonical contact, or a validation error naming the
/// missing link (never a write to the legacy `sales_leads.contact_name`
/// fallback). A dangling `contact_id` (the bridge has no FK, migration
/// 200:90) is reported as missing rather than surfacing as a database error.
async fn lead_contact_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    lead_id: &str,
) -> Result<uuid::Uuid, ApiError> {
    let contact_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT l.contact_id \
         FROM sales_leads l \
         JOIN sales_contacts c ON c.id = l.contact_id AND c.tenant_id = l.tenant_id \
         WHERE l.tenant_id = $1 AND l.id = $2",
    )
    .bind(tenant_id)
    .bind(lead_id)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    contact_id.ok_or_else(|| {
        ApiError::Validation(vec![format!(
            "lead `{lead_id}` has no live canonical contact; add the address through the \
             canonical contact API before editing its identity"
        )])
    })
}

/// Apply the CP's lead update. Extracted from [`update_leads`] so DB-backed
/// tests can drive the production statement path without auth scaffolding.
///
/// Transactional contract: the whole request is one transaction and every
/// requested id is validated before the first write, so a bulk update that
/// mixes valid and invalid ids (or a lead whose canonical contact was
/// deleted) writes NOTHING.
async fn apply_lead_update(
    db: &sqlx::PgPool,
    tenant_id: &str,
    body: &LeadUpdate,
) -> Result<u64, ApiError> {
    let requested: Vec<String> = if let Some(ref single) = body.id {
        vec![single.clone()]
    } else if let Some(ref bulk) = body.ids {
        bulk.clone()
    } else {
        return Err(ApiError::Validation(vec!["id or ids required".into()]));
    };

    if requested.is_empty() || requested.len() > 100 {
        return Err(ApiError::Validation(vec!["1-100 IDs allowed".into()]));
    }

    // Dedupe while preserving order: a repeated id is one lead, not a
    // phantom "missing row" in the preflight below.
    let mut ids: Vec<String> = Vec::with_capacity(requested.len());
    for id in requested {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }

    if body.status.is_none()
        && body.notes.is_none()
        && body.tags.is_none()
        && body.contact_email.is_none()
        && body.contact_name.is_none()
        && body.deal_value.is_none()
    {
        return Err(ApiError::Validation(vec!["No fields to update".into()]));
    }

    if (body.contact_email.is_some() || body.contact_name.is_some()) && ids.len() != 1 {
        return Err(ApiError::Validation(vec![
            "contactEmail/contactName updates apply to exactly one lead per request: identity \
             is canonical (sales_contacts.full_name / sales_contact_points), and a bulk \
             request cannot map one address onto many contacts"
                .into(),
        ]));
    }

    // Fail fast on an unsupported status before opening a transaction.
    if let Some(requested) = body.status.as_deref() {
        if canonical_lead_status(requested).is_none() {
            return Err(ApiError::Validation(vec![unsupported_status_message(
                requested,
            )]));
        }
    }

    let mut tx = db.begin().await?;

    // All-or-nothing preflight: every requested lead must exist for the
    // tenant before any statement writes.
    let found: Vec<String> =
        sqlx::query_scalar("SELECT id FROM sales_leads WHERE tenant_id = $1 AND id = ANY($2)")
            .bind(tenant_id)
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await?;
    if found.len() != ids.len() {
        let missing = ids
            .iter()
            .find(|id| !found.contains(id))
            .cloned()
            .unwrap_or_default();
        return Err(ApiError::Validation(vec![format!(
            "lead `{missing}` was not found for this tenant"
        )]));
    }

    if let Some(requested) = body.status.as_deref() {
        apply_lead_status_in_tx(&mut tx, tenant_id, &ids, requested)
            .await
            .map_err(lead_status_write_error)?;
    }

    // Bounded legacy projection: the only `sales_leads` columns this path
    // still writes (see [`LeadEntry`] for each field's reader and retirement
    // condition). Identity and status never land here.
    let projection_fields: Vec<&str> = [
        body.notes.is_some().then_some("notes"),
        body.tags.is_some().then_some("tags"),
        body.deal_value.is_some().then_some("deal_value"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !projection_fields.is_empty() {
        let mut builder =
            sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE sales_leads SET updated_at = NOW()");
        if let Some(ref notes) = body.notes {
            builder.push(", notes = ").push_bind(notes.clone());
        }
        if let Some(ref tags) = body.tags {
            builder.push(", tags = ").push_bind(serde_json::json!(tags));
        }
        if let Some(deal_value) = body.deal_value {
            builder.push(", deal_value = ").push_bind(deal_value);
        }
        builder
            .push(" WHERE tenant_id = ")
            .push_bind(tenant_id.to_string());
        builder.push(" AND id = ANY(").push_bind(ids.clone());
        builder.push(")");
        builder.build().execute(&mut *tx).await?;
    }

    if let Some(ref email) = body.contact_email {
        update_canonical_contact_email(&mut tx, tenant_id, &ids[0], email).await?;
    }
    if let Some(ref name) = body.contact_name {
        update_canonical_contact_name(&mut tx, tenant_id, &ids[0], name).await?;
    }

    tx.commit().await?;
    Ok(u64::try_from(ids.len()).unwrap_or(u64::MAX))
}

// ──────────────────────────────────────────
// Lead updates (single + bulk)
// ──────────────────────────────────────────

/// CP lead update request. Identity and status are canonical:
///
/// - `status` — see [`CanonicalLeadStatus`]; unsupported values are rejected
///   with a message naming the supported vocabulary.
/// - `contactEmail` / `contactName` — written to `sales_contact_points` /
///   `sales_contacts`; single-lead requests only.
/// - `notes` / `tags` / `dealValue` — the bounded legacy projection on the
///   `sales_leads` bridge row (see [`LeadEntry`]).
///
/// The whole request is atomic (one transaction): a partial write is never
/// possible.
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

    let ids: Vec<String> = body
        .id
        .clone()
        .into_iter()
        .chain(body.ids.clone().unwrap_or_default())
        .collect();
    let updated = apply_lead_update(&state.db, &auth.tenant_id, &body).await?;

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
            "updated": updated,
            "status": body.status,
            "canonicalStatus": body
                .status
                .as_deref()
                .and_then(canonical_lead_status)
                .map(|status| json!({
                    "lifecycle": status.lifecycle(),
                    "rendered": status.rendered_status(),
                })),
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
        "updated": updated
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

        // Canonical key for the account upsert; the imported lead's domain
        // column is normalized too so the dedupe check below matches.
        let domain = crate::routes::contact::normalize_domain(&domain);

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
        let company = company_name.unwrap_or_else(|| domain.clone());

        // Imported leads arrive without an email address, so they can only be
        // linked to their canonical account: there is no address to put in a
        // `sales_contact_points` row and none is fabricated — the lead has no
        // reachable contact point until enrichment supplies one. The account
        // write and the lead row share one transaction: if the lead insert
        // fails, the account is not left behind either.
        let mut tx = state.db.begin().await?;
        let account_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO sales_accounts
                 (id, tenant_id, company, domain, lifecycle, created_at, updated_at)
             VALUES ($1, $2, $3, $4, 'discovered', NOW(), NOW())
             ON CONFLICT (tenant_id, domain) DO UPDATE SET updated_at = NOW()
             RETURNING id",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&auth.tenant_id)
        .bind(&company)
        .bind(&domain)
        .fetch_one(&mut *tx)
        .await?;

        // `status` is deliberately not listed: the legacy column is never
        // chosen by a write path (the NOT NULL DEFAULT 'new' applies), and
        // the CP read derives status from the canonical lifecycle anyway.
        sqlx::query(
            "INSERT INTO sales_leads (
                tenant_id, id, company_name, domain, source, notes,
                account_id, contact_id, created_at, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NOW(), NOW())",
        )
        .bind(&auth.tenant_id)
        .bind(&lead_id)
        .bind(&company)
        .bind(&domain)
        .bind(&primary_source)
        .bind(description.or(industry.clone()))
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
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

    /// Item 17 test 7: CP read parity. For a seeded lead, the canonical-join
    /// read returns the same identity/email the old lead-only query returned —
    /// so the UI shape does not change — while `status` now derives from the
    /// canonical lifecycle instead of the legacy independently mutable column.
    ///
    /// DB-backed on the api-server canonical test pool; soft-skips without
    /// `TEST_DATABASE_URL`.
    #[tokio::test]
    async fn canonical_lead_read_is_parity_with_the_legacy_read_on_identity() {
        let Some(pool) = crate::test_db::optional_pg_pool("cp_canonical_lead_parity").await else {
            return;
        };
        let tenant = format!("cp17{}", &uuid::Uuid::new_v4().simple().to_string()[..20]);
        let account_id = uuid::Uuid::new_v4();
        let contact_id = uuid::Uuid::new_v4();
        let point_id = uuid::Uuid::new_v4();
        let lead_id = format!("lead_{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);

        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain, lifecycle) \
             VALUES ($1, $2, 'Canonical Co', 'acme.example', 'discovered')",
        )
        .bind(account_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed account");
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name) \
             VALUES ($1, $2, $3, 'Ada Lovelace')",
        )
        .bind(contact_id)
        .bind(&tenant)
        .bind(account_id)
        .execute(&pool)
        .await
        .expect("seed contact");
        sqlx::query(
            "INSERT INTO sales_contact_points \
                 (id, tenant_id, contact_id, channel, value, normalized_value, verification, confidence) \
             VALUES ($1, $2, $3, 'email', 'ada@acme.example', 'ada@acme.example', 'valid', 0.95)",
        )
        .bind(point_id)
        .bind(&tenant)
        .bind(contact_id)
        .execute(&pool)
        .await
        .expect("seed contact point");
        // The legacy status is deliberately `qualified`: the canonical read
        // must NOT surface it (the canonical lifecycle says 'new').
        sqlx::query(
            "INSERT INTO sales_leads \
                 (id, tenant_id, company_name, domain, contact_email, contact_name, \
                  score, source, status, notes, tags, deal_value, \
                  account_id, contact_id, created_at, updated_at) \
             VALUES ($1, $2, 'Legacy Co', 'legacy.example', 'ada@acme.example', 'Ada Lovelace', \
                     42, 'import', 'qualified', 'seed notes', '[\"vip\"]'::jsonb, 1234.5, \
                     $3, $4, NOW(), NOW())",
        )
        .bind(&lead_id)
        .bind(&tenant)
        .bind(account_id)
        .bind(contact_id)
        .execute(&pool)
        .await
        .expect("seed lead bridge row");

        let old: (String, String, String) = sqlx::query_as(
            "SELECT id, COALESCE(email, contact_email, ''), COALESCE(contact_name, '') \
             FROM sales_leads WHERE tenant_id = $1 AND id = $2",
        )
        .bind(&tenant)
        .bind(&lead_id)
        .fetch_one(&pool)
        .await
        .expect("legacy-shaped read");

        let rows = load_lead_entries(&pool, &tenant, None, None, 50, 0)
            .await
            .expect("canonical read");
        assert_eq!(rows.len(), 1, "one canonical lead for one contact");

        let entry = &rows[0];
        assert_eq!(entry.id, old.0, "row identity");
        assert_eq!(
            entry.contact_email.as_deref().unwrap_or_default(),
            old.1,
            "email identity is unchanged for a linked lead"
        );
        assert_eq!(
            entry.contact_name.as_deref().unwrap_or_default(),
            old.2,
            "contact name identity is unchanged"
        );
        // Canonical fields win over stale legacy duplicates.
        assert_eq!(entry.company_name, "Canonical Co");
        assert_eq!(entry.domain, "acme.example");
        // Lead-only fields still come from the bridge.
        assert_eq!(entry.source, "import");
        assert_eq!(entry.score, Some(42));
        assert_eq!(entry.notes.as_deref(), Some("seed notes"));
        assert_eq!(entry.tags, vec!["vip".to_string()]);
        assert_eq!(entry.deal_value, Some(1234.5));
        // Status is canonical (contact active, account discovered → 'new'),
        // NOT the legacy 'qualified' still sitting in sales_leads.status.
        assert_eq!(
            entry.status, "new",
            "the legacy status column must not be presented as truth"
        );

        for statement in [
            "DELETE FROM sales_leads WHERE tenant_id = $1",
            "DELETE FROM sales_contact_points WHERE tenant_id = $1",
            "DELETE FROM sales_contacts WHERE tenant_id = $1",
            "DELETE FROM sales_accounts WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(&tenant)
                .execute(&pool)
                .await
                .expect("cleanup parity fixture");
        }
    }

    // ── Item 17: operator status decisions go canonical ─────────────────

    struct OperatorLeadFixture {
        contact_id: uuid::Uuid,
        lead_id: String,
    }

    /// Seed one canonical account/contact/point plus the bridge row. The
    /// legacy `status` starts at `legacy_status` so each test can prove the
    /// column is neither written nor read.
    async fn seed_operator_lead(
        pool: &sqlx::PgPool,
        tenant: &str,
        suffix: &str,
        legacy_status: &str,
    ) -> OperatorLeadFixture {
        let account_id = uuid::Uuid::new_v4();
        let contact_id = uuid::Uuid::new_v4();
        let point_id = uuid::Uuid::new_v4();
        let lead_id = format!("lead_{suffix}");
        let domain = format!("{suffix}.example");
        let email = format!("{suffix}@example.com");

        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain, lifecycle) \
             VALUES ($1, $2, $3, $4, 'discovered')",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(format!("{suffix} Co"))
        .bind(&domain)
        .execute(pool)
        .await
        .expect("seed operator account");
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(contact_id)
        .bind(tenant)
        .bind(account_id)
        .bind(format!("{suffix} Contact"))
        .execute(pool)
        .await
        .expect("seed operator contact");
        sqlx::query(
            "INSERT INTO sales_contact_points \
                 (id, tenant_id, contact_id, channel, value, normalized_value, verification, confidence) \
             VALUES ($1, $2, $3, 'email', $4, lower($4), 'valid', 0.9)",
        )
        .bind(point_id)
        .bind(tenant)
        .bind(contact_id)
        .bind(&email)
        .execute(pool)
        .await
        .expect("seed operator contact point");
        sqlx::query(
            "INSERT INTO sales_leads \
                 (id, tenant_id, company_name, domain, contact_email, contact_name, \
                  score, source, status, account_id, contact_id) \
             VALUES ($1, $2, $3, $4, $5, $6, 0, 'test', $7, $8, $9)",
        )
        .bind(&lead_id)
        .bind(tenant)
        .bind(format!("{suffix} Co"))
        .bind(&domain)
        .bind(&email)
        .bind(format!("{suffix} Contact"))
        .bind(legacy_status)
        .bind(account_id)
        .bind(contact_id)
        .execute(pool)
        .await
        .expect("seed operator lead bridge row");

        OperatorLeadFixture {
            contact_id,
            lead_id,
        }
    }

    async fn cleanup_operator_fixture(pool: &sqlx::PgPool, tenant: &str) {
        for statement in [
            "DELETE FROM sales_leads WHERE tenant_id = $1",
            "DELETE FROM sales_contact_points WHERE tenant_id = $1",
            "DELETE FROM sales_contacts WHERE tenant_id = $1",
            "DELETE FROM sales_accounts WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(tenant)
                .execute(pool)
                .await
                .expect("cleanup operator fixture");
        }
    }

    fn status_only_update(lead_id: &str, status: &str) -> LeadUpdate {
        LeadUpdate {
            id: Some(lead_id.to_string()),
            ids: None,
            status: Some(status.to_string()),
            notes: None,
            tags: None,
            contact_email: None,
            contact_name: None,
            deal_value: None,
        }
    }

    /// The vocabulary that the canonical read can actually render. Guards
    /// against a future edit silently accepting a status nothing displays.
    #[test]
    fn canonical_status_vocabulary_maps_to_the_read_derivation() {
        assert_eq!(
            canonical_lead_status("qualified"),
            Some(CanonicalLeadStatus::AccountLifecycle("qualified"))
        );
        assert_eq!(
            canonical_lead_status("prospect"),
            Some(CanonicalLeadStatus::AccountLifecycle("nurturing"))
        );
        assert_eq!(
            canonical_lead_status("converted"),
            Some(CanonicalLeadStatus::ContactLifecycle("customer"))
        );
        assert_eq!(
            canonical_lead_status("unqualified"),
            Some(CanonicalLeadStatus::ContactLifecycle("do_not_contact"))
        );
        assert_eq!(
            canonical_lead_status("lost"),
            Some(CanonicalLeadStatus::ContactLifecycle("do_not_contact"))
        );
        // Derived-from-activity labels have no canonical destination.
        for unmappable in ["new", "contacted", "engaged", "demo_scheduled", "bogus"] {
            assert!(
                canonical_lead_status(unmappable).is_none(),
                "`{unmappable}` must not be writable as a lifecycle"
            );
        }
    }

    /// Adversarial test 1: the operator round trip. An `unqualified` decision
    /// through the admin update path must land on the canonical contact
    /// lifecycle AND be visible in the CP's own read — not merely written to
    /// a column. The legacy column starts at a contradictory `qualified` and
    /// must stay untouched.
    #[tokio::test]
    async fn operator_unqualified_decision_is_canonical_and_visible_in_the_cp_read() {
        let Some(pool) = crate::test_db::optional_pg_pool("cp_item17_unqualified").await else {
            return;
        };
        let tenant = format!("cp17u{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);
        let fixture = seed_operator_lead(&pool, &tenant, "unq", "qualified").await;

        let updated = apply_lead_update(
            &pool,
            &tenant,
            &status_only_update(&fixture.lead_id, "unqualified"),
        )
        .await
        .expect("the operator decision must be accepted");
        assert_eq!(updated, 1);

        let lifecycle: String = sqlx::query_scalar(
            "SELECT lifecycle FROM sales_contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(fixture.contact_id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("canonical contact lifecycle");
        assert_eq!(
            lifecycle, "do_not_contact",
            "the operator's unqualified intent must land on the canonical lifecycle"
        );

        let legacy: String =
            sqlx::query_scalar("SELECT status FROM sales_leads WHERE id = $1 AND tenant_id = $2")
                .bind(&fixture.lead_id)
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("legacy status");
        assert_eq!(
            legacy, "qualified",
            "the legacy status column must not be written"
        );

        let rows = load_lead_entries(&pool, &tenant, None, None, 50, 0)
            .await
            .expect("CP canonical read");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].status, "lost",
            "the canonical CP read must surface the operator's decision"
        );

        cleanup_operator_fixture(&pool, &tenant).await;
    }

    /// Adversarial test 2: a status with no canonical equivalent is rejected
    /// with the supported vocabulary named, and NOTHING is written (neither
    /// the legacy column nor canonical state).
    #[tokio::test]
    async fn unsupported_status_is_rejected_with_the_supported_list_and_writes_nothing() {
        let Some(pool) = crate::test_db::optional_pg_pool("cp_item17_unsupported").await else {
            return;
        };
        let tenant = format!("cp17x{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);
        let fixture = seed_operator_lead(&pool, &tenant, "bad", "qualified").await;

        let error = apply_lead_update(
            &pool,
            &tenant,
            &status_only_update(&fixture.lead_id, "engaged"),
        )
        .await
        .expect_err("`engaged` is derived from enrollment activity and must be rejected");
        let message = match &error {
            ApiError::Validation(messages) => messages.join("; "),
            other => panic!("expected a validation rejection, got {other:?}"),
        };
        assert!(
            message.contains("qualified") && message.contains("do_not_contact"),
            "the rejection must name the supported values and their canonical effect, got: {message}"
        );

        let (contact_lifecycle, account_lifecycle): (String, String) = sqlx::query_as(
            "SELECT c.lifecycle, a.lifecycle FROM sales_contacts c \
             JOIN sales_accounts a ON a.id = c.account_id \
             WHERE c.id = $1 AND c.tenant_id = $2",
        )
        .bind(fixture.contact_id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("canonical state");
        assert_eq!(
            (contact_lifecycle.as_str(), account_lifecycle.as_str()),
            ("active", "discovered"),
            "a rejected status must not write canonical state"
        );
        let legacy: String =
            sqlx::query_scalar("SELECT status FROM sales_leads WHERE id = $1 AND tenant_id = $2")
                .bind(&fixture.lead_id)
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("legacy status");
        assert_eq!(
            legacy, "qualified",
            "a rejected status must not write the legacy column either"
        );

        cleanup_operator_fixture(&pool, &tenant).await;
    }

    /// Adversarial test 6a: a bulk update mixing a valid and an unknown id is
    /// rejected as a whole — no partial write. The transaction contract is
    /// all-or-nothing (one transaction, ids prevalidated before any write).
    #[tokio::test]
    async fn bulk_update_mixing_valid_and_invalid_ids_writes_nothing() {
        let Some(pool) = crate::test_db::optional_pg_pool("cp_item17_mixed_bulk").await else {
            return;
        };
        let tenant = format!("cp17m{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);
        let fixture = seed_operator_lead(&pool, &tenant, "mix", "qualified").await;

        let body = LeadUpdate {
            id: None,
            ids: Some(vec![fixture.lead_id.clone(), "missing_lead_id".to_string()]),
            status: Some("lost".to_string()),
            notes: Some("should never be written".to_string()),
            tags: None,
            contact_email: None,
            contact_name: None,
            deal_value: None,
        };
        let error = apply_lead_update(&pool, &tenant, &body)
            .await
            .expect_err("the whole request must fail on the unknown id");
        assert!(
            matches!(error, ApiError::Validation(_)),
            "expected a validation rejection, got {error:?}"
        );

        let lifecycle: String = sqlx::query_scalar(
            "SELECT lifecycle FROM sales_contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(fixture.contact_id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("canonical lifecycle");
        assert_eq!(
            lifecycle, "active",
            "the valid id's canonical state must be untouched when another id is invalid"
        );
        let notes: Option<String> =
            sqlx::query_scalar("SELECT notes FROM sales_leads WHERE id = $1 AND tenant_id = $2")
                .bind(&fixture.lead_id)
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("legacy projection row");
        assert!(
            notes.is_none(),
            "the projection field must not be partially written"
        );

        cleanup_operator_fixture(&pool, &tenant).await;
    }

    /// Adversarial test 6b: a status update on a lead whose canonical contact
    /// was deleted is rejected (never panics, never partially writes the
    /// other leads in the batch).
    #[tokio::test]
    async fn status_on_a_lead_with_a_deleted_contact_is_rejected_without_partial_write() {
        let Some(pool) = crate::test_db::optional_pg_pool("cp_item17_deleted_contact").await else {
            return;
        };
        let tenant = format!("cp17d{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);
        let first = seed_operator_lead(&pool, &tenant, "keep", "qualified").await;
        let second = seed_operator_lead(&pool, &tenant, "gone", "qualified").await;

        // The bridge row keeps the dangling uuid: `sales_leads.contact_id`
        // has no FK (migration 200:90), so a deleted contact is a real state.
        sqlx::query("DELETE FROM sales_contacts WHERE id = $1 AND tenant_id = $2")
            .bind(second.contact_id)
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("delete the second contact");

        let body = LeadUpdate {
            id: None,
            ids: Some(vec![first.lead_id.clone(), second.lead_id.clone()]),
            status: Some("lost".to_string()),
            notes: None,
            tags: None,
            contact_email: None,
            contact_name: None,
            deal_value: None,
        };
        let error = apply_lead_update(&pool, &tenant, &body)
            .await
            .expect_err("the deleted canonical contact must reject the batch");
        let message = match &error {
            ApiError::Validation(messages) => messages.join("; "),
            other => panic!("expected a validation rejection, got {other:?}"),
        };
        assert!(
            message.contains("canonical contact"),
            "the rejection must name the missing canonical link, got: {message}"
        );

        let first_lifecycle: String = sqlx::query_scalar(
            "SELECT lifecycle FROM sales_contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(first.contact_id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("first contact lifecycle");
        assert_eq!(
            first_lifecycle, "active",
            "the live lead must not be written when its batch mate has no canonical contact"
        );

        cleanup_operator_fixture(&pool, &tenant).await;
    }

    /// Identity updates are canonical too: `contactEmail`/`contactName` land
    /// on `sales_contact_points`/`sales_contacts`, leaving the legacy bridge
    /// identity columns untouched, and the CP read reflects the new values.
    #[tokio::test]
    async fn contact_identity_updates_are_written_canonically_not_to_the_bridge() {
        let Some(pool) = crate::test_db::optional_pg_pool("cp_item17_identity").await else {
            return;
        };
        let tenant = format!("cp17i{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);
        let fixture = seed_operator_lead(&pool, &tenant, "ident", "new").await;

        let body = LeadUpdate {
            id: Some(fixture.lead_id.clone()),
            ids: None,
            status: None,
            notes: None,
            tags: None,
            contact_email: Some("Grace@Hopper.Example".to_string()),
            contact_name: Some("Grace Hopper".to_string()),
            deal_value: None,
        };
        apply_lead_update(&pool, &tenant, &body)
            .await
            .expect("identity update must be accepted");

        let (normalized, contact_name): (String, String) = sqlx::query_as(
            "SELECT cp.normalized_value, c.full_name \
             FROM sales_contact_points cp JOIN sales_contacts c ON c.id = cp.contact_id \
             WHERE c.id = $1 AND c.tenant_id = $2 AND cp.channel = 'email'",
        )
        .bind(fixture.contact_id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("canonical identity");
        assert_eq!(
            normalized, "grace@hopper.example",
            "the canonical contact point must be normalized"
        );
        assert_eq!(contact_name, "Grace Hopper");

        let (legacy_email, legacy_name): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT contact_email, contact_name FROM sales_leads WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&fixture.lead_id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("legacy identity columns");
        assert_eq!(
            (legacy_email.as_deref(), legacy_name.as_deref()),
            (Some("ident@example.com"), Some("ident Contact")),
            "the bridge identity columns must not be the write target"
        );

        let rows = load_lead_entries(&pool, &tenant, None, None, 50, 0)
            .await
            .expect("CP canonical read");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].contact_email.as_deref(),
            Some("Grace@Hopper.Example"),
            "the CP read must show the canonical identity"
        );
        assert_eq!(rows[0].contact_name.as_deref(), Some("Grace Hopper"));

        cleanup_operator_fixture(&pool, &tenant).await;
    }

    /// Writer regression guard: the production halves of the two CP files
    /// must not write the legacy `sales_leads.status` column. (The CP read
    /// guard is the seeded `qualified` → `new` assertion above.)
    #[test]
    fn cp_production_paths_never_write_the_legacy_lead_status() {
        let sales = include_str!("sales.rs");
        let sales_production = sales
            .split("#[cfg(test)]")
            .next()
            .expect("sales.rs has a test module");
        assert!(
            !sales_production.contains(&["SET status", "="].join(" ")),
            "the admin sales route must not write sales_leads.status"
        );

        // web.rs has `#[cfg(test)]` blocks mid-file, so scan the whole file:
        // the fragments below are specific SQL writes, not prose.
        let web = include_str!("../web.rs");
        for fragment in [
            ["UPDATE sales_leads", "SET"].join(" "),
            ["INSERT INTO", "sales_leads"].join(" "),
            ["DELETE FROM", "sales_leads"].join(" "),
        ] {
            assert!(
                !web.contains(&fragment),
                "the SSR sales handlers must not write sales_leads (`{fragment}` found)"
            );
        }
    }
}
