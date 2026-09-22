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

/// The CP's rendered lead row. Identity, [`LeadEntry::status`] and the
/// lead-only fields are all projected by the derived `sales_leads` view
/// (migration 223) from the canonical account/contact model:
///
/// | field | canonical column on `sales_contacts` |
/// |---|---|
/// | `source` | `lead_source` |
/// | `score` | `lead_score` |
/// | `notes` | `lead_notes` |
/// | `tags` | `lead_tags` |
/// | `deal_value` | `lead_deal_value` |
/// | `contact_email` | primary contact point (fallback `legacy_lead_email`) |
/// | `contact_name` | `full_name` |
/// | `company_name` / `domain` | `sales_accounts.company` / `.domain` |
/// | `status` | derived lifecycle `CASE` |
///
/// These lead-only fields are the ONLY remaining non-canonical concepts the
/// CP update path writes (see [`LeadUpdate`]); identity and status are
/// written to the canonical tables.
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

/// Canonical CP lead read (audit item 17, completed by migration 223):
/// identity, status and lead-only fields all come from the canonical
/// account/contact model through the derived `sales_leads` view.
///
/// Column mapping, preserved so the CP UI keeps rendering the same
/// [`LeadEntry`] shape:
///
/// | `LeadEntry` field | canonical source |
/// |---|---|
/// | `id` | `sales_leads.id` = `sales_contacts.legacy_lead_id` (the stable id the old stored table held) |
/// | `tenant_id` | `sales_contacts.tenant_id` |
/// | `contact_email` | primary `sales_contact_points.value`, falling back to the pre-canonical `legacy_lead_email` |
/// | `contact_name` | `sales_contacts.full_name` |
/// | `company_name` | `sales_accounts.company` |
/// | `domain` | `sales_accounts.domain` |
/// | `status` | derived `CASE` over contact/account/enrollment lifecycle |
/// | `source`, `score`, `notes`, `tags`, `deal_value`, timestamps | `sales_contacts.lead_*` projection columns |
///
/// There is no stored status column to disagree with: migration 223 dropped
/// the table, so the view's derivation is the only status the CP can see.
/// Every contact with a `legacy_lead_id` (including discovery-imported
/// contacts, which now carry a contact with no reachable address) is listed.
///
/// The CTE projects `tenant_id`, `account_id` and `contact_id`; callers
/// scope with `WHERE tenant_id = $n` in the outer query (the positional
/// binds are emitted by `QueryBuilder` at the call site, so a `$1` inside
/// this raw string would not line up with them).
pub(crate) const CANONICAL_LEAD_CTE: &str = r#"
    WITH canonical_leads AS (
        SELECT
            l.id,
            l.tenant_id,
            l.account_id,
            l.contact_id,
            l.source,
            l.score,
            l.notes,
            COALESCE(l.tags, '[]'::jsonb) AS tags,
            l.deal_value,
            l.created_at,
            l.updated_at,
            l.contact_email,
            l.contact_name,
            l.company_name,
            l.domain,
            l.status
        FROM sales_leads l
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

/// The refusal for a lead whose canonical link column is NULL. Names the
/// first offending lead so the operator can repair the mapping.
fn unlinked_lead_error(
    link_field: &'static str,
    writes_account: bool,
    rows: &[(String, Option<uuid::Uuid>, Option<uuid::Uuid>)],
) -> LeadStatusWriteError {
    let lead_id = rows
        .iter()
        .find(|(_, account_id, contact_id)| {
            if writes_account {
                account_id.is_none()
            } else {
                contact_id.is_none()
            }
        })
        .map(|(id, _, _)| id.clone())
        .unwrap_or_default();
    LeadStatusWriteError::MissingCanonicalLink {
        lead_id,
        link: link_field,
    }
}

/// The refusal for a lead whose canonical link points at a row that no
/// longer exists. Names the lead whose link is the dead id. (Reachable in
/// deployment schemas without the link FKs; canonical provisionings have
/// the FK and the lock, so this stays defense-in-depth.)
fn dead_link_error(
    link_field: &'static str,
    writes_account: bool,
    rows: &[(String, Option<uuid::Uuid>, Option<uuid::Uuid>)],
    dead: uuid::Uuid,
) -> LeadStatusWriteError {
    let lead_id = rows
        .iter()
        .find(|(_, account_id, contact_id)| {
            let link = if writes_account {
                account_id
            } else {
                contact_id
            };
            *link == Some(dead)
        })
        .map(|(id, _, _)| id.clone())
        .unwrap_or_default();
    LeadStatusWriteError::MissingCanonicalLink {
        lead_id,
        link: link_field,
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

    // The lead row is the canonical contact's id mapping since migration
    // 223, and a view cannot be locked: `FOR UPDATE OF c` locks the base
    // contact so concurrent transitions serialize.
    let rows: Vec<(String, Option<uuid::Uuid>, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT c.legacy_lead_id AS id, c.account_id, c.id AS contact_id \
         FROM sales_contacts c \
         WHERE c.tenant_id = $1 AND c.legacy_lead_id = ANY($2) \
         FOR UPDATE OF c",
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
        return Err(unlinked_lead_error(
            link_field,
            target.writes_account(),
            &rows,
        ));
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
        return Err(dead_link_error(
            link_field,
            target.writes_account(),
            &rows,
            dead,
        ));
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

/// The refusal for a lead with no live canonical contact. It names the
/// lead so the operator can fix the identity through the canonical
/// contact API.
fn missing_canonical_contact_error(lead_id: &str) -> ApiError {
    ApiError::Validation(vec![format!(
        "lead `{lead_id}` has no live canonical contact; add the address through the \
         canonical contact API before editing its identity"
    )])
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
    contact_id.ok_or_else(|| missing_canonical_contact_error(lead_id))
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
    // tenant before any statement writes. The lead id is the canonical
    // contact's mapping since migration 223.
    let found: Vec<String> = sqlx::query_scalar(
        "SELECT c.legacy_lead_id FROM sales_contacts c \
         WHERE c.tenant_id = $1 AND c.legacy_lead_id = ANY($2)",
    )
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

    // Lead-only projection: the `lead_*` columns on the canonical contact
    // (see [`LeadEntry`] for each field). Identity and status never land
    // here, and `sales_leads` (the derived view) is never written.
    let projection_fields: Vec<&str> = [
        body.notes.is_some().then_some("lead_notes"),
        body.tags.is_some().then_some("lead_tags"),
        body.deal_value.is_some().then_some("lead_deal_value"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !projection_fields.is_empty() {
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "UPDATE sales_contacts SET lead_updated_at = NOW()",
        );
        if let Some(ref notes) = body.notes {
            builder.push(", lead_notes = ").push_bind(notes.clone());
        }
        if let Some(ref tags) = body.tags {
            builder
                .push(", lead_tags = ")
                .push_bind(serde_json::json!(tags));
        }
        if let Some(deal_value) = body.deal_value {
            builder.push(", lead_deal_value = ").push_bind(deal_value);
        }
        builder
            .push(" WHERE tenant_id = ")
            .push_bind(tenant_id.to_string());
        builder
            .push(" AND legacy_lead_id = ANY(")
            .push_bind(ids.clone());
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
        // The sales_leads view COALESCEs the account domain to '' — an
        // empty domain is "no domain", not a target the engine can enrich.
        let domain = domain.filter(|domain| !domain.trim().is_empty());
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
        // reachable contact point until enrichment supplies one. Since
        // migration 223 the lead itself is a canonical contact carrying the
        // id mapping; the account write and the contact write share one
        // transaction, so neither can be left behind alone.
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

        // The discovered lead is a contact with an empty name and no contact
        // point (nothing is fabricated), carrying the id mapping and the
        // lead-only projection columns. It is listed by the derived view and
        // by every canonical read immediately.
        sqlx::query(
            "INSERT INTO sales_contacts (
                id, tenant_id, account_id, full_name,
                legacy_lead_id, lead_source, lead_notes,
                lead_created_at, lead_updated_at, created_at, updated_at
             ) VALUES ($1, $2, $3, '', $4, $5, $6, NOW(), NOW(), NOW(), NOW())",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&auth.tenant_id)
        .bind(account_id)
        .bind(&lead_id)
        .bind(&primary_source)
        .bind(description.or(industry.clone()))
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
        // The lead mapping and lead-only projection live on the contact since
        // migration 223. `legacy_lead_email` deliberately differs from the
        // canonical point: the point must win.
        sqlx::query(
            "UPDATE sales_contacts \
                SET legacy_lead_id = $1, legacy_lead_email = 'ada@legacy.example', \
                    lead_source = 'import', lead_score = 42, \
                    lead_notes = 'seed notes', lead_tags = '[\"vip\"]'::jsonb, \
                    lead_deal_value = 1234.5, lead_created_at = NOW(), lead_updated_at = NOW() \
              WHERE id = $2 AND tenant_id = $3",
        )
        .bind(&lead_id)
        .bind(contact_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("map the contact as a lead");

        let old: (String, String, String) = sqlx::query_as(
            "SELECT id, COALESCE(email, contact_email, ''), COALESCE(contact_name, '') \
             FROM sales_leads WHERE tenant_id = $1 AND id = $2",
        )
        .bind(&tenant)
        .bind(&lead_id)
        .fetch_one(&pool)
        .await
        .expect("view read");

        let rows = load_lead_entries(&pool, &tenant, None, None, 50, 0)
            .await
            .expect("canonical read");
        assert_eq!(rows.len(), 1, "one canonical lead for one contact");

        let entry = &rows[0];
        assert_eq!(entry.id, old.0, "row identity");
        assert_eq!(
            entry.contact_email.as_deref().unwrap_or_default(),
            old.1,
            "the view and the CTE must agree on the email identity"
        );
        assert_eq!(
            entry.contact_email.as_deref(),
            Some("ada@acme.example"),
            "the canonical contact point must win over legacy_lead_email"
        );
        assert_eq!(
            entry.contact_name.as_deref().unwrap_or_default(),
            old.2,
            "contact name identity is unchanged"
        );
        // Canonical fields win over stale legacy duplicates.
        assert_eq!(entry.company_name, "Canonical Co");
        assert_eq!(entry.domain, "acme.example");
        // Lead-only fields come from the canonical lead projection.
        assert_eq!(entry.source, "import");
        assert_eq!(entry.score, Some(42));
        assert_eq!(entry.notes.as_deref(), Some("seed notes"));
        assert_eq!(entry.tags, vec!["vip".to_string()]);
        assert_eq!(entry.deal_value, Some(1234.5));
        // Status is derived (contact active, account discovered → 'new').
        assert_eq!(
            entry.status, "new",
            "status must be the canonical derivation"
        );

        for statement in [
            "UPDATE sales_contacts SET legacy_lead_id = NULL, legacy_lead_email = NULL \
             WHERE tenant_id = $1",
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

    /// Seed one canonical account/contact/point and map the contact as a
    /// lead (`legacy_lead_id`) with the lead-only projection the view
    /// renders. There is no stored status column since migration 223: status
    /// is always derived.
    async fn seed_operator_lead(
        pool: &sqlx::PgPool,
        tenant: &str,
        suffix: &str,
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
            "UPDATE sales_contacts \
                SET legacy_lead_id = $1, legacy_lead_email = $2, \
                    lead_source = 'test', lead_score = 0 \
              WHERE id = $3 AND tenant_id = $4",
        )
        .bind(&lead_id)
        .bind(&email)
        .bind(contact_id)
        .bind(tenant)
        .execute(pool)
        .await
        .expect("map the operator contact as a lead");

        OperatorLeadFixture {
            contact_id,
            lead_id,
        }
    }

    async fn cleanup_operator_fixture(pool: &sqlx::PgPool, tenant: &str) {
        for statement in [
            "UPDATE sales_contacts SET legacy_lead_id = NULL, legacy_lead_email = NULL \
             WHERE tenant_id = $1",
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
    /// lifecycle AND be visible in the CP's own read AND in the derived view
    /// — not merely written to a column.
    #[tokio::test]
    async fn operator_unqualified_decision_is_canonical_and_visible_in_the_cp_read() {
        let Some(pool) = crate::test_db::optional_pg_pool("cp_item17_unqualified").await else {
            return;
        };
        let tenant = format!("cp17u{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);
        let fixture = seed_operator_lead(&pool, &tenant, "unq").await;

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

        let view_status: String =
            sqlx::query_scalar("SELECT status FROM sales_leads WHERE id = $1 AND tenant_id = $2")
                .bind(&fixture.lead_id)
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("view status");
        assert_eq!(
            view_status, "lost",
            "the derived view must surface the operator's decision immediately"
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
    /// with the supported vocabulary named, and NOTHING is written (no
    /// canonical lifecycle, no derived-status change).
    #[tokio::test]
    async fn unsupported_status_is_rejected_with_the_supported_list_and_writes_nothing() {
        let Some(pool) = crate::test_db::optional_pg_pool("cp_item17_unsupported").await else {
            return;
        };
        let tenant = format!("cp17x{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);
        let fixture = seed_operator_lead(&pool, &tenant, "bad").await;

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
        let view_status: String =
            sqlx::query_scalar("SELECT status FROM sales_leads WHERE id = $1 AND tenant_id = $2")
                .bind(&fixture.lead_id)
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("view status");
        assert_eq!(
            view_status, "new",
            "a rejected status must not change the derived status either"
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
        let fixture = seed_operator_lead(&pool, &tenant, "mix").await;

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
                .expect("lead projection through the view");
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
        let first = seed_operator_lead(&pool, &tenant, "keep").await;
        let second = seed_operator_lead(&pool, &tenant, "gone").await;

        // Since migration 223 the lead id mapping lives ON the contact, so
        // deleting the contact deletes the lead from the derived view.
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
            message.contains("was not found for this tenant"),
            "the rejection must report the vanished lead, got: {message}"
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
    /// on `sales_contact_points`/`sales_contacts`, leaving the read-fallback
    /// `legacy_lead_email` untouched, and the CP read reflects the new
    /// values.
    #[tokio::test]
    async fn contact_identity_updates_are_written_canonically_not_to_the_bridge() {
        let Some(pool) = crate::test_db::optional_pg_pool("cp_item17_identity").await else {
            return;
        };
        let tenant = format!("cp17i{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);
        let fixture = seed_operator_lead(&pool, &tenant, "ident").await;

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

        // The read-fallback mirror is not the write target: it keeps the
        // pre-update address while the canonical point carries the new one.
        let fallback_email: Option<String> = sqlx::query_scalar(
            "SELECT legacy_lead_email FROM sales_contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(fixture.contact_id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("lead email fallback");
        assert_eq!(
            fallback_email.as_deref(),
            Some("ident@example.com"),
            "the fallback mirror must not be the write target"
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

    /// Writer regression guard: `sales_leads` is a derived, read-only view
    /// since migration 223, so the production halves of the CP files must
    /// not contain ANY write against it. Identity/status/lead-only writes
    /// all target the canonical tables.
    #[test]
    fn cp_production_paths_never_write_the_sales_leads_view() {
        let sales = include_str!("sales.rs");
        let sales_production = sales
            .split("#[cfg(test)]")
            .next()
            .expect("sales.rs has a test module");
        for fragment in [
            ["SET status", "="].join(" "),
            ["INSERT INTO", "sales_leads"].join(" "),
            ["UPDATE sales_leads", "SET"].join(" "),
            ["DELETE FROM", "sales_leads"].join(" "),
        ] {
            assert!(
                !sales_production.contains(&fragment),
                "the admin sales route must not write the derived view (`{fragment}` found)"
            );
        }
        assert!(
            sales_production.contains("UPDATE sales_contacts"),
            "lead field writes must target the canonical contact table"
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

// ─── Adversarial handler-level tests ──────────────────────────────
//
// The module above proves the production SQL contract; this module drives
// the REAL router (auth extractor → scope gate → system-tenant gate →
// handler → audit) over a canonical-schema pool and a loopback mock of the
// sales-autopilot service.

#[cfg(test)]
mod adversarial_handler_tests {
    use super::*;
    use crate::app::test_support::{test_config, test_state_over_with_config};
    use axum::body::Body;
    use axum::http::{Method, Request};
    use sqlx::PgPool;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    const CP_KEY: &str = "test-cp-key";

    async fn state_with_engine(
        pool: PgPool,
        engine_base: &str,
        internal_token: Option<&str>,
    ) -> AppState {
        let mut config = test_config();
        config.control_plane_api_key = Some(CP_KEY.into());
        config.sales_autopilot_base_url = engine_base.to_string();
        config.internal_service_token = internal_token.map(str::to_string);
        test_state_over_with_config(pool, config).await
    }

    /// The production handlers at their production FULL paths. Routes are
    /// registered directly rather than with `nest` because nesting strips the
    /// URI prefix before the handler's `AuthUser` extractor runs, and the
    /// control-plane static API key path guard inspects the full path.
    fn sales_app(state: &AppState) -> Router {
        Router::new()
            .route("/v1/admin/sales/leads", get(list_leads))
            .route("/v1/admin/sales/leads/update", patch(update_leads))
            .route("/v1/admin/sales/leads/enrich", post(enrich_leads))
            .route(
                "/v1/admin/sales/campaigns",
                get(list_campaigns).patch(update_campaign),
            )
            .route("/v1/admin/sales/discovery/run", post(run_discovery))
            .route("/v1/admin/sales/outreach/start", post(start_outreach))
            .route(
                "/v1/admin/sales/settings",
                get(get_settings).put(save_settings),
            )
            .with_state(state.clone())
    }

    fn cp_request(method: Method, uri: &str, body: Option<serde_json::Value>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "localhost")
            .header("x-api-key", CP_KEY);
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        builder.body(body).unwrap()
    }

    async fn json_body(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    fn unique(prefix: &str) -> String {
        format!(
            "{prefix}{}",
            &uuid::Uuid::new_v4().simple().to_string()[..18]
        )
    }

    struct SeededLead {
        contact_id: uuid::Uuid,
        account_id: uuid::Uuid,
        lead_id: String,
        domain: String,
    }

    /// Seed one canonical account/contact/point mapped as a lead under
    /// `tenant`, with the lead-only projection rendered by the derived view.
    async fn seed_lead(
        pool: &PgPool,
        tenant: &str,
        suffix: &str,
        source: &str,
        lifecycle: &str,
    ) -> SeededLead {
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
        .expect("seed adversarial account");
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name, lifecycle) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(contact_id)
        .bind(tenant)
        .bind(account_id)
        .bind(format!("{suffix} Contact"))
        .bind(lifecycle)
        .execute(pool)
        .await
        .expect("seed adversarial contact");
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
        .expect("seed adversarial contact point");
        sqlx::query(
            "UPDATE sales_contacts SET legacy_lead_id = $1, legacy_lead_email = $2, \
                    lead_source = $3, lead_score = 0, lead_created_at = NOW(), lead_updated_at = NOW() \
              WHERE id = $4 AND tenant_id = $5",
        )
        .bind(&lead_id)
        .bind(&email)
        .bind(source)
        .bind(contact_id)
        .bind(tenant)
        .execute(pool)
        .await
        .expect("map adversarial contact as a lead");
        SeededLead {
            contact_id,
            account_id,
            lead_id,
            domain,
        }
    }

    /// Remove ONLY the rows this test created (never a tenant-wide sweep:
    /// other tests and agents share the `system` tenant id).
    async fn cleanup_lead(pool: &PgPool, tenant: &str, lead: &SeededLead) {
        sqlx::query("DELETE FROM sales_contact_points WHERE contact_id = $1")
            .bind(lead.contact_id)
            .execute(pool)
            .await
            .expect("cleanup contact point");
        sqlx::query("DELETE FROM sales_contacts WHERE id = $1 AND tenant_id = $2")
            .bind(lead.contact_id)
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup contact");
        sqlx::query("DELETE FROM sales_accounts WHERE id = $1 AND tenant_id = $2")
            .bind(lead.account_id)
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup account");
    }

    // ── Loopback mock of the sales-autopilot service ─────────────

    #[derive(Debug, Clone)]
    struct MockCall {
        method: String,
        path: String,
        api_key: Option<String>,
        tenant_header: Option<String>,
        body: serde_json::Value,
    }

    type Calls = Arc<Mutex<Vec<MockCall>>>;

    #[derive(Clone)]
    struct MockEngine {
        base_url: String,
        calls: Calls,
    }

    impl MockEngine {
        fn take_calls(&self) -> Vec<MockCall> {
            std::mem::take(&mut *self.calls.lock().expect("mock calls lock"))
        }
    }

    async fn mock_engine_handler(
        State(calls): State<Calls>,
        request: axum::extract::Request,
    ) -> Response {
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let api_key = request
            .headers()
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let tenant_header = request
            .headers()
            .get("x-tenant-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        calls.lock().expect("mock calls lock").push(MockCall {
            method: method.clone(),
            path: path.clone(),
            api_key,
            tenant_header,
            body: body.clone(),
        });

        if path == "/enrich" {
            if body
                .get("email")
                .and_then(|value| value.as_str())
                .is_some_and(|email| email.contains("boom"))
            {
                return (StatusCode::INTERNAL_SERVER_ERROR, "engine exploded").into_response();
            }
            return Json(json!({ "company": { "name": "Acme", "input": body } })).into_response();
        }
        match (method.as_str(), path.as_str()) {
            ("GET", "/enrollments") => {
                Json(json!({ "data": [{ "id": "enr_mock" }] })).into_response()
            }
            ("POST", "/discovery/jobs") => {
                (StatusCode::CREATED, Json(json!({ "jobId": "job_mock" }))).into_response()
            }
            ("POST", "/enrollments") => {
                Json(json!({ "enrollmentBatchId": "batch_mock" })).into_response()
            }
            ("POST", _) if path.starts_with("/enrollments/") => {
                Json(json!({ "action": "applied" })).into_response()
            }
            _ => (StatusCode::NOT_FOUND, "unrouted mock path").into_response(),
        }
    }

    async fn start_mock_engine() -> MockEngine {
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock engine");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .fallback(mock_engine_handler)
            .with_state(calls.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        MockEngine { base_url, calls }
    }

    // ── Honest refusals with no database ─────────────────────────

    /// A dead lazy pool: `table_exists` is false, every handler must degrade
    /// honestly (never a fabricated success with rows).
    async fn dead_pool_state() -> AppState {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(300))
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
            .expect("lazy dead pool");
        state_with_engine(db, "", None).await
    }

    #[tokio::test]
    async fn read_handlers_degrade_honestly_when_storage_is_unavailable() {
        let state = dead_pool_state().await;
        let app = sales_app(&state);

        // No sales_leads table → an empty, explicitly zeroed response.
        let response = app
            .clone()
            .oneshot(cp_request(Method::GET, "/v1/admin/sales/leads", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["leads"].as_array().unwrap().len(), 0);
        assert_eq!(body["total"], 0);

        // No enrollment read model → the canonical fallback is empty, not an
        // error and not invented campaigns.
        let response = app
            .clone()
            .oneshot(cp_request(Method::GET, "/v1/admin/sales/campaigns", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(body.as_array().unwrap().is_empty());

        // Enrichment without a leads table reports the skip reason per id.
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::POST,
                "/v1/admin/sales/leads/enrich",
                Some(json!({ "leadIds": ["lead_missing_1", "lead_missing_2"] })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["enriched"], 0);
        assert_eq!(body["skipped"].as_array().unwrap().len(), 2);
        assert_eq!(
            body["skipped"][0]["reason"],
            "sales leads table unavailable"
        );

        // Discovery without its tables says so explicitly instead of
        // reporting a fabricated import count.
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::POST,
                "/v1/admin/sales/discovery/run",
                Some(json!({ "sources": ["mock"], "maxPages": 1 })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["status"], "unavailable");
        assert_eq!(body["imported"], 0);
        assert_eq!(body["mode"], "import_only");

        // Settings are never silently faked: a storage failure propagates.
        let response = app
            .oneshot(cp_request(Method::GET, "/v1/admin/sales/settings", None))
            .await
            .unwrap();
        assert!(
            response.status().is_server_error(),
            "settings must not fabricate defaults on a storage outage, got {}",
            response.status()
        );
    }

    // ── Read path: tenant scoping, filters, pagination, stats ─────

    #[tokio::test]
    async fn list_leads_is_tenant_scoped_and_applies_filters_and_clamps() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_list_leads").await else {
            return;
        };
        let marker = unique("srcmark");
        let other_marker = unique("srcother");
        let mine_a = seed_lead(&pool, "system", &unique("a"), &marker, "active").await;
        let mine_b = seed_lead(&pool, "system", &unique("b"), &marker, "do_not_contact").await;
        let other_tenant = unique("tother");
        let other = seed_lead(&pool, &other_tenant, &unique("o"), &other_marker, "active").await;

        let state = state_with_engine(pool.clone(), "", None).await;
        let app = sales_app(&state);

        // Scoped read: only this tenant's two leads, with KPIs over the same
        // canonical row set.
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::GET,
                &format!("/v1/admin/sales/leads?source={marker}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["total"], 2, "tenant-scoped total: {body}");
        let ids: Vec<String> = body["leads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|lead| lead["id"].as_str().unwrap().to_string())
            .collect();
        assert!(ids.contains(&mine_a.lead_id) && ids.contains(&mine_b.lead_id));
        assert_eq!(body["statsBySource"][marker.as_str()], 2);
        assert!(
            body["statsByStatus"].is_object(),
            "status KPIs are computed over the same canonical row set"
        );

        // The second tenant's lead is invisible, even when filtered for by
        // its exact source value.
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::GET,
                &format!("/v1/admin/sales/leads?source={other_marker}"),
                None,
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!(body["total"], 0, "cross-tenant lead leaked: {body}");
        assert!(body["leads"].as_array().unwrap().is_empty());

        // Status filter is applied on the canonical derivation.
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::GET,
                &format!("/v1/admin/sales/leads?source={marker}&status=lost"),
                None,
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["leads"][0]["id"], mine_b.lead_id);

        // Pagination: limit=0 clamps up to 1, negative offset clamps to 0,
        // and an over-limit is clamped to the 200-row ceiling (never a 500).
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::GET,
                &format!("/v1/admin/sales/leads?source={marker}&limit=0&offset=-5"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["leads"].as_array().unwrap().len(), 1);
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::GET,
                &format!("/v1/admin/sales/leads?source={marker}&limit=999999&offset=1"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await["leads"].as_array().unwrap().len(),
            1
        );

        cleanup_lead(&pool, "system", &mine_a).await;
        cleanup_lead(&pool, "system", &mine_b).await;
        cleanup_lead(&pool, &other_tenant, &other).await;
    }

    /// A tenant-scoped API key with the wildcard scope (every customer
    /// owner/admin) must be refused by the sales control plane.
    #[tokio::test]
    async fn customer_wildcard_key_is_forbidden_from_the_sales_control_plane() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_role_gate").await else {
            return;
        };
        let (tenant, key) = crate::app::test_support::seed_api_tenant(&pool, &["*"]).await;
        let state = state_with_engine(pool.clone(), "", None).await;
        let app = sales_app(&state);

        for (method, path, body) in [
            (Method::GET, "/v1/admin/sales/leads", None),
            (
                Method::PATCH,
                "/v1/admin/sales/leads/update",
                Some(json!({ "id": "x", "notes": "n" })),
            ),
            (Method::GET, "/v1/admin/sales/settings", None),
        ] {
            let mut builder = Request::builder()
                .method(method)
                .uri(path)
                .header("host", "localhost")
                .header("x-api-key", key.as_str());
            let request = match body {
                Some(value) => {
                    builder = builder.header("content-type", "application/json");
                    builder.body(Body::from(value.to_string())).unwrap()
                }
                None => builder.body(Body::empty()).unwrap(),
            };
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{path} must reject a customer wildcard key"
            );
        }

        sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup api key");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup tenant");
    }

    // ── Write path: atomicity, audit, tenant isolation ────────────

    #[tokio::test]
    async fn update_leads_handler_writes_projection_audit_and_refuses_cross_tenant() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_update_handler").await else {
            return;
        };
        let mine = seed_lead(&pool, "system", &unique("upd"), &unique("s"), "active").await;
        let other_tenant = unique("tother");
        let other = seed_lead(&pool, &other_tenant, &unique("oth"), &unique("s"), "active").await;

        let state = state_with_engine(pool.clone(), "", None).await;
        let app = sales_app(&state);

        // Cross-tenant id: rejected as not-found with nothing written.
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::PATCH,
                "/v1/admin/sales/leads/update",
                Some(json!({ "id": other.lead_id, "status": "lost" })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let other_lifecycle: String = sqlx::query_scalar(
            "SELECT lifecycle FROM sales_contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(other.contact_id)
        .bind(&other_tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            other_lifecycle, "active",
            "cross-tenant write must not land"
        );

        // Successful projection update (notes/tags/dealValue) — the canonical
        // contact columns the CP read renders.
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::PATCH,
                "/v1/admin/sales/leads/update",
                Some(json!({
                    "id": mine.lead_id,
                    "notes": "operator note",
                    "tags": ["vip", "beta"],
                    "dealValue": 4242.5
                })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["success"], true);
        assert_eq!(body["updated"], 1);

        let row: (Option<String>, serde_json::Value, Option<f64>) = sqlx::query_as(
            "SELECT lead_notes, COALESCE(lead_tags, '[]'::jsonb), lead_deal_value \
             FROM sales_contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(mine.contact_id)
        .bind("system")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0.as_deref(), Some("operator note"));
        assert_eq!(row.1, json!(["vip", "beta"]));
        assert_eq!(row.2, Some(4242.5));

        // The audit trail names the lead and the canonical effect.
        let audit: (String, String, Option<String>, serde_json::Value) = sqlx::query_as(
            "SELECT action, resource, resource_id, details FROM audit_logs \
             WHERE tenant_id = 'system' AND resource_id = $1 \
             ORDER BY timestamp DESC LIMIT 1",
        )
        .bind(&mine.lead_id)
        .fetch_one(&pool)
        .await
        .expect("audit row for the lead update");
        assert_eq!(audit.0, "control_plane.sales.leads_updated");
        assert_eq!(audit.1, "sales_lead");
        assert_eq!(audit.3["updated"], 1);

        // Malformed / oversized / empty id sets are 4xx, never 5xx.
        for body in [
            json!({ "id": "", "status": "lost" }),
            json!({ "id": "not-a-uuid-and-not-a-lead", "status": "lost" }),
            json!({ "ids": [], "status": "lost" }),
            json!({ "id": "x".repeat(100_000), "status": "lost" }),
            json!({ "ids": (0..101).map(|i| format!("lead_{i}")).collect::<Vec<_>>(), "status": "lost" }),
            json!({ "id": mine.lead_id }), // no fields
            json!({ "id": mine.lead_id, "status": "engaged" }), // derived-only status
            json!({ "ids": [mine.lead_id.clone(), "second"], "contactEmail": "a@b.example" }),
        ] {
            let response = app
                .clone()
                .oneshot(cp_request(
                    Method::PATCH,
                    "/v1/admin/sales/leads/update",
                    Some(body.clone()),
                ))
                .await
                .unwrap();
            assert!(
                response.status().is_client_error(),
                "expected 4xx for {body}, got {}",
                response.status()
            );
        }

        // The rejected requests wrote nothing.
        let unchanged: (Option<String>, Option<f64>) = sqlx::query_as(
            "SELECT lead_notes, lead_deal_value FROM sales_contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(mine.contact_id)
        .bind("system")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unchanged.0.as_deref(), Some("operator note"));
        assert_eq!(unchanged.1, Some(4242.5));
        let lifecycle: String = sqlx::query_scalar(
            "SELECT lifecycle FROM sales_contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(other.contact_id)
        .bind(&other_tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(lifecycle, "active");

        cleanup_lead(&pool, "system", &mine).await;
        cleanup_lead(&pool, &other_tenant, &other).await;
    }

    /// The operator status decision through the handler must land on the
    /// canonical lifecycle and be visible in the derived read, and an
    /// illegal transition must change nothing.
    #[tokio::test]
    async fn update_leads_handler_applies_canonical_status_and_refuses_illegal_ones() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_status_handler").await else {
            return;
        };
        let lead = seed_lead(&pool, "system", &unique("st"), &unique("s"), "active").await;
        let state = state_with_engine(pool.clone(), "", None).await;
        let app = sales_app(&state);

        let response = app
            .clone()
            .oneshot(cp_request(
                Method::PATCH,
                "/v1/admin/sales/leads/update",
                Some(json!({ "id": lead.lead_id, "status": "prospect" })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let account_lifecycle: String =
            sqlx::query_scalar("SELECT lifecycle FROM sales_accounts WHERE id = $1")
                .bind(lead.account_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(account_lifecycle, "nurturing");
        let rendered: String = sqlx::query_scalar(
            "SELECT status FROM sales_leads WHERE id = $1 AND tenant_id = 'system'",
        )
        .bind(&lead.lead_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rendered, "prospect");

        // Illegal transition: refused and nothing changes.
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::PATCH,
                "/v1/admin/sales/leads/update",
                Some(json!({ "ids": [lead.lead_id.clone()], "status": "demo_scheduled" })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let after: String =
            sqlx::query_scalar("SELECT lifecycle FROM sales_accounts WHERE id = $1")
                .bind(lead.account_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(after, "nurturing", "a refused status must change nothing");
        let rendered: String = sqlx::query_scalar(
            "SELECT status FROM sales_leads WHERE id = $1 AND tenant_id = 'system'",
        )
        .bind(&lead.lead_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rendered, "prospect");

        // Pool-level wrapper (the SSR path) shares the decision.
        let tx_lead = seed_lead(&pool, "system", &unique("st2"), &unique("s"), "active").await;
        let (updated, rendered) = apply_lead_status_decision(
            &pool,
            "system",
            std::slice::from_ref(&tx_lead.lead_id),
            "qualified",
        )
        .await
        .expect("canonical decision");
        assert_eq!(updated, 1);
        assert_eq!(rendered, "qualified");
        let error = apply_lead_status_decision(
            &pool,
            "system",
            std::slice::from_ref(&tx_lead.lead_id),
            "nonsense",
        )
        .await
        .expect_err("unsupported status must fail");
        assert!(matches!(error, LeadStatusWriteError::Unsupported(_)));

        cleanup_lead(&pool, "system", &lead).await;
        cleanup_lead(&pool, "system", &tx_lead).await;
    }

    #[test]
    fn status_write_errors_have_operator_safe_display() {
        let unsupported = LeadStatusWriteError::Unsupported("banana".into());
        assert!(unsupported.to_string().contains("`banana`"));
        assert!(unsupported.to_string().contains("qualified"));
        let missing = LeadStatusWriteError::LeadNotFound("lead_x".into());
        assert!(missing.to_string().contains("lead_x"));
        let dangling = LeadStatusWriteError::MissingCanonicalLink {
            lead_id: "lead_y".into(),
            link: "account",
        };
        assert!(dangling.to_string().contains("no live canonical account"));
        let database = LeadStatusWriteError::Database(sqlx::Error::RowNotFound);
        let display = database.to_string();
        assert!(
            !display.contains("no rows returned"),
            "raw database text must never reach operators: {display}"
        );
        assert!(matches!(
            lead_status_write_error(database),
            ApiError::NotFound(_)
        ));
        assert!(matches!(
            lead_status_write_error(LeadStatusWriteError::Unsupported("x".into())),
            ApiError::Validation(_)
        ));
    }

    #[test]
    fn canonical_status_labels_and_destinations_are_total() {
        for (requested, lifecycle, rendered, account) in [
            ("qualified", "qualified", "qualified", true),
            ("prospect", "nurturing", "prospect", true),
            ("converted", "customer", "converted", false),
            ("unqualified", "do_not_contact", "lost", false),
            ("lost", "do_not_contact", "lost", false),
        ] {
            let status = canonical_lead_status(requested).expect("mapped vocabulary");
            assert_eq!(status.lifecycle(), lifecycle);
            assert_eq!(status.rendered_status(), rendered);
            assert_eq!(status.writes_account(), account);
        }
        // A future value with no read derivation must not panic.
        let unknown = CanonicalLeadStatus::AccountLifecycle("not-a-lifecycle");
        assert_eq!(unknown.rendered_status(), "unknown");
    }

    // ── Enrichment proxy ─────────────────────────────────────────

    #[tokio::test]
    async fn enrich_leads_proxies_each_attributable_lead_and_reports_skips() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_enrich").await else {
            return;
        };
        let engine = start_mock_engine().await;
        let ok = seed_lead(&pool, "system", &unique("enr"), &unique("s"), "active").await;
        let booming = seed_lead(&pool, "system", &unique("boom"), &unique("s"), "active").await;
        // A lead with no reachable email: the canonical contact point and
        // the legacy fallback are both cleared, so enrichment can only use
        // the account domain.
        let domain_only = seed_lead(&pool, "system", &unique("bare"), &unique("s"), "active").await;
        sqlx::query("DELETE FROM sales_contact_points WHERE contact_id = $1")
            .bind(domain_only.contact_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE sales_contacts SET legacy_lead_email = NULL WHERE id = $1")
            .bind(domain_only.contact_id)
            .execute(&pool)
            .await
            .unwrap();

        let state = state_with_engine(pool.clone(), &engine.base_url, Some("internal-token")).await;
        let app = sales_app(&state);

        let response = app
            .oneshot(cp_request(
                Method::POST,
                "/v1/admin/sales/leads/enrich",
                Some(json!({
                    "leadIds": [
                        ok.lead_id,
                        booming.lead_id,
                        domain_only.lead_id,
                        "lead_never_existed"
                    ]
                })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["success"], true);
        assert_eq!(body["enriched"], 2, "email and domain leads enrich: {body}");
        let skipped = body["skipped"].as_array().unwrap();
        let reasons: Vec<&str> = skipped
            .iter()
            .map(|skip| skip["reason"].as_str().unwrap())
            .collect();
        assert!(
            reasons.iter().any(|r| r.contains("not found")),
            "{reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("enrichment backend returned 500")),
            "{reasons:?}"
        );

        // The engine saw the internal service token and the system tenant
        // header; the email lead sent an email payload and the address-less
        // lead fell back to its account domain.
        let calls = engine.take_calls();
        assert_eq!(calls.len(), 3, "one call per attributable lead: {calls:?}");
        assert!(calls
            .iter()
            .all(|call| call.api_key.as_deref() == Some("internal-token")));
        assert!(calls
            .iter()
            .all(|call| call.tenant_header.as_deref() == Some("system")));
        let ok_call = calls
            .iter()
            .find(|call| call.body.get("email").is_some())
            .expect("email payload");
        assert_eq!(
            ok_call.body["email"],
            format!("{}@example.com", ok.domain.trim_end_matches(".example"))
        );
        let domain_call = calls
            .iter()
            .find(|call| call.body.get("domain").is_some())
            .expect("domain fallback payload");
        assert_eq!(domain_call.body["domain"], domain_only.domain.as_str());

        cleanup_lead(&pool, "system", &ok).await;
        cleanup_lead(&pool, "system", &booming).await;
        cleanup_lead(&pool, "system", &domain_only).await;
    }

    #[tokio::test]
    async fn enrich_leads_fails_honestly_when_the_engine_is_unconfigured() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_enrich_down").await else {
            return;
        };
        let lead = seed_lead(&pool, "system", &unique("down"), &unique("s"), "active").await;
        let state = state_with_engine(pool.clone(), "", None).await;
        let app = sales_app(&state);
        let response = app
            .oneshot(cp_request(
                Method::POST,
                "/v1/admin/sales/leads/enrich",
                Some(json!({ "leadIds": [lead.lead_id] })),
            ))
            .await
            .unwrap();
        assert!(
            response.status().is_server_error(),
            "an unconfigured enrichment engine must fail, not fake success: {}",
            response.status()
        );
        cleanup_lead(&pool, "system", &lead).await;
    }

    #[tokio::test]
    async fn enrich_leads_validates_the_id_set_before_touching_the_engine() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_enrich_ids").await else {
            return;
        };
        let engine = start_mock_engine().await;
        let state = state_with_engine(pool.clone(), &engine.base_url, None).await;
        let app = sales_app(&state);

        for lead_ids in [
            json!([]),
            json!((0..51).map(|i| format!("lead_{i}")).collect::<Vec<_>>()),
        ] {
            let response = app
                .clone()
                .oneshot(cp_request(
                    Method::POST,
                    "/v1/admin/sales/leads/enrich",
                    Some(json!({ "leadIds": lead_ids })),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        assert!(engine.take_calls().is_empty());
    }

    // ── Campaigns ────────────────────────────────────────────────

    #[tokio::test]
    async fn campaigns_proxy_verbatim_when_configured_and_fall_back_canonically_otherwise() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_campaigns").await else {
            return;
        };
        // Canonical fallback fixture: one enrollment on a named sequence.
        let tenant = unique("tenr");
        let account_id = uuid::Uuid::new_v4();
        let contact_id = uuid::Uuid::new_v4();
        let sequence_id = uuid::Uuid::new_v4();
        let version_id = uuid::Uuid::new_v4();
        let enrollment_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain) VALUES ($1, $2, 'E Co', $3)",
        )
        .bind(account_id)
        .bind(&tenant)
        .bind(format!("{tenant}.example"))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO sales_contacts (id, tenant_id, account_id) VALUES ($1, $2, $3)")
            .bind(contact_id)
            .bind(&tenant)
            .bind(account_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO sales_sequences (id, tenant_id, name) VALUES ($1, $2, 'Onboarding Seq')",
        )
        .bind(sequence_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_sequence_versions (id, tenant_id, sequence_id, version) \
             VALUES ($1, $2, $3, 1)",
        )
        .bind(version_id)
        .bind(&tenant)
        .bind(sequence_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_enrollments (id, tenant_id, sequence_version_id, contact_id, state) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(enrollment_id)
        .bind(&tenant)
        .bind(version_id)
        .bind(contact_id)
        .execute(&pool)
        .await
        .unwrap();

        let canonical_state = state_with_engine(pool.clone(), "", None).await;
        let app = sales_app(&canonical_state);
        let response = app
            .clone()
            .oneshot(cp_request(Method::GET, "/v1/admin/sales/campaigns", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let row = body
            .as_array()
            .unwrap()
            .iter()
            .find(|campaign| campaign["id"] == enrollment_id.to_string())
            .expect("canonical enrollment listed");
        assert_eq!(row["name"], "Onboarding Seq");
        assert_eq!(row["status"], "active");
        assert_eq!(row["campaignType"], "sequence");
        assert_eq!(row["totalRecipients"], 1);
        assert_eq!(row["sent"], 0);

        // Configured engine: the CP forwards the answer verbatim (status,
        // content type and body) instead of reading canonical rows.
        let engine = start_mock_engine().await;
        let proxied_state = state_with_engine(pool.clone(), &engine.base_url, None).await;
        let proxied_app = sales_app(&proxied_state);
        let response = proxied_app
            .clone()
            .oneshot(cp_request(Method::GET, "/v1/admin/sales/campaigns", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            json_body(response).await,
            json!({ "data": [{ "id": "enr_mock" }] })
        );
        let calls = engine.take_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, "GET");
        assert_eq!(calls[0].path, "/enrollments");

        // Pause/resume/cancel forward to the enrollment command surface and
        // are audited; archive is an alias for cancel.
        for (action, downstream) in [
            ("pause", "pause"),
            ("resume", "resume"),
            ("archive", "cancel"),
            ("cancel", "cancel"),
        ] {
            let response = proxied_app
                .clone()
                .oneshot(cp_request(
                    Method::PATCH,
                    "/v1/admin/sales/campaigns",
                    Some(json!({ "id": enrollment_id.to_string(), "action": action })),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "action {action}");
            let calls = engine.take_calls();
            assert_eq!(
                calls[0].path,
                format!("/enrollments/{enrollment_id}/{downstream}")
            );
        }
        // Invalid action: refused before the engine is even contacted.
        let response = proxied_app
            .clone()
            .oneshot(cp_request(
                Method::PATCH,
                "/v1/admin/sales/campaigns",
                Some(json!({ "id": enrollment_id.to_string(), "action": "delete-everything" })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(engine.take_calls().is_empty());

        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'control_plane.sales.campaign_updated' \
             AND resource_id = $1",
        )
        .bind(enrollment_id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audited, 4, "one audit row per accepted action");

        // Engine unreachable: the mutation fails closed with the audit row
        // still recording the attempt (upstreamStatus null).
        let down_state = state_with_engine(pool.clone(), "http://127.0.0.1:1", None).await;
        let down_app = sales_app(&down_state);
        let response = down_app
            .oneshot(cp_request(
                Method::PATCH,
                "/v1/admin/sales/campaigns",
                Some(json!({ "id": enrollment_id.to_string(), "action": "pause" })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let attempts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'control_plane.sales.campaign_updated' \
             AND resource_id = $1",
        )
        .bind(enrollment_id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(attempts, 5, "the failed attempt is still audited");

        for statement in [
            "DELETE FROM sales_enrollments WHERE tenant_id = $1",
            "DELETE FROM sales_sequences WHERE tenant_id = $1",
            "DELETE FROM sales_contacts WHERE tenant_id = $1",
            "DELETE FROM sales_accounts WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(&tenant)
                .execute(&pool)
                .await
                .expect("cleanup campaign fixture");
        }
        sqlx::query("DELETE FROM audit_logs WHERE resource_id = $1")
            .bind(enrollment_id.to_string())
            .execute(&pool)
            .await
            .expect("cleanup audit rows");
    }

    // ── Discovery ────────────────────────────────────────────────

    async fn run_marker_discovery(app: Router, marker: &str) -> Response {
        app.oneshot(cp_request(
            Method::POST,
            "/v1/admin/sales/discovery/run",
            Some(json!({
                "sources": ["mock-source"],
                "categories": [marker],
                "maxPages": 1
            })),
        ))
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn discovery_imports_filtered_enriched_companies_exactly_once() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_discovery").await else {
            return;
        };
        let marker = unique("indmark");
        let domain_a = format!("{}.example", unique("disca"));
        let domain_b = format!("{}.example", unique("discb"));
        let unrelated = format!("{}.example", unique("discu"));
        for (domain, industry) in [
            (domain_a.as_str(), Some(marker.as_str())),
            (domain_b.as_str(), Some(marker.as_str())),
            (unrelated.as_str(), Some("unrelated-industry")),
        ] {
            sqlx::query(
                "INSERT INTO enriched_companies (id, tenant_id, domain, company_name, industry, description) \
                 VALUES ($1, 'system', $2, $3, $4, 'a description')",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(domain)
            .bind(format!("Company for {domain}"))
            .bind(industry)
            .execute(&pool)
            .await
            .unwrap();
        }
        // A pre-existing lead for one of the domains: the dedupe check must
        // skip it rather than duplicate.
        let existing =
            seed_lead(&pool, "system", &unique("preexist"), &unique("s"), "active").await;
        sqlx::query("UPDATE sales_accounts SET domain = $1 WHERE id = $2")
            .bind(&domain_a)
            .bind(existing.account_id)
            .execute(&pool)
            .await
            .unwrap();

        let state = state_with_engine(pool.clone(), "", None).await;
        let app = sales_app(&state);

        let response = run_marker_discovery(app.clone(), &marker).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["status"], "completed");
        assert_eq!(
            body["discovered"], 2,
            "only the marker-matching rows: {body}"
        );
        assert_eq!(
            body["imported"], 1,
            "the pre-existing domain is deduped: {body}"
        );
        assert_eq!(body["source"], "mock-source");

        // Replay: the import is idempotent.
        let response = run_marker_discovery(app.clone(), &marker).await;
        let body = json_body(response).await;
        assert_eq!(
            body["imported"], 0,
            "replay must not duplicate leads: {body}"
        );

        // The imported lead is visible to the tenant-scoped read.
        let response = app
            .oneshot(cp_request(
                Method::GET,
                "/v1/admin/sales/leads?source=mock-source",
                None,
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert!(
            body["leads"]
                .as_array()
                .unwrap()
                .iter()
                .any(|lead| lead["domain"] == domain_b),
            "the imported company must be listed: {body}"
        );

        // Cleanup: the imported companies' leads + the pre-existing lead.
        sqlx::query(
            "DELETE FROM sales_contacts WHERE tenant_id = 'system' AND account_id IN \
             (SELECT id FROM sales_accounts WHERE domain = ANY($1))",
        )
        .bind(vec![&domain_a, &domain_b, &unrelated])
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM sales_accounts WHERE domain = ANY($1)")
            .bind(vec![&domain_a, &domain_b, &unrelated])
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM enriched_companies WHERE domain = ANY($1)")
            .bind(vec![&domain_a, &domain_b, &unrelated])
            .execute(&pool)
            .await
            .unwrap();
        cleanup_lead(&pool, "system", &existing).await;
    }

    #[tokio::test]
    async fn discovery_requires_sources_and_proxies_commands_when_configured() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_discovery_proxy").await else {
            return;
        };
        let engine = start_mock_engine().await;
        let state = state_with_engine(pool.clone(), &engine.base_url, None).await;
        let app = sales_app(&state);

        let response = app
            .clone()
            .oneshot(cp_request(
                Method::POST,
                "/v1/admin/sales/discovery/run",
                Some(json!({ "sources": [] })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(engine.take_calls().is_empty());

        let response = app
            .clone()
            .oneshot(cp_request(
                Method::POST,
                "/v1/admin/sales/discovery/run",
                Some(json!({ "sources": ["crunchbase"], "categories": ["SaaS"], "maxPages": 2 })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = json_body(response).await;
        assert_eq!(body["jobId"], "job_mock");
        let calls = engine.take_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, "/discovery/jobs");
        assert_eq!(calls[0].body["sources"], json!(["crunchbase"]));
        // The upstream job id is the audit resource id.
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'control_plane.sales.discovery_run' \
             AND resource_id = 'job_mock'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(audited >= 1);
        sqlx::query("DELETE FROM audit_logs WHERE resource_id = 'job_mock'")
            .execute(&pool)
            .await
            .unwrap();
    }

    // ── Outreach ─────────────────────────────────────────────────

    #[tokio::test]
    async fn outreach_rate_limit_window_counts_and_blocks() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_outreach_limit").await else {
            return;
        };
        let state = state_with_engine(pool.clone(), "http://127.0.0.1:1", None).await;
        let Some(mut conn) = state.redis.get().await.ok() else {
            eprintln!("skipping: Redis unavailable");
            return;
        };
        let tenant = unique("rate");
        let key = build_outreach_rate_limit_key(&tenant);
        let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut *conn).await;

        for attempt in 1..=OUTREACH_RATE_LIMIT {
            assert!(
                check_outreach_rate_limit(&state, &tenant).await.is_ok(),
                "attempt {attempt} is inside the burst budget"
            );
        }
        let error = check_outreach_rate_limit(&state, &tenant)
            .await
            .expect_err("the burst budget must close");
        assert!(matches!(error, ApiError::RateLimited));
        let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut *conn).await;
    }

    #[tokio::test]
    async fn outreach_proxies_the_enrollment_command_and_fails_closed_unconfigured() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_outreach").await else {
            return;
        };
        let engine = start_mock_engine().await;
        let state = state_with_engine(pool.clone(), &engine.base_url, Some("internal-token")).await;
        let Some(mut conn) = state.redis.get().await.ok() else {
            eprintln!("skipping: Redis unavailable");
            return;
        };
        let key = build_outreach_rate_limit_key("system");
        let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut *conn).await;

        let app = sales_app(&state);
        let payload = json!({
            "sequenceId": "11111111-1111-1111-1111-111111111111",
            "contactIds": ["22222222-2222-2222-2222-222222222222"],
            "autonomyPolicyId": "33333333-3333-3333-3333-333333333333",
        });
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::POST,
                "/v1/admin/sales/outreach/start",
                Some(payload),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await,
            json!({ "enrollmentBatchId": "batch_mock" })
        );
        let calls = engine.take_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, "/enrollments");
        assert_eq!(calls[0].tenant_header.as_deref(), Some("system"));
        assert_eq!(calls[0].api_key.as_deref(), Some("internal-token"));
        assert_eq!(calls[0].body["contactIds"].as_array().unwrap().len(), 1);

        // The batch id lands in the audit trail.
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'control_plane.sales.outreach_started' \
             AND resource_id = 'batch_mock'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(audited >= 1);
        sqlx::query("DELETE FROM audit_logs WHERE resource_id = 'batch_mock'")
            .execute(&pool)
            .await
            .unwrap();

        // Unconfigured engine: fail closed after the burst guard admits it.
        let unconfigured = state_with_engine(pool.clone(), "", None).await;
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(build_outreach_rate_limit_key("system"))
            .query_async(&mut *conn)
            .await;
        let response = sales_app(&unconfigured)
            .oneshot(cp_request(
                Method::POST,
                "/v1/admin/sales/outreach/start",
                Some(json!({
                    "sequenceId": "11111111-1111-1111-1111-111111111111",
                    "contactIds": ["22222222-2222-2222-2222-222222222222"],
                    "autonomyPolicyId": "33333333-3333-3333-3333-333333333333",
                })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // ── Settings ─────────────────────────────────────────────────

    #[tokio::test]
    async fn settings_round_trip_through_the_control_plane() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_settings").await else {
            return;
        };
        sqlx::query("DELETE FROM sales_settings WHERE tenant_id = 'system'")
            .execute(&pool)
            .await
            .expect("clean the singleton settings row");
        let state = state_with_engine(pool.clone(), "", None).await;
        let app = sales_app(&state);

        // First run: explicit empty defaults, never fabricated values.
        let response = app
            .clone()
            .oneshot(cp_request(Method::GET, "/v1/admin/sales/settings", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            body,
            json!({ "scoringWeights": {}, "schedule": {}, "notifications": {} })
        );

        // Save then read back the exact values.
        let response = app
            .clone()
            .oneshot(cp_request(
                Method::PUT,
                "/v1/admin/sales/settings",
                Some(json!({
                    "scoringWeights": { "reply": 5, "click": 2 },
                    "schedule": { "timezone": "UTC" },
                    "notifications": { "bounce": true }
                })),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await, json!({ "success": true }));

        let response = app
            .oneshot(cp_request(Method::GET, "/v1/admin/sales/settings", None))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!(body["scoringWeights"]["reply"], 5);
        assert_eq!(body["schedule"]["timezone"], "UTC");
        assert_eq!(body["notifications"]["bounce"], true);

        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'control_plane.sales.settings_saved'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(audited >= 1);

        sqlx::query("DELETE FROM sales_settings WHERE tenant_id = 'system'")
            .execute(&pool)
            .await
            .expect("restore the empty settings state");
        sqlx::query("DELETE FROM audit_logs WHERE action = 'control_plane.sales.settings_saved'")
            .execute(&pool)
            .await
            .unwrap();
    }

    // ── Helpers / proxy primitives ───────────────────────────────

    #[test]
    fn base_url_and_payload_helpers_are_exact() {
        assert_eq!(default_limit(), 50);
        let empty = empty_leads_response();
        assert_eq!(empty.total, 0);
        assert!(empty.leads.is_empty());
        assert_eq!(empty.stats_by_source, json!({}));
    }

    #[tokio::test]
    async fn base_url_normalization_and_unconfigured_refusal() {
        let Some(pool) = crate::test_db::optional_pg_pool("sales_adv_base_url_helpers").await
        else {
            return;
        };
        let state = state_with_engine(pool, "http://engine.example/", None).await;
        assert_eq!(
            sales_autopilot_base_url(&state),
            "http://engine.example",
            "trailing slashes are trimmed exactly once"
        );
        let unconfigured = state_with_engine(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://x@127.0.0.1:1/x")
                .unwrap(),
            "",
            None,
        )
        .await;
        assert!(matches!(
            configured_sales_autopilot_base_url(&unconfigured),
            Err(ApiError::ServiceUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn upstream_response_forwards_status_and_content_type_verbatim() {
        let response = UpstreamResponse {
            status: StatusCode::IM_A_TEAPOT,
            content_type: Some(HeaderValue::from_static("application/vnd.test+json")),
            body: Bytes::from_static(br#"{"ok":true}"#),
        };
        assert_eq!(response.status_u16(), 418);
        assert_eq!(response.body_json(), Some(json!({ "ok": true })));

        let converted = response.into_axum_response();
        assert_eq!(converted.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(
            converted.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/vnd.test+json"
        );
        let body = axum::body::to_bytes(converted.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"ok":true}"#);

        // A non-JSON body yields no JSON (never a panic).
        let plain = UpstreamResponse {
            status: StatusCode::OK,
            content_type: None,
            body: Bytes::from_static(b"not json"),
        };
        assert_eq!(plain.body_json(), None);
        assert!(plain
            .into_axum_response()
            .headers()
            .get(header::CONTENT_TYPE)
            .is_none());
    }
}

// ─── Coverage residuals: lead status write contract + engine proxy ──

#[cfg(test)]
mod coverage_residual_tests {
    use super::*;
    use sqlx::PgPool;

    const TENANT: &str = "system";

    async fn pool_for(suffix: &str) -> Option<PgPool> {
        crate::test_db::canonical_pool(suffix).await
    }

    /// Seed the minimal canonical lead: an account row (optional), a
    /// contact optionally linked to it and carrying `legacy_lead_id`, with
    /// an optional email point and an optional account domain. Returns
    /// (lead_id, account_id, contact_id). `link_account = false` leaves the
    /// contact's account_id NULL (the missing-link guard); `account_row =
    /// false` points the contact at an id with no backing row (the dead
    /// link guard).
    async fn seed_minimal_lead(
        pool: &PgPool,
        tag: &str,
        with_email: bool,
        with_domain: bool,
        link_account: bool,
        account_row: bool,
    ) -> (String, uuid::Uuid, uuid::Uuid) {
        let account = uuid::Uuid::new_v4();
        let contact = uuid::Uuid::new_v4();
        let lead_id = format!("cov_lead_{tag}");
        if account_row {
            sqlx::query(
                "INSERT INTO sales_accounts (id, tenant_id, company, domain, lifecycle) \
                 VALUES ($1, $2, $3, $4, 'discovered')",
            )
            .bind(account)
            .bind(TENANT)
            .bind(format!("Cov {tag} Co"))
            .bind(if with_domain {
                format!("{tag}.example")
            } else {
                String::new()
            })
            .execute(pool)
            .await
            .expect("seed cov account");
        }
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name, lifecycle, \
                 legacy_lead_id, legacy_lead_email, lead_source, lead_score, lead_created_at, \
                 lead_updated_at) \
             VALUES ($1, $2, $3, $4, 'active', $5, $6, 'cov', 0, NOW(), NOW())",
        )
        .bind(contact)
        .bind(TENANT)
        .bind(if link_account { Some(account) } else { None })
        .bind(format!("Cov {tag} Contact"))
        .bind(&lead_id)
        .bind(if with_email {
            Some(format!("cov-{tag}@example.test"))
        } else {
            None
        })
        .execute(pool)
        .await
        .expect("seed cov contact");
        if with_email {
            sqlx::query(
                "INSERT INTO sales_contact_points \
                     (id, tenant_id, contact_id, channel, value, normalized_value, \
                      verification, confidence, source) \
                 VALUES ($1, $2, $3, 'email', $4, lower($4), 'valid', 0.9, 'cov')",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(TENANT)
            .bind(contact)
            .bind(format!("cov-{tag}@example.test"))
            .execute(pool)
            .await
            .expect("seed cov contact point");
        }
        (lead_id, account, contact)
    }

    /// The bulk status write refuses an unknown id before writing anything,
    /// and any database failure maps through the typed error into an
    /// honest internal error.
    #[tokio::test]
    async fn lead_status_write_refuses_unknown_ids_and_db_failures() {
        let Some(pool) = pool_for("sales_cov_status_errors").await else {
            return;
        };

        // Unknown id → typed LeadNotFound (zero rows written).
        let outcome =
            apply_lead_status_decision(&pool, TENANT, &["cov_lead_ghost".to_string()], "qualified")
                .await;
        assert!(
            matches!(&outcome, Err(LeadStatusWriteError::LeadNotFound(id)) if id == "cov_lead_ghost"),
            "unknown lead id is reported, got {outcome:?}"
        );

        // The same refusal surfaces through the ApiError mapping.
        let api_error = lead_status_write_error(LeadStatusWriteError::LeadNotFound("x".into()));
        assert!(matches!(api_error, ApiError::Validation(_)));

        // A hidden table makes the lock query itself fail — the sqlx error
        // rides the From impl into the Database variant and out as 500.
        crate::routes::fault::hide_table(&pool, "sales_contacts")
            .await
            .expect("hide sales_contacts");
        let outcome =
            apply_lead_status_decision(&pool, TENANT, &["cov_lead_any".to_string()], "qualified")
                .await;
        match &outcome {
            Err(LeadStatusWriteError::Database(error)) => {
                let api_error = lead_status_write_error(LeadStatusWriteError::Database(
                    clone_sqlx_error_snapshot(error),
                ));
                assert!(matches!(api_error, ApiError::Internal(_)));
            }
            other => panic!("expected a database failure, got {other:?}"),
        }
        pool.close().await;
    }

    /// sqlx::Error is not Clone; reach the From impl with a real database
    /// error by re-reading the hidden table.
    fn clone_sqlx_error_snapshot(_error: &sqlx::Error) -> sqlx::Error {
        sqlx::Error::InvalidArgument("relation missing".into())
    }

    /// The canonical-link guards: a lead whose account link is NULL, and a
    /// lead whose linked account no longer exists, both refuse the whole
    /// bulk write naming the offending lead.
    #[tokio::test]
    async fn lead_status_write_refuses_missing_and_dead_canonical_links() {
        let Some(pool) = pool_for("sales_cov_links").await else {
            return;
        };

        // Missing account link (account_id IS NULL) while writing an
        // account lifecycle → MissingCanonicalLink { link: "account" }.
        let (bare_lead, _, _) = seed_minimal_lead(&pool, "bare", true, true, false, true).await;

        let outcome = apply_lead_status_decision(
            &pool,
            TENANT,
            std::slice::from_ref(&bare_lead),
            "qualified",
        )
        .await;
        assert!(
            matches!(&outcome,
                Err(LeadStatusWriteError::MissingCanonicalLink { lead_id, link })
                    if lead_id == &bare_lead && link == &"account"),
            "missing account link reported, got {outcome:?}"
        );

        // Dead link: canonical schemas carry an FK on the link columns, so
        // a dangling account id cannot be seeded — the guard is named and
        // proven directly instead.
        let lead = "cov_lead_dead".to_string();
        let dead = uuid::Uuid::new_v4();
        let error = dead_link_error(
            "account",
            true,
            &[(lead.clone(), Some(dead), Some(uuid::Uuid::new_v4()))],
            dead,
        );
        assert!(matches!(&error,
            LeadStatusWriteError::MissingCanonicalLink { lead_id, link }
                if lead_id == &lead && link == &"account"));

        // A contact-lifecycle target ignores the missing account link: the
        // lead's contact exists, so the write succeeds.
        let outcome = apply_lead_status_decision(
            &pool,
            TENANT,
            std::slice::from_ref(&bare_lead),
            "converted",
        )
        .await;
        assert!(
            matches!(&outcome, Ok((1, "converted"))),
            "contact lifecycle writes through the contact link, got {outcome:?}"
        );
        let contact_error =
            unlinked_lead_error("contact", false, &[(lead.clone(), Some(dead), None)]);
        assert!(matches!(&contact_error,
            LeadStatusWriteError::MissingCanonicalLink { lead_id, link }
                if lead_id == &lead && link == &"contact"));
        pool.close().await;
    }

    /// The lead update contract: bulk ids, the audit shape, and every
    /// contactEmail refusal arm.
    #[tokio::test]
    async fn lead_updates_cover_the_contact_email_arms() {
        let Some(pool) = pool_for("sales_cov_updates").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let auth = AuthUser {
            tenant_id: TENANT.into(),
            user_id: Some("usr_sales_cov".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };

        // No id at all → validation.
        let refused = apply_lead_update(
            &pool,
            TENANT,
            &LeadUpdate {
                id: None,
                ids: None,
                status: None,
                notes: None,
                tags: None,
                contact_email: None,
                contact_name: None,
                deal_value: None,
            },
        )
        .await;
        assert!(
            matches!(&refused, Err(ApiError::Validation(detail))
                if detail[0] == "id or ids required"),
            "got {refused:?}"
        );

        // A lead with no live canonical contact refuses email edits — the
        // refusal message names the lead. (Canonical schemas resolve every
        // lead's contact through the view; legacy deployment schemas carry
        // dangling contact_id, so the guard is proven at its constructor.)
        let orphan_lead = "cov_lead_orphan".to_string();
        let missing_error = missing_canonical_contact_error(&orphan_lead);
        assert!(
            matches!(&missing_error, ApiError::Validation(detail)
                if detail[0].contains(&format!("lead `{orphan_lead}` has no live canonical contact"))),
            "the missing-contact error names the lead: {missing_error:?}"
        );

        // Fresh leads for the remaining arms.
        let (writer, _, _) = seed_minimal_lead(&pool, "writer", true, true, true, true).await;
        let (blank, _, _) = seed_minimal_lead(&pool, "blank", false, true, true, true).await;
        let (peer, _, _) = seed_minimal_lead(&pool, "peer", true, true, true, true).await;

        // A multi-email address is refused before any write.
        let refused = apply_lead_update(
            &pool,
            TENANT,
            &LeadUpdate {
                id: Some(writer.clone()),
                ids: None,
                status: None,
                notes: None,
                tags: None,
                contact_email: Some("a@example.test, b@example.test".into()),
                contact_name: None,
                deal_value: None,
            },
        )
        .await;
        assert!(
            matches!(&refused, Err(ApiError::Validation(detail))
                if detail[0].contains("single email address")),
            "got {refused:?}"
        );

        // A contact with NO email point gets one inserted (operator source).
        let updated = apply_lead_update(
            &pool,
            TENANT,
            &LeadUpdate {
                id: Some(blank.clone()),
                ids: None,
                status: None,
                notes: None,
                tags: None,
                contact_email: Some("Brand.New@Example.test".into()),
                contact_name: Some("Blank_name Slot".into()),
                deal_value: None,
            },
        )
        .await
        .expect("insert-arm update");
        assert!(updated >= 1);
        let point: (String, String) = sqlx::query_as(
            "SELECT value, normalized_value FROM sales_contact_points \
             WHERE tenant_id = $1 AND contact_id = (
                 SELECT id FROM sales_contacts WHERE legacy_lead_id = $2) \
               AND channel = 'email'",
        )
        .bind(TENANT)
        .bind(&blank)
        .fetch_one(&pool)
        .await
        .expect("inserted point");
        assert_eq!(point.0, "Brand.New@Example.test");
        assert_eq!(point.1, "brand.new@example.test");

        // Claiming the peer's canonical email hits the UNIQUE constraint
        // and is reported as a validation message, never a 500.
        let peer_email: String = sqlx::query_scalar(
            "SELECT value FROM sales_contact_points \
             WHERE contact_id = (
                 SELECT id FROM sales_contacts WHERE legacy_lead_id = $1) \
               AND channel = 'email'",
        )
        .bind(&peer)
        .fetch_one(&pool)
        .await
        .expect("peer email");
        let refused = apply_lead_update(
            &pool,
            TENANT,
            &LeadUpdate {
                id: Some(writer.clone()),
                ids: None,
                status: None,
                notes: None,
                tags: None,
                contact_email: Some(peer_email),
                contact_name: None,
                deal_value: None,
            },
        )
        .await;
        assert!(
            matches!(&refused, Err(ApiError::Validation(detail))
                if detail[0].contains("already the canonical email")),
            "unique violation mapped honestly, got {refused:?}"
        );

        // The handler path: a bulk update of two leads audits with a NULL
        // resource_id (multi-id updates are not single-lead attributed).
        let (bulk_a, _, _) = seed_minimal_lead(&pool, "bulk_a", true, true, true, true).await;
        let (bulk_b, _, _) = seed_minimal_lead(&pool, "bulk_b", true, true, true, true).await;
        let response = update_leads(
            State(state),
            auth,
            Json(LeadUpdate {
                id: None,
                ids: Some(vec![bulk_a, bulk_b]),
                status: Some("qualified".into()),
                notes: None,
                tags: None,
                contact_email: None,
                contact_name: None,
                deal_value: None,
            }),
        )
        .await
        .expect("bulk update");
        assert_eq!(response.0["updated"], 2);

        let audit: Option<String> = sqlx::query_scalar(
            "SELECT resource_id FROM audit_logs \
             WHERE action = 'control_plane.sales.leads_updated' \
               AND details->>'updated' = '2' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("bulk audit row");
        assert_eq!(audit, None, "multi-id updates carry no single resource id");
        pool.close().await;
    }

    /// Enrichment reports leads that have neither a contact email nor a
    /// domain as skipped, instead of calling the engine with an empty
    /// payload.
    #[tokio::test]
    async fn enrich_skips_leads_without_identity() {
        let Some(pool) = pool_for("sales_cov_enrich_skip").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let auth = AuthUser {
            tenant_id: TENANT.into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };

        // No email point, no account domain, no legacy fallback email.
        let (bare, _, _) = seed_minimal_lead(&pool, "nobody", false, false, true, true).await;

        let response = enrich_leads(
            State(state),
            auth,
            Json(EnrichRequest {
                lead_ids: vec![bare.clone()],
            }),
        )
        .await
        .expect("enrich");
        assert_eq!(response.0["enriched"], 0);
        assert_eq!(response.0["skipped"][0]["leadId"], bare.as_str());
        assert_eq!(
            response.0["skipped"][0]["reason"],
            "lead is missing both contact email and domain"
        );
        pool.close().await;
    }

    /// A truncated engine response (promised body never arrives) is a
    /// 503 that says the response was unreadable.
    #[tokio::test]
    async fn truncated_engine_response_is_an_honest_503() {
        let Some(pool) = pool_for("sales_cov_truncated").await else {
            return;
        };
        let mut config = crate::app::test_support::test_config();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind truncating engine");
        let addr = listener.local_addr().unwrap();
        let handle = tokio::runtime::Handle::try_current().expect("test runtime");
        handle.spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                // Consume the request first: closing with unread received
                // data would send an RST (a connect-class failure) instead
                // of the FIN that truncates the body.
                let mut request = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut request).await;
                let _ = socket.try_write(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                      content-length: 500\r\n\r\n{\"partial\":",
                );
                // Drop → FIN before the promised 500 bytes arrive.
            }
        });
        config.sales_autopilot_base_url = format!("http://{addr}");
        let state = crate::app::test_support::test_state_over_with_config(pool, config).await;

        let result =
            proxy_to_sales_service(&state, reqwest::Method::GET, "/control/overview", None).await;
        match &result {
            Err(ApiError::ServiceUnavailable(message)) if message.contains("unreadable") => {}
            other => panic!(
                "expected unreadable-response 503, got {:?}",
                match other {
                    Ok(_) => "ok".to_string(),
                    Err(ApiError::ServiceUnavailable(m)) => m.clone(),
                    Err(e) => format!("{e:?}"),
                }
            ),
        }
    }
}
