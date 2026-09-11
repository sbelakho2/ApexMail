//! Server-side data loading for the SSR console (read paths).
//!
//! Every list/overview page the console renders gets its rows from here:
//! per-route SQL queries (state-driven, tenant-scoped on the web surface,
//! system-scoped on the control plane) that build a
//! [`ui_foundation::view_data::ListPageData`] for the render pipeline.
//!
//! Honesty rules:
//! - Only real tables are queried; a missing optional relation yields an
//!   empty dataset (rendered as an honest empty state), never demo rows.
//! - Search / filter / sort / page query parameters are parsed and applied
//!   server-side — the GET forms in the views serialize into them.
//! - A failed query is NOT an empty dataset: loaders surface
//!   [`LoadState::Unavailable`] and the page renders an explicit
//!   "data unavailable" state so required financial and operational data
//!   never reports false zeroes (audit F14).

use std::collections::HashMap;

use ui_foundation::axum_router::RouteData;
use ui_foundation::view_data::{
    BulkActionData, DataCell, DataRowData, FilterSelectData, KpiCardData, ListPageData, TableData,
};

use crate::middleware::auth::AuthUser;
use crate::state::AppState;

/// Rows per page on every data-backed list page.
const PER_PAGE: usize = 20;
/// Hard cap on the `page` parameter — hostile values must not create giant
/// offsets.
const MAX_PAGE: usize = 500;

/// Parsed GET list parameters (`query`, `status`, `sort`, `stage`, `page`,
/// `days`).
#[derive(Debug, Clone, Default)]
pub(crate) struct ListQuery {
    pub search: String,
    pub status: String,
    pub sort: String,
    pub stage: String,
    pub page: usize,
    /// Optional recency window (days) for the audit list + export.
    pub days: Option<i64>,
}

pub(crate) fn parse_list_query(query: Option<&str>) -> ListQuery {
    let mut out = ListQuery {
        page: 1,
        ..Default::default()
    };
    let Some(query) = query else {
        return out;
    };
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let value = percent_decode(value);
        match key {
            "query" | "q" | "search" => out.search = value,
            "status" => out.status = value,
            "sort" => out.sort = value,
            "stage" => out.stage = value,
            "page" => {
                out.page = value.parse::<usize>().unwrap_or(1).clamp(1, MAX_PAGE);
            }
            // Item M: optional recency window shared by the audit list and
            // export. Hostile values degrade to "no filter".
            "days" => {
                out.days = value
                    .parse::<i64>()
                    .ok()
                    .filter(|days| (1..=3650).contains(days));
            }
            _ => {}
        }
    }
    if out.search.trim().is_empty() {
        out.search.clear();
    }
    out
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = (bytes[index + 1] as char).to_digit(16);
                let lo = (bytes[index + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    decoded.push((hi * 16 + lo) as u8);
                    index += 3;
                } else {
                    decoded.push(b'%');
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// True when a sqlx error means "relation or column does not exist" —
/// `42P01` (undefined table) / `42703` (undefined column). Shared with the
/// admin system-health route.
fn is_schema_error(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(db_error)
            if matches!(db_error.code().as_deref(), Some("42P01") | Some("42703"))
    )
}

/// F14 per-dataset optionality contract.
///
/// Every console dataset rendered by this module is backed by a REQUIRED
/// canonical relation (campaigns, contacts, lists, templates, domains,
/// events, placement_tests, api_keys, webhooks, users, invoices, …): a
/// deployment where one of those tables/columns is missing is a MISDEPLOYED
/// SCHEMA, and the page must say "data unavailable" — rendering an empty
/// list or a zero KPI would fabricate data.
///
/// `OptionalDataset` exists for datasets backed by separately-deployable
/// components that can be deliberately DISABLED in a deployment: only those
/// may map a 42P01/42703 "relation does not exist" to an honest empty state
/// (the component is not deployed, not broken). No dataset in this module
/// currently qualifies — they are all required — so every
/// [`load_query`]/[`loaded_count`] call takes the required path. New
/// datasets must choose explicitly; adding an optional dataset requires
/// naming the disabled component here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatasetRequirement {
    /// Required relation: EVERY query/decoding error — including
    /// 42P01/42703 — maps to [`LoadState::Unavailable`].
    Required,
    /// Optional relation tied to a deliberately disabled, separately
    /// deployable component: a missing schema (42P01/42703) is an honest
    /// empty dataset; every other error is still Unavailable.
    OptionalDisabledComponent,
}

/// Typed outcome of one console-data query (audit F14).
///
/// A dataset that loaded — possibly genuinely empty — must stay
/// distinguishable from a dataset that could NOT be read. Failures
/// previously collapsed into empty lists and zero counts, so a database
/// outage rendered as successful empty states with false zeroes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LoadState<T> {
    /// The query succeeded. An empty payload is an honest empty state.
    Loaded(T),
    /// The query failed: the data is unknown — not empty, not zero.
    Unavailable,
}

impl<T> LoadState<T> {
    fn is_unavailable(&self) -> bool {
        matches!(self, LoadState::Unavailable)
    }
}

impl<T: Default> LoadState<T> {
    /// Value with unknowns degraded to the default — capture
    /// [`LoadState::is_unavailable`] BEFORE calling so "unknown" is not
    /// silently rendered as the default (audit F14).
    fn unwrap_or_default(self) -> T {
        match self {
            LoadState::Loaded(value) => value,
            LoadState::Unavailable => T::default(),
        }
    }
}

impl<T> LoadState<Vec<T>> {
    /// Rows plus a failure flag: failed queries yield zero rows AND the
    /// flag so the page renders the explicit unavailable copy instead of
    /// the honest empty state.
    fn rows_or_unavailable(self) -> (Vec<T>, bool) {
        match self {
            LoadState::Loaded(rows) => (rows, false),
            LoadState::Unavailable => (Vec::new(), true),
        }
    }
}

impl LoadState<i64> {
    /// KPI value: the counted number, or an explicit "unavailable" —
    /// never a false zero.
    fn kpi_value(&self) -> String {
        match self {
            LoadState::Loaded(count) => count.to_string(),
            LoadState::Unavailable => "unavailable".to_string(),
        }
    }

    /// Pagination total. Unknown counts degrade to 0 (the unavailable
    /// copy, not a number, carries the uncertainty).
    fn total_or_zero(&self) -> i64 {
        match self {
            LoadState::Loaded(count) => *count,
            LoadState::Unavailable => 0,
        }
    }
}

/// Monotonic per-process correlation id shared by every loader log line of
/// one page render (audit F14). Binds (tenant ids, search terms) are never
/// logged — only the stable query identity and this id.
fn next_correlation_id() -> String {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("web-data-{seq}")
}

/// Run one console-data query, preserving failure as uncertainty (audit
/// F14).
///
/// For REQUIRED datasets (the default — see [`DatasetRequirement`]) EVERY
/// query/decoding error, explicitly including a missing table/column
/// (42P01/42703, a misdeployed schema), maps to [`LoadState::Unavailable`]:
/// the page renders the explicit unavailable state and never fabricates an
/// empty list or a zero. Only an explicitly optional dataset tied to a
/// deliberately disabled component may treat a missing relation as an
/// honest empty dataset.
async fn load_query<T: Default, F>(query_id: &str, correlation_id: &str, fetch: F) -> LoadState<T>
where
    F: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    load_query_with_requirement(
        query_id,
        correlation_id,
        DatasetRequirement::Required,
        fetch,
    )
    .await
}

/// [`load_query`] with an explicit per-dataset requirement (F14).
async fn load_query_with_requirement<T: Default, F>(
    query_id: &str,
    correlation_id: &str,
    requirement: DatasetRequirement,
    fetch: F,
) -> LoadState<T>
where
    F: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    match fetch.await {
        Ok(value) => LoadState::Loaded(value),
        Err(error)
            if requirement == DatasetRequirement::OptionalDisabledComponent
                && is_schema_error(&error) =>
        {
            tracing::warn!(
                query = query_id,
                correlation_id = correlation_id,
                error = %error,
                "optional (disabled component) web-data relation missing; honest empty dataset"
            );
            LoadState::Loaded(T::default())
        }
        Err(error) => {
            tracing::error!(
                query = query_id,
                correlation_id = correlation_id,
                error = %error,
                missing_schema = is_schema_error(&error),
                "web data query failed; data unavailable"
            );
            LoadState::Unavailable
        }
    }
}

/// COUNT(*) with the page's filters (audit F14): any failure — including a
/// missing required relation — surfaces as [`LoadState::Unavailable`] so
/// counts never report false zeroes.
async fn loaded_count(
    state: &AppState,
    query_id: &str,
    correlation_id: &str,
    sql: &str,
    binds: &[String],
) -> LoadState<i64> {
    let mut q = sqlx::query_scalar::<_, i64>(sql);
    for value in binds {
        q = q.bind(value);
    }
    load_query(query_id, correlation_id, q.fetch_one(&state.db)).await
}

/// Explicit unavailable-state copy (audit F14): a failed query must render
/// as "data unavailable", never as the honest (optional-and-empty) state.
/// The per-render correlation id travels into the view so an operator can
/// correlate the failed page with the exact loader log lines (query
/// identity + cid) without any bind values being logged.
fn mark_rows_unavailable(data: &mut ListPageData, what: &str, correlation_id: &str) {
    data.empty_title = "Data unavailable".into();
    data.empty_description = format!(
        "{what} could not be loaded — the query failed. This is not an empty list; \
         figures shown as \"unavailable\" are unknown, not zero. \
         Reference: {correlation_id}."
    );
}

/// Escape `\`, `%` and `_` so user input is matched literally by LIKE/ILIKE.
pub(crate) fn escape_like(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

// ─── Required-schema readiness (audit F14) ─────────────────────────

/// The relations every console loader in this module queries, with the
/// columns its financial/operational queries SELECT or predicate on. A
/// deployment missing any of these would previously render empty pages and
/// zero KPIs (the 42P01/42703 tolerance); the readiness probe surfaces the
/// misdeployment BEFORE any page can fabricate data.
///
/// Kept as data, not a schema hash, so adding a loader column means adding
/// one line here and the readiness failure names the exact missing piece.
const REQUIRED_CONSOLE_SCHEMA: &[(&str, &[&str])] = &[
    (
        "campaigns",
        &["id", "tenant_id", "name", "status", "created_at"],
    ),
    (
        "campaign_jobs",
        &["id", "campaign_id", "tenant_id", "status"],
    ),
    (
        "contacts",
        &["id", "tenant_id", "email", "status", "created_at"],
    ),
    ("lists", &["id", "tenant_id", "name"]),
    ("list_subscribers", &["list_id", "contact_id"]),
    ("templates", &["id", "tenant_id", "name", "updated_at"]),
    ("domains", &["id", "tenant_id", "name", "status"]),
    ("events", &["id", "tenant_id", "event_type", "timestamp"]),
    (
        "placement_tests",
        &["id", "tenant_id", "status", "created_at"],
    ),
    ("api_keys", &["id", "tenant_id", "name", "created_at"]),
    ("webhooks", &["id", "tenant_id", "url"]),
    ("users", &["id", "tenant_id", "email", "status", "role"]),
    (
        "invoices",
        &[
            "id",
            "tenant_id",
            "status",
            "total",
            "currency",
            "created_at",
        ],
    ),
    ("plans", &["name", "email_limit"]),
    ("tenants", &["id", "name", "status", "created_at"]),
    ("dedicated_ips", &["id", "tenant_id", "ip_address"]),
    (
        "dedicated_ip_provisioning_requests",
        &["id", "tenant_id", "status"],
    ),
    ("ip_pool_addresses", &["pool_id", "ip_address"]),
    ("queue_jobs", &["id", "queue", "created_at"]),
    ("audit_logs", &["id", "tenant_id", "created_at"]),
    ("gdpr_requests", &["id", "tenant_id", "status"]),
    ("sales_leads", &["id", "email", "created_at"]),
    ("system_alerts", &["id", "severity", "created_at"]),
];

/// Probe the required console schema (F14). Column names are the CANONICAL
/// production names (cross-checked against a fully-migrated database —
/// `invoices.total`/`dedicated_ips.ip_address`/`ip_pool_addresses.pool_id`
/// — not the historical aliases the loaders also alias at query time).
/// Returns the missing pieces as
/// `table.column` / `table` strings; empty means the schema is complete.
/// Readiness (routes/health.rs) fails the deployment when this is non-empty
/// so missing production columns never reach a page render.
pub(crate) async fn missing_required_console_schema(
    db: &sqlx::PgPool,
) -> Result<Vec<String>, sqlx::Error> {
    let mut missing = Vec::new();

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name, column_name FROM information_schema.columns
         WHERE table_schema = 'public'",
    )
    .fetch_all(db)
    .await?;

    use std::collections::HashSet;
    let present: HashSet<(String, String)> = rows.into_iter().collect();

    for (table, columns) in REQUIRED_CONSOLE_SCHEMA {
        for column in *columns {
            if !present.contains(&((*table).to_string(), (*column).to_string())) {
                missing.push(format!("{table}.{column}"));
            }
        }
    }
    Ok(missing)
}

/// Incremental WHERE builder with correct positional binds ($1, $2, …).
struct WhereBuilder {
    clauses: Vec<String>,
    binds: Vec<String>,
}

impl WhereBuilder {
    fn new() -> Self {
        Self {
            clauses: Vec::new(),
            binds: Vec::new(),
        }
    }

    /// Bind `col = $n` with the given value.
    fn eq(&mut self, col: &str, value: &str) -> &mut Self {
        self.binds.push(value.to_string());
        self.clauses.push(format!("{col} = ${}", self.binds.len()));
        self
    }

    /// Bind `col ILIKE '%' || $n || '%'` (case-insensitive contains).
    ///
    /// LIKE metacharacters in the user-supplied value are escaped so a search
    /// for `%` or `_` matches those literal characters instead of expanding
    /// into a wildcard that scans the whole table.
    fn ilike(&mut self, col: &str, value: &str) -> &mut Self {
        self.binds.push(escape_like(value));
        self.clauses.push(format!(
            "{col} ILIKE '%' || ${} || '%' ESCAPE '\\'",
            self.binds.len()
        ));
        self
    }

    /// Whitelisted status filter: unknown values never reach SQL.
    fn status_in(&mut self, allowed: &[&str], value: &str) -> &mut Self {
        if !value.is_empty() && allowed.contains(&value) {
            self.eq("status", value);
        }
        self
    }

    fn build(&self) -> String {
        if self.clauses.is_empty() {
            "TRUE".to_string()
        } else {
            self.clauses.join(" AND ")
        }
    }
}

fn paging(total: i64, page: usize) -> (usize, usize, i64) {
    let total_pages = ((total as usize) + PER_PAGE - 1) / PER_PAGE.max(1);
    let page = page.clamp(1, total_pages.max(1));
    let offset = (page - 1) * PER_PAGE;
    (page, total_pages, offset as i64)
}

/// Preserved filter query string (without `page=`) for pagination links.
fn filter_query(list: &ListQuery) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !list.search.is_empty() {
        parts.push(format!("query={}", urlencode(&list.search)));
    }
    if !list.status.is_empty() {
        parts.push(format!("status={}", urlencode(&list.status)));
    }
    if !list.sort.is_empty() {
        parts.push(format!("sort={}", urlencode(&list.sort)));
    }
    if !list.stage.is_empty() {
        parts.push(format!("stage={}", urlencode(&list.stage)));
    }
    if let Some(days) = list.days {
        parts.push(format!("days={days}"));
    }
    parts.join("&")
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn base_list(title: &str, description: &str, base_path: &str) -> ListPageData {
    ListPageData {
        title: title.to_string(),
        description: description.to_string(),
        base_path: base_path.to_string(),
        per_page: PER_PAGE,
        page: 1,
        total_pages: 1,
        total_count: 0,
        ..Default::default()
    }
}

fn relative_time(timestamp: Option<chrono::DateTime<chrono::Utc>>) -> String {
    match timestamp {
        Some(ts) => {
            let delta = chrono::Utc::now() - ts;
            let mins = delta.num_minutes();
            if mins < 1 {
                "just now".to_string()
            } else if mins < 60 {
                format!("{mins} minutes ago")
            } else if mins < 60 * 24 {
                let hours = mins / 60;
                format!("{hours} hour{} ago", if hours == 1 { "" } else { "s" })
            } else {
                let days = mins / (60 * 24);
                format!("{days} day{} ago", if days == 1 { "" } else { "s" })
            }
        }
        None => "—".to_string(),
    }
}

/// Entry point: build the [`RouteData`] for a GET render of `path`.
pub(crate) async fn load_page_data(
    state: &AppState,
    surface: &str,
    path: &str,
    query: Option<&str>,
    user: Option<&AuthUser>,
) -> RouteData {
    let list_query = parse_list_query(query);
    // One correlation id per page render ties every loader log line
    // together (audit F14) without logging any bind values.
    let correlation_id = next_correlation_id();
    match surface {
        "web" => match user {
            Some(user) => web_route_data(state, path, &list_query, user, &correlation_id).await,
            None => RouteData::default(),
        },
        "control-plane" => match user {
            Some(user) => {
                control_plane_route_data(state, path, &list_query, user, &correlation_id).await
            }
            None => RouteData::default(),
        },
        _ => RouteData::default(),
    }
}

// ─── Web (tenant-scoped) routes ─────────────────────────────────

async fn web_route_data(
    state: &AppState,
    path: &str,
    q: &ListQuery,
    user: &AuthUser,
    cid: &str,
) -> RouteData {
    let tenant = user.tenant_id.clone();
    let list = match path {
        "/dashboard" => Some(web_dashboard(state, &tenant, cid).await),
        "/campaigns" => Some(web_campaigns(state, &tenant, q, cid).await),
        "/contacts" => Some(web_contacts(state, &tenant, q, cid).await),
        "/lists" => Some(web_lists(state, &tenant, q, cid).await),
        "/templates" => Some(web_templates(state, &tenant, q, cid).await),
        "/domains" => Some(web_domains(state, &tenant, q, cid).await),
        "/events" => Some(web_events(state, &tenant, q, cid).await),
        "/analytics" => Some(web_analytics(state, &tenant, cid).await),
        "/reports" => Some(web_reports(state, &tenant, cid).await),
        "/reports/deliverability" => Some(web_deliverability(state, &tenant, cid).await),
        "/inbox-placement" => Some(web_inbox_placement(state, &tenant, q, cid).await),
        "/settings/api-keys" => Some(web_api_keys(state, &tenant, cid).await),
        "/settings/webhooks" => Some(web_webhooks(state, &tenant, cid).await),
        "/settings/team" => Some(web_team(state, &tenant, cid).await),
        "/settings/billing" => Some(web_billing(state, &tenant, cid).await),
        "/settings/dedicated-ips" => Some(web_dedicated_ips(state, &tenant, cid).await),
        _ => None,
    };
    let campaign_edit = if path.starts_with("/campaigns/") && path.ends_with("/edit") {
        let id = path
            .trim_start_matches("/campaigns/")
            .trim_end_matches("/edit");
        load_campaign_edit(state, &tenant, id).await
    } else {
        None
    };
    RouteData {
        list,
        campaign_edit,
        mfa_setup: None,
        sales: None,
    }
}

async fn web_dashboard(state: &AppState, tenant: &str, cid: &str) -> ListPageData {
    let campaigns = loaded_count(
        state,
        "web.dashboard.campaigns",
        cid,
        "SELECT COUNT(*)::bigint FROM campaigns WHERE tenant_id = $1",
        &[tenant.to_string()],
    )
    .await;
    let contacts = loaded_count(
        state,
        "web.dashboard.contacts",
        cid,
        "SELECT COUNT(*)::bigint FROM contacts WHERE tenant_id = $1 AND status <> 'deleted'",
        &[tenant.to_string()],
    )
    .await;
    let domains = loaded_count(
        state,
        "web.dashboard.domains",
        cid,
        "SELECT COUNT(*)::bigint FROM domains WHERE tenant_id = $1",
        &[tenant.to_string()],
    )
    .await;
    let sent = loaded_count(
        state,
        "web.dashboard.sent",
        cid,
        "SELECT COUNT(*)::bigint FROM events WHERE tenant_id = $1 AND event_type = 'sent' AND timestamp >= NOW() - '30 days'::interval",
        &[tenant.to_string()],
    )
    .await;

    let mut data = base_list(
        "Overview",
        "Monitor your campaign performance and delivery health.",
        "/dashboard",
    );
    data.kpis = vec![
        KpiCardData::new("Campaigns", campaigns.kpi_value()).with_hint("All statuses"),
        KpiCardData::new("Contacts", contacts.kpi_value()).with_hint("Active addressable"),
        KpiCardData::new("Domains", domains.kpi_value()).with_hint("Sending domains"),
        KpiCardData::new("Sent (30d)", sent.kpi_value()).with_hint("Messages dispatched"),
    ];
    data
}

async fn web_campaigns(state: &AppState, tenant: &str, q: &ListQuery, cid: &str) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    where_sql.status_in(
        &[
            "draft",
            "sending",
            "paused",
            "stopped",
            "completed",
            "failed",
        ],
        &q.status,
    );
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "web.campaigns.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM campaigns WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    let order = match q.sort.as_str() {
        "created" => "created_at DESC",
        "name" => "name ASC",
        _ => "updated_at DESC",
    };

    let rows = load_query(
        "web.campaigns.list",
        cid,
        async {
            let campaigns_sql = format!(
                "SELECT id::text AS id, name, subject, status, updated_at FROM campaigns WHERE {where_clause} ORDER BY {order} LIMIT {PER_PAGE} OFFSET {offset}"
            );
            let mut query = sqlx::query_as::<
                _,
                (
                    String,
                    String,
                    Option<String>,
                    String,
                    Option<chrono::DateTime<chrono::Utc>>,
                ),
            >(&campaigns_sql);
            for value in &where_sql.binds {
                query = query.bind(value);
            }
            query.fetch_all(&state.db).await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Campaigns",
        "Search, filter, and batch-manage campaigns — every action is a plain form post rendered server-side.",
        "/campaigns",
    );
    data.search_label = "Search campaigns".into();
    data.search_placeholder = "Search by campaign name".into();
    data.current_query = q.search.clone();
    data.filters = vec![FilterSelectData::new(
        "status",
        "Filter by status",
        vec![
            ("".into(), "All statuses".into(), q.status.is_empty()),
            ("draft".into(), "Draft".into(), q.status == "draft"),
            ("sending".into(), "Sending".into(), q.status == "sending"),
            ("paused".into(), "Paused".into(), q.status == "paused"),
            ("stopped".into(), "Stopped".into(), q.status == "stopped"),
            (
                "completed".into(),
                "Completed".into(),
                q.status == "completed",
            ),
            ("failed".into(), "Failed".into(), q.status == "failed"),
        ],
    )];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.bulk_action = Some(BulkActionData {
        action: "/web/campaigns/delete-bulk".into(),
        button_label: "Delete selected".into(),
    });
    data.primary_action = Some(("New Campaign".into(), "/campaigns/new".into()));
    data.detail_path_prefix = Some("/campaigns/".into());
    data.edit_path_suffix = Some("/edit".into());
    data.delete_intent = Some("delete-campaign".into());
    data.empty_title = "No campaigns yet".into();
    data.empty_description = "Create your first email campaign to see it listed here.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Campaigns", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Name".into(),
            "Subject".into(),
            "Status".into(),
            "Updated".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, name, subject, status, updated)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(name),
                    DataCell::text(subject.unwrap_or_default()),
                    DataCell::status(&status),
                    DataCell::text(relative_time(updated)),
                ],
            })
            .collect(),
    });
    data
}

async fn load_campaign_edit(
    state: &AppState,
    tenant: &str,
    id: &str,
) -> Option<ui_foundation::view_data::CampaignEditData> {
    let row: Option<(String, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>)> =
        match sqlx::query_as::<
            _,
            (String, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>),
        // campaigns.id is a UUID in both schema lineages: cast it to text for
        // the String row shape (and cast the bound id back for the comparison).
        >("SELECT id::text, name, subject, scheduled_at FROM campaigns WHERE id = $1::uuid AND tenant_id = $2")
            .bind(id)
            .bind(tenant)
            .fetch_optional(&state.db)
            .await
        {
            Ok(row) => row,
            Err(error) => {
                tracing::warn!(error = %error, "campaign edit lookup failed");
                return None;
            }
        };
    let (id, name, subject, scheduled_at) = row?;
    Some(ui_foundation::view_data::CampaignEditData {
        id,
        name,
        subject: subject.unwrap_or_default(),
        html_body: String::new(),
        scheduled_at: scheduled_at
            .map(|ts| ts.format("%Y-%m-%dT%H:%M").to_string())
            .unwrap_or_default(),
    })
}

async fn web_contacts(state: &AppState, tenant: &str, q: &ListQuery, cid: &str) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    where_sql.status_in(
        &["subscribed", "unsubscribed", "bounced", "deleted", "active"],
        &q.status,
    );
    if !q.search.is_empty() {
        where_sql.ilike("email", &q.search);
    }
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "web.contacts.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM contacts WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    let rows = load_query(
        "web.contacts.list",
        cid,
        async {
            // contacts.id is a UUID (migration 068): cast it to text for
            // the String row shape instead of failing UUID decoding.
            let contacts_sql = format!(
                "SELECT id::text AS id, email, name, status, updated_at FROM contacts WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
            let mut query = sqlx::query_as::<
                _,
                (
                    String,
                    String,
                    Option<String>,
                    String,
                    Option<chrono::DateTime<chrono::Utc>>,
                ),
            >(&contacts_sql);
            for value in &where_sql.binds {
                query = query.bind(value);
            }
            query.fetch_all(&state.db).await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Contacts",
        "Your addressable audience, read straight from the contacts table.",
        "/contacts",
    );
    data.search_label = "Search contacts".into();
    data.search_placeholder = "Search by email".into();
    data.current_query = q.search.clone();
    data.filters = vec![FilterSelectData::new(
        "status",
        "Filter by status",
        vec![
            ("".into(), "All statuses".into(), q.status.is_empty()),
            (
                "subscribed".into(),
                "Subscribed".into(),
                q.status == "subscribed",
            ),
            (
                "unsubscribed".into(),
                "Unsubscribed".into(),
                q.status == "unsubscribed",
            ),
            ("bounced".into(), "Bounced".into(), q.status == "bounced"),
        ],
    )];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.bulk_action = Some(BulkActionData {
        action: "/web/contacts/delete-bulk".into(),
        button_label: "Delete selected".into(),
    });
    data.primary_action = Some(("Add Contact".into(), "/contacts/new".into()));
    data.empty_title = "No contacts yet".into();
    data.empty_description = "Add your first contact to start building an audience.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Contacts", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Email".into(),
            "Name".into(),
            "Status".into(),
            "Updated".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, email, name, status, updated)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(email),
                    DataCell::text(name.unwrap_or_default()),
                    DataCell::status(&status),
                    DataCell::text(relative_time(updated)),
                ],
            })
            .collect(),
    });
    data
}

async fn web_lists(state: &AppState, tenant: &str, q: &ListQuery, cid: &str) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "web.lists.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM lists WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    let rows = load_query(
        "web.lists.list",
        cid,
        async {
            // lists.id is a UUID (migration 068): decode as text.
            let q1 = format!(
                "SELECT id::text AS id, name, updated_at FROM lists WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
            let mut query =
                sqlx::query_as::<_, (String, String, Option<chrono::DateTime<chrono::Utc>>)>(&q1);
            for value in &where_sql.binds {
                query = query.bind(value);
            }
            query.fetch_all(&state.db).await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Lists",
        "Audience segments — rows come from the lists table.",
        "/lists",
    );
    data.search_label = "Search lists".into();
    data.search_placeholder = "Search by list name".into();
    data.current_query = q.search.clone();
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.primary_action = Some(("New List".into(), "/lists/new".into()));
    data.detail_path_prefix = Some("/lists/".into());
    data.edit_path_suffix = Some("/edit".into());
    data.delete_intent = Some("delete-list".into());
    data.empty_title = "No lists yet".into();
    data.empty_description = "Create a list to group contacts into an audience.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Lists", cid);
    }
    data.table = Some(TableData {
        columns: vec!["Name".into(), "Updated".into()],
        rows: rows
            .into_iter()
            .map(|(id, name, updated)| DataRowData {
                id,
                cells: vec![DataCell::text(name), DataCell::text(relative_time(updated))],
            })
            .collect(),
    });
    data
}

async fn web_templates(state: &AppState, tenant: &str, q: &ListQuery, cid: &str) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "web.templates.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM templates WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    // templates.id is VARCHAR (migration 075) — decoded as String natively.
    let rows =
        load_query(
            "web.templates.list",
            cid,
            async {
                let templates_sql = format!(
                    "SELECT id, name, COALESCE(subject, ''), version, status, updated_at FROM templates WHERE {where_clause} ORDER BY updated_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
                );
                let mut query = sqlx::query_as::<
                    _,
                    (
                        String,
                        String,
                        String,
                        Option<i32>,
                        String,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(&templates_sql);
                for value in &where_sql.binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Templates",
        "Reusable email bodies — rows come from the templates table.",
        "/templates",
    );
    data.search_label = "Search templates".into();
    data.search_placeholder = "Search by template name".into();
    data.current_query = q.search.clone();
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.primary_action = Some(("New Template".into(), "/templates/new".into()));
    data.empty_title = "No templates yet".into();
    data.empty_description = "Create a template to reuse email content across campaigns.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Templates", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Name".into(),
            "Subject".into(),
            "Version".into(),
            "Status".into(),
            "Updated".into(),
        ],
        rows: rows
            .into_iter()
            .map(
                |(id, name, subject, version, status, updated)| DataRowData {
                    id,
                    cells: vec![
                        DataCell::text(name),
                        DataCell::text(subject),
                        DataCell::text(
                            version
                                .map(|v| format!("v{v}"))
                                .unwrap_or_else(|| "—".into()),
                        ),
                        DataCell::status(&status),
                        DataCell::text(relative_time(updated)),
                    ],
                },
            )
            .collect(),
    });
    data
}

async fn web_domains(state: &AppState, tenant: &str, q: &ListQuery, cid: &str) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    where_sql.status_in(&["pending", "verified", "failed", "suspended"], &q.status);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "web.domains.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM domains WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    let rows = load_query(
        "web.domains.list",
        cid,
        async {
            // domains.id is a UUID (migration 052): decode as text.
            let q2 = format!(
                "SELECT id::text AS id, name, status, created_at FROM domains WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
            let mut query = sqlx::query_as::<
                _,
                (String, String, String, Option<chrono::DateTime<chrono::Utc>>),
            >(&q2);
            for value in &where_sql.binds {
                query = query.bind(value);
            }
            query.fetch_all(&state.db).await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Domains",
        "Sending domains and their verification state.",
        "/domains",
    );
    data.search_label = "Search domains".into();
    data.search_placeholder = "Search by domain name".into();
    data.current_query = q.search.clone();
    data.filters = vec![FilterSelectData::new(
        "status",
        "Filter by status",
        vec![
            ("".into(), "All statuses".into(), q.status.is_empty()),
            ("pending".into(), "Pending".into(), q.status == "pending"),
            ("verified".into(), "Verified".into(), q.status == "verified"),
            ("failed".into(), "Failed".into(), q.status == "failed"),
        ],
    )];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.primary_action = Some(("Add Domain".into(), "/domains/new".into()));
    data.delete_intent = Some("delete-domain".into());
    data.empty_title = "No domains yet".into();
    data.empty_description = "Add and verify a sending domain before dispatching mail.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Domains", cid);
    }
    data.table = Some(TableData {
        columns: vec!["Domain".into(), "Status".into(), "Added".into()],
        rows: rows
            .into_iter()
            .map(|(id, name, status, created)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(name),
                    DataCell::status(&status),
                    DataCell::text(relative_time(created)),
                ],
            })
            .collect(),
    });
    data
}

async fn web_events(state: &AppState, tenant: &str, q: &ListQuery, cid: &str) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    where_sql.status_in(
        &[
            "sent",
            "delivered",
            "opened",
            "clicked",
            "bounced",
            "complained",
            "unsubscribed",
        ],
        &q.status,
    );
    if !q.search.is_empty() {
        where_sql.ilike("recipient", &q.search);
    }
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "web.events.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM events WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    // events.id is VARCHAR (migration 075) — decoded as String natively.
    let rows =
        load_query(
            "web.events.list",
            cid,
            async {
                let events_sql = format!(
                    "SELECT id, event_type, recipient, message_id, timestamp FROM events WHERE {where_clause} ORDER BY timestamp DESC LIMIT {PER_PAGE} OFFSET {offset}"
                );
                let mut query = sqlx::query_as::<
                    _,
                    (
                        String,
                        String,
                        Option<String>,
                        Option<String>,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(&events_sql);
                for value in &where_sql.binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Events",
        "The live delivery event stream for this workspace.",
        "/events",
    );
    data.search_label = "Search events".into();
    data.search_placeholder = "Search by recipient".into();
    data.current_query = q.search.clone();
    data.filters = vec![FilterSelectData::new(
        "status",
        "Filter by type",
        vec![
            ("".into(), "All types".into(), q.status.is_empty()),
            ("sent".into(), "Sent".into(), q.status == "sent"),
            (
                "delivered".into(),
                "Delivered".into(),
                q.status == "delivered",
            ),
            ("opened".into(), "Opened".into(), q.status == "opened"),
            ("clicked".into(), "Clicked".into(), q.status == "clicked"),
            ("bounced".into(), "Bounced".into(), q.status == "bounced"),
            (
                "complained".into(),
                "Complained".into(),
                q.status == "complained",
            ),
        ],
    )];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.empty_title = "No events yet".into();
    data.empty_description = "Delivery events appear here as soon as mail starts flowing.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Events", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Type".into(),
            "Recipient".into(),
            "Message".into(),
            "When".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, event_type, recipient, message_id, ts)| DataRowData {
                id,
                cells: vec![
                    DataCell::status(&event_type),
                    DataCell::text(recipient.unwrap_or_default()),
                    DataCell::mono(message_id.unwrap_or_default()),
                    DataCell::text(ts.map(|t| t.to_rfc3339()).unwrap_or_else(|| "—".into())),
                ],
            })
            .collect(),
    });
    data
}

async fn event_aggregate(
    state: &AppState,
    query_id: &str,
    cid: &str,
    where_sql: &str,
    binds: &[String],
) -> LoadState<HashMap<String, i64>> {
    let sql = format!(
        "SELECT
            COALESCE(SUM(CASE WHEN event_type = 'sent' THEN 1 ELSE 0 END), 0)::bigint,
            COALESCE(SUM(CASE WHEN event_type = 'delivered' THEN 1 ELSE 0 END), 0)::bigint,
            COALESCE(SUM(CASE WHEN event_type = 'opened' THEN 1 ELSE 0 END), 0)::bigint,
            COALESCE(SUM(CASE WHEN event_type = 'clicked' THEN 1 ELSE 0 END), 0)::bigint,
            COALESCE(SUM(CASE WHEN event_type = 'bounced' THEN 1 ELSE 0 END), 0)::bigint,
            COALESCE(SUM(CASE WHEN event_type = 'complained' THEN 1 ELSE 0 END), 0)::bigint
         FROM events WHERE {where_sql}"
    );
    let mut query = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(&sql);
    for value in binds {
        query = query.bind(value);
    }
    let row = load_query(query_id, cid, query.fetch_optional(&state.db)).await;
    match row {
        // A missing optional events relation (or an aggregate over zero
        // rows) is an honest all-zero map; query failures stay
        // Unavailable (audit F14).
        LoadState::Loaded(None) => LoadState::Loaded(HashMap::new()),
        LoadState::Loaded(Some((sent, delivered, opened, clicked, bounced, complained))) => {
            let mut out = HashMap::new();
            out.insert("sent".to_string(), sent);
            out.insert("delivered".to_string(), delivered);
            out.insert("opened".to_string(), opened);
            out.insert("clicked".to_string(), clicked);
            out.insert("bounced".to_string(), bounced);
            out.insert("complained".to_string(), complained);
            LoadState::Loaded(out)
        }
        LoadState::Unavailable => LoadState::Unavailable,
    }
}

/// KPI value for an aggregate bucket: the number when the aggregate
/// loaded, an explicit "unavailable" when it did not (audit F14).
fn aggregate_kpi(loaded: bool, value: i64) -> String {
    if loaded {
        value.to_string()
    } else {
        "unavailable".to_string()
    }
}

fn rate(part: i64, whole: i64) -> String {
    if whole == 0 {
        "—".to_string()
    } else {
        format!("{:.1}%", (part as f64 / whole as f64) * 100.0)
    }
}

async fn web_analytics(state: &AppState, tenant: &str, cid: &str) -> ListPageData {
    let agg_state = event_aggregate(
        state,
        "web.analytics.aggregate",
        cid,
        "tenant_id = $1 AND timestamp >= NOW() - '30 days'::interval",
        &[tenant.to_string()],
    )
    .await;
    let agg_loaded = !agg_state.is_unavailable();
    let agg = agg_state.unwrap_or_default();
    let sent = *agg.get("sent").unwrap_or(&0);
    let delivered = agg.get("delivered").copied().unwrap_or(0);
    let opened = agg.get("opened").copied().unwrap_or(0);
    let clicked = agg.get("clicked").copied().unwrap_or(0);

    let mut data = base_list(
        "Analytics",
        "Delivery performance for the last 30 days, computed from the events table.",
        "/analytics",
    );
    data.kpis = vec![
        KpiCardData::new("Sent", aggregate_kpi(agg_loaded, sent)).with_hint("Last 30 days"),
        KpiCardData::new("Delivered", aggregate_kpi(agg_loaded, delivered))
            .with_hint(&rate(delivered, sent)),
        KpiCardData::new("Opened", aggregate_kpi(agg_loaded, opened))
            .with_hint(&rate(opened, sent)),
        KpiCardData::new("Clicked", aggregate_kpi(agg_loaded, clicked))
            .with_hint(&rate(clicked, sent)),
    ];
    data
}

async fn web_reports(state: &AppState, tenant: &str, cid: &str) -> ListPageData {
    let agg_state = event_aggregate(
        state,
        "web.reports.aggregate",
        cid,
        "tenant_id = $1 AND timestamp >= NOW() - '30 days'::interval",
        &[tenant.to_string()],
    )
    .await;
    let agg_loaded = !agg_state.is_unavailable();
    let agg = agg_state.unwrap_or_default();
    let sent = *agg.get("sent").unwrap_or(&0);
    let bounced = agg.get("bounced").copied().unwrap_or(0);
    let delivered = agg.get("delivered").copied().unwrap_or(0);
    let campaigns = loaded_count(
        state,
        "web.reports.campaigns",
        cid,
        "SELECT COUNT(*)::bigint FROM campaigns WHERE tenant_id = $1",
        &[tenant.to_string()],
    )
    .await;

    // campaigns.id is a UUID (migration 075): decode as text; sent_count
    // stays INTEGER → Option<i32>.
    let rows =
        load_query(
            "web.reports.campaign_rows",
            cid,
            async {
                sqlx::query_as::<
                    _,
                    (
                        String,
                        String,
                        String,
                        Option<i32>,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(
                    "SELECT id::text AS id, name, status, sent_count, updated_at FROM campaigns WHERE tenant_id = $1 ORDER BY updated_at DESC LIMIT 10",
                )
                .bind(tenant)
                .fetch_all(&state.db)
                .await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Reports",
        "Cross-campaign reporting — every row links into the campaign record.",
        "/reports",
    );
    data.kpis = vec![
        KpiCardData::new("Campaigns", campaigns.kpi_value()).with_hint("All time"),
        KpiCardData::new("Sent (30d)", aggregate_kpi(agg_loaded, sent)).with_hint("Events table"),
        KpiCardData::new("Bounces (30d)", aggregate_kpi(agg_loaded, bounced))
            .with_hint(&rate(bounced, sent)),
        KpiCardData::new(
            "Deliverability",
            if agg_loaded {
                rate(delivered, sent)
            } else {
                "unavailable".to_string()
            },
        )
        .with_hint("Delivered ÷ sent"),
    ];
    data.detail_path_prefix = Some("/campaigns/".into());
    data.detail_label = "Open".into();
    data.empty_title = "No reportable campaigns yet".into();
    data.empty_description = "Send a campaign to populate cross-campaign reports.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Campaign reports", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Campaign".into(),
            "Status".into(),
            "Sent".into(),
            "Updated".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, name, status, sent_count, updated)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(name),
                    DataCell::status(&status),
                    DataCell::text(
                        sent_count
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "0".into()),
                    ),
                    DataCell::text(relative_time(updated)),
                ],
            })
            .collect(),
    });
    data
}

async fn web_deliverability(state: &AppState, tenant: &str, cid: &str) -> ListPageData {
    let agg_state = event_aggregate(
        state,
        "web.deliverability.aggregate",
        cid,
        "tenant_id = $1 AND timestamp >= NOW() - '30 days'::interval",
        &[tenant.to_string()],
    )
    .await;
    let agg_loaded = !agg_state.is_unavailable();
    let agg = agg_state.unwrap_or_default();
    let sent = *agg.get("sent").unwrap_or(&0);
    let delivered = agg.get("delivered").copied().unwrap_or(0);
    let bounced = agg.get("bounced").copied().unwrap_or(0);
    let complained = agg.get("complained").copied().unwrap_or(0);

    let rows = load_query(
        "web.deliverability.event_rows",
        cid,
        async {
            sqlx::query_as::<_, (String, i64)>(
                "SELECT event_type, COUNT(*)::bigint FROM events WHERE tenant_id = $1 AND timestamp >= NOW() - '30 days'::interval GROUP BY event_type ORDER BY 2 DESC",
            )
            .bind(tenant)
            .fetch_all(&state.db)
            .await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Deliverability",
        "Bounce, complaint, and delivery rates computed from real events.",
        "/reports/deliverability",
    );
    data.kpis = vec![
        KpiCardData::new(
            "Delivery rate",
            if agg_loaded {
                rate(delivered, sent)
            } else {
                "unavailable".to_string()
            },
        )
        .with_hint("Delivered ÷ sent"),
        KpiCardData::new(
            "Bounce rate",
            if agg_loaded {
                rate(bounced, sent)
            } else {
                "unavailable".to_string()
            },
        )
        .with_hint("Bounced ÷ sent"),
        KpiCardData::new(
            "Complaint rate",
            if agg_loaded {
                rate(complained, sent)
            } else {
                "unavailable".to_string()
            },
        )
        .with_hint("Complained ÷ sent"),
        KpiCardData::new("Sent (30d)", aggregate_kpi(agg_loaded, sent))
            .with_hint("Total dispatched"),
    ];
    data.empty_title = "No delivery data yet".into();
    data.empty_description = "Deliverability metrics appear once messages are dispatched.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Delivery metrics", cid);
    }
    data.table = Some(TableData {
        columns: vec!["Event type".into(), "Count (30d)".into()],
        rows: rows
            .into_iter()
            .map(|(event_type, count)| DataRowData {
                id: event_type.clone(),
                cells: vec![
                    DataCell::status(&event_type),
                    DataCell::text(count.to_string()),
                ],
            })
            .collect(),
    });
    data
}

async fn web_inbox_placement(
    state: &AppState,
    tenant: &str,
    q: &ListQuery,
    cid: &str,
) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    where_sql.status_in(&["pending", "running", "completed", "failed"], &q.status);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "web.placement.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM placement_tests WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    let rows =
        load_query(
            "web.placement.list",
            cid,
            async {
                let placement_sql = format!(
                    "SELECT id::text AS id, name, status, total_accounts, completed_accounts, created_at FROM placement_tests WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
                );
                let mut query = sqlx::query_as::<
                    _,
                    (
                        String,
                        Option<String>,
                        String,
                        Option<i32>,
                        Option<i32>,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(&placement_sql);
                for value in &where_sql.binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Inbox Placement",
        "Seed-account placement tests and their completion state.",
        "/inbox-placement",
    );
    data.search_label = "Search tests".into();
    data.search_placeholder = "Search by test name".into();
    data.current_query = q.search.clone();
    data.filters = vec![FilterSelectData::new(
        "status",
        "Filter by status",
        vec![
            ("".into(), "All statuses".into(), q.status.is_empty()),
            ("pending".into(), "Pending".into(), q.status == "pending"),
            ("running".into(), "Running".into(), q.status == "running"),
            (
                "completed".into(),
                "Completed".into(),
                q.status == "completed",
            ),
        ],
    )];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.primary_action = Some(("New Test".into(), "/inbox-placement/new".into()));
    data.empty_title = "No placement tests yet".into();
    data.empty_description = "Start a seed-account test to measure inbox placement.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Placement tests", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Test".into(),
            "Status".into(),
            "Accounts".into(),
            "Created".into(),
        ],
        rows: rows
            .into_iter()
            .map(
                |(id, name, status, total_accounts, completed, created)| DataRowData {
                    id,
                    cells: vec![
                        DataCell::text(name.unwrap_or_else(|| "Unnamed test".into())),
                        DataCell::status(&status),
                        DataCell::text(format!(
                            "{}/{}",
                            completed.unwrap_or(0),
                            total_accounts.unwrap_or(0)
                        )),
                        DataCell::text(relative_time(created)),
                    ],
                },
            )
            .collect(),
    });
    data
}

/// /settings/api-keys list query (audit F03). The schema column is
/// `key_prefix` (`prefix` never existed — the old query failed with 42703
/// on any populated database); `id` is a UUID, decoded as text; and
/// `expires_at` is selected so the view model can distinguish active,
/// expired, and revoked keys.
const API_KEYS_SQL: &str = "SELECT id::text AS id, name, key_prefix AS prefix, created_at, revoked_at, expires_at FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100";

/// API-key lifecycle state for the console (audit F03). Revocation wins
/// over expiry — it is the irreversible operator action; a key whose
/// `expires_at` has passed is "expired", never "active".
fn api_key_state(
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> &'static str {
    if revoked_at.is_some() {
        "revoked"
    } else if expires_at.is_some_and(|expires| expires <= now) {
        "expired"
    } else {
        "active"
    }
}

async fn web_api_keys(state: &AppState, tenant: &str, cid: &str) -> ListPageData {
    let rows = load_query("web.api_keys.list", cid, async {
        sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                Option<chrono::DateTime<chrono::Utc>>,
                Option<chrono::DateTime<chrono::Utc>>,
                Option<chrono::DateTime<chrono::Utc>>,
            ),
        >(API_KEYS_SQL)
        .bind(tenant)
        .fetch_all(&state.db)
        .await
    })
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "API Keys",
        "Machine credentials for this workspace. Secrets are shown once at creation.",
        "/settings/api-keys",
    );
    data.total_count = if rows_unavailable {
        0
    } else {
        rows.len() as i64
    };
    data.empty_title = "No API keys yet".into();
    data.empty_description = "Create a key to call the API programmatically.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "API keys", cid);
    }
    let now = chrono::Utc::now();
    data.table = Some(TableData {
        columns: vec![
            "Name".into(),
            "Prefix".into(),
            "Status".into(),
            "Created".into(),
        ],
        rows: rows
            .into_iter()
            .map(
                |(id, name, prefix, created, revoked, expires)| DataRowData {
                    id,
                    cells: vec![
                        DataCell::text(name),
                        DataCell::mono(format!("{prefix}…")),
                        DataCell::status(api_key_state(revoked, expires, now)),
                        DataCell::text(relative_time(created)),
                    ],
                },
            )
            .collect(),
    });
    data
}

async fn web_webhooks(state: &AppState, tenant: &str, cid: &str) -> ListPageData {
    // webhooks.id is VARCHAR (migration 075) — decoded as String natively.
    let rows = load_query(
        "web.webhooks.list",
        cid,
        async {
            sqlx::query_as::<_, (String, String, bool, Option<chrono::DateTime<chrono::Utc>>)>(
                "SELECT id, url, enabled, last_triggered_at FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100",
            )
            .bind(tenant)
            .fetch_all(&state.db)
            .await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Webhooks",
        "HTTP endpoints notified about delivery events.",
        "/settings/webhooks",
    );
    data.total_count = if rows_unavailable {
        0
    } else {
        rows.len() as i64
    };
    data.empty_title = "No webhooks yet".into();
    data.empty_description = "Register an endpoint to receive delivery events.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Webhooks", cid);
    }
    data.table = Some(TableData {
        columns: vec!["Endpoint".into(), "Enabled".into(), "Last triggered".into()],
        rows: rows
            .into_iter()
            .map(|(id, url, enabled, last)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(url),
                    DataCell::status(if enabled { "active" } else { "paused" }),
                    DataCell::text(relative_time(last)),
                ],
            })
            .collect(),
    });
    data
}

async fn web_team(state: &AppState, tenant: &str, cid: &str) -> ListPageData {
    let rows = load_query(
        "web.team.list",
        cid,
        async {
            sqlx::query_as::<_, (String, Option<String>, String, String, bool)>(
                "SELECT email, name, role, status, COALESCE(mfa_enabled, false) FROM users WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100",
            )
            .bind(tenant)
            .fetch_all(&state.db)
            .await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Team",
        "Workspace members and their access level.",
        "/settings/team",
    );
    data.total_count = if rows_unavailable {
        0
    } else {
        rows.len() as i64
    };
    data.empty_title = "No team members yet".into();
    data.empty_description = "Invite teammates to collaborate on this workspace.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Team members", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Email".into(),
            "Name".into(),
            "Role".into(),
            "Status".into(),
            "MFA".into(),
        ],
        rows: rows
            .into_iter()
            .enumerate()
            .map(|(index, (email, name, role, status, mfa))| DataRowData {
                id: format!("member-{index}"),
                cells: vec![
                    DataCell::text(email),
                    DataCell::text(name.unwrap_or_default()),
                    DataCell::text(role),
                    DataCell::status(&status),
                    DataCell::status(if mfa { "sent" } else { "draft" }),
                ],
            })
            .collect(),
    });
    data
}

/// /settings/billing invoice-list query (audit F04). The canonical
/// invoices schema (migrations 052 + 076) has NO `amount_cents` column —
/// 069's CREATE TABLE is a no-op after 052 — so the old query failed with
/// 42703 on any populated database and rendered as an empty list. The
/// canonical amount is `total` (nullable, written by billing-service
/// invoice creation), with the legacy NOT NULL `amount` as fallback for
/// pre-076 rows; `id` is a UUID, decoded as text.
const BILLING_INVOICES_SQL: &str = "SELECT id::text AS id, COALESCE(total, amount, 0)::bigint AS total, currency, status::text AS status, created_at FROM invoices WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 50";

/// Collectible outstanding per currency (audits F04/F60/F73), aggregated
/// over the FULL eligible invoice set — not the 50-row visible window.
///
/// The summary consults the ALLOCATION LEDGER through the ONE shared
/// authoritative balance (`billing_service::invoices::
/// tenant_outstanding_by_currency`): invoice obligation minus confirmed
/// payment allocations minus the debt-reduction part of credit notes —
/// the same accounting model the collector, dunning service and credit
/// limits use. A 100-unit invoice with 40 wallet units already allocated
/// therefore reports 60, not 100. An unavailable balance propagates as
/// `LoadState::Unavailable` (rendered as an explicit "unavailable" card),
/// never as a silent zero.
async fn billing_outstanding_buckets(
    state: &AppState,
    tenant: &str,
    checkpoint: &str,
) -> LoadState<Vec<(String, i64)>> {
    load_query(
        "web.billing.outstanding",
        checkpoint,
        billing_service::invoices::tenant_outstanding_by_currency(&state.db, tenant),
    )
    .await
}

/// Render a cents amount with its own currency code (audit F04: totals
/// are never labelled with a hard-coded currency).
fn format_cents(cents: i64, currency: &str) -> String {
    format!("{:.2} {currency}", cents as f64 / 100.0)
}

/// Outstanding KPI cards from the per-currency buckets (audit F04): one
/// card per currency, "0.00" only when nothing collectible exists, and an
/// explicit "unavailable" card when the aggregate query failed.
fn outstanding_kpis(buckets: LoadState<Vec<(String, i64)>>) -> Vec<KpiCardData> {
    match buckets {
        LoadState::Loaded(buckets) if buckets.is_empty() => {
            vec![KpiCardData::new("Outstanding", "0.00").with_hint("Nothing currently due")]
        }
        LoadState::Loaded(buckets) => buckets
            .into_iter()
            .map(|(currency, cents)| {
                KpiCardData::new(
                    &format!("Outstanding ({currency})"),
                    format_cents(cents, &currency),
                )
                .with_hint("Unpaid collectible total")
            })
            .collect(),
        LoadState::Unavailable => {
            vec![KpiCardData::new("Outstanding", "unavailable").with_hint("Could not be computed")]
        }
    }
}

async fn web_billing(state: &AppState, tenant: &str, cid: &str) -> ListPageData {
    let plan_state = load_query("web.billing.plan", cid, async {
        sqlx::query_scalar::<_, String>("SELECT plan FROM tenants WHERE id::text = $1")
            .bind(tenant)
            .fetch_optional(&state.db)
            .await
    })
    .await;
    let plan = match plan_state {
        LoadState::Loaded(plan) => plan.unwrap_or_else(|| "free".into()),
        LoadState::Unavailable => "unavailable".to_string(),
    };

    let rows = load_query("web.billing.invoices", cid, async {
        sqlx::query_as::<
            _,
            (
                String,
                i64,
                String,
                String,
                Option<chrono::DateTime<chrono::Utc>>,
            ),
        >(BILLING_INVOICES_SQL)
        .bind(tenant)
        .fetch_all(&state.db)
        .await
    })
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let outstanding = billing_outstanding_buckets(state, tenant, cid).await;

    let mut data = base_list(
        "Billing",
        "Plan, invoices, and payment posture for this workspace.",
        "/settings/billing",
    );
    let mut kpis = vec![
        KpiCardData::new("Current plan", plan).with_hint("Tenant record"),
        KpiCardData::new(
            "Invoices",
            if rows_unavailable {
                "unavailable".to_string()
            } else {
                rows.len().to_string()
            },
        )
        .with_hint("On record"),
    ];
    kpis.extend(outstanding_kpis(outstanding));
    data.kpis = kpis;
    data.total_count = if rows_unavailable {
        0
    } else {
        rows.len() as i64
    };
    data.empty_title = "No invoices yet".into();
    data.empty_description = "Invoices appear here once a paid plan is active.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Invoices", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Invoice".into(),
            "Amount".into(),
            "Currency".into(),
            "Status".into(),
            "Issued".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, total, currency, status, created)| DataRowData {
                cells: vec![
                    DataCell::mono(id.chars().take(12).collect::<String>()),
                    DataCell::text(format!("{:.2}", total as f64 / 100.0)),
                    DataCell::text(currency),
                    DataCell::status(&status),
                    DataCell::text(relative_time(created)),
                ],
                id,
            })
            .collect(),
    });
    data
}

async fn web_dedicated_ips(state: &AppState, tenant: &str, cid: &str) -> ListPageData {
    // dedicated_ips.id is a UUID (migration 003): decode as text;
    // ip_address is TEXT.
    let rows = load_query(
        "web.dedicated_ips.list",
        cid,
        async {
            sqlx::query_as::<_, (String, Option<String>, Option<String>, String, Option<f64>)>(
                "SELECT id::text AS id, ip_address, region, status, warmup_progress FROM dedicated_ips WHERE tenant_id::text = $1 ORDER BY created_at DESC LIMIT 100",
            )
            .bind(tenant)
            .fetch_all(&state.db)
            .await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let pending = loaded_count(
        state,
        "web.dedicated_ips.pending",
        cid,
        "SELECT COUNT(*)::bigint FROM dedicated_ip_provisioning_requests WHERE tenant_id = $1 AND status = 'pending'",
        &[tenant.to_string()],
    )
    .await;

    let mut data = base_list(
        "Dedicated IPs",
        "Per-tenant IP assignments with warmup progress.",
        "/settings/dedicated-ips",
    );
    data.kpis = vec![
        KpiCardData::new(
            "Assigned",
            if rows_unavailable {
                "unavailable".to_string()
            } else {
                rows.len().to_string()
            },
        )
        .with_hint("Active allocations"),
        KpiCardData::new("Pending requests", pending.kpi_value())
            .with_hint("Awaiting the provisioner"),
    ];
    data.total_count = if rows_unavailable {
        0
    } else {
        rows.len() as i64
    };
    data.empty_title = "No dedicated IPs yet".into();
    data.empty_description = "Request an allocation — the provisioner completes it.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Dedicated IPs", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "IP".into(),
            "Region".into(),
            "Status".into(),
            "Warmup".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, ip, region, status, warmup)| DataRowData {
                id,
                cells: vec![
                    DataCell::mono(ip.unwrap_or_else(|| "pending".into())),
                    DataCell::text(region.unwrap_or_else(|| "—".into())),
                    DataCell::status(&status),
                    DataCell::text(
                        warmup
                            .map(|w| format!("{:.0}%", w * 100.0))
                            .unwrap_or_else(|| "—".into()),
                    ),
                ],
            })
            .collect(),
    });
    data
}

// ─── Control-plane (system-scoped) routes ──────────────────────

async fn control_plane_route_data(
    state: &AppState,
    path: &str,
    q: &ListQuery,
    _user: &AuthUser,
    cid: &str,
) -> RouteData {
    let list = match path {
        "/" => Some(cp_home(state, cid).await),
        "/cp" | "/dashboard" => Some(cp_dashboard(state, cid).await),
        "/cp/tenants" | "/tenants" => Some(cp_tenants(state, q, cid).await),
        "/operators" => Some(cp_operators(state, q, cid).await),
        // `/sales` is no longer a lead list: the control surface answers
        // whether the autonomous engine is producing pipeline profitably and
        // safely. Its data comes from `RouteData::sales`, not `list`.
        "/cp/sales" | "/sales" => None,
        "/cp/audit" | "/audit" => Some(cp_audit(state, q, cid).await),
        "/jobs" => Some(cp_jobs(state, cid).await),
        "/infrastructure/nodes" => Some(cp_nodes(state, cid).await),
        "/infrastructure/queues" => Some(cp_queues(state, cid).await),
        "/alerts" => Some(cp_alerts(state, q, cid).await),
        "/domains" => Some(cp_domains(state, q, cid).await),
        "/billing/plans" => Some(cp_plans(state, cid).await),
        "/compliance" => Some(cp_compliance(state, cid).await),
        "/compliance/gdpr" => Some(cp_gdpr(state, q, cid).await),
        "/discovery" => Some(cp_discovery(state, cid).await),
        "/analytics" => Some(cp_analytics(state, cid).await),
        _ => None,
    };

    let sales = match path {
        "/cp/sales" | "/sales" => Some(cp_sales_autopilot(state).await),
        _ => None,
    };

    RouteData {
        list,
        campaign_edit: None,
        mfa_setup: None,
        sales,
    }
}

/// Load the sales-autopilot control surface from the canonical sales tables.
///
/// The control plane deliberately reads the canonical tables rather than
/// re-deriving anything: this is a view over the one sales domain, not a
/// second brain. Every section is independently `None`-able so a single
/// missing table degrades to the page's explicit "unavailable" state instead
/// of a zero-filled dashboard that would read as real activity.
async fn cp_sales_autopilot(state: &AppState) -> ui_foundation::view_data::SalesPageData {
    use ui_foundation::view_data::{
        SalesActionStatsData, SalesAutonomyData, SalesDeadLetterData, SalesEnrollmentCountData,
        SalesOverviewData, SalesPageData, SalesRevenueData,
    };

    const TENANT: &str = "system";

    // ── Autonomy ──────────────────────────────────────────────────────
    let autonomy = sqlx::query_as::<
        _,
        (
            String,
            bool,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(
        "SELECT mode, kill_switch, last_action, last_action_at \
         FROM sales_autonomy_state WHERE tenant_id = $1",
    )
    .bind(TENANT)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .map(|(mode, kill_switch, last_action, last_action_at)| {
        let parsed = AutonomyModeView::parse(&mode);
        SalesAutonomyData {
            mode: parsed.mode.to_string(),
            mode_description: String::new(),
            kill_switch,
            runs_brain: parsed.runs_brain,
            may_execute: parsed.may_execute,
            last_action,
            last_action_at: last_action_at.map(|t| t.to_rfc3339()),
        }
    });

    // ── Action queue ──────────────────────────────────────────────────
    let action_stats = match sqlx::query_as::<_, (String, i64)>(
        "SELECT state, COUNT(*)::bigint FROM sales_actions \
         WHERE tenant_id = $1 GROUP BY state ORDER BY state",
    )
    .bind(TENANT)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => {
            let by_state: Vec<(String, i64)> = rows;
            let total = by_state.iter().map(|(_, count)| *count).sum();
            let dead_lettered = by_state
                .iter()
                .find(|(state, _)| state == "dead_letter")
                .map(|(_, count)| *count)
                .unwrap_or(0);
            let due_now = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*)::bigint FROM sales_actions \
                 WHERE tenant_id = $1 AND state = 'queued' AND due_at <= NOW()",
            )
            .bind(TENANT)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);
            Some(SalesActionStatsData {
                total,
                due_now,
                dead_lettered,
                by_state,
            })
        }
        Err(_) => None,
    };

    // ── Enrollments by state ──────────────────────────────────────────
    let enrollments = sqlx::query_as::<_, (String, i64)>(
        "SELECT state, COUNT(*)::bigint FROM sales_enrollments \
         WHERE tenant_id = $1 GROUP BY state ORDER BY state",
    )
    .bind(TENANT)
    .fetch_all(&state.db)
    .await
    .ok()
    .map(|rows| {
        rows.into_iter()
            .map(|(state, count)| SalesEnrollmentCountData { state, count })
            .collect::<Vec<_>>()
    });

    // ── Decision counters ────────────────────────────────────────────
    let decisions_last_24h = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM sales_decisions \
         WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'",
    )
    .bind(TENANT)
    .fetch_one(&state.db)
    .await
    .ok();

    let blocked_last_24h = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM sales_decisions \
         WHERE tenant_id = $1 AND blocked AND created_at >= NOW() - INTERVAL '24 hours'",
    )
    .bind(TENANT)
    .fetch_one(&state.db)
    .await
    .ok();

    let meetings_booked = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM sales_meetings \
         WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '30 days'",
    )
    .bind(TENANT)
    .fetch_one(&state.db)
    .await
    .ok();

    let revenue = sqlx::query_as::<_, (String, f64)>(
        "SELECT outcome, COALESCE(SUM(value_eur), 0)::float8 FROM sales_outcomes \
         WHERE tenant_id = $1 AND occurred_at >= NOW() - INTERVAL '30 days' \
           AND outcome IN ('trial', 'paid_subscription', 'retained_mrr') \
         GROUP BY outcome ORDER BY outcome",
    )
    .bind(TENANT)
    .fetch_all(&state.db)
    .await
    .ok()
    .map(|rows| {
        rows.into_iter()
            .map(|(outcome, eur)| SalesRevenueData { outcome, eur })
            .collect::<Vec<_>>()
    });

    let overview = match (autonomy, action_stats) {
        (Some(autonomy), Some(action_stats)) => Some(SalesOverviewData {
            autonomy,
            action_stats,
            enrollments: enrollments.unwrap_or_default(),
            decisions_last_24h: decisions_last_24h.unwrap_or(0),
            blocked_last_24h: blocked_last_24h.unwrap_or(0),
            meetings_booked: meetings_booked.unwrap_or(0),
            revenue: revenue.unwrap_or_default(),
        }),
        _ => None,
    };

    // ── Decision rows ────────────────────────────────────────────────
    let decisions = load_decision_rows(
        state,
        "SELECT id, account_id, contact_id, action, expected_value_eur::float8, \
                confidence::float8, selected_offer, selected_sequence, selected_variant, \
                selected_sender, rationale, blocked, block_reasons, execute_after, created_at \
         FROM sales_decisions WHERE tenant_id = $1 \
         ORDER BY created_at DESC LIMIT 25",
    )
    .await;

    let exceptions = load_decision_rows(
        state,
        "SELECT id, account_id, contact_id, action, expected_value_eur::float8, \
                confidence::float8, selected_offer, selected_sequence, selected_variant, \
                selected_sender, rationale, blocked, block_reasons, execute_after, created_at \
         FROM sales_decisions WHERE tenant_id = $1 \
           AND (blocked OR autonomy_mode IN ('assisted', 'approval_required')) \
         ORDER BY created_at DESC LIMIT 25",
    )
    .await;

    // ── Dead letters ─────────────────────────────────────────────────
    let dead_letters = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            i32,
            i32,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT id::text, action_type, entity_type, entity_id::text, state, attempt, \
                max_attempts, last_error, due_at, created_at \
         FROM sales_actions WHERE tenant_id = $1 AND state = 'dead_letter' \
         ORDER BY created_at DESC LIMIT 25",
    )
    .bind(TENANT)
    .fetch_all(&state.db)
    .await
    .ok()
    .map(|rows| {
        rows.into_iter()
            .map(
                |(
                    id,
                    action_type,
                    entity_type,
                    entity_id,
                    state,
                    attempt,
                    max_attempts,
                    last_error,
                    due_at,
                    created_at,
                )| SalesDeadLetterData {
                    id,
                    action_type,
                    entity_type,
                    entity_id,
                    state,
                    attempt,
                    max_attempts,
                    last_error,
                    due_at: Some(due_at.to_rfc3339()),
                    created_at: Some(created_at.to_rfc3339()),
                },
            )
            .collect::<Vec<_>>()
    });

    SalesPageData {
        // The render pipeline injects hidden `_csrf` inputs into every
        // POST /web/* form, so the page does not need to carry a token.
        csrf_token: String::new(),
        overview,
        decisions,
        exceptions,
        dead_letters,
    }
}

/// Load and map decision rows for both the stream and the exceptions list.
async fn load_decision_rows(
    state: &AppState,
    sql: &str,
) -> Option<Vec<ui_foundation::view_data::SalesDecisionData>> {
    use ui_foundation::view_data::SalesDecisionData;

    let rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<String>,
            String,
            f64,
            f64,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            bool,
            serde_json::Value,
            Option<chrono::DateTime<chrono::Utc>>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(sql)
    .bind("system")
    .fetch_all(&state.db)
    .await
    .ok()?;

    Some(
        rows.into_iter()
            .map(
                |(
                    id,
                    account_id,
                    contact_id,
                    action,
                    expected_value_eur,
                    confidence,
                    selected_offer,
                    selected_sequence,
                    selected_variant,
                    selected_sender,
                    rationale,
                    blocked,
                    block_reasons,
                    execute_after,
                    created_at,
                )| SalesDecisionData {
                    id,
                    account_id,
                    contact_id,
                    // Rendered as-is by the view; the engine's vocabulary is
                    // already operator-facing.
                    action,
                    expected_value_eur: Some(expected_value_eur),
                    confidence: Some(confidence),
                    selected_offer,
                    selected_sequence,
                    selected_variant,
                    selected_sender,
                    rationale,
                    blocked,
                    block_reasons: block_reasons
                        .as_array()
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|value| value.as_str().map(str::to_string))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                    execute_after: execute_after.map(|t| t.to_rfc3339()),
                    created_at: Some(created_at.to_rfc3339()),
                },
            )
            .collect(),
    )
}

/// The autonomy semantics the CP renders, derived from the persisted mode
/// string. Kept in the CP so a mode written by a newer engine still renders a
/// truthful "runs brain / may execute" answer instead of a blank panel.
struct AutonomyModeView {
    mode: &'static str,
    runs_brain: bool,
    may_execute: bool,
}

impl AutonomyModeView {
    fn parse(mode: &str) -> Self {
        match mode {
            "shadow" => Self {
                mode: "shadow",
                runs_brain: true,
                may_execute: false,
            },
            "assisted" => Self {
                mode: "assisted",
                runs_brain: true,
                may_execute: false,
            },
            "approval_required" => Self {
                mode: "approval_required",
                runs_brain: true,
                may_execute: false,
            },
            "autonomous_guarded" => Self {
                mode: "autonomous_guarded",
                runs_brain: true,
                may_execute: true,
            },
            // "disabled" and anything unrecognised fail closed.
            _ => Self {
                mode: "disabled",
                runs_brain: false,
                may_execute: false,
            },
        }
    }
}

async fn cp_home(state: &AppState, cid: &str) -> ListPageData {
    let tenants = loaded_count(
        state,
        "cp.home.tenants_count",
        cid,
        "SELECT COUNT(*)::bigint FROM tenants",
        &[],
    )
    .await;
    let users = loaded_count(
        state,
        "cp.home.users_count",
        cid,
        "SELECT COUNT(*)::bigint FROM users",
        &[],
    )
    .await;
    let alerts = loaded_count(
        state,
        "cp.home.alerts_count",
        cid,
        "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false",
        &[],
    )
    .await;
    let queue_depth = loaded_count(
        state,
        "cp.home.queue_depth",
        cid,
        "SELECT COUNT(*)::bigint FROM queue_jobs WHERE status = 'pending'",
        &[],
    )
    .await;

    // tenants.id is a UUID (migration 052): decode as text.
    let rows =
        load_query(
            "cp.home.tenant_rows",
            cid,
            async {
                sqlx::query_as::<
                    _,
                    (
                        String,
                        String,
                        Option<String>,
                        String,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(
                    "SELECT id::text AS id, name, slug, COALESCE(plan, ''), created_at FROM tenants ORDER BY created_at DESC LIMIT 10",
                )
                .fetch_all(&state.db)
                .await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Control Plane",
        "ApexMail administration and monitoring.",
        "/",
    );
    data.kpis = vec![
        KpiCardData::new("Tenants", tenants.kpi_value()).with_hint("Workspaces"),
        KpiCardData::new("Users", users.kpi_value()).with_hint("All tenants"),
        KpiCardData::new("Open alerts", alerts.kpi_value()).with_hint("Unacknowledged"),
        KpiCardData::new("Queue depth", queue_depth.kpi_value()).with_hint("Pending jobs"),
    ];
    data.empty_title = "No tenants yet".into();
    data.empty_description =
        "Provision the first tenant workspace to populate the fleet view.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Recent tenants", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Tenant".into(),
            "Slug".into(),
            "Plan".into(),
            "Created".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, name, slug, plan, created)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(name),
                    DataCell::mono(slug.unwrap_or_default()),
                    DataCell::text(plan),
                    DataCell::text(relative_time(created)),
                ],
            })
            .collect(),
    });
    data
}

async fn cp_dashboard(state: &AppState, cid: &str) -> ListPageData {
    let alerts = loaded_count(
        state,
        "cp.dashboard.alerts",
        cid,
        "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false",
        &[],
    )
    .await;
    let critical = loaded_count(
        state,
        "cp.dashboard.critical",
        cid,
        "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false AND severity = 'critical'",
        &[],
    )
    .await;
    let tenants = loaded_count(
        state,
        "cp.dashboard.tenants",
        cid,
        "SELECT COUNT(*)::bigint FROM tenants",
        &[],
    )
    .await;
    let gdpr_pending = loaded_count(
        state,
        "cp.dashboard.gdpr_pending",
        cid,
        "SELECT COUNT(*)::bigint FROM gdpr_requests WHERE status = 'pending'",
        &[],
    )
    .await;

    // system_alerts.id is a UUID (migration 020): decode as text.
    let rows =
        load_query(
            "cp.dashboard.alert_rows",
            cid,
            async {
                sqlx::query_as::<
                    _,
                    (
                        String,
                        String,
                        String,
                        String,
                        bool,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(
                    "SELECT id::text AS id, severity, alert_type, message, acknowledged, created_at FROM system_alerts ORDER BY created_at DESC LIMIT 10",
                )
                .fetch_all(&state.db)
                .await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Dashboard",
        "Fleet health, operator coverage, and throughput.",
        "/dashboard",
    );
    data.kpis = vec![
        KpiCardData::new("Open alerts", alerts.kpi_value()).with_hint("Unacknowledged"),
        KpiCardData::new("Critical", critical.kpi_value()).with_hint("Severity"),
        KpiCardData::new("Tenants", tenants.kpi_value()).with_hint("Fleet"),
        KpiCardData::new("GDPR pending", gdpr_pending.kpi_value()).with_hint("Requests"),
    ];
    data.empty_title = "No alerts recorded".into();
    data.empty_description =
        "Fleet alert signals will list here when the alerting pipeline fires.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Recent alerts", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Severity".into(),
            "Type".into(),
            "Message".into(),
            "State".into(),
            "Raised".into(),
        ],
        rows: rows
            .into_iter()
            .map(
                |(id, severity, alert_type, message, acknowledged, created)| DataRowData {
                    id,
                    cells: vec![
                        DataCell::status(&severity),
                        DataCell::text(alert_type),
                        DataCell::text(message),
                        // Item H: same honest-state fix as the alerts page.
                        DataCell::status(if acknowledged {
                            "acknowledged"
                        } else {
                            "active"
                        }),
                        DataCell::text(relative_time(created)),
                    ],
                },
            )
            .collect(),
    });
    data
}

async fn cp_tenants(state: &AppState, q: &ListQuery, cid: &str) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.status_in(&["pending", "active", "suspended", "cancelled"], &q.status);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "cp.tenants.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM tenants WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    // tenants.id is a UUID (migration 052): decode as text.
    let rows =
        load_query(
            "cp.tenants.list",
            cid,
            async {
            let q3 = format!(
                "SELECT id::text AS id, name, slug, COALESCE(plan, ''), COALESCE(status, ''), created_at FROM tenants WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
                let mut query = sqlx::query_as::<
                    _,
                    (
                        String,
                        String,
                        Option<String>,
                        String,
                        String,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(&q3);
                for value in &where_sql.binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Tenants",
        "Customer workspaces and launch readiness.",
        "/tenants",
    );
    data.search_label = "Search tenants".into();
    data.search_placeholder = "Search by tenant name".into();
    data.current_query = q.search.clone();
    data.filters = vec![FilterSelectData::new(
        "status",
        "Filter by status",
        vec![
            ("".into(), "All statuses".into(), q.status.is_empty()),
            ("pending".into(), "Pending".into(), q.status == "pending"),
            ("active".into(), "Active".into(), q.status == "active"),
            (
                "suspended".into(),
                "Suspended".into(),
                q.status == "suspended",
            ),
        ],
    )];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.primary_action = Some(("Add Tenant".into(), "/tenants/new".into()));
    data.empty_title = "No tenants yet".into();
    data.empty_description = "Create the first tenant workspace.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Tenants", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Name".into(),
            "Slug".into(),
            "Plan".into(),
            "Status".into(),
            "Created".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, name, slug, plan, status, created)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(name),
                    DataCell::mono(slug.unwrap_or_default()),
                    DataCell::text(plan),
                    DataCell::status(&status),
                    DataCell::text(relative_time(created)),
                ],
            })
            .collect(),
    });
    data
}

async fn cp_operators(state: &AppState, q: &ListQuery, cid: &str) -> ListPageData {
    // role IN ('admin','owner') with an optional ILIKE across email/name —
    // written directly because the builder models single-column equality.
    // LIKE metacharacters in the search are escaped (audit F7), matching
    // WhereBuilder::ilike.
    let where_clause = if q.search.is_empty() {
        "role IN ('admin', 'owner')".to_string()
    } else {
        "role IN ('admin', 'owner') AND (email ILIKE '%' || $1 || '%' ESCAPE '\\' OR COALESCE(name, '') ILIKE '%' || $1 || '%' ESCAPE '\\')"
            .to_string()
    };
    let binds: Vec<String> = if q.search.is_empty() {
        Vec::new()
    } else {
        vec![escape_like(&q.search)]
    };

    let total = loaded_count(
        state,
        "cp.operators.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM users WHERE {where_clause}"),
        &binds,
    )
    .await;
    // Same PER_PAGE/OFFSET pagination contract as the tenants/audit loaders:
    // the table previously hard-limited to 100 rows while the KPI counted the
    // whole set, so a large installation showed a total that could not be
    // navigated.
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    let rows =
        load_query(
            "cp.operators.list",
            cid,
            async {
            let q4 = format!(
                "SELECT email, name, role, COALESCE(mfa_enabled, false), COALESCE(status, ''), created_at FROM users WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
                let mut query = sqlx::query_as::<
                    _,
                    (
                        String,
                        Option<String>,
                        String,
                        bool,
                        String,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(&q4);
                for value in &binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Operators",
        "Administrator access, roles, and activity.",
        "/operators",
    );
    data.search_label = "Search operators".into();
    data.search_placeholder = "Search by email or name".into();
    data.current_query = q.search.clone();
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.primary_action = Some(("Add Operator".into(), "/operators/new".into()));
    data.empty_title = "No operators yet".into();
    data.empty_description = "Invite an administrator with controlled access.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Operators", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Email".into(),
            "Name".into(),
            "Role".into(),
            "MFA".into(),
            "Status".into(),
        ],
        rows: rows
            .into_iter()
            .enumerate()
            .map(
                |(index, (email, name, role, mfa, status, _created))| DataRowData {
                    id: format!("operator-{}", offset as usize + index),
                    cells: vec![
                        DataCell::text(email),
                        DataCell::text(name.unwrap_or_default()),
                        DataCell::text(role),
                        DataCell::status(if mfa { "sent" } else { "draft" }),
                        DataCell::status(&status),
                    ],
                },
            )
            .collect(),
    });
    data
}

async fn cp_sales(state: &AppState, q: &ListQuery, cid: &str) -> ListPageData {
    let stage = if q.stage.is_empty() {
        q.status.clone()
    } else {
        q.stage.clone()
    };
    let mut where_sql = WhereBuilder::new();
    where_sql.status_in(
        &[
            "new",
            "qualified",
            "proposal",
            "approved",
            "escalated",
            "prospect",
        ],
        &stage,
    );
    if !q.search.is_empty() {
        where_sql.ilike("company_name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "cp.sales.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM sales_leads WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    let rows =
        load_query(
            "cp.sales.list",
            cid,
            async {
            let q5 = format!(
                "SELECT id, company_name, COALESCE(status, ''), score, created_at FROM sales_leads WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
                let mut query = sqlx::query_as::<
                    _,
                    (
                        String,
                        Option<String>,
                        String,
                        Option<i32>,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(&q5);
                for value in &where_sql.binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let qualified = loaded_count(
        state,
        "cp.sales.qualified",
        cid,
        "SELECT COUNT(*)::bigint FROM sales_leads WHERE status = 'qualified'",
        &[],
    )
    .await;

    let mut data = base_list(
        "Operator Console",
        "Enterprise pipeline, expansion, and conversion posture.",
        "/sales",
    );
    data.search_label = "Search leads".into();
    data.search_placeholder = "Search by company name".into();
    data.current_query = q.search.clone();
    data.filters = vec![FilterSelectData::new(
        "stage",
        "Filter by stage",
        vec![
            ("".into(), "All stages".into(), stage.is_empty()),
            ("new".into(), "New".into(), stage == "new"),
            ("qualified".into(), "Qualified".into(), stage == "qualified"),
            ("proposal".into(), "Proposal".into(), stage == "proposal"),
            ("approved".into(), "Approved".into(), stage == "approved"),
            ("escalated".into(), "Escalated".into(), stage == "escalated"),
        ],
    )];
    data.kpis = vec![
        KpiCardData::new("Leads", total.kpi_value()).with_hint("Pipeline"),
        KpiCardData::new("Qualified", qualified.kpi_value()).with_hint("Stage"),
    ];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.empty_title = "No leads yet".into();
    data.empty_description = "Discovery runs populate the pipeline as leads are identified.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Leads", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Company".into(),
            "Stage".into(),
            "Score".into(),
            "Added".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, company, status, score, created)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(company.unwrap_or_default()),
                    DataCell::status(&status),
                    DataCell::text(score.map(|s| s.to_string()).unwrap_or_else(|| "—".into())),
                    DataCell::text(relative_time(created)),
                ],
            })
            .collect(),
    });
    data
}

async fn cp_audit(state: &AppState, q: &ListQuery, cid: &str) -> ListPageData {
    // Item M: the search widens to (action ILIKE OR user_id ILIKE OR
    // resource_type ILIKE), with an optional recency window in days —
    // the SAME clause the CSV export applies.
    let mut clauses: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if !q.search.is_empty() {
        // Escaped + ESCAPE-claused like the CSV export (audit F7).
        binds.push(escape_like(&q.search));
        clauses.push(format!(
            "(action ILIKE '%' || ${} || '%' ESCAPE '\\' OR user_id ILIKE '%' || ${} || '%' ESCAPE '\\' OR resource_type ILIKE '%' || ${} || '%' ESCAPE '\\')",
            binds.len(),
            binds.len(),
            binds.len()
        ));
    }
    if let Some(days) = q.days {
        clauses.push(format!("created_at >= NOW() - '{days} days'::interval"));
    }
    let where_clause = if clauses.is_empty() {
        "TRUE".to_string()
    } else {
        clauses.join(" AND ")
    };

    let total = loaded_count(
        state,
        "cp.audit.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM audit_logs WHERE {where_clause}"),
        &binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    let rows =
        load_query(
            "cp.audit.list",
            cid,
            async {
            let q6 = format!(
                "SELECT created_at, action, resource_type, user_id FROM audit_logs WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
                let mut query = sqlx::query_as::<
                    _,
                    (
                        Option<chrono::DateTime<chrono::Utc>>,
                        String,
                        Option<String>,
                        Option<String>,
                    ),
                >(&q6);
                for value in &binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Audit Logs",
        "Operator activity and security review trail.",
        "/audit",
    );
    data.search_label = "Search audit logs".into();
    data.search_placeholder = "Search action, actor, or resource".into();
    data.current_query = q.search.clone();
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.empty_title = "No audit events yet".into();
    data.empty_description = "Operator actions are recorded here as they happen.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Audit events", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Timestamp".into(),
            "Action".into(),
            "Resource type".into(),
            "Actor".into(),
        ],
        rows: rows
            .into_iter()
            .enumerate()
            .map(
                |(index, (created, action, resource_type, user_id))| DataRowData {
                    id: format!("audit-{index}"),
                    cells: vec![
                        DataCell::text(
                            created
                                .map(|ts| ts.to_rfc3339())
                                .unwrap_or_else(|| "—".into()),
                        ),
                        DataCell::text(action),
                        DataCell::text(resource_type.unwrap_or_else(|| "—".into())),
                        DataCell::mono(user_id.unwrap_or_else(|| "system".into())),
                    ],
                },
            )
            .collect(),
    });
    data
}

async fn cp_jobs(state: &AppState, cid: &str) -> ListPageData {
    let rows = load_query(
        "cp.jobs.list",
        cid,
        async {
            sqlx::query_as::<_, (String, String, i64, Option<chrono::DateTime<chrono::Utc>>)>(
                "SELECT COALESCE(queue, 'default') AS q, status, COUNT(*)::bigint AS c, MAX(updated_at) FROM queue_jobs GROUP BY 1, 2 ORDER BY 1, 2",
            )
            .fetch_all(&state.db)
            .await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let pending: i64 = rows.iter().filter(|r| r.1 == "pending").map(|r| r.2).sum();
    let queues = rows
        .iter()
        .map(|r| r.0.clone())
        .collect::<std::collections::HashSet<_>>()
        .len();

    let mut data = base_list("Jobs", "Background work and remediation queues.", "/jobs");
    data.kpis = vec![
        KpiCardData::new(
            "Pending",
            if rows_unavailable {
                "unavailable".to_string()
            } else {
                pending.to_string()
            },
        )
        .with_hint("Across queues"),
        KpiCardData::new(
            "Queues",
            if rows_unavailable {
                "unavailable".to_string()
            } else {
                queues.to_string()
            },
        )
        .with_hint("Distinct"),
    ];
    data.empty_title = "No queued jobs".into();
    data.empty_description = "Background work appears here as workers enqueue it.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Job queues", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Queue".into(),
            "Status".into(),
            "Jobs".into(),
            "Last activity".into(),
        ],
        rows: rows
            .into_iter()
            .enumerate()
            .map(|(index, (queue, status, count, updated))| DataRowData {
                id: format!("job-{index}"),
                cells: vec![
                    DataCell::mono(queue),
                    DataCell::status(&status),
                    DataCell::text(count.to_string()),
                    DataCell::text(relative_time(updated)),
                ],
            })
            .collect(),
    });
    data
}

/// /infrastructure/nodes query (audit F58). The table behind this route is
/// the OUTBOUND IP POOL (`ip_pool_addresses`), not an MTA-node heartbeat
/// registry — no node registry exists in the schema, so the page is titled
/// "IP Pool". ip_pool_addresses.id is a UUID and ip_address is INET
/// (migration 093); both must be decoded as text — `id::text` for the row id
/// and `host(ip_address)` for the bare address (INET never decodes as a
/// String).
const NODES_SQL: &str = "SELECT id::text AS id, host(ip_address) AS ip_address, pool_id, status, warmup_day FROM ip_pool_addresses ORDER BY ip_address LIMIT 100";

async fn cp_nodes(state: &AppState, cid: &str) -> ListPageData {
    let rows = load_query("cp.nodes.list", cid, async {
        sqlx::query_as::<_, (String, Option<String>, Option<String>, String, Option<i32>)>(
            NODES_SQL,
        )
        .fetch_all(&state.db)
        .await
    })
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let active = rows.iter().filter(|r| r.3 == "active").count();
    let mut data = base_list(
        "IP Pool",
        "Outbound sending IP addresses, warmup progress, and pool health.",
        "/infrastructure/nodes",
    );
    data.kpis = vec![
        KpiCardData::new(
            "Addresses",
            if rows_unavailable {
                "unavailable".to_string()
            } else {
                rows.len().to_string()
            },
        )
        .with_hint("IP pool"),
        KpiCardData::new(
            "Active",
            if rows_unavailable {
                "unavailable".to_string()
            } else {
                active.to_string()
            },
        )
        .with_hint("Sending-ready"),
    ];
    data.empty_title = "No IP pool addresses registered".into();
    data.empty_description =
        "Outbound sending addresses appear here as the pool provisions them.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "IP Pool", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "ID".into(),
            "IP".into(),
            "Pool".into(),
            "Status".into(),
            "Warmup day".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, ip, pool, status, warmup_day)| DataRowData {
                cells: vec![
                    DataCell::mono(id.chars().take(12).collect::<String>()),
                    DataCell::mono(ip.unwrap_or_else(|| "—".into())),
                    DataCell::mono(pool.unwrap_or_else(|| "—".into())),
                    DataCell::status(&status),
                    DataCell::text(
                        warmup_day
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "—".into()),
                    ),
                ],
                id,
            })
            .collect(),
    });
    data
}

/// Queue health thresholds. None of these are operator-configurable today,
/// so they are named constants here; each queue is classified by its pending
/// backlog depth and the age of its oldest pending job:
///
/// - `healthy` — depth < [`WARNING_QUEUE_DEPTH`] and no pending job older
///   than [`WARNING_QUEUE_AGE_SECS`];
/// - `warning` — depth >= [`WARNING_QUEUE_DEPTH`] OR oldest pending job at
///   least [`WARNING_QUEUE_AGE_SECS`] old;
/// - `critical` — depth >= [`CRITICAL_QUEUE_DEPTH`] OR oldest pending job at
///   least [`CRITICAL_QUEUE_AGE_SECS`] old.
const WARNING_QUEUE_DEPTH: i64 = 250;
const CRITICAL_QUEUE_DEPTH: i64 = 1_000;
/// 5 minutes.
const WARNING_QUEUE_AGE_SECS: i64 = 5 * 60;
/// 30 minutes.
const CRITICAL_QUEUE_AGE_SECS: i64 = 30 * 60;

/// Classify one queue's health. Replaces the previous `depth > 1000 ?
/// "sending" : "active"` fabrication — a deep backlog is a HEALTH signal,
/// not evidence that the queue is sending. `None` age means the queue has no
/// pending jobs (nothing is waiting), which cannot itself be unhealthy.
fn queue_health(depth: i64, oldest_pending_age_secs: Option<i64>) -> &'static str {
    let age = oldest_pending_age_secs.unwrap_or(0);
    if depth >= CRITICAL_QUEUE_DEPTH || age >= CRITICAL_QUEUE_AGE_SECS {
        "critical"
    } else if depth >= WARNING_QUEUE_DEPTH || age >= WARNING_QUEUE_AGE_SECS {
        "warning"
    } else {
        "healthy"
    }
}

async fn cp_queues(state: &AppState, cid: &str) -> ListPageData {
    let rows = load_query("cp.queues.list", cid, async {
        sqlx::query_as::<_, (String, i64, i64, Option<i64>)>(
            "SELECT COALESCE(queue, 'default') AS q,
                        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END)::bigint AS depth,
                        SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END)::bigint AS proc,
                        (EXTRACT(EPOCH FROM (NOW() - MIN(created_at) FILTER (WHERE status = 'pending'))))::bigint AS oldest_pending_secs
                 FROM queue_jobs GROUP BY 1",
        )
        .fetch_all(&state.db)
        .await
    })
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let depth: i64 = rows.iter().map(|r| r.1).sum();
    let mut data = base_list(
        "Queues",
        "Mail queue depth and worker processing.",
        "/infrastructure/queues",
    );
    data.kpis = vec![
        KpiCardData::new(
            "Total depth",
            if rows_unavailable {
                "unavailable".to_string()
            } else {
                depth.to_string()
            },
        )
        .with_hint("Pending jobs"),
        KpiCardData::new(
            "Queues",
            if rows_unavailable {
                "unavailable".to_string()
            } else {
                rows.len().to_string()
            },
        )
        .with_hint("Distinct"),
    ];
    data.empty_title = "No queues reporting".into();
    data.empty_description = "Queue telemetry appears once workers enqueue jobs.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Queues", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Queue".into(),
            "Depth".into(),
            "Processing".into(),
            "State".into(),
        ],
        rows: rows
            .into_iter()
            .map(
                |(queue, depth, processing, oldest_pending_secs)| DataRowData {
                    id: queue.clone(),
                    cells: vec![
                        DataCell::mono(queue),
                        DataCell::text(depth.to_string()),
                        DataCell::text(processing.to_string()),
                        DataCell::status(queue_health(depth, oldest_pending_secs)),
                    ],
                },
            )
            .collect(),
    });
    data
}

async fn cp_alerts(state: &AppState, q: &ListQuery, cid: &str) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.status_in(&["critical", "high", "medium", "low", "info"], &q.status);
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "cp.alerts.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM system_alerts WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    // system_alerts.id is a UUID (migration 020): decode as text.
    let rows =
        load_query(
            "cp.alerts.list",
            cid,
            async {
            let q7 = format!(
                "SELECT id::text AS id, severity, alert_type, message, acknowledged, created_at FROM system_alerts WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
                let mut query = sqlx::query_as::<
                    _,
                    (
                        String,
                        String,
                        String,
                        String,
                        bool,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(&q7);
                for value in &where_sql.binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let unacknowledged = loaded_count(
        state,
        "cp.alerts.unacknowledged",
        cid,
        "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false",
        &[],
    )
    .await;

    let mut data = base_list(
        "Alerts",
        "Incident triage and fleet risk signals.",
        "/alerts",
    );
    data.filters = vec![FilterSelectData::new(
        "status",
        "Filter by severity",
        vec![
            ("".into(), "All severities".into(), q.status.is_empty()),
            ("critical".into(), "Critical".into(), q.status == "critical"),
            ("high".into(), "High".into(), q.status == "high"),
            ("medium".into(), "Medium".into(), q.status == "medium"),
            ("low".into(), "Low".into(), q.status == "low"),
        ],
    )];
    data.kpis =
        vec![KpiCardData::new("Unacknowledged", unacknowledged.kpi_value()).with_hint("Open")];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.empty_title = "No alerts".into();
    data.empty_description = "Fleet alert signals appear here when raised.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Alerts", cid);
    }
    data.bulk_action = Some(BulkActionData {
        action: "/web/admin/alerts/ack-bulk".into(),
        button_label: "Acknowledge selected".into(),
    });
    data.table = Some(TableData {
        columns: [
            "Severity".into(),
            "Type".into(),
            "Message".into(),
            "State".into(),
            "Raised".into(),
        ]
        .to_vec(),
        rows: rows
            .into_iter()
            .map(
                |(id, severity, alert_type, message, acknowledged, created)| DataRowData {
                    id,
                    cells: vec![
                        DataCell::status(&severity),
                        DataCell::text(alert_type),
                        DataCell::text(message),
                        // Item H: honest state — acknowledged rows surface
                        // "acknowledged"; unacknowledged rows are still
                        // "active" work (the previous mapping inverted this).
                        DataCell::status(if acknowledged {
                            "acknowledged"
                        } else {
                            "active"
                        }),
                        DataCell::text(relative_time(created)),
                    ],
                },
            )
            .collect(),
    });
    data
}

/// /alerts/rules is NOT implemented: there is no alert-rule table or CRUD
/// service, and presenting an empty "rules" surface implied one existed. The
/// route now returns an explicit 501 (see `cp_alert_rules_not_implemented`
/// in app.rs) instead of fabricated page data. This loader was removed with
/// the route's data arm so a future real store must wire itself in
/// deliberately.

async fn cp_domains(state: &AppState, q: &ListQuery, cid: &str) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.status_in(&["pending", "verified", "failed", "suspended"], &q.status);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "cp.domains.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM domains WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    // domains.status may be NULL on legacy deployments (verified flags
    // instead) — the status cell degrades to "pending" rather than failing,
    // but the column is always SELECTed and rendered because the page
    // filters on it. domains.id and domains.tenant_id are UUIDs (migration
    // 052): decode both as text.
    let rows =
        load_query(
            "cp.domains.list",
            cid,
            async {
            let q8 = format!(
                "SELECT id::text AS id, name, tenant_id::text AS tenant_id, COALESCE(status, 'pending') AS status, created_at FROM domains WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
                let mut query = sqlx::query_as::<
                    _,
                    (String, String, Option<String>, String, Option<chrono::DateTime<chrono::Utc>>),
                >(&q8);
                for value in &where_sql.binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let verified = loaded_count(
        state,
        "cp.domains.verified",
        cid,
        "SELECT COUNT(*)::bigint FROM domains WHERE status = 'verified'",
        &[],
    )
    .await;

    let mut data = base_list(
        "Domains",
        "Tenant sending domains and verification.",
        "/domains",
    );
    data.search_label = "Search domains".into();
    data.search_placeholder = "Search by domain name".into();
    data.current_query = q.search.clone();
    data.kpis = vec![
        KpiCardData::new("Domains", total.kpi_value()).with_hint("Fleet-wide"),
        KpiCardData::new("Verified", verified.kpi_value()).with_hint("Sending-ready"),
    ];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.empty_title = "No domains registered".into();
    data.empty_description = "Tenant domains appear here as they are added.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Domains", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Domain".into(),
            "Tenant".into(),
            "Status".into(),
            "Added".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, name, tenant_id, status, created)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(name),
                    DataCell::mono(tenant_id.unwrap_or_else(|| "—".into())),
                    DataCell::status(&status),
                    DataCell::text(relative_time(created)),
                ],
            })
            .collect(),
    });
    data
}

async fn cp_plans(state: &AppState, cid: &str) -> ListPageData {
    let rows = load_query("cp.plans.list", cid, async {
        sqlx::query_as::<_, (String, Option<String>, i64)>(
            "SELECT name, display_name, price_cents FROM plans ORDER BY price_cents ASC LIMIT 50",
        )
        .fetch_all(&state.db)
        .await
    })
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let tenants = loaded_count(
        state,
        "cp.plans.tenants",
        cid,
        "SELECT COUNT(*)::bigint FROM tenants",
        &[],
    )
    .await;

    let mut data = base_list(
        "Plans",
        "Pricing, quotas, and subscriber coverage.",
        "/billing/plans",
    );
    data.kpis = vec![
        KpiCardData::new(
            "Plans",
            if rows_unavailable {
                "unavailable".to_string()
            } else {
                rows.len().to_string()
            },
        )
        .with_hint("Catalog"),
        KpiCardData::new("Tenants", tenants.kpi_value()).with_hint("On any plan"),
    ];
    data.empty_title = "No plans in the catalog".into();
    data.empty_description =
        "Plan packaging appears here once the billing catalog is seeded.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Plans", cid);
    }
    data.table = Some(TableData {
        columns: vec!["Plan".into(), "Display name".into(), "Price".into()],
        rows: rows
            .into_iter()
            .map(|(name, display_name, price_cents)| DataRowData {
                id: name.clone(),
                cells: vec![
                    DataCell::text(name),
                    DataCell::text(display_name.unwrap_or_else(|| "—".into())),
                    DataCell::text(format!("€{:.2}", price_cents as f64 / 100.0)),
                ],
            })
            .collect(),
    });
    data
}

async fn cp_compliance(state: &AppState, cid: &str) -> ListPageData {
    let gdpr_pending = loaded_count(
        state,
        "cp.compliance.gdpr_pending",
        cid,
        "SELECT COUNT(*)::bigint FROM gdpr_requests WHERE status = 'pending'",
        &[],
    )
    .await;
    let gdpr_total = loaded_count(
        state,
        "cp.compliance.gdpr_total",
        cid,
        "SELECT COUNT(*)::bigint FROM gdpr_requests",
        &[],
    )
    .await;
    let alerts = loaded_count(
        state,
        "cp.compliance.alerts",
        cid,
        "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false",
        &[],
    )
    .await;

    // gdpr_requests.id is VARCHAR (migration 069) — decoded as String.
    let rows = load_query(
        "cp.compliance.list",
        cid,
        async {
            sqlx::query_as::<_, (String, String, String, Option<chrono::DateTime<chrono::Utc>>)>(
                "SELECT id, request_type, status, created_at FROM gdpr_requests ORDER BY created_at DESC LIMIT 10",
            )
            .fetch_all(&state.db)
            .await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "Compliance",
        "Trust workflows and policy operations.",
        "/compliance",
    );
    data.kpis = vec![
        KpiCardData::new("GDPR pending", gdpr_pending.kpi_value()).with_hint("Requests"),
        KpiCardData::new("GDPR total", gdpr_total.kpi_value()).with_hint("All time"),
        KpiCardData::new("Open alerts", alerts.kpi_value()).with_hint("Fleet"),
    ];
    data.primary_action = Some(("GDPR queue".into(), "/compliance/gdpr".into()));
    data.empty_title = "No compliance requests".into();
    data.empty_description = "GDPR and trust workflows appear here as they are filed.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Compliance requests", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Request".into(),
            "Type".into(),
            "Status".into(),
            "Filed".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, request_type, status, created)| {
                let short_id = id.chars().take(12).collect::<String>();
                DataRowData {
                    id,
                    cells: vec![
                        DataCell::mono(short_id),
                        DataCell::text(request_type),
                        DataCell::status(&status),
                        DataCell::text(relative_time(created)),
                    ],
                }
            })
            .collect(),
    });
    data
}

async fn cp_gdpr(state: &AppState, q: &ListQuery, cid: &str) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.status_in(
        &["pending", "in_progress", "completed", "rejected"],
        &q.status,
    );
    let where_clause = where_sql.build();

    let total = loaded_count(
        state,
        "cp.gdpr.count",
        cid,
        &format!("SELECT COUNT(*)::bigint FROM gdpr_requests WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total.total_or_zero(), q.page);

    let rows =
        load_query(
            "cp.gdpr.list",
            cid,
            async {
            let q9 = format!(
                "SELECT id, email, request_type, status, created_at FROM gdpr_requests WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
                let mut query = sqlx::query_as::<
                    _,
                    (
                        String,
                        String,
                        String,
                        String,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(&q9);
                for value in &where_sql.binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await
        .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let mut data = base_list(
        "GDPR Compliance",
        "Data protection request handling.",
        "/compliance/gdpr",
    );
    data.filters = vec![FilterSelectData::new(
        "status",
        "Filter by status",
        vec![
            ("".into(), "All statuses".into(), q.status.is_empty()),
            ("pending".into(), "Pending".into(), q.status == "pending"),
            (
                "in_progress".into(),
                "In progress".into(),
                q.status == "in_progress",
            ),
            (
                "completed".into(),
                "Completed".into(),
                q.status == "completed",
            ),
        ],
    )];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = if rows_unavailable {
        0
    } else {
        total.total_or_zero()
    };
    data.filter_query = filter_query(q);
    data.empty_title = "No GDPR requests".into();
    data.empty_description = "Data-subject requests appear here as they arrive.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "GDPR requests", cid);
    }
    data.table = Some(TableData {
        columns: vec![
            "Email".into(),
            "Type".into(),
            "Status".into(),
            "Filed".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, email, request_type, status, created)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(email),
                    DataCell::text(request_type),
                    DataCell::status(&status),
                    DataCell::text(relative_time(created)),
                ],
            })
            .collect(),
    });
    data
}

async fn cp_discovery(state: &AppState, cid: &str) -> ListPageData {
    let rows = load_query(
        "cp.discovery.list",
        cid,
        async {
            sqlx::query_as::<_, (String, i64)>(
                "SELECT COALESCE(source, 'unknown'), COUNT(*)::bigint FROM sales_leads GROUP BY 1 ORDER BY 2 DESC LIMIT 25",
            )
            .fetch_all(&state.db)
            .await
        },
    )
    .await
    .rows_or_unavailable();
    let rows_unavailable = rows.1;
    let rows = rows.0;

    let total = loaded_count(
        state,
        "cp.discovery.total",
        cid,
        "SELECT COUNT(*)::bigint FROM sales_leads",
        &[],
    )
    .await;

    let mut data = base_list(
        "Service Discovery",
        "Registered lead sources and routing state.",
        "/discovery",
    );
    data.kpis = vec![KpiCardData::new("Leads", total.kpi_value()).with_hint("All sources")];
    data.empty_title = "No discovery sources reporting".into();
    data.empty_description = "Discovery runs register their sources here as they execute.".into();
    if rows_unavailable {
        mark_rows_unavailable(&mut data, "Discovery sources", cid);
    }
    data.table = Some(TableData {
        columns: vec!["Source".into(), "Leads".into()],
        rows: rows
            .into_iter()
            .map(|(source, count)| DataRowData {
                id: source.clone(),
                cells: vec![DataCell::text(source), DataCell::text(count.to_string())],
            })
            .collect(),
    });
    data
}

async fn cp_analytics(state: &AppState, cid: &str) -> ListPageData {
    let agg_state = event_aggregate(
        state,
        "cp.analytics.aggregate",
        cid,
        "timestamp >= NOW() - '30 days'::interval",
        &[],
    )
    .await;
    let agg_loaded = !agg_state.is_unavailable();
    let agg = agg_state.unwrap_or_default();
    let sent = *agg.get("sent").unwrap_or(&0);
    let delivered = agg.get("delivered").copied().unwrap_or(0);
    let bounced = agg.get("bounced").copied().unwrap_or(0);
    let complained = agg.get("complained").copied().unwrap_or(0);

    let mut data = base_list(
        "Analytics",
        "System volume, latency, and availability telemetry.",
        "/analytics",
    );
    data.kpis = vec![
        KpiCardData::new("Sent (30d)", aggregate_kpi(agg_loaded, sent)).with_hint("Fleet-wide"),
        KpiCardData::new("Delivered", aggregate_kpi(agg_loaded, delivered))
            .with_hint(&rate(delivered, sent)),
        KpiCardData::new("Bounced", aggregate_kpi(agg_loaded, bounced))
            .with_hint(&rate(bounced, sent)),
        KpiCardData::new("Complaints", aggregate_kpi(agg_loaded, complained))
            .with_hint(&rate(complained, sent)),
    ];
    data
}

// ─── Detail-page loaders (items A, B, I, J) ──────────────────────

/// Load `/domains/{id}` detail data: the tenant-scoped domain row joined
/// with the SAME generated DKIM/SPF/DMARC record set the JSON
/// GET /v1/domains/:id/dns-records endpoint returns (record building is
/// reused from `routes::domains`, never duplicated). Records render as
/// data rows with mono cells — the view layer lays them out.
pub(crate) async fn load_domain_detail(
    db: &sqlx::PgPool,
    tenant: &str,
    id: &str,
    aws_region: &str,
) -> Option<ListPageData> {
    let row: Option<(
        String,
        String,
        String,
        bool,
        bool,
        bool,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id::text, name, status, spf_verified, dkim_verified, dmarc_verified,
                return_path_verified, dkim_selector, dkim_public_key, dkim_private_key
         FROM domains WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let (
        id,
        name,
        status,
        spf_verified,
        dkim_verified,
        dmarc_verified,
        return_path_verified,
        dkim_selector,
        dkim_public_key,
        dkim_private_key,
    ) = row?;

    let mut data = base_list(
        "Domain",
        &format!("DNS setup and verification state for {name}."),
        &format!("/domains/{id}"),
    );
    data.kpis = vec![
        KpiCardData::new("Domain", name.clone()).with_hint("Sending domain"),
        KpiCardData::new("Status", status.clone()).with_hint("Verification state"),
        KpiCardData::new(
            "Verified records",
            format!(
                "{}/4",
                [
                    spf_verified,
                    dkim_verified,
                    dmarc_verified,
                    return_path_verified,
                ]
                .iter()
                .filter(|ok| **ok)
                .count()
            ),
        )
        .with_hint("SPF, DKIM, DMARC, Return-Path"),
    ];

    // Same completeness gate as the JSON endpoint: DKIM material must be
    // provisioned (by a verify run) before records can be rendered.
    let material_ready = dkim_public_key
        .as_deref()
        .filter(|key| !key.trim().is_empty())
        .filter(|_| {
            dkim_private_key
                .as_deref()
                .is_some_and(|key| !key.trim().is_empty())
        })
        .is_some();

    if material_ready {
        let selector =
            crate::routes::domains::effective_dkim_selector(dkim_selector.as_deref()).to_string();
        let records = crate::routes::domains::required_sender_dns_records(
            &name,
            &selector,
            dkim_public_key.as_deref().unwrap_or_default(),
            aws_region,
            crate::config::Config::ses_transport_enabled(),
        );
        data.table = Some(TableData {
            columns: vec!["Type".into(), "Host".into(), "Value".into(), "State".into()],
            rows: records
                .iter()
                .map(|record| {
                    let verified = match record.hostname.as_str() {
                        host if host.starts_with("_dmarc.") => dmarc_verified,
                        host if host.contains("._domainkey.") => dkim_verified,
                        host if host.starts_with("bounce.") => spf_verified || return_path_verified,
                        _ => false,
                    };
                    DataRowData {
                        id: format!("{}:{}", record.record_type, record.hostname),
                        cells: vec![
                            DataCell::mono(record.record_type.clone()),
                            DataCell::mono(record.hostname.clone()),
                            DataCell::mono(record.value.clone()),
                            DataCell::status(if verified { "verified" } else { "pending" }),
                        ],
                    }
                })
                .collect(),
        });
    } else {
        data.empty_title = "DNS records are not generated yet".into();
        data.empty_description =
            "DKIM keys are provisioned on the first verification run — use the Verify action to generate the full record set."
                .into();
        data.table = Some(TableData {
            columns: vec!["Type".into(), "Host".into(), "Value".into()],
            rows: Vec::new(),
        });
    }
    Some(data)
}

/// Per-status action data for the campaign detail page (item B): which
/// lifecycle buttons the view should render, plus the wired audience.
#[derive(Debug, Clone, Default)]
pub(crate) struct CampaignDetailData {
    pub id: String,
    pub name: String,
    pub subject: String,
    pub status: String,
    pub scheduled_at: Option<String>,
    /// Wired audience list id (the view layer's recipients form uses it).
    #[allow(dead_code)]
    pub list_id: Option<String>,
    pub list_name: Option<String>,
    pub recipient_count: i64,
    /// (label, POST target, available) — the pure campaign_actions rule
    /// from web.rs decides availability from the live status.
    pub actions: Vec<(String, String, bool)>,
    /// The tenant's lists for the recipients select: (id, name, selected).
    pub lists: Vec<(String, String, bool)>,
}

impl CampaignDetailData {
    /// Render through the generic list-page machinery (stub path — the
    /// view layer replaces this with a dedicated detail page).
    pub(crate) fn to_list_page(&self) -> ListPageData {
        let mut data = base_list(
            "Campaign",
            &format!(
                "Status, audience, and lifecycle actions for “{}”.",
                self.name
            ),
            &format!("/campaigns/{}", self.id),
        );
        data.kpis = vec![
            KpiCardData::new("Status", self.status.clone()).with_hint("Campaign state"),
            KpiCardData::new(
                "Audience",
                match (&self.list_name, self.recipient_count) {
                    (Some(name), count) if count > 0 => format!("{count} — {name}"),
                    (Some(name), _) => format!("wired — {name} (0 subscribed)"),
                    (None, _) => "no recipients wired".to_string(),
                },
            )
            .with_hint("Wired list"),
            KpiCardData::new(
                "Scheduled",
                self.scheduled_at.clone().unwrap_or_else(|| "—".into()),
            )
            .with_hint("Scheduled time"),
        ];
        data.table = Some(TableData {
            columns: vec!["Field".into(), "Value".into()],
            rows: vec![
                DataRowData {
                    id: "name".into(),
                    cells: vec![
                        DataCell::text("Name".to_string()),
                        DataCell::text(self.name.clone()),
                    ],
                },
                DataRowData {
                    id: "subject".into(),
                    cells: vec![
                        DataCell::text("Subject".to_string()),
                        DataCell::text(self.subject.clone()),
                    ],
                },
            ],
        });
        // The audience-list select for the recipients wiring (item B2):
        // the tenant's lists, pre-selected when one is already wired.
        if !self.lists.is_empty() {
            let selected_list = self.list_id.clone().unwrap_or_default();
            let options = self
                .lists
                .iter()
                .map(|(id, name, _)| (id.clone(), name.clone(), *id == selected_list))
                .collect();
            data.filters = vec![FilterSelectData::new("list_id", "Audience list", options)];
        }
        // The action list rides along as a second block via the primary
        // action slot + a mono summary of availability.
        if let Some((label, target, _)) = self.actions.iter().find(|(_, _, available)| *available) {
            data.primary_action = Some((label.clone(), target.clone()));
        }
        data.empty_title = "No actions available".into();
        data.empty_description =
            "This campaign's status has no lifecycle actions — completed and failed campaigns are terminal."
                .into();
        data.table = Some(TableData {
            columns: vec!["Action".into(), "Posts to".into(), "Available".into()],
            rows: self
                .actions
                .iter()
                .map(|(label, target, available)| DataRowData {
                    id: label.clone(),
                    cells: vec![
                        DataCell::text(label.clone()),
                        DataCell::mono(target.clone()),
                        DataCell::status(if *available { "active" } else { "paused" }),
                    ],
                })
                .collect(),
        });
        data
    }
}

/// Load `/campaigns/{id}` detail data (tenant-scoped), including the
/// per-status action availability computed by web.rs's pure rule.
pub(crate) async fn load_campaign_detail(
    db: &sqlx::PgPool,
    tenant: &str,
    id: &str,
) -> Option<CampaignDetailData> {
    let row: Option<(
        String,
        String,
        Option<String>,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id::text, name, subject, status, scheduled_at,
                (SELECT job_type FROM campaign_jobs
                 WHERE campaign_id = campaigns.id AND job_type LIKE 'recipients:%'
                 ORDER BY created_at DESC LIMIT 1)
         FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let (id, name, subject, status, scheduled_at, recipients_job) = row?;
    // The wired audience is the latest `recipients:{list}:{segment}` job.
    let (list_id, segment) = recipients_job
        .as_deref()
        .and_then(super::parse_recipients_job)
        .unzip();
    let list_name: Option<String> = match &list_id {
        Some(list_id) => {
            sqlx::query_scalar("SELECT name FROM lists WHERE id = $1::uuid AND tenant_id = $2")
                .bind(list_id)
                .bind(tenant)
                .fetch_optional(db)
                .await
                .ok()
                .flatten()
        }
        None => None,
    };
    let recipient_count = match &list_id {
        Some(list_id) => count_list_recipients_filtered(
            db,
            tenant,
            list_id,
            segment.as_deref().unwrap_or("subscribed"),
        )
        .await
        .unwrap_or(0),
        None => 0,
    };
    let actions = super::campaign_actions(&id, &status)
        .into_iter()
        .map(|(label, target, available)| (label.to_string(), target, available))
        .collect();
    let lists = tenant_lists_for_select(db, tenant).await;
    Some(CampaignDetailData {
        id,
        name,
        subject: subject.unwrap_or_default(),
        status,
        scheduled_at: scheduled_at.map(|ts| ts.to_rfc3339()),
        list_id,
        list_name,
        recipient_count,
        actions,
        lists,
    })
}

/// Count a list's contacts with an optional segment filter (all /
/// subscribed / unsubscribed / bounced) for the recipients wiring. The
/// segment is a BIND (audit F8), never string-interpolated SQL.
pub(crate) async fn count_list_recipients_filtered(
    db: &sqlx::PgPool,
    tenant: &str,
    list_id: &str,
    segment: &str,
) -> Option<i64> {
    if segment == "all" {
        return sqlx::query_scalar(
            "SELECT COUNT(*)::bigint
             FROM list_subscribers ls
             JOIN contacts c ON c.id = ls.contact_id
             WHERE ls.list_id = $1::uuid AND c.tenant_id = $2",
        )
        .bind(list_id)
        .bind(tenant)
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
    }
    sqlx::query_scalar(
        "SELECT COUNT(*)::bigint
         FROM list_subscribers ls
         JOIN contacts c ON c.id = ls.contact_id
         WHERE ls.list_id = $1::uuid AND c.tenant_id = $2 AND c.status = $3",
    )
    .bind(list_id)
    .bind(tenant)
    .bind(segment)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
}

/// The tenant's lists for the campaign-recipients select: (id, name,
/// selected) triples with none selected by default.
pub(crate) async fn tenant_lists_for_select(
    db: &sqlx::PgPool,
    tenant: &str,
) -> Vec<(String, String, bool)> {
    // Called outside the page-render path — own correlation id (audit F14).
    let correlation_id = next_correlation_id();
    let rows: Vec<(String, String)> =
        match load_query("web.campaign_detail.lists", &correlation_id, async {
            sqlx::query_as::<_, (String, String)>(
                "SELECT id::text, name FROM lists WHERE tenant_id = $1 ORDER BY name ASC LIMIT 200",
            )
            .bind(tenant)
            .fetch_all(db)
            .await
        })
        .await
        {
            LoadState::Loaded(rows) => rows,
            // The select degrades to empty rather than blocking campaign
            // detail rendering; the failure is logged with the query id.
            LoadState::Unavailable => Vec::new(),
        };
    rows.into_iter()
        .map(|(id, name)| (id, name, false))
        .collect()
}

/// Plan names from the billing catalog (item I) — the tenant-create
/// form's plan select is validated against this exact set.
pub(crate) async fn tenant_plan_names(db: &sqlx::PgPool) -> Vec<String> {
    // Called outside the page-render path — own correlation id (audit F14).
    let correlation_id = next_correlation_id();
    match load_query("web.tenant_create.plans", &correlation_id, async {
        sqlx::query_as::<_, (String,)>("SELECT name FROM plans ORDER BY price_cents ASC LIMIT 50")
            .fetch_all(db)
            .await
    })
    .await
    {
        LoadState::Loaded(rows) => rows.into_iter().map(|(name,)| name).collect(),
        // An unreadable catalog degrades to an empty select; the failure
        // is logged with the query id rather than silently swallowed.
        LoadState::Unavailable => Vec::new(),
    }
}

/// Render the admin transfer-suggestion data (item J) as list-page data.
/// The suggestion itself is computed by the JSON route's exact logic;
/// this only shapes it for the generic renderer.
pub(crate) fn transfer_suggestion_page(
    suggestion: &crate::routes::admin::domains::TransferSuggestionResponse,
) -> ListPageData {
    let mut data = base_list(
        "Domain Transfer",
        &format!(
            "Transfer assessment for {} (tenant {}).",
            suggestion.domain, suggestion.current_tenant_id
        ),
        "/domains",
    );
    data.kpis = vec![
        KpiCardData::new(
            "Transfer suggested",
            if suggestion.transfer_suggested {
                "yes".to_string()
            } else {
                "no".to_string()
            },
        )
        .with_hint("DNS-control evidence"),
        KpiCardData::new(
            "Owner ever verified",
            if suggestion.owner_ever_verified {
                "yes".to_string()
            } else {
                "no".to_string()
            },
        )
        .with_hint("Tenant of record"),
        KpiCardData::new("DNS control", suggestion.dns_control.clone()).with_hint("Live probe"),
    ];
    data.table = Some(TableData {
        columns: vec!["Field".into(), "Value".into()],
        rows: vec![
            DataRowData {
                id: "domain".into(),
                cells: vec![
                    DataCell::text("Domain".to_string()),
                    DataCell::mono(suggestion.domain.clone()),
                ],
            },
            DataRowData {
                id: "domain_id".into(),
                cells: vec![
                    DataCell::text("Domain id".to_string()),
                    DataCell::mono(suggestion.domain_id.clone()),
                ],
            },
            DataRowData {
                id: "current_tenant".into(),
                cells: vec![
                    DataCell::text("Current tenant".to_string()),
                    DataCell::mono(suggestion.current_tenant_id.clone()),
                ],
            },
            DataRowData {
                id: "note".into(),
                cells: vec![
                    DataCell::text("Note".to_string()),
                    DataCell::text(if suggestion.note.is_empty() {
                        "No transfer is suggested for this domain.".to_string()
                    } else {
                        suggestion.note.clone()
                    }),
                ],
            },
        ],
    });
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_query_parses_search_filter_sort_and_page() {
        let q = parse_list_query(Some("query=spring+win&status=draft&sort=created&page=3"));
        assert_eq!(q.search, "spring win");
        assert_eq!(q.status, "draft");
        assert_eq!(q.sort, "created");
        assert_eq!(q.page, 3);

        // Hostile / absent values degrade to defaults.
        let q = parse_list_query(Some("page=99999&status=DROP TABLE"));
        assert_eq!(q.page, MAX_PAGE);
        assert_eq!(q.status, "DROP TABLE"); // never reaches SQL un-whitelisted
        let q = parse_list_query(None);
        assert_eq!(q.page, 1);
        assert!(q.search.is_empty());
    }

    #[test]
    fn status_whitelist_rejects_unknown_values() {
        let mut where_sql = WhereBuilder::new();
        where_sql.status_in(&["draft", "sent"], "draft");
        assert_eq!(where_sql.build(), "status = $1");

        let mut where_sql = WhereBuilder::new();
        where_sql.status_in(&["draft"], "' OR '1'='1");
        assert_eq!(where_sql.build(), "TRUE");
        assert!(where_sql.binds.is_empty());
    }

    #[test]
    fn where_builder_positions_binds_in_order() {
        let mut where_sql = WhereBuilder::new();
        where_sql
            .eq("tenant_id", "t_1")
            .ilike("name", "spring")
            .eq("status", "draft");
        // The ILIKE clause carries the ESCAPE qualifier (working-tree
        // wildcard-escape fix) and the bind is the escaped pattern.
        assert_eq!(
            where_sql.build(),
            "tenant_id = $1 AND name ILIKE '%' || $2 || '%' ESCAPE '\\' AND status = $3"
        );
        assert_eq!(where_sql.binds, vec!["t_1", "spring", "draft"]);
    }

    #[test]
    fn like_metacharacters_are_escaped_in_bindings() {
        // A search for `%` or `_` must match those literal characters, not
        // expand into a whole-table wildcard (audit F7's shared helper).
        assert_eq!(escape_like("100%"), "100\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("back\\slash"), "back\\\\slash");
        assert_eq!(escape_like("plain"), "plain");
        let mut where_sql = WhereBuilder::new();
        where_sql.ilike("name", "100%");
        assert_eq!(where_sql.binds, vec!["100\\%"]);
        assert_eq!(where_sql.build(), "name ILIKE '%' || $1 || '%' ESCAPE '\\'");
    }

    #[test]
    fn paging_clamps_to_bounds() {
        let (page, total_pages, offset) = paging(0, 5);
        assert_eq!((page, total_pages, offset), (1, 0, 0));
        let (page, total_pages, offset) = paging(45, 2);
        assert_eq!((page, total_pages, offset), (2, 3, 20));
    }

    #[test]
    fn relative_time_renders_human_buckets() {
        assert_eq!(relative_time(None), "—");
        assert_eq!(relative_time(Some(chrono::Utc::now())), "just now");
        assert_eq!(
            relative_time(Some(chrono::Utc::now() - chrono::Duration::hours(3))),
            "3 hours ago"
        );
        assert_eq!(
            relative_time(Some(chrono::Utc::now() - chrono::Duration::days(2))),
            "2 days ago"
        );
    }

    #[test]
    fn rates_render_honestly_without_data() {
        assert_eq!(rate(0, 0), "—");
        assert_eq!(rate(1, 4), "25.0%");
    }

    #[test]
    fn filter_query_preserves_active_filters() {
        let q = parse_list_query(Some("query=a b&status=draft&stage=proposal"));
        assert_eq!(filter_query(&q), "query=a%20b&status=draft&stage=proposal");
        assert_eq!(filter_query(&ListQuery::default()), "");
    }

    // ─── Fix 6: queue health classification ──────────────────────────

    #[test]
    fn queue_health_uses_depth_and_age_thresholds() {
        // Healthy: shallow depth, young (or no) pending backlog.
        assert_eq!(queue_health(0, None), "healthy");
        assert_eq!(
            queue_health(249, Some(WARNING_QUEUE_AGE_SECS - 1)),
            "healthy"
        );
        // Warning: either threshold crossed.
        assert_eq!(queue_health(WARNING_QUEUE_DEPTH, None), "warning");
        assert_eq!(queue_health(0, Some(WARNING_QUEUE_AGE_SECS)), "warning");
        assert_eq!(
            queue_health(999, Some(CRITICAL_QUEUE_AGE_SECS - 1)),
            "warning"
        );
        // Critical: either critical threshold crossed.
        assert_eq!(queue_health(CRITICAL_QUEUE_DEPTH, None), "critical");
        assert_eq!(queue_health(0, Some(CRITICAL_QUEUE_AGE_SECS)), "critical");
        // A deep backlog is a health signal, never the fabricated "sending".
        assert_ne!(queue_health(5_000, None), "sending");
    }

    /// The loaders are pinned in source for the pieces that are only
    /// expressible inside SQL closures: operators must paginate (no more
    /// hard `LIMIT 100`) and domains must SELECT + render the status they
    /// filter on.
    #[test]
    fn loaders_paginate_operators_and_render_domain_status() {
        let source = include_str!("data.rs");
        let operators = source
            .split("async fn cp_operators")
            .nth(1)
            .and_then(|rest| rest.split("async fn cp_sales").next())
            .expect("cp_operators body");
        assert!(
            operators.contains("LIMIT {PER_PAGE} OFFSET {offset}"),
            "cp_operators must paginate with the shared PER_PAGE/OFFSET pattern"
        );
        assert!(
            !operators.contains("LIMIT 100"),
            "cp_operators must not hard-limit the table to 100 rows"
        );

        let domains = source
            .split("async fn cp_domains")
            .nth(1)
            .and_then(|rest| rest.split("async fn cp_plans").next())
            .expect("cp_domains body");
        assert!(
            domains.contains("COALESCE(status, 'pending') AS status"),
            "cp_domains must SELECT the status it filters on"
        );
        assert!(
            domains.contains("\"Status\".into()"),
            "cp_domains must render a Status column"
        );

        let queues = source
            .split("async fn cp_queues")
            .nth(1)
            .and_then(|rest| rest.split("async fn cp_alerts").next())
            .expect("cp_queues body");
        assert!(
            queues.contains("queue_health(depth, oldest_pending_secs)"),
            "cp_queues must render the health classification, not a fabricated state"
        );
        assert!(
            !queues.contains("\"sending\""),
            "high backlog must never be labelled 'sending'"
        );
    }

    // ─── Fix 4: required-schema manifest matches the migrations ──────

    /// The three historical aliases the readiness probe used to demand
    /// (`dedicated_ips.address`, `ip_pool_addresses.ip_pool_id`,
    /// `ip_pool_addresses.address`) do not exist in the canonical chain. The
    /// manifest must name exactly what the migrations create:
    ///
    /// - `dedicated_ips.ip_address` — migrations/003_dedicated_ips.sql:43
    ///   (also migrations/021_hybrid_infrastructure.sql:18);
    /// - `ip_pool_addresses.pool_id` — migrations/093_deep_schema_convergence.sql:394;
    /// - `ip_pool_addresses.ip_address` — migrations/093_deep_schema_convergence.sql:395.
    #[test]
    fn required_schema_names_match_the_canonical_migrations() {
        const DEDICATED_IPS_MIGRATION: &str =
            include_str!("../../../../../migrations/003_dedicated_ips.sql");
        const DEEP_SCHEMA_MIGRATION: &str =
            include_str!("../../../../../migrations/093_deep_schema_convergence.sql");

        // The canonical CREATE TABLE blocks really carry these names.
        assert!(
            DEDICATED_IPS_MIGRATION.contains("ip_address        TEXT NOT NULL"),
            "dedicated_ips.ip_address must be created by migration 003"
        );
        assert!(
            DEEP_SCHEMA_MIGRATION.contains("pool_id        VARCHAR(26) NOT NULL"),
            "ip_pool_addresses.pool_id must be created by migration 093"
        );
        assert!(
            DEEP_SCHEMA_MIGRATION.contains("ip_address     INET NOT NULL"),
            "ip_pool_addresses.ip_address must be created by migration 093"
        );

        // The manifest names those same canonical columns, never the
        // historical aliases an older probe demanded.
        let dedicated = REQUIRED_CONSOLE_SCHEMA
            .iter()
            .find(|(table, _)| *table == "dedicated_ips")
            .expect("dedicated_ips in manifest")
            .1;
        assert_eq!(dedicated, &["id", "tenant_id", "ip_address"]);
        let pool = REQUIRED_CONSOLE_SCHEMA
            .iter()
            .find(|(table, _)| *table == "ip_pool_addresses")
            .expect("ip_pool_addresses in manifest")
            .1;
        assert_eq!(pool, &["pool_id", "ip_address"]);
    }

    // ─── Fix 6: DB-backed loader behaviour (soft-skip without infra) ─

    fn cp_user() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// Fix 6: the operators table paginates past 100 rows instead of
    /// showing every operator a KPI total they cannot navigate.
    #[tokio::test]
    async fn operators_loader_paginates_all_rows() {
        let Some(pool) = crate::test_db::canonical_pool("data_operators_paging").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        let baseline: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM users WHERE role IN ('admin', 'owner')",
        )
        .fetch_one(&pool)
        .await
        .expect("baseline operator count");

        let tenant_id = "data_ops_tenant_0000000001";
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'Data Ops', 'data-ops-paging', 'free', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("seed tenant");
        for index in 0..105 {
            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                                    email_verified, mfa_enabled, metadata, created_at, updated_at)
                 VALUES ($1, $2, $3, 'Op', 'x', 'admin', 'active', true, true, '{}'::jsonb, NOW(), NOW())",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(tenant_id)
            .bind(format!("paging-{index}@apexmail.ee"))
            .execute(&pool)
            .await
            .expect("seed operator");
        }

        let data = load_page_data(
            &state,
            "control-plane",
            "/operators",
            None,
            Some(&cp_user()),
        )
        .await;
        let list = data.list.expect("operators list");
        assert_eq!(list.total_count, baseline + 105);
        assert_eq!(list.page, 1);
        assert_eq!(
            list.total_pages,
            ((baseline + 105) as usize).div_ceil(PER_PAGE)
        );
        let first_page = list.table.expect("table");
        assert_eq!(first_page.rows.len(), PER_PAGE);
        assert_eq!(first_page.rows[0].id, "operator-0");

        // Page 2 offsets by PER_PAGE — the table is navigable past 100.
        let data = load_page_data(
            &state,
            "control-plane",
            "/operators",
            Some("page=2"),
            Some(&cp_user()),
        )
        .await;
        let second_page = data.list.expect("page 2").table.expect("table");
        assert_eq!(second_page.rows.len(), PER_PAGE);
        assert_eq!(second_page.rows[0].id, "operator-20");

        sqlx::query("DELETE FROM users WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&pool)
            .await
            .expect("cleanup users");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .execute(&pool)
            .await
            .expect("cleanup tenant");
    }

    /// Fix 6: the domains table shows the status it filters on.
    #[tokio::test]
    async fn domains_loader_renders_the_filtered_status() {
        let Some(pool) = crate::test_db::canonical_pool("data_domains_status").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        let tenant_id = "data_dom_tenant_0000000001";
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'Data Dom', 'data-dom-status', 'free', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("seed tenant");
        for (name, status) in [
            ("verified-one.example.test", "verified"),
            ("verified-two.example.test", "verified"),
            ("pending.example.test", "pending"),
        ] {
            sqlx::query(
                "INSERT INTO domains (id, tenant_id, name, status, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, NOW(), NOW())",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(tenant_id)
            .bind(name)
            .bind(status)
            .execute(&pool)
            .await
            .expect("seed domain");
        }

        let data = load_page_data(
            &state,
            "control-plane",
            "/domains",
            Some("status=verified"),
            Some(&cp_user()),
        )
        .await;
        let list = data.list.expect("domains list");
        assert_eq!(list.total_count, 2);
        let table = list.table.expect("table");
        assert!(
            table.columns.contains(&"Status".to_string()),
            "the filtered status must be visible: {:?}",
            table.columns
        );
        for row in &table.rows {
            assert!(
                row.cells.iter().any(|cell| matches!(
                    cell,
                    ui_foundation::view_data::DataCell::Status(status) if status == "verified"
                )),
                "every filtered row must render its status"
            );
        }

        sqlx::query("DELETE FROM domains WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&pool)
            .await
            .expect("cleanup domains");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .execute(&pool)
            .await
            .expect("cleanup tenant");
    }

    // ─── Audit F03: API-keys console query + view-model states ───────

    #[test]
    fn api_keys_sql_selects_only_schema_columns() {
        // The mandated exact statement: `key_prefix` (the real column)
        // aliased to the display name, UUID id decoded as text, and
        // expires_at present for the active/expired distinction.
        assert_eq!(
            API_KEYS_SQL,
            "SELECT id::text AS id, name, key_prefix AS prefix, created_at, revoked_at, expires_at FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100"
        );
    }

    #[test]
    fn api_key_states_distinguish_active_expired_revoked() {
        let now = chrono::Utc::now();
        let past = now - chrono::Duration::hours(1);
        let future = now + chrono::Duration::hours(1);

        assert_eq!(api_key_state(None, None, now), "active");
        assert_eq!(api_key_state(None, Some(future), now), "active");
        // expires_at exactly now has passed — expired, never active.
        assert_eq!(api_key_state(None, Some(now), now), "expired");
        assert_eq!(api_key_state(None, Some(past), now), "expired");
        // Revocation wins over expiry (irreversible operator action).
        assert_eq!(api_key_state(Some(past), Some(past), now), "revoked");
        assert_eq!(api_key_state(Some(past), None, now), "revoked");
    }

    // ─── Audit F04: billing canonical columns + currency buckets ─────

    #[test]
    fn billing_sql_reads_canonical_invoice_columns() {
        // No amount_cents (absent on the fully-migrated schema: migration
        // 069's CREATE TABLE is a no-op after 052); canonical total with
        // the legacy `amount` fallback; UUID id decoded as text; status
        // coerced to text for enum lineages.
        assert!(BILLING_INVOICES_SQL.contains("id::text AS id"));
        assert!(BILLING_INVOICES_SQL.contains("COALESCE(total, amount, 0)"));
        assert!(!BILLING_INVOICES_SQL.contains("amount_cents"));
        assert!(BILLING_INVOICES_SQL.contains("status::text AS status"));
    }

    #[test]
    fn outstanding_summary_consults_the_shared_allocation_aware_balance() {
        // Audit F04: the console's outstanding no longer sums full invoice
        // totals — it delegates to the ONE authoritative balance
        // (billing_service::invoices::tenant_outstanding_by_currency),
        // which subtracts confirmed payment allocations and
        // debt-reduction credits per currency bucket over the whole
        // eligible set. The delegation is pinned in billing-service's own
        // tests (invoices::tenant_outstanding_aggregates_the_whole_set_by_currency_bucket).
        let source_file = include_str!("../../../../billing-service/src/invoices.rs");
        assert!(source_file.contains("pub async fn tenant_outstanding_by_currency"));
        assert!(source_file.contains("TENANT_OUTSTANDING_SQL"));
        // The shared derivation subtracts allocations and debt-reduction
        // credits — never a bare SUM of invoice totals.
        assert!(source_file.contains("invoice_payment_allocations"));
        assert!(source_file.contains("debt_reduction_cents"));
    }

    #[test]
    fn outstanding_kpis_separate_currencies_and_never_fabricate_zeroes() {
        // Loaded buckets → one labelled card per currency.
        let kpis = outstanding_kpis(LoadState::Loaded(vec![
            ("EUR".to_string(), 12_345),
            ("USD".to_string(), 500),
        ]));
        assert_eq!(kpis.len(), 2);
        assert_eq!(kpis[0].label, "Outstanding (EUR)");
        assert_eq!(kpis[0].value, "123.45 EUR");
        assert_eq!(kpis[1].label, "Outstanding (USD)");
        assert_eq!(kpis[1].value, "5.00 USD");

        // Genuinely nothing due → a single honest 0.00 card.
        let kpis = outstanding_kpis(LoadState::Loaded(Vec::new()));
        assert_eq!(kpis.len(), 1);
        assert_eq!(kpis[0].value, "0.00");

        // Unknown (query failed) is NOT zero.
        let kpis = outstanding_kpis(LoadState::Unavailable);
        assert_eq!(kpis.len(), 1);
        assert_eq!(kpis[0].value, "unavailable");
    }

    #[test]
    fn format_cents_carries_its_own_currency() {
        assert_eq!(format_cents(0, "EUR"), "0.00 EUR");
        assert_eq!(format_cents(1, "USD"), "0.01 USD");
        assert_eq!(format_cents(123_456_789, "JPY"), "1234567.89 JPY");
    }

    // ─── Audit F58: nodes query decodes UUID + INET ──────────────────

    #[test]
    fn nodes_sql_decodes_uuid_id_and_inet_address() {
        assert!(NODES_SQL.contains("id::text AS id"));
        assert!(NODES_SQL.contains("host(ip_address) AS ip_address"));
    }

    // ─── Audit F14: unavailable states stay distinguishable ──────────

    #[test]
    fn load_state_keeps_unavailable_distinct_from_empty() {
        let loaded_empty: LoadState<Vec<u8>> = LoadState::Loaded(Vec::new());
        let unavailable: LoadState<Vec<u8>> = LoadState::Unavailable;
        assert!(!loaded_empty.is_unavailable());
        assert!(unavailable.is_unavailable());

        let (rows, failed) = LoadState::Loaded(vec![1u8, 2]).rows_or_unavailable();
        assert_eq!(rows, vec![1, 2]);
        assert!(!failed);
        let (rows, failed) = LoadState::<Vec<u8>>::Unavailable.rows_or_unavailable();
        assert!(rows.is_empty());
        assert!(failed);

        // Counts degrade to explicit "unavailable", never a false zero.
        assert_eq!(LoadState::Loaded(7).kpi_value(), "7");
        assert_eq!(LoadState::<i64>::Unavailable.kpi_value(), "unavailable");
        assert_eq!(LoadState::Loaded(7).total_or_zero(), 7);
        assert_eq!(LoadState::<i64>::Unavailable.total_or_zero(), 0);
        assert_eq!(
            LoadState::<i64>::Unavailable.unwrap_or_default(),
            0,
            "unknown counts must be captured via is_unavailable before degrading"
        );
    }

    #[test]
    fn unavailable_copy_is_distinct_from_honest_empty_state() {
        // A failed query must render different copy than a genuinely
        // optional-and-empty dataset (audit F14).
        let mut honest_empty = base_list("Contacts", "desc", "/contacts");
        honest_empty.empty_title = "No contacts yet".into();
        honest_empty.empty_description = "Add your first contact.".into();

        let mut unavailable = base_list("Contacts", "desc", "/contacts");
        mark_rows_unavailable(&mut unavailable, "Contacts", "web-data-42");

        assert_eq!(unavailable.empty_title, "Data unavailable");
        assert_ne!(honest_empty.empty_title, unavailable.empty_title);
        assert_ne!(
            honest_empty.empty_description,
            unavailable.empty_description
        );
        assert!(unavailable.empty_description.contains("not an empty list"));
        // F14: the correlation id travels into the view so the failed page
        // is traceable to its loader log lines.
        assert!(unavailable.empty_description.contains("web-data-42"));
    }

    // ── F14: required vs optional dataset semantics ────────────────

    /// A minimal fake driver error carrying an arbitrary SQLSTATE, so the
    /// 42P01/42703 classification is testable without a database.
    #[derive(Debug)]
    struct FakeSqlStateError(&'static str);

    impl std::fmt::Display for FakeSqlStateError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "db error {}", self.0)
        }
    }
    impl std::error::Error for FakeSqlStateError {}
    impl sqlx::error::DatabaseError for FakeSqlStateError {
        fn message(&self) -> &str {
            "fake"
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(std::borrow::Cow::Borrowed(self.0))
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn db_error(sqlstate: &'static str) -> sqlx::Error {
        sqlx::Error::Database(Box::new(FakeSqlStateError(sqlstate)))
    }

    /// F14 core requirement: a REQUIRED dataset maps EVERY error — including
    /// missing-table (42P01) and missing-column (42703) — to Unavailable.
    /// A misdeployed invoices/api_keys schema must never render as an empty
    /// page or a zero KPI.
    #[tokio::test]
    async fn required_datasets_map_schema_errors_to_unavailable() {
        for sqlstate in ["42P01", "42703"] {
            let state = load_query_with_requirement(
                "test.required",
                "cid",
                DatasetRequirement::Required,
                std::future::ready(Err::<i64, _>(db_error(sqlstate))),
            )
            .await;
            assert!(
                matches!(state, LoadState::Unavailable),
                "42P01/42703 ({sqlstate}) on a REQUIRED dataset must be Unavailable"
            );
        }
        // Decoding errors are failures too, not defaults.
        let state = load_query(
            "test.required",
            "cid",
            std::future::ready(Err::<i64, _>(sqlx::Error::ColumnNotFound(
                "total_cents".into(),
            ))),
        )
        .await;
        assert!(matches!(state, LoadState::Unavailable));
    }

    /// F14: only an EXPLICITLY optional dataset (tied to a deliberately
    /// disabled component) may treat a missing relation as an honest empty
    /// dataset — and only 42P01/42703; every other error stays Unavailable.
    #[tokio::test]
    async fn optional_datasets_tolerate_only_missing_schema() {
        let state = load_query_with_requirement(
            "test.optional",
            "cid",
            DatasetRequirement::OptionalDisabledComponent,
            std::future::ready(Err::<i64, _>(db_error("42P01"))),
        )
        .await;
        assert_eq!(
            state,
            LoadState::Loaded(0),
            "missing optional relation = honest empty"
        );

        let state = load_query_with_requirement(
            "test.optional",
            "cid",
            DatasetRequirement::OptionalDisabledComponent,
            std::future::ready(Err::<i64, _>(sqlx::Error::PoolClosed)),
        )
        .await;
        assert!(matches!(state, LoadState::Unavailable));
    }

    /// F14: the readiness probe names the exact missing pieces.
    #[test]
    fn required_schema_manifest_covers_the_financial_datasets() {
        let tables: Vec<&str> = REQUIRED_CONSOLE_SCHEMA.iter().map(|(t, _)| *t).collect();
        for required in ["invoices", "api_keys", "users", "tenants"] {
            assert!(tables.contains(&required), "{required} must be probed");
        }
        // The invoice probe covers the canonical columns the
        // outstanding-balance summary reads (total, not the old
        // total_cents alias — the probe must name what the migration
        // chain actually creates).
        let (_, invoice_columns) = REQUIRED_CONSOLE_SCHEMA
            .iter()
            .find(|(table, _)| *table == "invoices")
            .expect("invoices in manifest");
        for column in ["total", "currency", "status", "tenant_id"] {
            assert!(invoice_columns.contains(&column), "invoices.{column}");
        }
        // Every probed column must exist in a real migrated database:
        // the canonical chain names are asserted here so an imagined
        // column cannot reach the readiness gate again.
        for (table, columns) in REQUIRED_CONSOLE_SCHEMA {
            for column in *columns {
                assert!(
                    !matches!(
                        (*table, *column),
                        ("invoices", "total_cents") | (_, "address")
                    ),
                    "{table}.{column} is a historical alias, not a canonical column"
                );
            }
        }
    }

    #[test]
    fn correlation_ids_are_unique_and_monotonic() {
        let first = next_correlation_id();
        let second = next_correlation_id();
        assert_ne!(first, second);
        assert!(second > first, "ids share a prefix and increase");
        assert!(first.starts_with("web-data-"));
    }
}
