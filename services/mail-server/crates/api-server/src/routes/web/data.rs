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

/// True when a sqlx error means "relation or column does not exist" — the
/// optional-table tolerance shared with the admin system-health route.
fn is_optional_schema_error(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(db_error)
            if matches!(db_error.code().as_deref(), Some("42P01") | Some("42703"))
    )
}

/// Fetch rows, tolerating a missing optional relation (returns empty).
async fn optional_rows<T, F>(fetch: F) -> Vec<T>
where
    F: std::future::Future<Output = Result<Vec<T>, sqlx::Error>>,
{
    match fetch.await {
        Ok(rows) => rows,
        Err(error) if is_optional_schema_error(&error) => {
            tracing::warn!(error = %error, "web data table missing; empty dataset");
            Vec::new()
        }
        Err(error) => {
            tracing::error!(error = %error, "web data query failed; empty dataset");
            Vec::new()
        }
    }
}

/// COUNT(*) with the page's filters. Never fails the render: schema errors
/// and query errors both yield 0.
async fn count_rows(state: &AppState, sql: &str, binds: &[String]) -> i64 {
    let mut q = sqlx::query_scalar::<_, i64>(sql);
    for value in binds {
        q = q.bind(value);
    }
    match q.fetch_one(&state.db).await {
        Ok(value) => value,
        Err(error) if is_optional_schema_error(&error) => 0,
        Err(error) => {
            tracing::warn!(error = %error, "count query failed");
            0
        }
    }
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
    match surface {
        "web" => match user {
            Some(user) => web_route_data(state, path, &list_query, user).await,
            None => RouteData::default(),
        },
        "control-plane" => match user {
            Some(user) => control_plane_route_data(state, path, &list_query, user).await,
            None => RouteData::default(),
        },
        _ => RouteData::default(),
    }
}

// ─── Web (tenant-scoped) routes ─────────────────────────────────

async fn web_route_data(state: &AppState, path: &str, q: &ListQuery, user: &AuthUser) -> RouteData {
    let tenant = user.tenant_id.clone();
    let list = match path {
        "/dashboard" => Some(web_dashboard(state, &tenant).await),
        "/campaigns" => Some(web_campaigns(state, &tenant, q).await),
        "/contacts" => Some(web_contacts(state, &tenant, q).await),
        "/lists" => Some(web_lists(state, &tenant, q).await),
        "/templates" => Some(web_templates(state, &tenant, q).await),
        "/domains" => Some(web_domains(state, &tenant, q).await),
        "/events" => Some(web_events(state, &tenant, q).await),
        "/analytics" => Some(web_analytics(state, &tenant).await),
        "/reports" => Some(web_reports(state, &tenant).await),
        "/reports/deliverability" => Some(web_deliverability(state, &tenant).await),
        "/inbox-placement" => Some(web_inbox_placement(state, &tenant, q).await),
        "/settings/api-keys" => Some(web_api_keys(state, &tenant).await),
        "/settings/webhooks" => Some(web_webhooks(state, &tenant).await),
        "/settings/team" => Some(web_team(state, &tenant).await),
        "/settings/billing" => Some(web_billing(state, &tenant).await),
        "/settings/dedicated-ips" => Some(web_dedicated_ips(state, &tenant).await),
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
    }
}

async fn web_dashboard(state: &AppState, tenant: &str) -> ListPageData {
    let campaigns = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM campaigns WHERE tenant_id = $1",
        &[tenant.to_string()],
    )
    .await;
    let contacts = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM contacts WHERE tenant_id = $1 AND status <> 'deleted'",
        &[tenant.to_string()],
    )
    .await;
    let domains = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM domains WHERE tenant_id = $1",
        &[tenant.to_string()],
    )
    .await;
    let sent = count_rows(
        state,
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
        KpiCardData::new("Campaigns", campaigns.to_string()).with_hint("All statuses"),
        KpiCardData::new("Contacts", contacts.to_string()).with_hint("Active addressable"),
        KpiCardData::new("Domains", domains.to_string()).with_hint("Sending domains"),
        KpiCardData::new("Sent (30d)", sent.to_string()).with_hint("Messages dispatched"),
    ];
    data
}

async fn web_campaigns(state: &AppState, tenant: &str, q: &ListQuery) -> ListPageData {
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

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM campaigns WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let order = match q.sort.as_str() {
        "created" => "created_at DESC",
        "name" => "name ASC",
        _ => "updated_at DESC",
    };

    let rows: Vec<(String, String, Option<String>, String, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
            async {
                let campaigns_sql = format!(
                    "SELECT id::text, name, subject, status, updated_at FROM campaigns WHERE {where_clause} ORDER BY {order} LIMIT {PER_PAGE} OFFSET {offset}"
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
        .await;

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
    data.total_count = total;
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

async fn web_contacts(state: &AppState, tenant: &str, q: &ListQuery) -> ListPageData {
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

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM contacts WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(String, String, Option<String>, String, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
            async {
                let contacts_sql = format!(
                    "SELECT id, email, name, status, updated_at FROM contacts WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
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
        .await;

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
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.bulk_action = Some(BulkActionData {
        action: "/web/contacts/delete-bulk".into(),
        button_label: "Delete selected".into(),
    });
    data.primary_action = Some(("Add Contact".into(), "/contacts/new".into()));
    data.empty_title = "No contacts yet".into();
    data.empty_description = "Add your first contact to start building an audience.".into();
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

async fn web_lists(state: &AppState, tenant: &str, q: &ListQuery) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM lists WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(String, String, Option<chrono::DateTime<chrono::Utc>>)> = optional_rows(
        async {
        let q1 = format!(
            "SELECT id, name, updated_at FROM lists WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
        );
            let mut query =
                sqlx::query_as::<_, (String, String, Option<chrono::DateTime<chrono::Utc>>)>(&q1);
            for value in &where_sql.binds {
                query = query.bind(value);
            }
            query.fetch_all(&state.db).await
        },
    )
    .await;

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
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.primary_action = Some(("New List".into(), "/lists/new".into()));
    data.detail_path_prefix = Some("/lists/".into());
    data.edit_path_suffix = Some("/edit".into());
    data.delete_intent = Some("delete-list".into());
    data.empty_title = "No lists yet".into();
    data.empty_description = "Create a list to group contacts into an audience.".into();
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

async fn web_templates(state: &AppState, tenant: &str, q: &ListQuery) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM templates WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(String, String, String, Option<i32>, String, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
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
        .await;

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
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.primary_action = Some(("New Template".into(), "/templates/new".into()));
    data.empty_title = "No templates yet".into();
    data.empty_description = "Create a template to reuse email content across campaigns.".into();
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

async fn web_domains(state: &AppState, tenant: &str, q: &ListQuery) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    where_sql.status_in(&["pending", "verified", "failed", "suspended"], &q.status);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM domains WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(String, String, String, Option<chrono::DateTime<chrono::Utc>>)> = optional_rows(
        async {
        let q2 = format!(
            "SELECT id, name, status, created_at FROM domains WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
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
    .await;

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
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.primary_action = Some(("Add Domain".into(), "/domains/new".into()));
    data.delete_intent = Some("delete-domain".into());
    data.empty_title = "No domains yet".into();
    data.empty_description = "Add and verify a sending domain before dispatching mail.".into();
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

async fn web_events(state: &AppState, tenant: &str, q: &ListQuery) -> ListPageData {
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

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM events WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(String, String, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
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
        .await;

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
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.empty_title = "No events yet".into();
    data.empty_description = "Delivery events appear here as soon as mail starts flowing.".into();
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
    where_sql: &str,
    binds: &[String],
) -> HashMap<String, i64> {
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
    let row: Option<(i64, i64, i64, i64, i64, i64)> = match query.fetch_optional(&state.db).await {
        Ok(row) => row,
        Err(error) if is_optional_schema_error(&error) => None,
        Err(error) => {
            tracing::warn!(error = %error, "event aggregate failed");
            None
        }
    };
    let mut out = HashMap::new();
    if let Some((sent, delivered, opened, clicked, bounced, complained)) = row {
        out.insert("sent".to_string(), sent);
        out.insert("delivered".to_string(), delivered);
        out.insert("opened".to_string(), opened);
        out.insert("clicked".to_string(), clicked);
        out.insert("bounced".to_string(), bounced);
        out.insert("complained".to_string(), complained);
    }
    out
}

fn rate(part: i64, whole: i64) -> String {
    if whole == 0 {
        "—".to_string()
    } else {
        format!("{:.1}%", (part as f64 / whole as f64) * 100.0)
    }
}

async fn web_analytics(state: &AppState, tenant: &str) -> ListPageData {
    let agg = event_aggregate(
        state,
        "tenant_id = $1 AND timestamp >= NOW() - '30 days'::interval",
        &[tenant.to_string()],
    )
    .await;
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
        KpiCardData::new("Sent", sent.to_string()).with_hint("Last 30 days"),
        KpiCardData::new("Delivered", delivered.to_string()).with_hint(&rate(delivered, sent)),
        KpiCardData::new("Opened", opened.to_string()).with_hint(&rate(opened, sent)),
        KpiCardData::new("Clicked", clicked.to_string()).with_hint(&rate(clicked, sent)),
    ];
    data
}

async fn web_reports(state: &AppState, tenant: &str) -> ListPageData {
    let agg = event_aggregate(
        state,
        "tenant_id = $1 AND timestamp >= NOW() - '30 days'::interval",
        &[tenant.to_string()],
    )
    .await;
    let sent = *agg.get("sent").unwrap_or(&0);
    let bounced = agg.get("bounced").copied().unwrap_or(0);
    let delivered = agg.get("delivered").copied().unwrap_or(0);
    let campaigns = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM campaigns WHERE tenant_id = $1",
        &[tenant.to_string()],
    )
    .await;

    let rows: Vec<(String, String, String, Option<i32>, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
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
                    "SELECT id, name, status, sent_count, updated_at FROM campaigns WHERE tenant_id = $1 ORDER BY updated_at DESC LIMIT 10",
                )
                .bind(tenant)
                .fetch_all(&state.db)
                .await
            },
        )
        .await;

    let mut data = base_list(
        "Reports",
        "Cross-campaign reporting — every row links into the campaign record.",
        "/reports",
    );
    data.kpis = vec![
        KpiCardData::new("Campaigns", campaigns.to_string()).with_hint("All time"),
        KpiCardData::new("Sent (30d)", sent.to_string()).with_hint("Events table"),
        KpiCardData::new("Bounces (30d)", bounced.to_string()).with_hint(&rate(bounced, sent)),
        KpiCardData::new("Deliverability", rate(delivered, sent)).with_hint("Delivered ÷ sent"),
    ];
    data.detail_path_prefix = Some("/campaigns/".into());
    data.detail_label = "Open".into();
    data.empty_title = "No reportable campaigns yet".into();
    data.empty_description = "Send a campaign to populate cross-campaign reports.".into();
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

async fn web_deliverability(state: &AppState, tenant: &str) -> ListPageData {
    let agg = event_aggregate(
        state,
        "tenant_id = $1 AND timestamp >= NOW() - '30 days'::interval",
        &[tenant.to_string()],
    )
    .await;
    let sent = *agg.get("sent").unwrap_or(&0);
    let delivered = agg.get("delivered").copied().unwrap_or(0);
    let bounced = agg.get("bounced").copied().unwrap_or(0);
    let complained = agg.get("complained").copied().unwrap_or(0);

    let rows: Vec<(String, i64)> = optional_rows(
        async {
            sqlx::query_as::<_, (String, i64)>(
                "SELECT event_type, COUNT(*)::bigint FROM events WHERE tenant_id = $1 AND timestamp >= NOW() - '30 days'::interval GROUP BY event_type ORDER BY 2 DESC",
            )
            .bind(tenant)
            .fetch_all(&state.db)
            .await
        },
    )
    .await;

    let mut data = base_list(
        "Deliverability",
        "Bounce, complaint, and delivery rates computed from real events.",
        "/reports/deliverability",
    );
    data.kpis = vec![
        KpiCardData::new("Delivery rate", rate(delivered, sent)).with_hint("Delivered ÷ sent"),
        KpiCardData::new("Bounce rate", rate(bounced, sent)).with_hint("Bounced ÷ sent"),
        KpiCardData::new("Complaint rate", rate(complained, sent)).with_hint("Complained ÷ sent"),
        KpiCardData::new("Sent (30d)", sent.to_string()).with_hint("Total dispatched"),
    ];
    data.empty_title = "No delivery data yet".into();
    data.empty_description = "Deliverability metrics appear once messages are dispatched.".into();
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

async fn web_inbox_placement(state: &AppState, tenant: &str, q: &ListQuery) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.eq("tenant_id", tenant);
    where_sql.status_in(&["pending", "running", "completed", "failed"], &q.status);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM placement_tests WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(String, Option<String>, String, Option<i32>, Option<i32>, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
            async {
                let placement_sql = format!(
                    "SELECT id::text, name, status, total_accounts, completed_accounts, created_at FROM placement_tests WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
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
        .await;

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
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.primary_action = Some(("New Test".into(), "/inbox-placement/new".into()));
    data.empty_title = "No placement tests yet".into();
    data.empty_description = "Start a seed-account test to measure inbox placement.".into();
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

async fn web_api_keys(state: &AppState, tenant: &str) -> ListPageData {
    let rows: Vec<(String, String, String, Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
            async {
                sqlx::query_as::<
                    _,
                    (
                        String,
                        String,
                        String,
                        Option<chrono::DateTime<chrono::Utc>>,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(
                    "SELECT id, name, prefix, created_at, revoked_at FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100",
                )
                .bind(tenant)
                .fetch_all(&state.db)
                .await
            },
        )
        .await;

    let mut data = base_list(
        "API Keys",
        "Machine credentials for this workspace. Secrets are shown once at creation.",
        "/settings/api-keys",
    );
    data.total_count = rows.len() as i64;
    data.empty_title = "No API keys yet".into();
    data.empty_description = "Create a key to call the API programmatically.".into();
    data.table = Some(TableData {
        columns: vec![
            "Name".into(),
            "Prefix".into(),
            "Status".into(),
            "Created".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(id, name, prefix, created, revoked)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(name),
                    DataCell::mono(format!("{prefix}…")),
                    DataCell::status(if revoked.is_some() {
                        "paused"
                    } else {
                        "active"
                    }),
                    DataCell::text(relative_time(created)),
                ],
            })
            .collect(),
    });
    data
}

async fn web_webhooks(state: &AppState, tenant: &str) -> ListPageData {
    let rows: Vec<(String, String, bool, Option<chrono::DateTime<chrono::Utc>>)> = optional_rows(
        async {
            sqlx::query_as::<_, (String, String, bool, Option<chrono::DateTime<chrono::Utc>>)>(
                "SELECT id, url, enabled, last_triggered_at FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100",
            )
            .bind(tenant)
            .fetch_all(&state.db)
            .await
        },
    )
    .await;

    let mut data = base_list(
        "Webhooks",
        "HTTP endpoints notified about delivery events.",
        "/settings/webhooks",
    );
    data.total_count = rows.len() as i64;
    data.empty_title = "No webhooks yet".into();
    data.empty_description = "Register an endpoint to receive delivery events.".into();
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

async fn web_team(state: &AppState, tenant: &str) -> ListPageData {
    let rows: Vec<(String, Option<String>, String, String, bool)> = optional_rows(
        async {
            sqlx::query_as::<_, (String, Option<String>, String, String, bool)>(
                "SELECT email, name, role, status, COALESCE(mfa_enabled, false) FROM users WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100",
            )
            .bind(tenant)
            .fetch_all(&state.db)
            .await
        },
    )
    .await;

    let mut data = base_list(
        "Team",
        "Workspace members and their access level.",
        "/settings/team",
    );
    data.total_count = rows.len() as i64;
    data.empty_title = "No team members yet".into();
    data.empty_description = "Invite teammates to collaborate on this workspace.".into();
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

async fn web_billing(state: &AppState, tenant: &str) -> ListPageData {
    let plan: Option<String> =
        sqlx::query_scalar::<_, String>("SELECT plan FROM tenants WHERE id::text = $1")
            .bind(tenant)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let rows: Vec<(String, i64, String, String, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
            async {
                sqlx::query_as::<
                    _,
                    (
                        String,
                        i64,
                        String,
                        String,
                        Option<chrono::DateTime<chrono::Utc>>,
                    ),
                >(
                    "SELECT id, amount_cents, currency, status, created_at FROM invoices WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 50",
                )
                .bind(tenant)
                .fetch_all(&state.db)
                .await
            },
        )
        .await;

    let outstanding: i64 = rows
        .iter()
        .filter(|row| row.3 != "paid")
        .map(|row| row.1)
        .sum();

    let mut data = base_list(
        "Billing",
        "Plan, invoices, and payment posture for this workspace.",
        "/settings/billing",
    );
    data.kpis = vec![
        KpiCardData::new("Current plan", plan.unwrap_or_else(|| "free".into()))
            .with_hint("Tenant record"),
        KpiCardData::new("Invoices", rows.len().to_string()).with_hint("On record"),
        KpiCardData::new(
            "Outstanding",
            format!("{:.2} EUR", outstanding as f64 / 100.0),
        )
        .with_hint("Unpaid total"),
    ];
    data.total_count = rows.len() as i64;
    data.empty_title = "No invoices yet".into();
    data.empty_description = "Invoices appear here once a paid plan is active.".into();
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
            .map(|(id, amount, currency, status, created)| DataRowData {
                cells: vec![
                    DataCell::mono(id.chars().take(12).collect::<String>()),
                    DataCell::text(format!("{:.2}", amount as f64 / 100.0)),
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

async fn web_dedicated_ips(state: &AppState, tenant: &str) -> ListPageData {
    let rows: Vec<(String, Option<String>, Option<String>, String, Option<f64>)> = optional_rows(
        async {
            sqlx::query_as::<_, (String, Option<String>, Option<String>, String, Option<f64>)>(
                "SELECT id, ip_address, region, status, warmup_progress FROM dedicated_ips WHERE tenant_id::text = $1 ORDER BY created_at DESC LIMIT 100",
            )
            .bind(tenant)
            .fetch_all(&state.db)
            .await
        },
    )
    .await;

    let pending = count_rows(
        state,
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
        KpiCardData::new("Assigned", rows.len().to_string()).with_hint("Active allocations"),
        KpiCardData::new("Pending requests", pending.to_string())
            .with_hint("Awaiting the provisioner"),
    ];
    data.total_count = rows.len() as i64;
    data.empty_title = "No dedicated IPs yet".into();
    data.empty_description = "Request an allocation — the provisioner completes it.".into();
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
) -> RouteData {
    let list = match path {
        "/" => Some(cp_home(state).await),
        "/cp" | "/dashboard" => Some(cp_dashboard(state).await),
        "/cp/tenants" | "/tenants" => Some(cp_tenants(state, q).await),
        "/operators" => Some(cp_operators(state, q).await),
        "/cp/sales" | "/sales" => Some(cp_sales(state, q).await),
        "/cp/audit" | "/audit" => Some(cp_audit(state, q).await),
        "/jobs" => Some(cp_jobs(state).await),
        "/infrastructure/nodes" => Some(cp_nodes(state).await),
        "/infrastructure/queues" => Some(cp_queues(state).await),
        "/alerts" => Some(cp_alerts(state, q).await),
        "/alerts/rules" => Some(cp_alert_rules()),
        "/domains" => Some(cp_domains(state, q).await),
        "/billing/plans" => Some(cp_plans(state).await),
        "/compliance" => Some(cp_compliance(state).await),
        "/compliance/gdpr" => Some(cp_gdpr(state, q).await),
        "/discovery" => Some(cp_discovery(state).await),
        "/analytics" => Some(cp_analytics(state).await),
        _ => None,
    };
    RouteData {
        list,
        campaign_edit: None,
        mfa_setup: None,
    }
}

async fn cp_home(state: &AppState) -> ListPageData {
    let tenants = count_rows(state, "SELECT COUNT(*)::bigint FROM tenants", &[]).await;
    let users = count_rows(state, "SELECT COUNT(*)::bigint FROM users", &[]).await;
    let alerts = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false",
        &[],
    )
    .await;
    let queue_depth = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM queue_jobs WHERE status = 'pending'",
        &[],
    )
    .await;

    let rows: Vec<(String, String, Option<String>, String, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
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
                    "SELECT id, name, slug, COALESCE(plan, ''), created_at FROM tenants ORDER BY created_at DESC LIMIT 10",
                )
                .fetch_all(&state.db)
                .await
            },
        )
        .await;

    let mut data = base_list(
        "Control Plane",
        "ApexMail administration and monitoring.",
        "/",
    );
    data.kpis = vec![
        KpiCardData::new("Tenants", tenants.to_string()).with_hint("Workspaces"),
        KpiCardData::new("Users", users.to_string()).with_hint("All tenants"),
        KpiCardData::new("Open alerts", alerts.to_string()).with_hint("Unacknowledged"),
        KpiCardData::new("Queue depth", queue_depth.to_string()).with_hint("Pending jobs"),
    ];
    data.empty_title = "No tenants yet".into();
    data.empty_description =
        "Provision the first tenant workspace to populate the fleet view.".into();
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

async fn cp_dashboard(state: &AppState) -> ListPageData {
    let alerts = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false",
        &[],
    )
    .await;
    let critical = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false AND severity = 'critical'",
        &[],
    )
    .await;
    let tenants = count_rows(state, "SELECT COUNT(*)::bigint FROM tenants", &[]).await;
    let gdpr_pending = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM gdpr_requests WHERE status = 'pending'",
        &[],
    )
    .await;

    let rows: Vec<(String, String, String, String, bool, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
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
                    "SELECT id, severity, alert_type, message, acknowledged, created_at FROM system_alerts ORDER BY created_at DESC LIMIT 10",
                )
                .fetch_all(&state.db)
                .await
            },
        )
        .await;

    let mut data = base_list(
        "Dashboard",
        "Fleet health, operator coverage, and throughput.",
        "/dashboard",
    );
    data.kpis = vec![
        KpiCardData::new("Open alerts", alerts.to_string()).with_hint("Unacknowledged"),
        KpiCardData::new("Critical", critical.to_string()).with_hint("Severity"),
        KpiCardData::new("Tenants", tenants.to_string()).with_hint("Fleet"),
        KpiCardData::new("GDPR pending", gdpr_pending.to_string()).with_hint("Requests"),
    ];
    data.empty_title = "No alerts recorded".into();
    data.empty_description =
        "Fleet alert signals will list here when the alerting pipeline fires.".into();
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

async fn cp_tenants(state: &AppState, q: &ListQuery) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.status_in(&["pending", "active", "suspended", "cancelled"], &q.status);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM tenants WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(String, String, Option<String>, String, String, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
            async {
            let q3 = format!(
                "SELECT id, name, slug, COALESCE(plan, ''), COALESCE(status, ''), created_at FROM tenants WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
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
        .await;

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
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.primary_action = Some(("Add Tenant".into(), "/tenants/new".into()));
    data.empty_title = "No tenants yet".into();
    data.empty_description = "Create the first tenant workspace.".into();
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

async fn cp_operators(state: &AppState, q: &ListQuery) -> ListPageData {
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

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM users WHERE {where_clause}"),
        &binds,
    )
    .await;

    let rows: Vec<(String, Option<String>, String, bool, String, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
            async {
            let q4 = format!(
                "SELECT email, name, role, COALESCE(mfa_enabled, false), COALESCE(status, ''), created_at FROM users WHERE {where_clause} ORDER BY created_at DESC LIMIT 100"
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
        .await;

    let mut data = base_list(
        "Operators",
        "Administrator access, roles, and activity.",
        "/operators",
    );
    data.search_label = "Search operators".into();
    data.search_placeholder = "Search by email or name".into();
    data.current_query = q.search.clone();
    data.total_count = total;
    data.primary_action = Some(("Add Operator".into(), "/operators/new".into()));
    data.empty_title = "No operators yet".into();
    data.empty_description = "Invite an administrator with controlled access.".into();
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
                    id: format!("operator-{index}"),
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

async fn cp_sales(state: &AppState, q: &ListQuery) -> ListPageData {
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

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM sales_leads WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(String, Option<String>, String, Option<i32>, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
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
        .await;

    let qualified = count_rows(
        state,
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
        KpiCardData::new("Leads", total.to_string()).with_hint("Pipeline"),
        KpiCardData::new("Qualified", qualified.to_string()).with_hint("Stage"),
    ];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.empty_title = "No leads yet".into();
    data.empty_description = "Discovery runs populate the pipeline as leads are identified.".into();
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

async fn cp_audit(state: &AppState, q: &ListQuery) -> ListPageData {
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

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM audit_logs WHERE {where_clause}"),
        &binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(Option<chrono::DateTime<chrono::Utc>>, String, Option<String>, Option<String>)> =
        optional_rows(
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
        .await;

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
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.empty_title = "No audit events yet".into();
    data.empty_description = "Operator actions are recorded here as they happen.".into();
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

async fn cp_jobs(state: &AppState) -> ListPageData {
    let rows: Vec<(String, String, i64, Option<chrono::DateTime<chrono::Utc>>)> = optional_rows(
        async {
            sqlx::query_as::<_, (String, String, i64, Option<chrono::DateTime<chrono::Utc>>)>(
                "SELECT COALESCE(queue, 'default') AS q, status, COUNT(*)::bigint AS c, MAX(updated_at) FROM queue_jobs GROUP BY 1, 2 ORDER BY 1, 2",
            )
            .fetch_all(&state.db)
            .await
        },
    )
    .await;

    let pending: i64 = rows.iter().filter(|r| r.1 == "pending").map(|r| r.2).sum();
    let queues = rows
        .iter()
        .map(|r| r.0.clone())
        .collect::<std::collections::HashSet<_>>()
        .len();

    let mut data = base_list("Jobs", "Background work and remediation queues.", "/jobs");
    data.kpis = vec![
        KpiCardData::new("Pending", pending.to_string()).with_hint("Across queues"),
        KpiCardData::new("Queues", queues.to_string()).with_hint("Distinct"),
    ];
    data.empty_title = "No queued jobs".into();
    data.empty_description = "Background work appears here as workers enqueue it.".into();
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

async fn cp_nodes(state: &AppState) -> ListPageData {
    let rows: Vec<(String, Option<String>, Option<String>, String, Option<i32>)> = optional_rows(
        async {
            sqlx::query_as::<_, (String, Option<String>, Option<String>, String, Option<i32>)>(
                "SELECT id, ip_address, pool_id, status, warmup_day FROM ip_pool_addresses ORDER BY ip_address LIMIT 100",
            )
            .fetch_all(&state.db)
            .await
        },
    )
    .await;

    let active = rows.iter().filter(|r| r.3 == "active").count();
    let mut data = base_list(
        "Nodes",
        "Cluster capacity and node health.",
        "/infrastructure/nodes",
    );
    data.kpis = vec![
        KpiCardData::new("Nodes", rows.len().to_string()).with_hint("MTA pool"),
        KpiCardData::new("Active", active.to_string()).with_hint("Sending"),
    ];
    data.empty_title = "No nodes registered".into();
    data.empty_description =
        "MTA pool addresses appear here as infrastructure registers them.".into();
    data.table = Some(TableData {
        columns: vec![
            "Node".into(),
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

async fn cp_queues(state: &AppState) -> ListPageData {
    let rows: Vec<(String, i64, i64)> = optional_rows(async {
        sqlx::query_as::<_, (String, i64, i64)>(
            "SELECT COALESCE(queue, 'default') AS q,
                        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END)::bigint AS depth,
                        SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END)::bigint AS proc
                 FROM queue_jobs GROUP BY 1",
        )
        .fetch_all(&state.db)
        .await
    })
    .await;

    let depth: i64 = rows.iter().map(|r| r.1).sum();
    let mut data = base_list(
        "Queues",
        "Mail queue depth and worker processing.",
        "/infrastructure/queues",
    );
    data.kpis = vec![
        KpiCardData::new("Total depth", depth.to_string()).with_hint("Pending jobs"),
        KpiCardData::new("Queues", rows.len().to_string()).with_hint("Distinct"),
    ];
    data.empty_title = "No queues reporting".into();
    data.empty_description = "Queue telemetry appears once workers enqueue jobs.".into();
    data.table = Some(TableData {
        columns: vec![
            "Queue".into(),
            "Depth".into(),
            "Processing".into(),
            "State".into(),
        ],
        rows: rows
            .into_iter()
            .map(|(queue, depth, processing)| DataRowData {
                id: queue.clone(),
                cells: vec![
                    DataCell::mono(queue),
                    DataCell::text(depth.to_string()),
                    DataCell::text(processing.to_string()),
                    DataCell::status(if depth > 1000 { "sending" } else { "active" }),
                ],
            })
            .collect(),
    });
    data
}

async fn cp_alerts(state: &AppState, q: &ListQuery) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.status_in(&["critical", "high", "medium", "low", "info"], &q.status);
    let where_clause = where_sql.build();

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM system_alerts WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(String, String, String, String, bool, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
            async {
            let q7 = format!(
                "SELECT id, severity, alert_type, message, acknowledged, created_at FROM system_alerts WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
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
        .await;

    let unacknowledged = count_rows(
        state,
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
        vec![KpiCardData::new("Unacknowledged", unacknowledged.to_string()).with_hint("Open")];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.empty_title = "No alerts".into();
    data.empty_description = "Fleet alert signals appear here when raised.".into();
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

/// /alerts/rules has no backing table yet — an honest empty state, never
/// fabricated rule rows.
fn cp_alert_rules() -> ListPageData {
    let mut data = base_list(
        "Alert Rules",
        "Alerting policy and escalation thresholds.",
        "/alerts/rules",
    );
    data.empty_title = "No rule store wired yet".into();
    data.empty_description =
        "Alert rules are enforced by the fleet alerting engine; a rules table is not provisioned yet, so there is nothing to list."
            .into();
    data.table = Some(TableData {
        columns: vec!["Rule".into()],
        rows: Vec::new(),
    });
    data
}

async fn cp_domains(state: &AppState, q: &ListQuery) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.status_in(&["pending", "verified", "failed", "suspended"], &q.status);
    if !q.search.is_empty() {
        where_sql.ilike("name", &q.search);
    }
    let where_clause = where_sql.build();

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM domains WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    // domains.status may be absent on legacy deployments (verified flags
    // instead) — the status cell degrades to "pending" rather than failing.
    let rows: Vec<(String, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
            async {
            let q8 = format!(
                "SELECT id, name, tenant_id, created_at FROM domains WHERE {where_clause} ORDER BY created_at DESC LIMIT {PER_PAGE} OFFSET {offset}"
            );
                let mut query = sqlx::query_as::<
                    _,
                    (String, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>),
                >(&q8);
                for value in &where_sql.binds {
                    query = query.bind(value);
                }
                query.fetch_all(&state.db).await
            },
        )
        .await;

    let verified = count_rows(
        state,
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
        KpiCardData::new("Domains", total.to_string()).with_hint("Fleet-wide"),
        KpiCardData::new("Verified", verified.to_string()).with_hint("Sending-ready"),
    ];
    data.page = page;
    data.total_pages = total_pages;
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.empty_title = "No domains registered".into();
    data.empty_description = "Tenant domains appear here as they are added.".into();
    data.table = Some(TableData {
        columns: vec!["Domain".into(), "Tenant".into(), "Added".into()],
        rows: rows
            .into_iter()
            .map(|(id, name, tenant_id, created)| DataRowData {
                id,
                cells: vec![
                    DataCell::text(name),
                    DataCell::mono(tenant_id.unwrap_or_else(|| "—".into())),
                    DataCell::text(relative_time(created)),
                ],
            })
            .collect(),
    });
    data
}

async fn cp_plans(state: &AppState) -> ListPageData {
    let rows: Vec<(String, Option<String>, i64)> = optional_rows(async {
        sqlx::query_as::<_, (String, Option<String>, i64)>(
            "SELECT name, display_name, price_cents FROM plans ORDER BY price_cents ASC LIMIT 50",
        )
        .fetch_all(&state.db)
        .await
    })
    .await;

    let tenants = count_rows(state, "SELECT COUNT(*)::bigint FROM tenants", &[]).await;

    let mut data = base_list(
        "Plans",
        "Pricing, quotas, and subscriber coverage.",
        "/billing/plans",
    );
    data.kpis = vec![
        KpiCardData::new("Plans", rows.len().to_string()).with_hint("Catalog"),
        KpiCardData::new("Tenants", tenants.to_string()).with_hint("On any plan"),
    ];
    data.empty_title = "No plans in the catalog".into();
    data.empty_description =
        "Plan packaging appears here once the billing catalog is seeded.".into();
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

async fn cp_compliance(state: &AppState) -> ListPageData {
    let gdpr_pending = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM gdpr_requests WHERE status = 'pending'",
        &[],
    )
    .await;
    let gdpr_total = count_rows(state, "SELECT COUNT(*)::bigint FROM gdpr_requests", &[]).await;
    let alerts = count_rows(
        state,
        "SELECT COUNT(*)::bigint FROM system_alerts WHERE acknowledged = false",
        &[],
    )
    .await;

    let rows: Vec<(String, String, String, Option<chrono::DateTime<chrono::Utc>>)> = optional_rows(
        async {
            sqlx::query_as::<_, (String, String, String, Option<chrono::DateTime<chrono::Utc>>)>(
                "SELECT id, request_type, status, created_at FROM gdpr_requests ORDER BY created_at DESC LIMIT 10",
            )
            .fetch_all(&state.db)
            .await
        },
    )
    .await;

    let mut data = base_list(
        "Compliance",
        "Trust workflows and policy operations.",
        "/compliance",
    );
    data.kpis = vec![
        KpiCardData::new("GDPR pending", gdpr_pending.to_string()).with_hint("Requests"),
        KpiCardData::new("GDPR total", gdpr_total.to_string()).with_hint("All time"),
        KpiCardData::new("Open alerts", alerts.to_string()).with_hint("Fleet"),
    ];
    data.primary_action = Some(("GDPR queue".into(), "/compliance/gdpr".into()));
    data.empty_title = "No compliance requests".into();
    data.empty_description = "GDPR and trust workflows appear here as they are filed.".into();
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

async fn cp_gdpr(state: &AppState, q: &ListQuery) -> ListPageData {
    let mut where_sql = WhereBuilder::new();
    where_sql.status_in(
        &["pending", "in_progress", "completed", "rejected"],
        &q.status,
    );
    let where_clause = where_sql.build();

    let total = count_rows(
        state,
        &format!("SELECT COUNT(*)::bigint FROM gdpr_requests WHERE {where_clause}"),
        &where_sql.binds,
    )
    .await;
    let (page, total_pages, offset) = paging(total, q.page);

    let rows: Vec<(String, String, String, String, Option<chrono::DateTime<chrono::Utc>>)> =
        optional_rows(
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
        .await;

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
    data.total_count = total;
    data.filter_query = filter_query(q);
    data.empty_title = "No GDPR requests".into();
    data.empty_description = "Data-subject requests appear here as they arrive.".into();
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

async fn cp_discovery(state: &AppState) -> ListPageData {
    let rows: Vec<(String, i64)> = optional_rows(
        async {
            sqlx::query_as::<_, (String, i64)>(
                "SELECT COALESCE(source, 'unknown'), COUNT(*)::bigint FROM sales_leads GROUP BY 1 ORDER BY 2 DESC LIMIT 25",
            )
            .fetch_all(&state.db)
            .await
        },
    )
    .await;

    let total = count_rows(state, "SELECT COUNT(*)::bigint FROM sales_leads", &[]).await;

    let mut data = base_list(
        "Service Discovery",
        "Registered lead sources and routing state.",
        "/discovery",
    );
    data.kpis = vec![KpiCardData::new("Leads", total.to_string()).with_hint("All sources")];
    data.empty_title = "No discovery sources reporting".into();
    data.empty_description = "Discovery runs register their sources here as they execute.".into();
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

async fn cp_analytics(state: &AppState) -> ListPageData {
    let agg = event_aggregate(state, "timestamp >= NOW() - '30 days'::interval", &[]).await;
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
        KpiCardData::new("Sent (30d)", sent.to_string()).with_hint("Fleet-wide"),
        KpiCardData::new("Delivered", delivered.to_string()).with_hint(&rate(delivered, sent)),
        KpiCardData::new("Bounced", bounced.to_string()).with_hint(&rate(bounced, sent)),
        KpiCardData::new("Complaints", complained.to_string()).with_hint(&rate(complained, sent)),
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
    let rows: Vec<(String, String)> = optional_rows(async {
        sqlx::query_as::<_, (String, String)>(
            "SELECT id::text, name FROM lists WHERE tenant_id = $1 ORDER BY name ASC LIMIT 200",
        )
        .bind(tenant)
        .fetch_all(db)
        .await
    })
    .await;
    rows.into_iter()
        .map(|(id, name)| (id, name, false))
        .collect()
}

/// Plan names from the billing catalog (item I) — the tenant-create
/// form's plan select is validated against this exact set.
pub(crate) async fn tenant_plan_names(db: &sqlx::PgPool) -> Vec<String> {
    optional_rows(async {
        sqlx::query_as::<_, (String,)>("SELECT name FROM plans ORDER BY price_cents ASC LIMIT 50")
            .fetch_all(db)
            .await
    })
    .await
    .into_iter()
    .map(|(name,)| name)
    .collect()
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
    fn alert_rules_empty_state_is_honest() {
        let data = cp_alert_rules();
        assert!(data.table.unwrap().rows.is_empty());
        assert!(data.empty_description.contains("not provisioned"));
    }

    #[test]
    fn filter_query_preserves_active_filters() {
        let q = parse_list_query(Some("query=a b&status=draft&stage=proposal"));
        assert_eq!(filter_query(&q), "query=a%20b&status=draft&stage=proposal");
        assert_eq!(filter_query(&ListQuery::default()), "");
    }
}
