//! Estonia OÜ compliance admin routes.
//!
//! Endpoints for managing Estonian legal compliance filings for
//! BEL CONSULTING OÜ (Registry Code 16588745).
//!
//! Routes:
//! - GET  /estonia/deadlines            — list upcoming deadlines
//! - GET  /estonia/deadlines/widget     — dashboard widget with deadline stats
//! - POST /estonia/deadlines/seed       — seed deadlines for 2025–2027
//! - POST /estonia/generate/annual-report/:year — generate annual report
//! - POST /estonia/generate/vat/:year/:month     — generate VAT declaration
//! - POST /estonia/generate/income-tax/:year/:month — income tax
//! - POST /estonia/generate/social-tax/:year/:month — social tax (TSD)
//! - POST /estonia/generate/statistical/:year       — statistical report
//! - GET  /estonia/submissions           — list past submissions
//! - GET  /estonia/submissions/:id/download/:format — download submission (pdf/csv/json)
//! - POST /estonia/reminders/trigger     — manually trigger reminder check

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use compliance::estonia_ou::{ComplianceCalendar, EstoniaOuCompliance, SubmissionType};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/estonia/deadlines", get(list_deadlines))
        .route("/estonia/deadlines/widget", get(deadlines_widget))
        .route("/estonia/deadlines/seed", post(seed_deadlines))
        .route(
            "/estonia/generate/annual-report/:year",
            post(generate_annual_report),
        )
        .route(
            "/estonia/generate/vat/:year/:month",
            post(generate_vat_declaration),
        )
        .route(
            "/estonia/generate/income-tax/:year/:month",
            post(generate_income_tax),
        )
        .route(
            "/estonia/generate/social-tax/:year/:month",
            post(generate_social_tax),
        )
        .route(
            "/estonia/generate/statistical/:year",
            post(generate_statistical_report),
        )
        .route("/estonia/submissions", get(list_submissions))
        .route(
            "/estonia/submissions/:id/download/:format",
            get(download_submission),
        )
        .route("/estonia/reminders/trigger", post(trigger_reminders))
        .route("/estonia/viewer", get(viewer_page))
}

// ---------------------------------------------------------------------------
// Query / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeadlineQuery {
    #[serde(default)]
    pub upcoming_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmissionQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadlineResponse {
    pub id: Uuid,
    pub deadline_type: String,
    pub label: String,
    pub period_start: String,
    pub period_end: String,
    pub due_date: String,
    pub status: String,
    pub indicator: String,
    pub submission_id: Option<Uuid>,
    pub reminded_7d: bool,
    pub reminded_1d: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionResponse {
    pub id: Uuid,
    pub submission_type: String,
    pub period_start: String,
    pub period_end: String,
    pub tax_year: i32,
    pub tax_month: Option<i32>,
    pub status: String,
    pub submitted_at: Option<String>,
    pub document_json: serde_json::Value,
    pub document_url: Option<String>,
    pub filing_reference: Option<String>,
    pub file_name: Option<String>,
    pub file_size: Option<i64>,
    pub period_label: Option<String>,
    pub checksum: Option<String>,
    pub has_pdf: bool,
    pub has_csv: bool,
    pub has_json: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn build_engine(state: &AppState) -> EstoniaOuCompliance {
    EstoniaOuCompliance::new(state.db.clone())
}

fn build_calendar(db: &PgPool) -> ComplianceCalendar {
    ComplianceCalendar::new(db.clone())
}

/// GET /v1/admin/compliance/estonia/deadlines
async fn list_deadlines(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<DeadlineQuery>,
) -> Result<Json<Vec<DeadlineResponse>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let calendar = build_calendar(&state.db);
    let deadlines = if let Some(days) = q.upcoming_days {
        calendar.list_upcoming(days).await.map_err(|e| {
            ApiError::Internal(format!("Failed to list upcoming deadlines: {e}"))
        })?
    } else {
        calendar.list_pending().await.map_err(|e| {
            ApiError::Internal(format!("Failed to list deadlines: {e}"))
        })?
    };

    let responses: Vec<DeadlineResponse> = deadlines
        .into_iter()
        .map(|d| {
            let status_enum = match d.status.as_str() {
                "pending" => compliance::estonia_ou::DeadlineStatus::Pending,
                "filed" => compliance::estonia_ou::DeadlineStatus::Filed,
                "overdue" => compliance::estonia_ou::DeadlineStatus::Overdue,
                _ => compliance::estonia_ou::DeadlineStatus::Exempt,
            };
            DeadlineResponse {
                id: d.id,
                deadline_type: d.deadline_type,
                label: d.label,
                period_start: d.period_start.to_string(),
                period_end: d.period_end.to_string(),
                due_date: d.due_date.to_string(),
                status: d.status,
                indicator: status_enum.indicator().into(),
                submission_id: d.submission_id,
                reminded_7d: d.reminded_7d_at.is_some(),
                reminded_1d: d.reminded_1d_at.is_some(),
            }
        })
        .collect();

    Ok(Json(responses))
}

/// GET /v1/admin/compliance/estonia/deadlines/widget
async fn deadlines_widget(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let engine = build_engine(&state).await;
    let widget = engine.deadline_widget().await.map_err(|e| {
        ApiError::Internal(format!("Failed to build deadline widget: {e}"))
    })?;

    Ok(Json(serde_json::to_value(widget).unwrap_or_default()))
}

/// POST /v1/admin/compliance/estonia/deadlines/seed
async fn seed_deadlines(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let calendar = build_calendar(&state.db);
    let created = calendar.seed_deadlines().await.map_err(|e| {
        ApiError::Internal(format!("Failed to seed deadlines: {e}"))
    })?;

    Ok(Json(serde_json::json!({
        "seeded": true,
        "count": created.len(),
    })))
}

/// POST /v1/admin/compliance/estonia/generate/annual-report/:year
async fn generate_annual_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(year): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let engine = build_engine(&state).await;
    let report = engine.generate_annual_report(year).await.map_err(|e| {
        ApiError::Internal(format!("Failed to generate annual report: {e}"))
    })?;

    let json = serde_json::to_value(&report).unwrap_or_default();
    let submission_id = engine
        .persist_submission(SubmissionType::AnnualReport, year, None, &json)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to persist submission: {e}")))?;

    Ok(Json(serde_json::json!({
        "submission_id": submission_id,
        "report": json,
    })))
}

/// POST /v1/admin/compliance/estonia/generate/vat/:year/:month
async fn generate_vat_declaration(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((year, month)): Path<(i32, u32)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let engine = build_engine(&state).await;
    let declaration = engine
        .generate_vat_declaration(year, month)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to generate VAT declaration: {e}")))?;

    let json = serde_json::to_value(&declaration).unwrap_or_default();
    let submission_id = engine
        .persist_submission(SubmissionType::VatDeclaration, year, Some(month), &json)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to persist submission: {e}")))?;

    Ok(Json(serde_json::json!({
        "submission_id": submission_id,
        "declaration": json,
    })))
}

/// POST /v1/admin/compliance/estonia/generate/income-tax/:year/:month
async fn generate_income_tax(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((year, month)): Path<(i32, u32)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let engine = build_engine(&state).await;
    let declaration = engine
        .generate_income_tax_declaration(year, month)
        .await
        .map_err(|e| {
            ApiError::Internal(format!("Failed to generate income tax declaration: {e}"))
        })?;

    let json = serde_json::to_value(&declaration).unwrap_or_default();
    let submission_id = engine
        .persist_submission(SubmissionType::IncomeTax, year, Some(month), &json)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to persist submission: {e}")))?;

    Ok(Json(serde_json::json!({
        "submission_id": submission_id,
        "declaration": json,
    })))
}

/// POST /v1/admin/compliance/estonia/generate/social-tax/:year/:month
async fn generate_social_tax(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((year, month)): Path<(i32, u32)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let engine = build_engine(&state).await;
    let declaration = engine
        .generate_social_tax_declaration(year, month)
        .await
        .map_err(|e| {
            ApiError::Internal(format!("Failed to generate social tax declaration: {e}"))
        })?;

    let json = serde_json::to_value(&declaration).unwrap_or_default();
    let submission_id = engine
        .persist_submission(SubmissionType::SocialTax, year, Some(month), &json)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to persist submission: {e}")))?;

    Ok(Json(serde_json::json!({
        "submission_id": submission_id,
        "declaration": json,
    })))
}

/// POST /v1/admin/compliance/estonia/generate/statistical/:year
async fn generate_statistical_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(year): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let engine = build_engine(&state).await;
    let report = engine
        .generate_statistical_report(year)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to generate statistical report: {e}")))?;

    let json = serde_json::to_value(&report).unwrap_or_default();
    let submission_id = engine
        .persist_submission(SubmissionType::StatisticalReport, year, None, &json)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to persist submission: {e}")))?;

    Ok(Json(serde_json::json!({
        "submission_id": submission_id,
        "report": json,
    })))
}

/// GET /v1/admin/compliance/estonia/submissions
async fn list_submissions(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<SubmissionQuery>,
) -> Result<Json<Vec<SubmissionResponse>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let engine = build_engine(&state).await;
    let submissions = engine
        .list_submissions_extended(q.limit, q.offset)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to list submissions: {e}")))?;

    let responses: Vec<SubmissionResponse> = submissions
        .into_iter()
        .map(|s| SubmissionResponse {
            id: s.id,
            submission_type: s.submission_type,
            period_start: s.period_start.to_string(),
            period_end: s.period_end.to_string(),
            tax_year: s.tax_year,
            tax_month: s.tax_month,
            status: s.status,
            submitted_at: s.submitted_at.map(|t| t.to_rfc3339()),
            document_json: s.document_json,
            document_url: s.document_url,
            filing_reference: s.filing_reference,
            file_name: s.file_name,
            file_size: s.file_size,
            period_label: s.period_label,
            checksum: s.checksum,
            has_pdf: s.has_pdf,
            has_csv: s.has_csv,
            has_json: s.has_json,
        })
        .collect();

    Ok(Json(responses))
}

/// GET /v1/admin/compliance/estonia/submissions/:id/download/:format
async fn download_submission(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((id, format)): Path<(Uuid, String)>,
) -> Result<impl IntoResponse, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let engine = build_engine(&state).await;
    let submission = engine
        .get_submission_download(id)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to get submission: {e}")))?
        .ok_or_else(|| ApiError::NotFound("Submission not found".into()))?;

    match format.as_str() {
        "pdf" => {
            let bytes = submission.pdf_data;
            let file_name = submission.file_name.clone();
            let headers = [
                (header::CONTENT_TYPE, "application/pdf"),
                (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", file_name)),
            ];
            Ok((axum::http::StatusCode::OK, headers, axum::body::Body::from(bytes)).into_response())
        }
        "csv" => {
            let csv_data = submission.csv_data;
            let csv_file = submission.file_name.replace(".pdf", ".csv");
            let headers = [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", csv_file)),
            ];
            Ok((axum::http::StatusCode::OK, headers, csv_data).into_response())
        }
        "json" => {
            let json_data = serde_json::to_string_pretty(&submission.json_data)
                .unwrap_or_else(|_| "{}".into());
            let json_file = submission.file_name.replace(".pdf", ".json");
            let headers = [
                (header::CONTENT_TYPE, "application/json; charset=utf-8"),
                (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", json_file)),
            ];
            Ok((axum::http::StatusCode::OK, headers, json_data).into_response())
        }
        other => Err(ApiError::BadRequest(format!(
            "Unsupported format: {other}. Use pdf, csv, or json."
        ))),
    }
}

/// GET /v1/admin/compliance/estonia/viewer
/// Admin panel compliance document viewer page.
async fn viewer_page(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<SubmissionQuery>,
) -> Result<axum::response::Html<String>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let engine = build_engine(&state).await;
    let submissions = engine
        .list_submissions_extended(q.limit, q.offset)
        .await
        .unwrap_or_default();

    let _now = chrono::Utc::now().date_naive();

    let mut rows_html = String::new();
    for s in &submissions {
        let status_class = match s.status.as_str() {
            "submitted" | "acknowledged" => "green",
            "overdue" => "red",
            "error" => "red",
            "draft" | "pending" => "amber",
            _ => "grey",
        };
        let status_label = &s.status;

        let period = if let Some(ref label) = s.period_label {
            label.clone()
        } else if let Some(m) = s.tax_month {
            format!("{} {:02}", s.tax_year, m)
        } else {
            format!("FY {}", s.tax_year)
        };

        let type_badge = match s.submission_type.as_str() {
            "annual_report" => "Annual Report",
            "vat_declaration" => "VAT Declaration",
            "income_tax" => "Income Tax",
            "social_tax" => "Social Tax",
            "statistical_report" => "Statistical",
            other => other,
        };

        let format_badges = {
            let mut badges = String::new();
            if s.has_pdf {
                badges.push_str("<span class='badge pdf'>PDF</span> ");
            }
            if s.has_csv {
                badges.push_str("<span class='badge csv'>CSV</span> ");
            }
            if s.has_json {
                badges.push_str("<span class='badge json'>JSON</span> ");
            }
            badges
        };

        let download_buttons = {
            let mut btns = String::new();
            let id = s.id;
            if s.has_pdf {
                btns.push_str(&format!(
                    "<a href='/v1/admin/compliance/estonia/submissions/{id}/download/pdf' class='btn-dl'>PDF</a> "
                ));
            }
            if s.has_csv {
                btns.push_str(&format!(
                    "<a href='/v1/admin/compliance/estonia/submissions/{id}/download/csv' class='btn-dl'>CSV</a> "
                ));
            }
            if s.has_json {
                btns.push_str(&format!(
                    "<a href='/v1/admin/compliance/estonia/submissions/{id}/download/json' class='btn-dl'>JSON</a> "
                ));
            }
            btns
        };

        let created = s.submitted_at
            .map(|t| t.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "—".into());

        let checksum_short = s.checksum.as_deref()
            .map(|c| {
                if c.len() > 12 {
                    format!("{}…", &c[..12])
                } else {
                    c.to_string()
                }
            })
            .unwrap_or_else(|| "—".into());

        rows_html.push_str(&format!(
            r#"<tr>
                <td>{period}</td>
                <td><span class="badge type">{type_badge}</span></td>
                <td><span class="badge status status-{status_class}">{status_label}</span></td>
                <td>{created}</td>
                <td>{format_badges}</td>
                <td>{download_buttons}</td>
                <td class="cksum" title="{full_checksum}">{checksum_short}</td>
            </tr>"#,
            period = html_escape(&period),
            type_badge = html_escape(type_badge),
            status_class = status_class,
            status_label = html_escape(status_label),
            created = html_escape(&created),
            format_badges = format_badges,
            download_buttons = download_buttons,
            full_checksum = html_escape(s.checksum.as_deref().unwrap_or("—")),
            checksum_short = html_escape(&checksum_short),
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compliance Documents — BEL CONSULTING OÜ</title>
<style>
:root {{ --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0;
  --muted: #94a3b8; --green: #22c55e; --red: #ef4444; --amber: #f59e0b;
  --blue: #3b82f6; --purple: #a855f7; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg); color: var(--text); padding: 2rem; }}
h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
.subtitle {{ color: var(--muted); margin-bottom: 1.5rem; font-size: 0.875rem; }}
.filters {{ display: flex; gap: 0.75rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
.filters input, .filters select {{ background: var(--surface); color: var(--text);
  border: 1px solid var(--border); padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.875rem; }}
.filters input::placeholder {{ color: var(--muted); }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.875rem; }}
th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
tr:hover {{ background: var(--surface); }}
.badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
.badge.type {{ background: var(--surface); color: var(--blue); border: 1px solid var(--blue); }}
.badge.pdf {{ background: #1e293b; color: var(--red); border: 1px solid var(--red); }}
.badge.csv {{ background: #1e293b; color: var(--green); border: 1px solid var(--green); }}
.badge.json {{ background: #1e293b; color: var(--purple); border: 1px solid var(--purple); }}
.status {{ padding: 0.25rem 0.75rem; border-radius: 9999px; }}
.status-green {{ background: #064e3b; color: var(--green); }}
.status-red {{ background: #450a0a; color: var(--red); }}
.status-amber {{ background: #451a03; color: var(--amber); }}
.btn-dl {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 4px;
  font-size: 0.75rem; font-weight: 600; text-decoration: none;
  background: var(--blue); color: white; cursor: pointer; }}
.btn-dl:hover {{ opacity: 0.85; }}
.cksum {{ font-family: monospace; font-size: 0.75rem; color: var(--muted); max-width: 120px; overflow: hidden; text-overflow: ellipsis; }}
.empty {{ text-align: center; padding: 3rem; color: var(--muted); }}
.legend {{ display: flex; gap: 1.5rem; margin-bottom: 1rem; font-size: 0.75rem; color: var(--muted); }}
.legend-item {{ display: flex; align-items: center; gap: 0.35rem; }}
.dot {{ width: 8px; height: 8px; border-radius: 50%; }}
.dot.green {{ background: var(--green); }}
.dot.red {{ background: var(--red); }}
.dot.amber {{ background: var(--amber); }}
</style>
</head>
<body>
<h1>Compliance Documents</h1>
<p class="subtitle">BEL CONSULTING OÜ (Registry Code 16588745) — Estonia Legal Filings</p>

<div class="legend">
  <div class="legend-item"><span class="dot green"></span> On time (submitted/acknowledged)</div>
  <div class="legend-item"><span class="dot amber"></span> Pending/draft</div>
  <div class="legend-item"><span class="dot red"></span> Overdue/error</div>
</div>

<div class="filters">
  <input type="text" id="searchInput" placeholder="Search by type, year, status…" oninput="filterTable()">
  <select id="typeFilter" onchange="filterTable()">
    <option value="">All Types</option>
    <option value="annual_report">Annual Report</option>
    <option value="vat_declaration">VAT Declaration</option>
    <option value="income_tax">Income Tax</option>
    <option value="social_tax">Social Tax</option>
    <option value="statistical_report">Statistical</option>
  </select>
  <select id="yearFilter" onchange="filterTable()">
    <option value="">All Years</option>
    <option value="2025">2025</option>
    <option value="2026">2026</option>
    <option value="2027">2027</option>
  </select>
  <select id="statusFilter" onchange="filterTable()">
    <option value="">All Statuses</option>
    <option value="draft">Draft</option>
    <option value="generated">Generated</option>
    <option value="submitted">Submitted</option>
    <option value="acknowledged">Acknowledged</option>
    <option value="overdue">Overdue</option>
    <option value="error">Error</option>
  </select>
</div>

<table id="complianceTable">
<thead>
  <tr>
    <th>Period</th>
    <th>Type</th>
    <th>Status</th>
    <th>Generated</th>
    <th>Formats</th>
    <th>Download</th>
    <th>Checksum</th>
  </tr>
</thead>
<tbody>
{rows}
</tbody>
</table>

<div id="emptyState" class="empty" style="display:none">
  <p>No compliance documents found matching your filters.</p>
  <p style="margin-top:0.5rem; font-size:0.8rem">Generate documents via the compliance API endpoints.</p>
</div>

<script>
function filterTable() {{
  var search = document.getElementById('searchInput').value.toLowerCase();
  var type = document.getElementById('typeFilter').value;
  var year = document.getElementById('yearFilter').value;
  var status = document.getElementById('statusFilter').value;
  var rows = document.querySelectorAll('#complianceTable tbody tr');
  var visible = 0;
  rows.forEach(function(r) {{
    var text = r.textContent.toLowerCase();
    var match = text.includes(search) &&
      (!type || text.includes(type.replace('_', ' '))) &&
      (!year || text.includes(year)) &&
      (!status || text.includes(status));
    r.style.display = match ? '' : 'none';
    if (match) visible++;
  }});
  document.getElementById('emptyState').style.display = visible === 0 ? '' : 'none';
}}
</script>
</body>
</html>"#,
        rows = if rows_html.is_empty() {
            r#"<tr><td colspan="7" class="empty">No compliance documents generated yet.</td></tr>"#.to_string()
        } else {
            rows_html
        }
    );

    Ok(axum::response::Html(html))
}

/// POST /v1/admin/compliance/estonia/reminders/trigger
async fn trigger_reminders(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let calendar = build_calendar(&state.db);

    calendar.refresh_overdue().await.map_err(|e| {
        ApiError::Internal(format!("Failed to refresh overdue: {e}"))
    })?;

    let seven_day = calendar.deadlines_for_7day_reminder().await.map_err(|e| {
        ApiError::Internal(format!("Failed to get 7-day reminders: {e}"))
    })?;

    for d in &seven_day {
        tracing::info!(
            deadline_type = %d.deadline_type,
            label = %d.label,
            due_date = %d.due_date,
            "7-day reminder triggered"
        );
        let _ = calendar.record_7day_reminder(d.id).await;
    }

    let one_day = calendar.deadlines_for_1day_reminder().await.map_err(|e| {
        ApiError::Internal(format!("Failed to get 1-day reminders: {e}"))
    })?;

    for d in &one_day {
        tracing::info!(
            deadline_type = %d.deadline_type,
            label = %d.label,
            due_date = %d.due_date,
            "1-day reminder triggered"
        );
        let _ = calendar.record_1day_reminder(d.id).await;
    }

    Ok(Json(serde_json::json!({
        "overdue_refreshed": true,
        "seven_day_reminders": seven_day.len(),
        "one_day_reminders": one_day.len(),
    })))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
