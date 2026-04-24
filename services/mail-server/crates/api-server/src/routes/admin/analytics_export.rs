//! Analytics CSV/JSON export endpoint.
//!

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(export_analytics))
}

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    #[serde(default = "default_range")]
    pub range: String,
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_range() -> String { "30d".into() }
fn default_format() -> String { "csv".into() }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportRow {
    pub date: String,
    pub sent: i64,
    pub delivered: i64,
    pub opened: i64,
    pub clicked: i64,
    pub bounced: i64,
    pub complaints: i64,
}

fn range_to_interval(range: &str) -> &str {
    match range {
        "24h" => "24 hours",
        "7d" => "7 days",
        "30d" => "30 days",
        "90d" => "90 days",
        "12m" => "365 days",
        _ => "30 days",
    }
}

async fn export_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let interval = range_to_interval(&params.range);

// Detect columns
    let type_col = super::analytics::detect_column(&state, "events", &["event_type", "type"])
        .await
        .unwrap_or_else(|| "event_type".into());
    let time_col = super::analytics::detect_column(&state, "events", &["created_at", "timestamp"])
        .await
        .unwrap_or_else(|| "created_at".into());

    let sql = format!(
        "SELECT DATE({time_col})::text as d,
            COALESCE(SUM(CASE WHEN {type_col} = 'sent' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'delivered' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'opened' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'clicked' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'bounced' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'complained' THEN 1 ELSE 0 END), 0)
         FROM events WHERE {time_col} >= NOW() - '{interval}'::interval
         GROUP BY d ORDER BY d ASC"
    );

    let rows = sqlx::query_as::<_, (String, i64, i64, i64, i64, i64, i64)>(&sql)
        .fetch_all(&state.db)
        .await?;

    let data: Vec<ExportRow> = rows
        .into_iter()
        .map(|(date, s, d, o, c, b, comp)| ExportRow {
            date, sent: s, delivered: d, opened: o, clicked: c, bounced: b, complaints: comp,
        })
        .collect();

    if params.format == "csv" {
        let mut csv = String::from("Date,Sent,Delivered,Opened,Clicked,Bounced,Complaints\n");
        for r in &data {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                r.date, r.sent, r.delivered, r.opened, r.clicked, r.bounced, r.complaints
            ));
        }
        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("analytics_export_{ts}.csv");
        Ok((
            [
                (header::CONTENT_TYPE, "text/csv".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
            ],
            csv,
        )
            .into_response())
    } else {
        let payload = serde_json::json!({
            "exportedAt": chrono::Utc::now().to_rfc3339(),
            "range": params.range,
            "data": data,
        });
        Ok(axum::Json(payload).into_response())
    }
}
