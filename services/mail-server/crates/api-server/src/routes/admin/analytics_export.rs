//! Analytics CSV/JSON export endpoint.
//!

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use billing_common::csv::quote_csv_field;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(export_analytics))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportQuery {
    #[serde(default = "default_range")]
    pub range: String,
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_range() -> String {
    "30d".into()
}
fn default_format() -> String {
    "csv".into()
}

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

fn build_export_query(
    columns: super::analytics::EventColumns,
    range: super::analytics::AnalyticsRange,
    tenant_scoped: bool,
) -> String {
    let tenant_filter = if tenant_scoped {
        "tenant_id = $1 AND "
    } else {
        ""
    };

    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();
    let interval = range.interval_sql();

    format!(
        "SELECT DATE({time_col})::text as d,
            COALESCE(SUM(CASE WHEN {type_col} = 'sent' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'delivered' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'opened' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'clicked' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'bounced' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'complained' THEN 1 ELSE 0 END), 0)
         FROM events WHERE {tenant_filter}{time_col} >= NOW() - '{interval}'::interval
         GROUP BY d ORDER BY d ASC"
    )
}

async fn export_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let range = super::analytics::parse_analytics_range(&params.range);
    let columns = super::analytics::detect_event_columns(&state).await;

    let tenant_scoped = auth.tenant_id != "system";
    let sql = build_export_query(columns, range, tenant_scoped);

    let rows = if tenant_scoped {
        sqlx::query_as::<_, (String, i64, i64, i64, i64, i64, i64)>(&sql)
            .bind(&auth.tenant_id)
            .fetch_all(&state.db)
            .await?
    } else {
        sqlx::query_as::<_, (String, i64, i64, i64, i64, i64, i64)>(&sql)
            .fetch_all(&state.db)
            .await?
    };

    let data: Vec<ExportRow> = rows
        .into_iter()
        .map(|(date, s, d, o, c, b, comp)| ExportRow {
            date,
            sent: s,
            delivered: d,
            opened: o,
            clicked: c,
            bounced: b,
            complaints: comp,
        })
        .collect();

    if params.format == "csv" {
        let csv = build_csv(&data);
        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("analytics_export_{ts}.csv");
        Ok((
            [
                (header::CONTENT_TYPE, "text/csv".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{filename}\""),
                ),
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

fn build_csv(data: &[ExportRow]) -> String {
    let mut csv = String::new();
    append_csv_row(
        &mut csv,
        &[
            "Date",
            "Sent",
            "Delivered",
            "Opened",
            "Clicked",
            "Bounced",
            "Complaints",
        ],
    );

    for row in data {
        let sent = row.sent.to_string();
        let delivered = row.delivered.to_string();
        let opened = row.opened.to_string();
        let clicked = row.clicked.to_string();
        let bounced = row.bounced.to_string();
        let complaints = row.complaints.to_string();

        append_csv_row(
            &mut csv,
            &[
                row.date.as_str(),
                sent.as_str(),
                delivered.as_str(),
                opened.as_str(),
                clicked.as_str(),
                bounced.as_str(),
                complaints.as_str(),
            ],
        );
    }

    csv
}

fn append_csv_row(csv: &mut String, fields: &[&str]) {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            csv.push(',');
        }
        csv.push_str(&quote_csv_field(field));
    }
    csv.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::admin::analytics;

    #[test]
    fn build_export_query_scopes_non_system_tenants() {
        let sql = build_export_query(
            analytics::EventColumns {
                type_col: analytics::EventTypeColumn::EventType,
                time_col: analytics::EventTimeColumn::CreatedAt,
            },
            analytics::AnalyticsRange::Days30,
            true,
        );

        assert!(sql.contains("WHERE tenant_id = $1 AND created_at >= NOW() - '30 days'::interval"));
    }

    #[test]
    fn build_export_query_allows_system_exports() {
        let sql = build_export_query(
            analytics::EventColumns {
                type_col: analytics::EventTypeColumn::EventType,
                time_col: analytics::EventTimeColumn::CreatedAt,
            },
            analytics::AnalyticsRange::Days30,
            false,
        );

        assert!(sql.contains("WHERE created_at >= NOW() - '30 days'::interval"));
        assert!(!sql.contains("tenant_id = $1"));
    }

    #[test]
    fn build_csv_quotes_header_and_values() {
        let csv = build_csv(&[ExportRow {
            date: "2024-01-01".into(),
            sent: 1,
            delivered: 2,
            opened: 3,
            clicked: 4,
            bounced: 5,
            complaints: 6,
        }]);

        assert!(csv.starts_with(
            "\"Date\",\"Sent\",\"Delivered\",\"Opened\",\"Clicked\",\"Bounced\",\"Complaints\"\n"
        ));
        assert!(csv.contains("\"2024-01-01\",\"1\",\"2\",\"3\",\"4\",\"5\",\"6\"\n"));
    }

    #[test]
    fn build_csv_sanitizes_formula_like_values() {
        let csv = build_csv(&[ExportRow {
            date: "=SUM(A1:A2)".into(),
            sent: 1,
            delivered: 0,
            opened: 0,
            clicked: 0,
            bounced: 0,
            complaints: 0,
        }]);

        assert!(csv.contains("\"'=SUM(A1:A2)\""));
    }
}
