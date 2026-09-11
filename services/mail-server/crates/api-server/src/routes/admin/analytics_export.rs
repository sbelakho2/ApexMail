//! Analytics CSV/JSON export endpoint.
//!

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use billing_common::csv::quote_csv_field;
use serde::{Deserialize, Serialize};

use crate::analytics_metrics::{
    detect_event_columns, distinct_message_time_series, parse_analytics_range, AnalyticsRange,
    DistinctTimeSeriesPoint, EventColumns,
};
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

/// Per-day rows for the export.
///
/// Sent/delivered/opened/clicked come from the canonical metric module
/// (`distinct_message_time_series` — the exact function
/// `GET /v1/admin/analytics` uses), so "one open per message, counted once"
/// holds in the CSV exactly as it does in the JSON API: a message opened
/// three times contributes 1.
///
/// The canonical time series does not expose per-day bounced/complaints (the
/// API reports them as window aggregates), so those two columns are fetched
/// with the same DISTINCT-message cardinality and merged in.
async fn load_export_rows(
    db: &sqlx::PgPool,
    tenant_id: Option<&str>,
    range: AnalyticsRange,
    columns: EventColumns,
) -> Result<Vec<ExportRow>, ApiError> {
    let series = distinct_message_time_series(db, tenant_id, range, columns).await?;
    let extras = load_bounce_complaint_days(db, tenant_id, range, columns).await?;
    Ok(merge_export_rows(series, extras))
}

/// Merge the canonical series with the per-day bounced/complaints supplement,
/// keyed by date. Days present in only one source still get a row.
fn merge_export_rows(
    series: Vec<DistinctTimeSeriesPoint>,
    extras: Vec<(String, i64, i64)>,
) -> Vec<ExportRow> {
    let mut by_date: std::collections::BTreeMap<String, ExportRow> = series
        .into_iter()
        .map(|point| {
            (
                point.date.clone(),
                ExportRow {
                    date: point.date,
                    sent: point.sent,
                    delivered: point.delivered,
                    opened: point.opened,
                    clicked: point.clicked,
                    bounced: 0,
                    complaints: 0,
                },
            )
        })
        .collect();

    for (date, bounced, complaints) in extras {
        let row = by_date.entry(date.clone()).or_insert_with(|| ExportRow {
            date,
            sent: 0,
            delivered: 0,
            opened: 0,
            clicked: 0,
            bounced: 0,
            complaints: 0,
        });
        row.bounced = bounced;
        row.complaints = complaints;
    }

    by_date.into_values().collect()
}

/// Per-day bounced/complaints, counted as DISTINCT message ids (the canonical
/// cardinality contract), bucketed by event occurrence.
fn build_bounce_complaint_query(columns: EventColumns, range: AnalyticsRange) -> String {
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();
    let interval = range.interval_sql();

    format!(
        "SELECT DATE({time_col})::text as d,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'bounced') as bounced,
            COUNT(DISTINCT message_id) FILTER (WHERE {type_col} = 'complained') as complaints
         FROM events
         WHERE {time_col} >= NOW() - '{interval}'::interval
           AND ($1::text IS NULL OR tenant_id = $1)
         GROUP BY d ORDER BY d ASC"
    )
}

async fn load_bounce_complaint_days(
    db: &sqlx::PgPool,
    tenant_id: Option<&str>,
    range: AnalyticsRange,
    columns: EventColumns,
) -> Result<Vec<(String, i64, i64)>, ApiError> {
    let sql = build_bounce_complaint_query(columns, range);
    let rows = sqlx::query_as::<_, (String, i64, i64)>(&sql)
        .bind(tenant_id)
        .fetch_all(db)
        .await?;
    Ok(rows)
}

async fn export_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let range = parse_analytics_range(&params.range);
    let columns = detect_event_columns(&state).await;

    // Slug-aware system-tenant resolution (audit F1): operators belong to
    // `system_internal_tenant01`; the literal check wrongly scoped them. A
    // system tenant exports FLEET-WIDE (`None`), matching the analytics API's
    // system-tenant semantics.
    let tenant_id = if crate::routes::web::is_system_tenant(&state, &auth.tenant_id).await {
        None
    } else {
        Some(auth.tenant_id.as_str())
    };
    let data = load_export_rows(&state.db, tenant_id, range, columns).await?;

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
    use crate::analytics_metrics::{AnalyticsRange, EventColumns};

    /// The export's per-day bounced/complaints supplement must follow the
    /// canonical cardinality contract (distinct message ids), never raw
    /// event-row counting.
    #[test]
    fn bounce_complaint_query_counts_distinct_messages_only() {
        let sql = build_bounce_complaint_query(EventColumns::default(), AnalyticsRange::Days30);

        assert_eq!(sql.matches("COUNT(DISTINCT message_id)").count(), 2);
        assert!(!sql.contains("COUNT(*)"));
        assert!(!sql.contains("SUM(CASE"));
        // Event-occurrence timestamps, not message creation.
        assert!(sql.contains("timestamp >= NOW() - '30 days'::interval"));
        assert!(!sql.contains("created_at"));
    }

    #[test]
    fn merge_fills_bounce_days_and_keeps_canonical_counts() {
        let series = vec![
            DistinctTimeSeriesPoint {
                date: "2024-01-01".into(),
                sent: 10,
                delivered: 9,
                opened: 4,
                clicked: 2,
            },
            DistinctTimeSeriesPoint {
                date: "2024-01-02".into(),
                sent: 3,
                delivered: 3,
                opened: 0,
                clicked: 0,
            },
        ];
        let extras = vec![
            ("2024-01-01".to_string(), 1, 0),
            ("2024-01-03".to_string(), 0, 2),
        ];

        let rows = merge_export_rows(series, extras);

        assert_eq!(rows.len(), 3, "union of both sources' dates");
        assert_eq!(rows[0].date, "2024-01-01");
        assert_eq!(rows[0].opened, 4);
        assert_eq!(rows[0].bounced, 1);
        assert_eq!(rows[1].date, "2024-01-02");
        assert_eq!(rows[1].sent, 3);
        assert_eq!(rows[2].date, "2024-01-03");
        assert_eq!(rows[2].complaints, 2);
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

    /// Adversarial proof against the canonical schema: a message opened THREE
    /// times must appear as ONE opened message in the exported CSV — the same
    /// value `GET /v1/admin/analytics` reports (both go through
    /// `distinct_message_time_series`). Gated on TEST_DATABASE_URL.
    #[tokio::test]
    async fn message_opened_three_times_counts_once_in_export_csv() {
        let Some(pool) = crate::test_db::canonical_pool("analytics_export_multi_open").await else {
            eprintln!(
                "skipping message_opened_three_times_counts_once_in_export_csv: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);
        let message = format!("msg-{suffix}");

        for _ in 0..3 {
            sqlx::query(
                "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp)
                 VALUES ($1, $2, $3, 'opened', 'user@example.com', NOW())",
            )
            .bind(format!("evt-{}", uuid::Uuid::new_v4().simple()))
            .bind(&tenant)
            .bind(&message)
            .execute(&pool)
            .await
            .expect("seed open event");
        }
        sqlx::query(
            "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp)
             VALUES ($1, $2, $3, 'sent', 'user@example.com', NOW())",
        )
        .bind(format!("evt-{}", uuid::Uuid::new_v4().simple()))
        .bind(&tenant)
        .bind(&message)
        .execute(&pool)
        .await
        .expect("seed sent event");

        let rows = load_export_rows(
            &pool,
            Some(&tenant),
            AnalyticsRange::Days7,
            EventColumns::default(),
        )
        .await
        .expect("export rows must load from the canonical schema");

        assert_eq!(rows.len(), 1, "all events fall on one UTC day");
        assert_eq!(rows[0].sent, 1);
        assert_eq!(
            rows[0].opened, 1,
            "three opens on ONE message must count once in the export"
        );
        assert_eq!(rows[0].clicked, 0);

        let csv = build_csv(&rows);
        let data_line = csv.lines().nth(1).expect("data line");
        assert!(
            data_line.contains("\"1\",\"0\",\"1\",\"0\",\"0\",\"0\""),
            "CSV must show Sent=1, Delivered=0, Opened=1, Clicked=0, Bounced=0, \
             Complaints=0 — got: {data_line}"
        );
        assert!(
            !data_line.contains("\"3\""),
            "three raw open events must never appear as 3: {data_line}"
        );

        pool.close().await;
    }
}
