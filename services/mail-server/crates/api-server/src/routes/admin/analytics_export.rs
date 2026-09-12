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
    detect_event_columns, parse_analytics_range, send_cohort_time_series, SendCohortTimeSeriesPoint,
};
use crate::analytics_metrics::{AnalyticsRange, EventColumns};
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
/// Every column — sent, delivered, opened, clicked, bounced, complaints —
/// comes from the ONE canonical metric definition
/// (`send_cohort_time_series`, the exact function `GET /v1/admin/analytics`
/// uses). Each row is a day of SEND cohorts with outcomes attached to that
/// cohort: a recipient-send opened three times contributes 1, and an open on
/// last week's send does not appear as today's open.
async fn load_export_rows(
    db: &sqlx::PgPool,
    tenant_id: Option<&str>,
    range: AnalyticsRange,
    columns: EventColumns,
) -> Result<Vec<ExportRow>, ApiError> {
    let series = send_cohort_time_series(db, tenant_id, range, columns).await?;
    Ok(series.into_iter().map(export_row_from_cohort).collect())
}

fn export_row_from_cohort(point: SendCohortTimeSeriesPoint) -> ExportRow {
    ExportRow {
        date: point.date,
        sent: point.sent,
        delivered: point.delivered,
        opened: point.opened,
        clicked: point.clicked,
        bounced: point.bounced,
        complaints: point.complained,
    }
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

    /// Every export column maps 1:1 from the canonical send-cohort series —
    /// no second, differently-bucketed source can disagree with the JSON API.
    #[test]
    fn export_row_maps_every_canonical_cohort_field() {
        let row = export_row_from_cohort(SendCohortTimeSeriesPoint {
            date: "2024-01-01".into(),
            sent: 10,
            delivered: 9,
            opened: 4,
            clicked: 2,
            bounced: 1,
            complained: 3,
        });

        assert_eq!(row.date, "2024-01-01");
        assert_eq!(row.sent, 10);
        assert_eq!(row.delivered, 9);
        assert_eq!(row.opened, 4);
        assert_eq!(row.clicked, 2);
        assert_eq!(row.bounced, 1);
        assert_eq!(row.complaints, 3);
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

    /// Adversarial proof against the canonical schema: a recipient-send
    /// opened THREE times must appear as ONE opened cohort row in the
    /// exported CSV — the same value `GET /v1/admin/analytics` reports (both
    /// go through `send_cohort_time_series`). Gated on TEST_DATABASE_URL.
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

        // The send comes FIRST (a cohort outcome must be at/after the send;
        // an open before the send is not an outcome of it).
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
