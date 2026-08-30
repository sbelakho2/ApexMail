//! Compliance overview endpoint.
//!

use super::super::helpers::table_exists;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use billing_common::vat_rates;
use chrono::Datelike;
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_compliance_overview))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskSummary {
    pub low: i64,
    pub medium: i64,
    pub high: i64,
    pub critical: i64,
}

#[derive(Debug, Serialize)]
pub struct GdprRequestSummary {
    pub pending: i64,
    pub processing: i64,
    pub completed: i64,
    pub overdue: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditStats {
    pub today_events: i64,
    pub week_events: i64,
    pub alerts_triggered: i64,
}

#[derive(Debug, Serialize)]
pub struct PolicyCompliance {
    pub name: String,
    pub compliant: i64,
    pub total: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub alert_type: String,
    pub message: String,
    pub severity: String,
    pub tenant_id: Option<String>,
    pub timestamp: String,
}

/// Current-period VAT summary appended to the compliance overview.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VatSummaryWidget {
    pub has_data: bool,
    pub tax_year: i32,
    pub tax_month: u32,
    pub invoice_count: i64,
    pub total_taxable_cents: i64,
    pub total_vat_cents: i64,
    pub rates: Vec<serde_json::Value>,
    pub latest_kmd_status: Option<String>,
    pub due_date: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceOverview {
    pub risk_summary: RiskSummary,
    pub gdpr_requests: GdprRequestSummary,
    pub audit_stats: AuditStats,
    pub policy_compliance: Vec<PolicyCompliance>,
    pub recent_alerts: Vec<AlertEntry>,
    pub vat_summary: VatSummaryWidget,
}

fn summarize_gdpr_request_counts(rows: &[(String, i64)], overdue: i64) -> GdprRequestSummary {
    let mut summary = GdprRequestSummary {
        pending: 0,
        processing: 0,
        completed: 0,
        overdue,
    };

    for (status, count) in rows {
        match status.as_str() {
            "pending" => summary.pending = *count,
            "processing" => summary.processing = *count,
            "completed" => summary.completed = *count,
            _ => {}
        }
    }

    summary
}

async fn get_compliance_overview(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ComplianceOverview>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let tenant_scoped = auth.tenant_id != "system";

    let has_gdpr = table_exists(db, "gdpr_requests").await;
    let has_alerts = table_exists(db, "system_alerts").await;
    let has_domains = table_exists(db, "domains").await;

    // Risk summary
    let mut risk_summary = RiskSummary {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
    };
    if has_alerts {
        let rows: Vec<(String, i64)> = if tenant_scoped {
            sqlx::query_as(
                "SELECT CASE
                WHEN severity = 'critical' THEN 'critical'
                WHEN severity = 'high' THEN 'high'
                WHEN severity = 'medium' THEN 'medium'
                ELSE 'low'
             END as risk_level,
             COUNT(*)::bigint
             FROM system_alerts WHERE acknowledged = false AND tenant_id = $1
             GROUP BY risk_level",
            )
            .bind(&auth.tenant_id)
            .fetch_all(db)
            .await?
        } else {
            sqlx::query_as(
                "SELECT CASE
                WHEN severity = 'critical' THEN 'critical'
                WHEN severity = 'high' THEN 'high'
                WHEN severity = 'medium' THEN 'medium'
                ELSE 'low'
             END as risk_level,
             COUNT(*)::bigint
             FROM system_alerts WHERE acknowledged = false
             GROUP BY risk_level",
            )
            .fetch_all(db)
            .await?
        };

        for (level, count) in &rows {
            match level.as_str() {
                "low" => risk_summary.low = *count,
                "medium" => risk_summary.medium = *count,
                "high" => risk_summary.high = *count,
                "critical" => risk_summary.critical = *count,
                _ => {}
            }
        }
    }

    // GDPR requests summary
    let mut gdpr_requests = GdprRequestSummary {
        pending: 0,
        processing: 0,
        completed: 0,
        overdue: 0,
    };
    if has_gdpr {
        let rows: Vec<(String, i64)> = if tenant_scoped {
            sqlx::query_as(
                "SELECT status, COUNT(*)::bigint
                 FROM gdpr_requests
                 WHERE tenant_id = $1
                 GROUP BY status",
            )
            .bind(&auth.tenant_id)
            .fetch_all(db)
            .await?
        } else {
            sqlx::query_as("SELECT status, COUNT(*)::bigint FROM gdpr_requests GROUP BY status")
                .fetch_all(db)
                .await?
        };

        // COUNT(*) always returns a row, so fetch_one will not fail from empty results
        let overdue = if tenant_scoped {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*)::bigint
             FROM gdpr_requests
             WHERE tenant_id = $1
               AND status NOT IN ('completed', 'rejected')
               AND sla_deadline < NOW()",
            )
            .bind(&auth.tenant_id)
            .fetch_one(db)
            .await?
        } else {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*)::bigint
             FROM gdpr_requests
             WHERE status NOT IN ('completed', 'rejected')
               AND sla_deadline < NOW()",
            )
            .fetch_one(db)
            .await?
        };

        gdpr_requests = summarize_gdpr_request_counts(&rows, overdue);
    }

    // Audit stats
    let has_audit_logs = table_exists(db, "audit_logs").await;
    let audit_stats = if has_audit_logs {
        let audit_row: (i64, i64) = if tenant_scoped {
            sqlx::query_as(
                "SELECT COUNT(*) FILTER (WHERE timestamp >= CURRENT_DATE)::bigint,
                    COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '7 days')::bigint
             FROM audit_logs
             WHERE tenant_id = $1",
            )
            .bind(&auth.tenant_id)
            .fetch_one(db)
            .await?
        } else {
            sqlx::query_as(
                "SELECT COUNT(*) FILTER (WHERE timestamp >= CURRENT_DATE)::bigint,
                    COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '7 days')::bigint
             FROM audit_logs",
            )
            .fetch_one(db)
            .await?
        };

        let alerts_triggered = if has_alerts {
            if tenant_scoped {
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*)::bigint
                     FROM system_alerts
                     WHERE tenant_id = $1
                       AND created_at >= NOW() - INTERVAL '24 hours'
                       AND severity IN ('high', 'critical')",
                )
                .bind(&auth.tenant_id)
                .fetch_one(db)
                .await?
            } else {
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*)::bigint
                     FROM system_alerts
                     WHERE created_at >= NOW() - INTERVAL '24 hours'
                       AND severity IN ('high', 'critical')",
                )
                .fetch_one(db)
                .await?
            }
        } else {
            0
        };

        AuditStats {
            today_events: audit_row.0,
            week_events: audit_row.1,
            alerts_triggered,
        }
    } else {
        AuditStats {
            today_events: 0,
            week_events: 0,
            alerts_triggered: 0,
        }
    };

    // Policy compliance (domains)
    let policy_compliance = if has_domains {
        let row: Option<(i64, i64, i64, i64, i64)> = if tenant_scoped {
            sqlx::query_as(
                "SELECT COUNT(*)::bigint,
                    COUNT(*) FILTER (WHERE spf_verified = true)::bigint,
                    COUNT(*) FILTER (WHERE dkim_enabled = true)::bigint,
                    COUNT(*) FILTER (WHERE dmarc_verified = true)::bigint,
                    COUNT(*) FILTER (WHERE verified = true)::bigint
             FROM domains
             WHERE tenant_id = $1",
            )
            .bind(&auth.tenant_id)
            .fetch_optional(db)
            .await?
        } else {
            sqlx::query_as(
                "SELECT COUNT(*)::bigint,
                    COUNT(*) FILTER (WHERE spf_verified = true)::bigint,
                    COUNT(*) FILTER (WHERE dkim_enabled = true)::bigint,
                    COUNT(*) FILTER (WHERE dmarc_verified = true)::bigint,
                    COUNT(*) FILTER (WHERE verified = true)::bigint
             FROM domains",
            )
            .fetch_optional(db)
            .await?
        };

        if let Some((total, spf, dkim, dmarc, verified)) = row {
            vec![
                PolicyCompliance {
                    name: "SPF Records".into(),
                    compliant: spf,
                    total,
                },
                PolicyCompliance {
                    name: "DKIM Signing".into(),
                    compliant: dkim,
                    total,
                },
                PolicyCompliance {
                    name: "DMARC Policy".into(),
                    compliant: dmarc,
                    total,
                },
                PolicyCompliance {
                    name: "Domain Verification".into(),
                    compliant: verified,
                    total,
                },
            ]
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    // Recent alerts
    let recent_alerts = if has_alerts {
        let rows: Vec<(
            String,
            String,
            String,
            String,
            Option<String>,
            Option<serde_json::Value>,
            chrono::DateTime<chrono::Utc>,
        )> = if tenant_scoped {
            sqlx::query_as(
                "SELECT id::text, alert_type, message, severity, tenant_id, metadata, created_at
                 FROM system_alerts
                 WHERE tenant_id = $1
                 ORDER BY created_at DESC LIMIT 10",
            )
            .bind(&auth.tenant_id)
            .fetch_all(db)
            .await?
        } else {
            sqlx::query_as(
                "SELECT id::text, alert_type, message, severity, tenant_id, metadata, created_at
                 FROM system_alerts ORDER BY created_at DESC LIMIT 10",
            )
            .fetch_all(db)
            .await?
        };

        rows.into_iter()
            .map(
                |(id, alert_type, message, severity, tenant_id, metadata, created_at)| {
                    let tenant_id = tenant_id.or_else(|| {
                        metadata
                            .as_ref()
                            .and_then(|m| m.get("tenantId"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    });

                    AlertEntry {
                        id,
                        alert_type,
                        message,
                        severity,
                        tenant_id,
                        timestamp: created_at.to_rfc3339(),
                    }
                },
            )
            .collect()
    } else {
        vec![]
    };

    // VAT summary (current month)
    let vat_summary = match compute_vat_summary(
        db,
        if tenant_scoped {
            Some(auth.tenant_id.as_str())
        } else {
            None
        },
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "VAT summary computation failed");
            let now = chrono::Utc::now();
            empty_vat_widget(now.year(), now.month())
        }
    };

    Ok(Json(ComplianceOverview {
        risk_summary,
        gdpr_requests,
        audit_stats,
        policy_compliance,
        recent_alerts,
        vat_summary,
    }))
}

/// Query current-month invoice totals for the VAT summary widget.
async fn compute_vat_summary(
    db: &sqlx::PgPool,
    tenant_id: Option<&str>,
) -> Result<VatSummaryWidget, sqlx::Error> {
    let has_kmd = table_exists(db, "vat_kmd_returns").await;
    let has_invoices = table_exists(db, "invoices").await;

    let now = chrono::Utc::now();
    let year = now.year();
    let month = now.month();

    if !has_invoices {
        return Ok(VatSummaryWidget {
            has_data: false,
            tax_year: year,
            tax_month: month,
            invoice_count: 0,
            total_taxable_cents: 0,
            total_vat_cents: 0,
            rates: vec![],
            latest_kmd_status: None,
            due_date: None,
        });
    }

    let period_start = match chrono::NaiveDate::from_ymd_opt(year, month, 1) {
        Some(d) => d
            .and_hms_opt(0, 0, 0)
            .expect("invariant: any NaiveDate supports 00:00:00")
            .and_utc(),
        None => return Ok(empty_vat_widget(year, month)),
    };

    let period_end = if month == 12 {
        match chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1) {
            Some(d) => d
                .and_hms_opt(0, 0, 0)
                .expect("invariant: any NaiveDate supports 00:00:00")
                .and_utc(),
            None => return Ok(empty_vat_widget(year, month)),
        }
    } else {
        match chrono::NaiveDate::from_ymd_opt(year, month + 1, 1) {
            Some(d) => d
                .and_hms_opt(0, 0, 0)
                .expect("invariant: any NaiveDate supports 00:00:00")
                .and_utc(),
            None => return Ok(empty_vat_widget(year, month)),
        }
    };

    // Total invoice counts for current month
    let tenant_filter = if tenant_id.is_some() {
        " AND tenant_id = $3"
    } else {
        ""
    };
    let totals_sql = format!(
        r#"
        SELECT
            COUNT(*)::bigint,
            COALESCE(SUM(subtotal), 0)::bigint,
            COALESCE(SUM(vat_total), 0)::bigint
        FROM invoices
        WHERE issued_at >= $1 AND issued_at < $2
          AND status IN ('paid', 'pending')
          {tenant_filter}
        "#
    );
    let mut totals_query = sqlx::query_as(&totals_sql)
        .bind(period_start)
        .bind(period_end);
    if let Some(tenant_id) = tenant_id {
        totals_query = totals_query.bind(tenant_id);
    }
    let totals: Option<(i64, i64, i64)> = totals_query.fetch_optional(db).await?;

    let (invoice_count, total_taxable_cents, total_vat_cents) = totals.unwrap_or((0, 0, 0));

    // Rate breakdown by country
    let rate_tenant_filter = if tenant_id.is_some() {
        " AND i.tenant_id = $3"
    } else {
        ""
    };
    let rate_sql = format!(
        r#"
        SELECT
            COALESCE(SUM(i.subtotal), 0)::bigint,
            COALESCE(SUM(i.vat_total), 0)::bigint,
            COALESCE(ba.country, 'EE') AS country,
            ba.vat_number
        FROM invoices i
        LEFT JOIN billing_addresses ba ON ba.tenant_id = i.tenant_id
        WHERE i.issued_at >= $1 AND i.issued_at < $2
          AND i.status IN ('paid', 'pending')
          {rate_tenant_filter}
        GROUP BY ba.country, ba.vat_number
        "#
    );
    let mut rate_query = sqlx::query_as(&rate_sql)
        .bind(period_start)
        .bind(period_end);
    if let Some(tenant_id) = tenant_id {
        rate_query = rate_query.bind(tenant_id);
    }
    let rate_rows: Vec<(i64, i64, String, Option<String>)> = rate_query.fetch_all(db).await?;

    let rates: Vec<serde_json::Value> = rate_rows
        .into_iter()
        .map(|(taxable, vat, country, vat_number)| {
            let country_up = country.to_uppercase();
            let is_eu = vat_rates::is_eu_country(&country_up);
            // Same validity gate as calculate_vat: a structurally invalid VAT
            // number does not make the sale reverse charge.
            let has_valid_vat = vat_number
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .map(|value| vat_rates::is_valid_vat_number(value, Some(&country_up)))
                .unwrap_or(false);

            let reason = if country_up == "EE" {
                None
            } else if is_eu && has_valid_vat {
                Some("reverse_charge")
            } else if is_eu {
                Some("eu_b2c")
            } else {
                Some("non_eu")
            };

            let vat_rate = if country_up == "EE" {
                vat_rates::ESTONIA_VAT_RATE
            } else if is_eu && !has_valid_vat {
                vat_rates::get_eu_vat_rate(&country_up).unwrap_or(0.0)
            } else {
                0.0
            };

            serde_json::json!({
                "rate": vat_rate,
                "taxableAmountCents": taxable,
                "vatAmountCents": vat,
                "reason": reason,
            })
        })
        .collect();

    // Latest KMD status
    let latest_kmd_status = if has_kmd && tenant_id.is_none() {
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM vat_kmd_returns ORDER BY tax_year DESC, tax_month DESC LIMIT 1",
        )
        .fetch_optional(db)
        .await?
    } else {
        None
    };

    // Due date for current period's VAT return
    let due_month = if month == 12 { 1 } else { month + 1 };
    let due_year = if month == 12 { year + 1 } else { year };
    let due_date = chrono::NaiveDate::from_ymd_opt(due_year, due_month, 20).map(|d| {
        d.and_hms_opt(23, 59, 59)
            .expect("invariant: any NaiveDate supports 23:59:59")
            .and_utc()
            .to_rfc3339()
    });

    Ok(VatSummaryWidget {
        has_data: invoice_count > 0,
        tax_year: year,
        tax_month: month,
        invoice_count,
        total_taxable_cents,
        total_vat_cents,
        rates,
        latest_kmd_status,
        due_date,
    })
}

fn empty_vat_widget(year: i32, month: u32) -> VatSummaryWidget {
    VatSummaryWidget {
        has_data: false,
        tax_year: year,
        tax_month: month,
        invoice_count: 0,
        total_taxable_cents: 0,
        total_vat_cents: 0,
        rates: vec![],
        latest_kmd_status: None,
        due_date: None,
    }
}

/// Replaced by billing_common::vat_rates::{EU_COUNTRIES, get_eu_vat_rate}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_gdpr_request_counts_uses_deadline_based_overdue_total() {
        let rows = vec![
            ("pending".to_string(), 3),
            ("processing".to_string(), 2),
            ("completed".to_string(), 5),
            ("overdue".to_string(), 99),
        ];

        let summary = summarize_gdpr_request_counts(&rows, 4);

        assert_eq!(summary.pending, 3);
        assert_eq!(summary.processing, 2);
        assert_eq!(summary.completed, 5);
        assert_eq!(summary.overdue, 4);
    }

    /// Verify that all 27 EU member states have a defined VAT rate and
    /// are listed in EU_COUNTRIES.
    #[test]
    fn test_all_eu_countries_have_vat_rates() {
        let expected: [(&str, f64); 27] = [
            ("AT", 20.0),
            ("BE", 21.0),
            ("BG", 20.0),
            ("HR", 25.0),
            ("CY", 19.0),
            ("CZ", 21.0),
            ("DK", 25.0),
            ("EE", 24.0),
            ("FI", 25.5),
            ("FR", 20.0),
            ("DE", 19.0),
            ("GR", 24.0),
            ("HU", 27.0),
            ("IE", 23.0),
            ("IT", 22.0),
            ("LV", 21.0),
            ("LT", 21.0),
            ("LU", 17.0),
            ("MT", 18.0),
            ("NL", 21.0),
            ("PL", 23.0),
            ("PT", 23.0),
            ("RO", 19.0),
            ("SK", 23.0),
            ("SI", 22.0),
            ("ES", 21.0),
            ("SE", 25.0),
        ];

        for (code, expected_rate) in &expected {
            assert!(
                vat_rates::EU_COUNTRIES.contains(&code.to_string()),
                "Country {code} missing from EU_COUNTRIES"
            );
            assert_eq!(
                vat_rates::get_eu_vat_rate(code),
                Some(*expected_rate),
                "Country {code} should have VAT rate {expected_rate}"
            );
        }

        // Verify the count is exactly 27
        assert_eq!(vat_rates::EU_COUNTRIES.len(), 27);
    }
}
