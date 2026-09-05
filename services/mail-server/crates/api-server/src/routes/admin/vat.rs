//! VAT / KMD return endpoints — control-plane access to Estonia VAT returns.
//!
//! Provides:
//! - GET /v1/admin/vat/kmd — list all KMD returns (paginated)
//! - GET /v1/admin/vat/kmd/latest — latest KMD return
//! - GET /v1/admin/vat/kmd/current — live current-month VAT summary
//! - POST /v1/admin/vat/kmd/generate — manually trigger KMD generation for a period
//! - GET /v1/admin/vat/kmd/:year/:month — specific period KMD return

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use billing_common::vat_rates;
use chrono::Datelike;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/kmd", get(list_kmd_returns))
        .route("/kmd/latest", get(get_latest_kmd))
        .route("/kmd/current", get(get_current_vat_summary))
        .route("/kmd/generate", post(trigger_kmd_generation))
        .route("/kmd/:year/:month", get(get_kmd_by_period))
}

// ---------------------------------------------------------------------------
// Query / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KmdListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    12
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KmdReturnResponse {
    pub id: String,
    pub tax_year: i32,
    pub tax_month: i32,
    pub status: String,
    pub breakdown: serde_json::Value,
    pub invoice_count: i32,
    pub total_taxable_cents: i64,
    pub total_vat_cents: i64,
    pub generated_at: String,
    pub filed_at: Option<String>,
    pub filing_reference: Option<String>,
    pub filing_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VatSummaryResponse {
    pub tax_year: i32,
    pub tax_month: u32,
    pub invoice_count: i64,
    pub tenant_count: i64,
    pub total_taxable_cents: i64,
    pub total_vat_cents: i64,
    pub rates: Vec<serde_json::Value>,
    pub status: String,
    pub due_date: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerateKmdBody {
    pub tax_year: i32,
    pub tax_month: u32,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a raw row from `vat_kmd_returns` into the API response type.
fn map_kmd_row(
    id: String,
    tax_year: i32,
    tax_month: i32,
    status: String,
    breakdown: serde_json::Value,
    invoice_count: i32,
    total_taxable_cents: i64,
    total_vat_cents: i64,
    generated_at: chrono::DateTime<chrono::Utc>,
    filed_at: Option<chrono::DateTime<chrono::Utc>>,
    filing_reference: Option<String>,
    filing_error: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> KmdReturnResponse {
    KmdReturnResponse {
        id,
        tax_year,
        tax_month,
        status,
        breakdown,
        invoice_count,
        total_taxable_cents,
        total_vat_cents,
        generated_at: generated_at.to_rfc3339(),
        filed_at: filed_at.map(|t| t.to_rfc3339()),
        filing_reference,
        filing_error,
        created_at: created_at.to_rfc3339(),
        updated_at: updated_at.to_rfc3339(),
    }
}

/// Check if the `vat_kmd_returns` table exists.
async fn kmd_table_exists(db: &sqlx::PgPool) -> bool {
    crate::routes::helpers::table_exists(db, "vat_kmd_returns").await
}

/// Slug-aware system-tenant membership (audit F1): human operators belong
/// to the seeded `system_internal_tenant01` tenant, not the literal
/// `system` sentinel only static API keys carry — the literal comparison
/// hard-403'd every human operator from the KMD console.
async fn is_system_admin(state: &AppState, auth: &AuthUser) -> bool {
    crate::routes::web::is_system_tenant(state, &auth.tenant_id).await
}

async fn require_system_kmd_access(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    if is_system_admin(state, auth).await {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "KMD returns are available only to system administrators".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /v1/admin/vat/kmd — list KMD returns, ordered by period descending.
async fn list_kmd_returns(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<KmdListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    require_system_kmd_access(&state, &auth).await?;

    if !kmd_table_exists(&state.db).await {
        return Ok(Json(serde_json::json!({
            "returns": [],
            "total": 0
        })));
    }

    // Clamp pagination: negative/unbounded limit/offset would 500 on bind
    // (P1) and OFFSET-past-end scans are pointless.
    let limit = query.limit.clamp(1, 200);
    let offset = query.offset.max(0);
    let rows: Vec<(
        String,
        i32,
        i32,
        String,
        serde_json::Value,
        i32,
        i64,
        i64,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        r#"
        SELECT id::text, tax_year, tax_month, status, breakdown,
               invoice_count, total_taxable_cents, total_vat_cents,
               generated_at, filed_at, filing_reference, filing_error,
               created_at, updated_at
        FROM vat_kmd_returns
        ORDER BY tax_year DESC, tax_month DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM vat_kmd_returns")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let returns: Vec<KmdReturnResponse> = rows
        .into_iter()
        .map(
            |(id, ty, tm, st, bd, ic, ttc, tvc, ga, fa, fr, fe, ca, ua)| {
                map_kmd_row(id, ty, tm, st, bd, ic, ttc, tvc, ga, fa, fr, fe, ca, ua)
            },
        )
        .collect();

    Ok(Json(serde_json::json!({
        "returns": returns,
        "total": count,
    })))
}

/// GET /v1/admin/vat/kmd/latest — most recent KMD return.
async fn get_latest_kmd(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    require_system_kmd_access(&state, &auth).await?;

    if !kmd_table_exists(&state.db).await {
        return Ok(Json(serde_json::json!(null)));
    }

    let row: Option<(
        String,
        i32,
        i32,
        String,
        serde_json::Value,
        i32,
        i64,
        i64,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        r#"
        SELECT id::text, tax_year, tax_month, status, breakdown,
               invoice_count, total_taxable_cents, total_vat_cents,
               generated_at, filed_at, filing_reference, filing_error,
               created_at, updated_at
        FROM vat_kmd_returns
        ORDER BY tax_year DESC, tax_month DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some((id, ty, tm, st, bd, ic, ttc, tvc, ga, fa, fr, fe, ca, ua)) => Ok(Json(
            serde_json::to_value(map_kmd_row(
                id, ty, tm, st, bd, ic, ttc, tvc, ga, fa, fr, fe, ca, ua,
            ))
            .unwrap_or(serde_json::Value::Null),
        )),
        None => Ok(Json(serde_json::json!(null))),
    }
}

/// GET /v1/admin/vat/kmd/current — live current-month VAT summary.
async fn get_current_vat_summary(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<VatSummaryResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let now = chrono::Utc::now();
    let year = now.year();
    let month = now.month();

    // Try to use the billing-service module via direct DB query
    // to avoid tight coupling. We query invoices directly for the current month.
    let has_invoices = crate::routes::helpers::table_exists(&state.db, "invoices").await;

    if !has_invoices {
        return Ok(Json(VatSummaryResponse {
            tax_year: year,
            tax_month: month,
            invoice_count: 0,
            tenant_count: 0,
            total_taxable_cents: 0,
            total_vat_cents: 0,
            rates: vec![],
            status: "no_data".into(),
            due_date: compute_due_date(year, month).to_rfc3339(),
        }));
    }

    // Query current month invoice totals directly
    let period_start = chrono::NaiveDate::from_ymd_opt(year, month, 1)
        .expect("invariant: current year/month always valid for from_ymd_opt")
        .and_hms_opt(0, 0, 0)
        .expect("invariant: valid date always has 00:00:00 time")
        .and_utc();

    let period_end = if month == 12 {
        chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1)
            .expect("invariant: year+1 with January 1st always valid")
            .and_hms_opt(0, 0, 0)
            .expect("invariant: valid date always has 00:00:00 time")
            .and_utc()
    } else {
        chrono::NaiveDate::from_ymd_opt(year, month + 1, 1)
            .expect("invariant: current year/next month 1st always valid")
            .and_hms_opt(0, 0, 0)
            .expect("invariant: valid date always has 00:00:00 time")
            .and_utc()
    };

    let tenant_scoped = !is_system_admin(&state, &auth).await;
    let tenant_filter = if tenant_scoped {
        "\n          AND tenant_id = $3"
    } else {
        ""
    };

    let totals_sql = format!(
        r#"
        SELECT
            COUNT(*)::bigint,
            COUNT(DISTINCT tenant_id)::bigint,
            COALESCE(SUM(subtotal), 0)::bigint,
            COALESCE(SUM(vat_total), 0)::bigint
        FROM invoices
        WHERE issued_at >= $1
          AND issued_at < $2
          AND status IN ('paid', 'pending')
          {tenant_filter}
        "#
    );

    let mut totals_query = sqlx::query_as(&totals_sql)
        .bind(period_start)
        .bind(period_end);
    if tenant_scoped {
        totals_query = totals_query.bind(&auth.tenant_id);
    }
    let totals: (i64, i64, i64, i64) = totals_query
        .fetch_optional(&state.db)
        .await?
        .unwrap_or((0, 0, 0, 0));

    let (invoice_count, tenant_count, total_taxable_cents, total_vat_cents) = totals;

    // Also query rate breakdown by joining with billing_addresses
    let rate_tenant_filter = if tenant_scoped {
        "\n          AND i.tenant_id = $3"
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
        WHERE i.issued_at >= $1
          AND i.issued_at < $2
          AND i.status IN ('paid', 'pending')
          {rate_tenant_filter}
        GROUP BY ba.country, ba.vat_number
        "#
    );
    let mut rate_query = sqlx::query_as(&rate_sql)
        .bind(period_start)
        .bind(period_end);
    if tenant_scoped {
        rate_query = rate_query.bind(&auth.tenant_id);
    }
    let rate_rows: Vec<(i64, i64, String, Option<String>)> =
        rate_query.fetch_all(&state.db).await?;

    let mut rates = Vec::new();
    for (taxable, vat, country, vat_number) in &rate_rows {
        let country_up = country.to_uppercase();
        let is_eu = vat_rates::is_eu_country(&country_up);
        // Reverse-charge classification must use the same validity gate as
        // calculate_vat — a merely *present* VAT number that fails structural
        // validation was charged destination VAT on the invoice and must not
        // be summarized as reverse charge here.
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

        rates.push(serde_json::json!({
            "rate": vat_rate,
            "taxableAmountCents": taxable,
            "vatAmountCents": vat,
            "reason": reason,
        }));
    }

    let status = if invoice_count > 0 { "live" } else { "no_data" };

    Ok(Json(VatSummaryResponse {
        tax_year: year,
        tax_month: month,
        invoice_count,
        tenant_count,
        total_taxable_cents,
        total_vat_cents,
        rates,
        status: status.into(),
        due_date: compute_due_date(year, month).to_rfc3339(),
    }))
}

/// POST /v1/admin/vat/kmd/generate — manually trigger KMD generation.
async fn trigger_kmd_generation(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<GenerateKmdBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    require_system_kmd_access(&state, &auth).await?;

    if body.tax_month < 1 || body.tax_month > 12 {
        return Err(ApiError::Validation(vec![
            "taxMonth must be between 1 and 12".into(),
        ]));
    }

    // We need to call the billing-service vat_kmd module
    // Since api-server depends on billing-service, we can use it directly
    let generation = billing_service::vat_kmd::generate_kmd_return(
        &state.db,
        body.tax_year,
        body.tax_month,
    )
    .await;

    // Manual KMD generation is a fiscal-control-plane mutation — it must be
    // audited with full actor attribution (P2-2) on BOTH outcomes; a
    // best-effort entry never fails the request.
    let is_production = state.config.environment.is_production();
    let (outcome, mut metadata) = match &generation {
        Ok(result) => (
            "success",
            serde_json::json!({
                "taxYear": result.tax_year,
                "taxMonth": result.tax_month,
                "kmdId": result.kmd_id.to_string(),
                "invoiceCount": result.invoice_count,
                "totalTaxableCents": result.total_taxable_cents,
                "totalVatCents": result.total_vat_cents,
            }),
        ),
        Err(error) => ("failure", serde_json::json!({ "error": error.to_string() })),
    };
    metadata["outcome"] = serde_json::json!(outcome);
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        is_production,
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        "control_plane.vat.kmd_generated",
        "vat_kmd_return",
        Some(&format!("{}/{}", body.tax_year, body.tax_month)),
        metadata,
        None,
        None,
    )
    .await;

    match generation {
        Ok(result) => {
            let response = serde_json::json!({
                "success": true,
                "kmdId": result.kmd_id.to_string(),
                "taxYear": result.tax_year,
                "taxMonth": result.tax_month,
                "invoiceCount": result.invoice_count,
                "totalTaxableCents": result.total_taxable_cents,
                "totalVatCents": result.total_vat_cents,
                "rates": result.rates,
            });
            Ok(Json(response))
        }
        Err(e) => Err(ApiError::Internal(format!(
            "Failed to generate KMD return: {e}"
        ))),
    }
}

/// GET /v1/admin/vat/kmd/:year/:month — get KMD return for a specific period.
async fn get_kmd_by_period(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((year, month)): Path<(i32, i32)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    require_system_kmd_access(&state, &auth).await?;

    if !(1..=12).contains(&month) {
        return Err(ApiError::Validation(vec![
            "month must be between 1 and 12".into()
        ]));
    }

    if !kmd_table_exists(&state.db).await {
        return Ok(Json(serde_json::json!(null)));
    }

    let row: Option<(
        String,
        i32,
        i32,
        String,
        serde_json::Value,
        i32,
        i64,
        i64,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        r#"
        SELECT id::text, tax_year, tax_month, status, breakdown,
               invoice_count, total_taxable_cents, total_vat_cents,
               generated_at, filed_at, filing_reference, filing_error,
               created_at, updated_at
        FROM vat_kmd_returns
        WHERE tax_year = $1 AND tax_month = $2
        "#,
    )
    .bind(year)
    .bind(month)
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some((id, ty, tm, st, bd, ic, ttc, tvc, ga, fa, fr, fe, ca, ua)) => Ok(Json(
            serde_json::to_value(map_kmd_row(
                id, ty, tm, st, bd, ic, ttc, tvc, ga, fa, fr, fe, ca, ua,
            ))
            .unwrap_or(serde_json::Value::Null),
        )),
        None => Ok(Json(serde_json::json!(null))),
    }
}

// ---------------------------------------------------------------------------
// Replaced by billing_common::vat_rates::{EU_COUNTRIES, is_eu_country, get_eu_vat_rate}
// ---------------------------------------------------------------------------

/// Compute VAT return due date: 20th of the following month.
fn compute_due_date(year: i32, month: u32) -> chrono::DateTime<chrono::Utc> {
    let due_month = if month == 12 { 1 } else { month + 1 };
    let due_year = if month == 12 { year + 1 } else { year };

    chrono::NaiveDate::from_ymd_opt(due_year, due_month, 20)
        .unwrap_or_else(|| {
            chrono::NaiveDate::from_ymd_opt(year, month, 20)
                .expect("invariant: fallback year/month is always valid")
        })
        .and_hms_opt(23, 59, 59)
        .expect("invariant: any NaiveDate supports 23:59:59")
        .and_utc()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_eu_country() {
        assert!(vat_rates::is_eu_country("EE"));
        assert!(vat_rates::is_eu_country("DE"));
        assert!(!vat_rates::is_eu_country("US"));
        assert!(!vat_rates::is_eu_country("GB"));
    }

    #[test]
    fn test_get_eu_vat_rate_ee() {
        assert_eq!(vat_rates::get_eu_vat_rate("EE"), Some(24.0));
        assert_eq!(vat_rates::get_eu_vat_rate("US"), None);
    }

    #[test]
    fn test_compute_due_date_january() {
        let due = compute_due_date(2026, 1);
        assert_eq!(due.month(), 2);
        assert_eq!(due.day(), 20);
        assert_eq!(due.year(), 2026);
    }

    #[test]
    fn test_compute_due_date_december() {
        let due = compute_due_date(2026, 12);
        assert_eq!(due.month(), 1);
        assert_eq!(due.day(), 20);
        assert_eq!(due.year(), 2027);
    }

    #[test]
    fn test_default_limit() {
        assert_eq!(default_limit(), 12);
    }

    #[test]
    fn test_map_kmd_row_basic() {
        let now = chrono::Utc::now();
        let resp = map_kmd_row(
            "abc".into(),
            2026,
            4,
            "draft".into(),
            serde_json::json!({"rates": []}),
            10,
            100000,
            24000,
            now,
            None,
            None,
            None,
            now,
            now,
        );
        assert_eq!(resp.tax_year, 2026);
        assert_eq!(resp.tax_month, 4);
        assert_eq!(resp.status, "draft");
        assert_eq!(resp.invoice_count, 10);
        assert_eq!(resp.total_vat_cents, 24000);
        assert!(resp.filing_reference.is_none());
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
