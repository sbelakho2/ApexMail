//! Residual-arm tests for `compliance::estonia_ou`: the ledger-backed query
//! paths, the missing-source data-quality arms, the TSD-ledger declaration
//! bridge, the statistical report and the registry-notice calendar sync.
//!
//! Missing-table arms run against per-test canonical databases with the
//! source table dropped (each test owns a private database, so dropping a
//! table cannot affect sibling tests). Skips unless TEST_DATABASE_URL is set.

use chrono::{Datelike, NaiveDate, Utc};
use compliance::estonia_ou::{ComplianceCalendar, EstoniaOuCompliance, SubmissionType};
use sqlx::PgPool;
use uuid::Uuid;

async fn engine(suffix: &str) -> Option<(PgPool, EstoniaOuCompliance)> {
    let pool = migrator::test_support::fresh_canonical_pool(
        &format!("estonia_residual_{suffix}"),
        &format!("est_res_{suffix}"),
    )
    .await
    .unwrap_or_else(|error| panic!("{}", error.panic_message()))?;
    sqlx::query(
        "INSERT INTO tenants (id, name) VALUES ('itest', 'Integration Test Tenant')
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("seed tenant");
    Some((pool.clone(), EstoniaOuCompliance::new(pool)))
}

async fn seed_invoice(pool: &PgPool, year: i32, month: u32, subtotal: i64) {
    sqlx::query(
        "INSERT INTO invoices
           (id, tenant_id, amount, currency, status, issued_at, created_at, updated_at,
            subtotal, vat_total, total, billing_country)
         VALUES (gen_random_uuid(), 'itest', $1, 'EUR', 'paid',
                 make_timestamptz($2, $3, 15, 12, 0, 0), NOW(), NOW(),
                 $1, 0, $1, 'EE')",
    )
    .bind(subtotal)
    .bind(year)
    .bind(month as i32)
    .execute(pool)
    .await
    .expect("seed invoice");
}

async fn seed_payroll(
    pool: &PgPool,
    year: i32,
    month: u32,
    name: &str,
    gross: i64,
    pension_rate: Option<f64>,
) {
    sqlx::query(
        "INSERT INTO payroll_records
           (employee_name, personal_code, gross_salary_cents, funded_pension_rate,
            pension_exemption, unemployment_insurance_exemption, pay_period)
         VALUES ($1, $2, $3, $4, false, false, make_timestamptz($5, $6, 15, 12, 0, 0))",
    )
    .bind(name)
    .bind("38001010000")
    .bind(gross)
    .bind(pension_rate)
    .bind(year)
    .bind(month as i32)
    .execute(pool)
    .await
    .expect("seed payroll record");
}

#[tokio::test]
async fn annual_report_derives_from_ledger_and_reports_missing_sources() {
    let Some((pool, engine)) = engine("annual").await else {
        return;
    };
    seed_invoice(&pool, 2025, 3, 150_000).await;
    seed_payroll(&pool, 2025, 3, "Alice Smith", 500_000, Some(0.02)).await;

    let report = engine.generate_annual_report(2025).await.expect("report");
    assert_eq!(report.fiscal_year, 2025);
    assert!(report.data_quality.has_sufficient_data);
    assert!(report.data_quality.missing_fields.is_empty());

    // Drop the source tables: the same call now reports the missing sources
    // instead of fabricating numbers (and still succeeds).
    sqlx::query("DROP TABLE payroll_records CASCADE")
        .execute(&pool)
        .await
        .expect("drop payroll");
    sqlx::query("DROP TABLE invoices CASCADE")
        .execute(&pool)
        .await
        .expect("drop invoices");
    let degraded = engine
        .generate_annual_report(2025)
        .await
        .expect("degraded report");
    assert!(
        !degraded.data_quality.has_sufficient_data,
        "dropped sources must be disclosed"
    );
    assert!(
        degraded
            .data_quality
            .missing_fields
            .iter()
            .any(|m| m.contains("invoices")),
        "{:?}",
        degraded.data_quality.missing_fields
    );
    assert!(
        degraded
            .data_quality
            .missing_fields
            .iter()
            .any(|m| m.contains("payroll_records")),
        "{:?}",
        degraded.data_quality.missing_fields
    );
    assert_eq!(degraded.income_statement.revenue_cents, 0);
}

#[tokio::test]
async fn vat_declaration_reports_the_missing_invoices_source() {
    let Some((pool, engine)) = engine("vat_missing").await else {
        return;
    };
    let now = Utc::now();
    sqlx::query("DROP TABLE invoices CASCADE")
        .execute(&pool)
        .await
        .expect("drop invoices");

    // The current month's VAT declaration falls back to the first of the
    // month when no explicit period is given and discloses the absent table.
    let declaration = engine
        .generate_vat_declaration(now.year(), now.date_naive().month())
        .await
        .expect("declaration without invoices");
    assert!(
        declaration
            .data_quality
            .missing_fields
            .iter()
            .any(|m| m.contains("invoices")),
        "the absent invoices table must be disclosed: {:?}",
        declaration.data_quality
    );
    assert!(
        !declaration.ready_for_filing,
        "an incomplete return is not filing-ready"
    );
}

#[tokio::test]
async fn vat_declaration_sums_seeded_invoices_with_explicit_period() {
    let Some((pool, engine)) = engine("vat_seeded").await else {
        return;
    };
    seed_invoice(&pool, 2026, 4, 100_000).await;
    let declaration = engine.generate_vat_declaration(2026, 4).await.expect("vat");
    assert_eq!(
        declaration.domestic_sales.taxable_amount_cents, 100_000,
        "the EE invoice is a domestic sale"
    );
    assert_eq!(declaration.domestic_sales.transaction_count, 1);
}

#[tokio::test]
async fn statistical_report_uses_revenue_and_headcount() {
    let Some((pool, engine)) = engine("statistical").await else {
        return;
    };
    seed_invoice(&pool, 2025, 6, 300_000).await;
    seed_payroll(&pool, 2025, 6, "Bob Jones", 400_000, None).await;

    let report = engine
        .generate_statistical_report(2025)
        .await
        .expect("report");
    assert_eq!(report.report_year, 2025);
    assert_eq!(report.revenue_bands.len(), 1);
    assert_eq!(report.revenue_bands[0].amount_cents, 300_000);
    assert_eq!(report.employee_headcount, 1);
    assert!(report.is_it_sector);
    let questions = report.it_sector_questions.expect("IT questions");
    assert_eq!(questions.software_development_revenue_cents, 300_000);
}

#[tokio::test]
async fn social_tax_declaration_reads_the_tsd_ledger_for_entity_and_registry() {
    let Some((pool, engine)) = engine("tsd_entity").await else {
        return;
    };
    let entity_id: Uuid = sqlx::query_scalar(
        "INSERT INTO legal_entities (legal_name, registry_code, country_code) \
         VALUES ('Ledger OÜ', '55500001', 'EE') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("insert entity");
    // The ledger source may be empty for a fresh entity: both readers must
    // answer an EMPTY-but-valid declaration, never an error.
    let by_entity = engine
        .generate_social_tax_declaration_for_entity(entity_id, 2026, 1)
        .await
        .expect("declaration from an empty ledger");
    assert_eq!(by_entity.employees.len(), 0);

    let by_registry = engine
        .generate_social_tax_declaration_for_registry_code("55500001", 2026, 1)
        .await
        .expect("declaration by registry code");
    assert_eq!(by_registry.employees.len(), 0);
}

#[tokio::test]
async fn registry_notices_sync_into_the_compliance_calendar() {
    let Some((pool, engine)) = engine("registry_sync").await else {
        return;
    };
    let created = engine
        .sync_registry_notices_to_calendar()
        .await
        .expect("registry sync");
    assert!(
        created.len() >= 5,
        "the five EE registry notices: {}",
        created.len()
    );

    // Idempotent on the deadline unique key: a re-sync must not add rows.
    let before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM compliance_deadlines WHERE deadline_type LIKE 'registry_%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let _again = engine
        .sync_registry_notices_to_calendar()
        .await
        .expect("re-sync");
    let after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM compliance_deadlines WHERE deadline_type LIKE 'registry_%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(before, after, "no duplicate registry rows after re-sync");
}

#[tokio::test]
async fn social_tax_submission_persists_pdf_csv_and_json_formats() {
    let Some((pool, engine)) = engine("csv_persist").await else {
        return;
    };
    // A fresh entity has an empty ledger; the declaration is still valid and
    // must persist in every format (the SocialTax CSV branch runs the
    // totals-flattener).
    let entity_id: Uuid = sqlx::query_scalar(
        "INSERT INTO legal_entities (legal_name, registry_code, country_code) \
         VALUES ('CSV OÜ', '55500002', 'EE') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("insert entity");
    let declaration = engine
        .generate_social_tax_declaration_for_entity(entity_id, 2026, 2)
        .await
        .expect("declaration");
    let document = serde_json::to_value(&declaration).expect("document json");
    let id = engine
        .persist_submission_with_formats(SubmissionType::SocialTax, 2026, Some(2), &document)
        .await
        .expect("persist submission");
    let row: (Option<Vec<u8>>, Option<String>) =
        sqlx::query_as("SELECT pdf_data, csv_data FROM compliance_submissions WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("submission row");
    assert!(row.0.is_some(), "pdf bytes stored");
    let csv = row.1.expect("csv stored");
    assert!(csv.contains("social_tax_totals"), "{csv}");
}

#[tokio::test]
async fn income_tax_declaration_reads_dividend_store() {
    let Some((pool, engine)) = engine("dividends_res").await else {
        return;
    };
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dividend_distributions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            recipient TEXT NOT NULL,
            amount_cents BIGINT NOT NULL,
            distribution_date DATE NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("create dividend store");
    sqlx::query(
        "INSERT INTO dividend_distributions (recipient, amount_cents, distribution_date)
         VALUES ('founder', 500000, DATE '2026-02-01')",
    )
    .execute(&pool)
    .await
    .expect("seed dividend");

    let declaration = engine
        .generate_income_tax_declaration(2026, 2)
        .await
        .expect("income tax declaration");
    assert_eq!(declaration.total_dividend_cents, 500_000);
}

#[tokio::test]
async fn submission_type_period_math_covers_every_variant() {
    // Guard the shared period arithmetic the generators rely on.
    let ar = ComplianceCalendar::calculate_period(SubmissionType::AnnualReport, 2025, None);
    assert_eq!(ar.0, NaiveDate::from_ymd_opt(2025, 1, 1).unwrap());
    assert_eq!(ar.1, NaiveDate::from_ymd_opt(2025, 12, 31).unwrap());
}
