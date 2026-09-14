//! Optional-source tests for `compliance::estonia_ou` that need fixture DDL.
//!
//! The crate's source scan forbids runtime schema DDL under `src/`; the
//! canonical chain has no `dividend_distributions` / `operating_costs`
//! stores, and the generators are documented to read them when present. This
//! suite creates those two migration-owned-but-not-yet-shipped tables in a
//! throwaway canonical database (the same pattern the crate's other suites
//! use) and proves the present-branch behaviour; the absent-branch behaviour
//! is asserted from the unit tests in `src/estonia_ou.rs`.

use compliance::estonia_ou::{ComplianceCalendar, EstoniaOuCompliance, SubmissionType};
use sqlx::PgPool;

async fn engine(suffix: &str) -> Option<(PgPool, EstoniaOuCompliance)> {
    let pool = migrator::test_support::fresh_canonical_pool(
        &format!("estonia_optional_{suffix}"),
        &format!("est_opt_{suffix}"),
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

#[tokio::test]
async fn income_tax_declaration_uses_the_date_effective_net_to_tax_fraction() {
    let Some((pool, engine)) = engine("dividends").await else {
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
         VALUES ('founder', 80000, DATE '2024-12-31'),
                ('founder', 78000, DATE '2025-01-01')",
    )
    .execute(&pool)
    .await
    .expect("seed dividends");

    // Before the boundary: 20/80 of the NET amount.
    let old = engine
        .generate_income_tax_declaration(2024, 12)
        .await
        .expect("2024-12");
    assert_eq!(old.total_dividend_cents, 80000);
    assert_eq!(old.income_tax_liability_cents, 20000, "80k × 20/80");
    assert_eq!(old.dividend_distributions[0].tax_rate, 0.25);
    // From 2025-01-01 the fraction is 22/78 of the net amount, and the tax
    // is NOT a flat 22% of the net amount (that would be 17 160).
    let new = engine
        .generate_income_tax_declaration(2025, 1)
        .await
        .expect("2025-01");
    assert_eq!(new.total_dividend_cents, 78000);
    assert_eq!(new.income_tax_liability_cents, 22000, "78k × 22/78");
    assert_ne!(new.income_tax_liability_cents, 17160);
    assert_eq!(new.total_tax_due_cents, new.income_tax_liability_cents);
    assert_eq!(new.taxable_portion_cents, new.total_dividend_cents);
    assert!(new
        .data_quality
        .note
        .contains("Dividend distributions detected"));
    assert_eq!(
        new.due_date,
        ComplianceCalendar::calculate_due_date(SubmissionType::IncomeTax, 2025, Some(1))
    );

    // A month with no distributions is an explicit zero declaration.
    let empty = engine
        .generate_income_tax_declaration(2026, 5)
        .await
        .expect("empty month");
    assert_eq!(empty.total_dividend_cents, 0);
    assert_eq!(empty.total_tax_due_cents, 0);
    assert!(empty.dividend_distributions.is_empty());
    assert!(empty
        .data_quality
        .note
        .contains("No dividend distributions"));
}

#[tokio::test]
async fn operating_costs_are_read_when_the_optional_store_exists() {
    let Some((pool, engine)) = engine("costs").await else {
        return;
    };
    // Absent store: the annual report still renders, with only the
    // placeholder lines plus any invoice-derived fee.
    let absent = engine.generate_annual_report(2026).await.expect("report");
    assert!(absent
        .expense_breakdown
        .iter()
        .any(|e| e.category.contains("Hetzner")));
    assert!(absent
        .expense_breakdown
        .iter()
        .any(|e| e.category.contains("AWS")));
    assert!(absent
        .expense_breakdown
        .iter()
        .all(|e| e.category != "Infrastructure: servers"));

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS operating_costs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            category TEXT,
            amount_cents BIGINT,
            incurred_at TIMESTAMPTZ NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("create operating_costs");
    sqlx::query(
        "INSERT INTO operating_costs (category, amount_cents, incurred_at)
         VALUES ('servers', 12000, make_timestamptz(2026, 4, 1, 0, 0, 0)),
                (NULL, 3000, make_timestamptz(2026, 4, 2, 0, 0, 0)),
                ('servers', 1000, make_timestamptz(2025, 4, 1, 0, 0, 0))",
    )
    .execute(&pool)
    .await
    .expect("seed costs");
    let report = engine.generate_annual_report(2026).await.expect("report");
    // A NULL category lands in the documented default bucket, and the 2025
    // row must not leak into the 2026 report.
    let servers: i64 = report
        .expense_breakdown
        .iter()
        .filter(|e| e.category == "Infrastructure: servers")
        .map(|e| e.amount_cents)
        .sum();
    assert_eq!(servers, 12000);
    assert!(report
        .expense_breakdown
        .iter()
        .any(|e| e.category == "Infrastructure: infrastructure" && e.amount_cents == 3000));

    // Revenue is read from the same live invoices; month scoping is asserted
    // in the src unit tests through the public annual/statistical reports.
    seed_invoice(&pool, 2026, 6, 1000).await;
    seed_invoice(&pool, 2026, 7, 2000).await;
    let with_revenue = engine.generate_annual_report(2026).await.expect("report");
    assert_eq!(
        with_revenue
            .revenue_sources
            .iter()
            .map(|r| r.amount_cents)
            .sum::<i64>(),
        3000
    );

    // The dividend store is still absent here: the declaration is an explicit
    // zero, never an invented liability.
    let declaration = engine
        .generate_income_tax_declaration(2026, 6)
        .await
        .expect("income tax");
    assert_eq!(declaration.total_dividend_cents, 0);
    assert!(declaration
        .data_quality
        .missing_fields
        .iter()
        .any(|f| f.contains("dividend")));
}
