//! DB-backed tests for the TSD (payroll/social-tax return) derivation from
//! the POSTED LEDGER.
//!
//! The TSD generator was rewired to read `v_accounting_payroll_taxes` (posted
//! entries only) through `accounting_core::derive::payroll_taxes_for_period`
//! instead of recomputing amounts from the operational payroll inputs. These
//! tests drive the real path — `payroll_records` → the ledger sweep → the
//! posted ledger → the declaration — against the canonical migration chain,
//! and prove the failure modes are reported rather than papered over:
//!
//! * amounts come from the books (`posting`, not recomputation);
//! * an unbooked month yields a visibly not-ready declaration;
//! * a year period containing the month is NOT accepted as a monthly period;
//! * payroll inputs not yet posted are counted and named;
//! * a posting with missing person facts or inconsistent arithmetic is
//!   flagged, never silently declared;
//! * an entity with no books is an error, not a zero declaration.
//!
//! Skips unless TEST_DATABASE_URL is set (workspace convention); a
//! CONFIGURED provisioning failure panics (audit F01).

use chrono::{DateTime, NaiveDate, Utc};
use compliance::estonia_ou::{EstoniaOuCompliance, REGISTRY_CODE};
use compliance::ledger_sweep::EstonianPayrollPolicy;
use compliance::tsd_ledger::{
    month_bounds, read_month, read_month_by_registry_code, TsdSourceError,
};
use accounting_core::chart::{self, LegalEntityInput};
use accounting_core::periods;
use accounting_core::sweeps::{PayrollAmountsPolicy, PayrollRecordFacts};
use accounting_core::types::{
    ROLE_INCOME_TAX_PAYABLE, ROLE_NET_WAGES_PAYABLE, ROLE_PAYROLL_EXPENSE, ROLE_PENSION_PAYABLE,
    ROLE_SOCIAL_TAX_PAYABLE, ROLE_UNEMPLOYMENT_PAYABLE,
};
use accounting_core::PayrollAmounts;
use sha2::Digest;
use sqlx::PgPool;
use uuid::Uuid;

// ── Canonical fixture ──────────────────────────────────────────────────────

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    let suffix = format!("tsd_{}", test_name);
    match migrator::test_support::fresh_canonical_pool(test_name, &suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn d(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("test date")
}

fn sha256_hex(value: &str) -> String {
    hex::encode(sha2::Sha256::digest(value.as_bytes()))
}

/// A legal entity with the registry code the TSD prints, plus the standard
/// chart of accounts.
///
/// `is_default` is set: the payroll sweep posts a `payroll_records` row to the
/// DEFAULT entity (migration 199's payroll model has no entity column), so a
/// realistic single-entity deployment — the one a TSD describes — has the
/// default entity carrying the books.
async fn seed_entity(pool: &PgPool, registry_code: &str) -> Uuid {
    let mut conn = pool.acquire().await.expect("pool acquire");
    let entity = chart::create_legal_entity(
        &mut conn,
        &LegalEntityInput {
            legal_name: format!("TSD Test OÜ {registry_code}"),
            trading_name: None,
            registry_code: registry_code.to_string(),
            vat_number: Some("EE102345678".to_string()),
            address_line1: None,
            city: None,
            postal_code: None,
            country_code: "EE".to_string(),
            default_currency: "EUR".to_string(),
            fiscal_year_start_month: 1,
            is_default: true,
        },
    )
    .await
    .expect("create legal entity");
    chart::ensure_standard_chart(&mut conn, entity)
        .await
        .expect("standard chart");
    entity
}

async fn create_period(
    pool: &PgPool,
    entity: Uuid,
    period_type: &str,
    label: &str,
    start: NaiveDate,
    end: NaiveDate,
    status: &str,
) -> Uuid {
    let mut conn = pool.acquire().await.expect("pool acquire");
    let id = periods::ensure_period(&mut conn, entity, period_type, label, start, end)
        .await
        .expect("fiscal period");
    if status != "open" {
        sqlx::query("UPDATE fiscal_periods SET status = $2 WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(pool)
            .await
            .expect("set period status");
    }
    id
}

async fn insert_payroll_record(
    pool: &PgPool,
    name: &str,
    personal_code: Option<&str>,
    gross_cents: i64,
    pension_rate: Option<f64>,
    pension_exemption: bool,
    pay_period: DateTime<Utc>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO payroll_records (employee_name, personal_code, gross_salary_cents, \
            funded_pension_rate, pension_exemption, pay_period) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(name)
    .bind(personal_code)
    .bind(gross_cents)
    .bind(pension_rate)
    .bind(pension_exemption)
    .bind(pay_period)
    .fetch_one(pool)
    .await
    .expect("payroll record")
}

fn stamp(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339(&format!(
        "{year:04}-{month:02}-{day:02}T12:00:00Z"
    ))
    .expect("timestamp")
    .with_timezone(&Utc)
}

/// Post a balanced journal entry (draft → lines → posted) and return its id.
async fn post_balanced_entry(
    pool: &PgPool,
    entity: Uuid,
    period: Uuid,
    entry_date: NaiveDate,
    memo: &str,
    debits: &[(Uuid, i64)],
    credits: &[(Uuid, i64)],
) -> Uuid {
    let entry_id: Uuid = sqlx::query_scalar(
        "INSERT INTO journal_entries \
            (legal_entity_id, fiscal_period_id, entry_date, entry_type, memo, source_hash, idempotency_key) \
         VALUES ($1, $2, $3, 'standard', $4, $5, $6) RETURNING id",
    )
    .bind(entity)
    .bind(period)
    .bind(entry_date)
    .bind(memo)
    .bind(sha256_hex(memo))
    .bind(format!("tsd-{}-{}", memo, Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("draft journal entry");

    let mut line_no = 0i32;
    for (account, amount) in debits {
        line_no += 1;
        sqlx::query(
            "INSERT INTO journal_lines (entry_id, line_no, account_id, debit_cents, credit_cents) \
             VALUES ($1, $2, $3, $4, 0)",
        )
        .bind(entry_id)
        .bind(line_no)
        .bind(account)
        .bind(amount)
        .execute(pool)
        .await
        .expect("debit line");
    }
    for (account, amount) in credits {
        line_no += 1;
        sqlx::query(
            "INSERT INTO journal_lines (entry_id, line_no, account_id, debit_cents, credit_cents) \
             VALUES ($1, $2, $3, 0, $4)",
        )
        .bind(entry_id)
        .bind(line_no)
        .bind(account)
        .bind(amount)
        .execute(pool)
        .await
        .expect("credit line");
    }

    sqlx::query("UPDATE journal_entries SET posted_at = NOW(), posted_by = 'tsd-test' WHERE id = $1")
        .bind(entry_id)
        .execute(pool)
        .await
        .expect("post entry");
    entry_id
}

/// Resolve an account by role for hand-built postings.
async fn account_id(pool: &PgPool, entity: Uuid, role: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM chart_of_accounts WHERE legal_entity_id = $1 AND account_role = $2",
    )
    .bind(entity)
    .bind(role)
    .fetch_one(pool)
    .await
    .expect("account by role")
}

/// The six accounts a payroll posting touches, resolved once per test.
async fn payroll_accounts(pool: &PgPool, entity: Uuid) -> PayrollAccounts {
    PayrollAccounts {
        expense: account_id(pool, entity, ROLE_PAYROLL_EXPENSE).await,
        net_wages: account_id(pool, entity, ROLE_NET_WAGES_PAYABLE).await,
        income_tax: account_id(pool, entity, ROLE_INCOME_TAX_PAYABLE).await,
        social: account_id(pool, entity, ROLE_SOCIAL_TAX_PAYABLE).await,
        unemployment: account_id(pool, entity, ROLE_UNEMPLOYMENT_PAYABLE).await,
        pension: account_id(pool, entity, ROLE_PENSION_PAYABLE).await,
    }
}

struct PayrollAccounts {
    expense: Uuid,
    net_wages: Uuid,
    income_tax: Uuid,
    social: Uuid,
    unemployment: Uuid,
    pension: Uuid,
}

/// Insert a `payroll_postings` row referencing a posted entry — the shape an
/// admin/import path would create, without going through the sweep policy.
#[allow(clippy::too_many_arguments)]
async fn insert_posting(
    pool: &PgPool,
    entity: Uuid,
    period: Uuid,
    record: Uuid,
    entry: Uuid,
    employee_name: Option<&str>,
    gross_cents: i64,
    amounts: &PayrollAmounts,
    currency: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO payroll_postings (legal_entity_id, fiscal_period_id, payroll_record_id, \
            employee_name, gross_cents, income_tax_cents, social_tax_cents, \
            unemployment_employee_cents, unemployment_employer_cents, pension_cents, net_cents, \
            currency, journal_entry_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id",
    )
    .bind(entity)
    .bind(period)
    .bind(record)
    .bind(employee_name)
    .bind(gross_cents)
    .bind(amounts.income_tax_cents)
    .bind(amounts.social_tax_cents)
    .bind(amounts.unemployment_employee_cents)
    .bind(amounts.unemployment_employer_cents)
    .bind(amounts.pension_cents)
    .bind(amounts.net_cents)
    .bind(currency)
    .bind(entry)
    .fetch_one(pool)
    .await
    .expect("payroll posting")
}

// ── Pure period arithmetic ─────────────────────────────────────────────────

#[test]
fn month_bounds_handles_short_months_leap_years_and_rejects_nonsense() {
    assert_eq!(
        month_bounds(2026, 6).unwrap(),
        (d(2026, 6, 1), d(2026, 6, 30))
    );
    assert_eq!(
        month_bounds(2026, 12).unwrap(),
        (d(2026, 12, 1), d(2026, 12, 31))
    );
    // Leap February.
    assert_eq!(
        month_bounds(2028, 2).unwrap(),
        (d(2028, 2, 1), d(2028, 2, 29))
    );
    // Non-leap February.
    assert_eq!(
        month_bounds(2027, 2).unwrap(),
        (d(2027, 2, 1), d(2027, 2, 28))
    );
    // Century non-leap year (1900) and 400-year leap (2000).
    assert_eq!(month_bounds(1900, 2).unwrap().1, d(1900, 2, 28));
    assert_eq!(month_bounds(2000, 2).unwrap().1, d(2000, 2, 29));
    assert!(matches!(
        month_bounds(2026, 13),
        Err(TsdSourceError::InvalidPeriod { .. })
    ));
    assert!(matches!(
        month_bounds(2026, 0),
        Err(TsdSourceError::InvalidPeriod { .. })
    ));
    // December of a year whose successor is not representable must not
    // overflow — it is an invalid period, not a panic.
    assert!(matches!(
        month_bounds(i32::MAX, 12),
        Err(TsdSourceError::InvalidPeriod { .. })
    ));
}

// ── Derivation ─────────────────────────────────────────────────────────────

/// The declaration reproduces the BOOKS: the sweep computes the amounts, the
/// ledger stores them, and the TSD reports exactly those numbers.
#[tokio::test]
async fn tsd_reports_the_posted_ledger_amounts_exactly() {
    let Some(pool) = canonical_pool("tsd_derives_posted").await else {
        return;
    };
    let entity = seed_entity(&pool, REGISTRY_CODE).await;
    create_period(
        &pool,
        entity,
        "month",
        "2026-06",
        d(2026, 6, 1),
        d(2026, 6, 30),
        "open",
    )
    .await;

    let standard = insert_payroll_record(
        &pool,
        "Mari Maasikas",
        Some("47101010033"),
        200_000,
        Some(0.02),
        false,
        stamp(2026, 6, 30),
    )
    .await;
    let exempt = insert_payroll_record(
        &pool,
        "Jaan Jaanus",
        Some("36001010011"),
        150_000,
        None,
        true,
        stamp(2026, 6, 30),
    )
    .await;

    // The REAL sweep posts both records through the Estonian policy.
    let report = compliance::ledger_sweep::sweep_payroll_and_expenses(&pool)
        .await
        .expect("sweep");
    assert_eq!(report.payroll.posted, 2, "{report:?}");

    // What the policy computed (the books' own arithmetic), for comparison.
    let policy = EstonianPayrollPolicy;
    let facts = |id: Uuid,
                 name: &str,
                 gross: i64,
                 pension_rate: Option<f64>,
                 pension_exemption: bool| PayrollRecordFacts {
        id,
        employee_name: Some(name.to_string()),
        gross_salary_cents: gross,
        funded_pension_rate: pension_rate,
        pension_exemption,
        unemployment_insurance_exemption: false,
        pay_period: stamp(2026, 6, 30),
    };
    let expected_standard = policy
        .amounts_for(&facts(
            standard,
            "Mari Maasikas",
            200_000,
            Some(0.02),
            false,
        ))
        .expect("policy")
        .expect("complete record");
    let expected_exempt = policy
        .amounts_for(&facts(exempt, "Jaan Jaanus", 150_000, None, true))
        .expect("policy")
        .expect("complete record");

    let compliance = EstoniaOuCompliance::new(pool.clone());
    let tsd = compliance
        .generate_social_tax_declaration(2026, 6)
        .await
        .expect("TSD");

    assert!(
        tsd.data_quality.has_sufficient_data,
        "declaration should be ready: {:?}",
        tsd.data_quality
    );
    assert!(
        tsd.data_quality.missing_fields.is_empty(),
        "{:?}",
        tsd.data_quality.missing_fields
    );
    // Identity comes from the entity whose books were read.
    assert_eq!(tsd.registry_code, REGISTRY_CODE);
    assert_eq!(
        tsd.company_name,
        format!("TSD Test OÜ {REGISTRY_CODE}")
    );
    assert_eq!(tsd.totals.employee_count, 2);
    assert_eq!(tsd.totals.total_gross_salary_cents, 350_000);
    assert_eq!(
        tsd.totals.total_social_tax_cents,
        expected_standard.social_tax_cents + expected_exempt.social_tax_cents
    );
    assert_eq!(
        tsd.totals.total_income_tax_withheld_cents,
        expected_standard.income_tax_cents + expected_exempt.income_tax_cents
    );
    assert_eq!(
        tsd.totals.total_funded_pension_cents,
        expected_standard.pension_cents + expected_exempt.pension_cents
    );
    assert_eq!(
        tsd.totals.total_unemployment_employee_cents,
        expected_standard.unemployment_employee_cents
            + expected_exempt.unemployment_employee_cents
    );
    assert_eq!(
        tsd.totals.total_employer_cost_cents,
        350_000
            + expected_standard.social_tax_cents
            + expected_standard.unemployment_employer_cents
            + expected_exempt.social_tax_cents
            + expected_exempt.unemployment_employer_cents
    );

    // Per-employee: the rate is the declared input, the amounts are the
    // posted amounts.
    let mari = tsd
        .employees
        .iter()
        .find(|e| e.employee_name == "Mari Maasikas")
        .expect("Mari");
    assert_eq!(mari.personal_code, "47101010033");
    assert_eq!(mari.funded_pension_rate, Some(0.02));
    assert_eq!(mari.gross_salary_cents, 200_000);
    assert_eq!(mari.net_salary_cents, expected_standard.net_cents);
    let jaan = tsd
        .employees
        .iter()
        .find(|e| e.employee_name == "Jaan Jaanus")
        .expect("Jaan");
    // Exempt: 0% is the declared rate, not "unknown".
    assert_eq!(jaan.funded_pension_rate, Some(0.0));
    assert_eq!(jaan.funded_pension_cents, 0);
    assert_eq!(jaan.net_salary_cents, expected_exempt.net_cents);

    // Every amount came from a posting backed by a posted journal entry.
    assert!(tsd.data_quality.note.contains("posted payroll posting"));
    assert!(tsd.data_quality.note.contains("2026-06"));
}

/// A CLOSED period is the filing-time state and carries no warning; an OPEN
/// one warns that corrections will move the figures.
#[tokio::test]
async fn tsd_warns_only_while_the_period_is_still_open() {
    let Some(pool) = canonical_pool("tsd_open_period_warning").await else {
        return;
    };
    let entity = seed_entity(&pool, "16588746").await;
    create_period(
        &pool,
        entity,
        "month",
        "2026-05",
        d(2026, 5, 1),
        d(2026, 5, 31),
        "open",
    )
    .await;
    insert_payroll_record(
        &pool,
        "Mari Maasikas",
        Some("47101010033"),
        200_000,
        Some(0.04),
        false,
        stamp(2026, 5, 29),
    )
    .await;
    compliance::ledger_sweep::sweep_payroll_and_expenses(&pool)
        .await
        .expect("sweep");

    let source_open = read_month(&pool, entity, 2026, 5).await.expect("read");
    assert_eq!(source_open.open_periods().len(), 1);
    assert!(source_open.note().contains("still OPEN"), "{}", source_open.note());
    assert!(source_open.has_sufficient_data());

    sqlx::query("UPDATE fiscal_periods SET status = 'closed' WHERE id = $1")
        .bind(source_open.periods[0].id)
        .execute(&pool)
        .await
        .expect("close period");

    let source_closed = read_month(&pool, entity, 2026, 5).await.expect("read");
    assert!(source_closed.open_periods().is_empty());
    assert!(!source_closed.note().contains("still OPEN"));
    assert!(source_closed.note().contains("closed"), "{}", source_closed.note());
    assert!(source_closed.has_sufficient_data());
    // Same amounts: closing a period changes the warning, not the figures.
    assert_eq!(source_open.employees, source_closed.employees);
}

/// Nothing booked for the month: the declaration is not-ready and empty. The
/// generator must NOT recompute amounts from the unposted payroll inputs.
#[tokio::test]
async fn tsd_reports_an_unbooked_month_as_not_ready_without_inventing_amounts() {
    let Some(pool) = canonical_pool("tsd_unbooked_month").await else {
        return;
    };
    let entity = seed_entity(&pool, REGISTRY_CODE).await;
    // Only a YEAR period: it contains the month but is not a monthly period.
    create_period(
        &pool,
        entity,
        "year",
        "FY 2026",
        d(2026, 1, 1),
        d(2026, 12, 31),
        "open",
    )
    .await;
    insert_payroll_record(
        &pool,
        "Mari Maasikas",
        Some("47101010033"),
        200_000,
        Some(0.02),
        false,
        stamp(2026, 6, 30),
    )
    .await;

    let compliance = EstoniaOuCompliance::new(pool.clone());
    let tsd = compliance
        .generate_social_tax_declaration(2026, 6)
        .await
        .expect("TSD");

    assert!(!tsd.data_quality.has_sufficient_data);
    assert!(tsd.employees.is_empty(), "{:?}", tsd.employees);
    // Every money field is zero: an empty declaration, not an estimate.
    assert_eq!(tsd.totals.total_gross_salary_cents, 0);
    assert_eq!(tsd.totals.total_social_tax_cents, 0);
    assert_eq!(tsd.totals.total_income_tax_withheld_cents, 0);
    assert_eq!(tsd.totals.total_employer_cost_cents, 0);
    assert_eq!(tsd.totals.employee_count, 0);
    let missing = tsd.data_quality.missing_fields.join(" | ");
    assert!(
        missing.contains("monthly fiscal period for 2026-06"),
        "{missing}"
    );
    // The unposted input is named, so the operator knows the sweep has not run.
    assert!(missing.contains("not posted to the ledger"), "{missing}");
    assert!(tsd.data_quality.note.contains("NOT READY TO FILE"), "{}", tsd.data_quality.note);
}

/// A payroll input added after the sweep is counted and named: the ledger is
/// the source, so the declaration is short by that row and says so.
#[tokio::test]
async fn tsd_counts_payroll_inputs_that_are_not_booked_yet() {
    let Some(pool) = canonical_pool("tsd_unposted_counted").await else {
        return;
    };
    let entity = seed_entity(&pool, "16588747").await;
    create_period(
        &pool,
        entity,
        "month",
        "2026-07",
        d(2026, 7, 1),
        d(2026, 7, 31),
        "open",
    )
    .await;
    insert_payroll_record(
        &pool,
        "Mari Maasikas",
        Some("47101010033"),
        200_000,
        Some(0.02),
        false,
        stamp(2026, 7, 31),
    )
    .await;
    compliance::ledger_sweep::sweep_payroll_and_expenses(&pool)
        .await
        .expect("sweep");

    let before = read_month(&pool, entity, 2026, 7).await.expect("read");
    assert_eq!(before.employees.len(), 1);
    assert_eq!(before.unposted_payroll_records, 0);
    assert!(before.has_sufficient_data());

    // A second employee is paid, but the payroll has not been booked.
    insert_payroll_record(
        &pool,
        "Jaan Jaanus",
        Some("36001010011"),
        150_000,
        Some(0.06),
        false,
        stamp(2026, 7, 31),
    )
    .await;

    let after = read_month(&pool, entity, 2026, 7).await.expect("read");
    assert_eq!(after.employees.len(), 1, "the ledger has one posting");
    assert_eq!(after.unposted_payroll_records, 1);
    assert!(!after.has_sufficient_data());
    assert!(
        after
            .missing_fields()
            .iter()
            .any(|m| m.contains("1 payroll record(s) for 2026-07 are not posted")),
        "{:?}",
        after.missing_fields()
    );
    // Totals reflect only what is booked.
    let gross: i64 = after.employees.iter().map(|e| e.gross_salary_cents).sum();
    assert_eq!(gross, 200_000);
}

/// A posting whose person facts are incomplete is flagged per field, and the
/// amounts still come from the ledger. Reachable through an admin/import path
/// that booked a posting without recording the II-pillar rate.
#[tokio::test]
async fn tsd_flags_postings_missing_person_facts() {
    let Some(pool) = canonical_pool("tsd_incomplete_person").await else {
        return;
    };
    let entity = seed_entity(&pool, "16588748").await;
    let period = create_period(
        &pool,
        entity,
        "month",
        "2026-08",
        d(2026, 8, 1),
        d(2026, 8, 31),
        "open",
    )
    .await;

    // Payroll input without a personal code and with UNKNOWN II-pillar
    // participation (migration 199: NULL = unknown, never assumed).
    let record = insert_payroll_record(
        &pool,
        "Tundmatu Isik",
        None,
        100_000,
        None,
        false,
        stamp(2026, 8, 31),
    )
    .await;

    let PayrollAccounts {
        expense,
        net_wages,
        income_tax,
        social,
        unemployment,
        pension,
    } = payroll_accounts(&pool, entity).await;

    // gross 100 000; income tax 10 000; social 33 000 (employer);
    // unemp 1 600 (employee) + 800 (employer); pension 2 000; net 86 400.
    let amounts = PayrollAmounts {
        income_tax_cents: 10_000,
        social_tax_cents: 33_000,
        unemployment_employee_cents: 1_600,
        unemployment_employer_cents: 800,
        pension_cents: 2_000,
        net_cents: 86_400,
    };
    let entry = post_balanced_entry(
        &pool,
        entity,
        period,
        d(2026, 8, 31),
        "payroll 2026-08 unrated",
        // Debit = gross + employer social + employer unemployment.
        &[(expense, 133_800)],
        &[
            (net_wages, 86_400),
            (income_tax, 10_000),
            (social, 33_000),
            (unemployment, 1_600 + 800),
            (pension, 2_000),
        ],
    )
    .await;
    let posting = insert_posting(
        &pool,
        entity,
        period,
        record,
        entry,
        Some("Tundmatu Isik"),
        100_000,
        &amounts,
        "EUR",
    )
    .await;

    let source = read_month(&pool, entity, 2026, 8).await.expect("read");
    assert_eq!(source.employees.len(), 1);
    assert_eq!(source.identity_violations, Vec::<Uuid>::new());
    // The amounts are the BOOKS' amounts.
    let employee = &source.employees[0];
    assert_eq!(employee.gross_salary_cents, 100_000);
    assert_eq!(employee.net_salary_cents, 86_400);
    // ...and the missing person facts are named per field.
    assert_eq!(source.incomplete_employees.len(), 1);
    let incomplete = &source.incomplete_employees[0];
    assert_eq!(incomplete.posting_id, posting);
    assert_eq!(
        incomplete.missing,
        vec!["personal_code".to_string(), "funded_pension_rate".to_string()]
    );
    assert!(!source.has_sufficient_data());
    let missing = source.missing_fields().join(" | ");
    assert!(missing.contains("personal_code"), "{missing}");
    assert!(missing.contains("funded_pension_rate"), "{missing}");
}

/// Books that disagree with themselves cannot produce a declaration.
#[tokio::test]
async fn tsd_flags_a_posting_whose_own_arithmetic_is_inconsistent() {
    let Some(pool) = canonical_pool("tsd_identity_violation").await else {
        return;
    };
    let entity = seed_entity(&pool, "16588749").await;
    let period = create_period(
        &pool,
        entity,
        "month",
        "2026-09",
        d(2026, 9, 1),
        d(2026, 9, 30),
        "open",
    )
    .await;
    let record = insert_payroll_record(
        &pool,
        "Vigane Kirje",
        Some("47101010033"),
        100_000,
        Some(0.02),
        false,
        stamp(2026, 9, 30),
    )
    .await;

    let PayrollAccounts {
        expense,
        net_wages,
        income_tax,
        social,
        unemployment,
        pension,
    } = payroll_accounts(&pool, entity).await;

    // net 99 999 does NOT equal 100 000 − 1 600 − 2 000 − 10 000 = 86 400.
    let amounts = PayrollAmounts {
        income_tax_cents: 10_000,
        social_tax_cents: 33_000,
        unemployment_employee_cents: 1_600,
        unemployment_employer_cents: 800,
        pension_cents: 2_000,
        net_cents: 99_999,
    };
    let entry = post_balanced_entry(
        &pool,
        entity,
        period,
        d(2026, 9, 30),
        "payroll 2026-09 inconsistent",
        &[(expense, 147_399)],
        &[
            (net_wages, 99_999),
            (income_tax, 10_000),
            (social, 33_000),
            (unemployment, 2_400),
            (pension, 2_000),
        ],
    )
    .await;
    let posting = insert_posting(
        &pool,
        entity,
        period,
        record,
        entry,
        Some("Vigane Kirje"),
        100_000,
        &amounts,
        "EUR",
    )
    .await;

    let source = read_month(&pool, entity, 2026, 9).await.expect("read");
    assert_eq!(source.identity_violations, vec![posting]);
    assert!(!source.has_sufficient_data());
    assert!(
        source
            .missing_fields()
            .iter()
            .any(|m| m.contains("internally inconsistent")),
        "{:?}",
        source.missing_fields()
    );
}

/// A non-EUR posting cannot be filed on a EUR return.
#[tokio::test]
async fn tsd_flags_a_foreign_currency_posting() {
    let Some(pool) = canonical_pool("tsd_foreign_currency").await else {
        return;
    };
    let entity = seed_entity(&pool, "16588750").await;
    let period = create_period(
        &pool,
        entity,
        "month",
        "2026-10",
        d(2026, 10, 1),
        d(2026, 10, 31),
        "open",
    )
    .await;
    let record = insert_payroll_record(
        &pool,
        "Välisvaluuta Isik",
        Some("47101010033"),
        100_000,
        Some(0.02),
        false,
        stamp(2026, 10, 31),
    )
    .await;
    let PayrollAccounts {
        expense,
        net_wages,
        income_tax,
        social,
        unemployment,
        pension,
    } = payroll_accounts(&pool, entity).await;
    let amounts = PayrollAmounts {
        income_tax_cents: 10_000,
        social_tax_cents: 33_000,
        unemployment_employee_cents: 1_600,
        unemployment_employer_cents: 800,
        pension_cents: 2_000,
        net_cents: 86_400,
    };
    let entry = post_balanced_entry(
        &pool,
        entity,
        period,
        d(2026, 10, 31),
        "payroll 2026-10 usd",
        // Debit = gross + employer social + employer unemployment.
        &[(expense, 133_800)],
        &[
            (net_wages, 86_400),
            (income_tax, 10_000),
            (social, 33_000),
            (unemployment, 2_400),
            (pension, 2_000),
        ],
    )
    .await;
    insert_posting(
        &pool,
        entity,
        period,
        record,
        entry,
        Some("Välisvaluuta Isik"),
        100_000,
        &amounts,
        "USD",
    )
    .await;

    let source = read_month(&pool, entity, 2026, 10).await.expect("read");
    assert_eq!(source.currencies, vec!["USD".to_string()]);
    assert!(!source.has_sufficient_data());
    assert!(
        source
            .missing_fields()
            .iter()
            .any(|m| m.contains("postings in a currency other than EUR: USD")),
        "{:?}",
        source.missing_fields()
    );
}

/// The declaration's printed identity must have books: no entity with that
/// registry code is an error, not a zero declaration.
#[tokio::test]
async fn tsd_refuses_an_entity_with_no_books() {
    let Some(pool) = canonical_pool("tsd_entity_absent").await else {
        return;
    };
    // A different entity exists; the TSD is for REGISTRY_CODE, which does not.
    seed_entity(&pool, "16588751").await;

    let error = read_month_by_registry_code(&pool, REGISTRY_CODE, 2026, 6)
        .await
        .expect_err("must refuse");
    assert!(
        matches!(&error, TsdSourceError::EntityNotFound { registry_code } if registry_code == REGISTRY_CODE),
        "{error:?}"
    );
    assert!(error.to_string().contains(REGISTRY_CODE));

    let compliance = EstoniaOuCompliance::new(pool.clone());
    let error = compliance
        .generate_social_tax_declaration(2026, 6)
        .await
        .expect_err("must refuse");
    assert!(error.to_string().contains(REGISTRY_CODE), "{error}");

    // An unknown entity id is refused too.
    let error = read_month(&pool, Uuid::new_v4(), 2026, 6)
        .await
        .expect_err("must refuse");
    assert!(
        matches!(error, TsdSourceError::EntityIdNotFound { .. }),
        "{error:?}"
    );

    // A nonsense month is refused before any read.
    assert!(matches!(
        read_month(&pool, Uuid::new_v4(), 2026, 13).await,
        Err(TsdSourceError::InvalidPeriod { .. })
    ));
}
