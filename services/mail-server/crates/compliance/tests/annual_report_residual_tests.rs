//! Residual-arm tests for `compliance::annual_report`: the taxonomy slot
//! naming, the binding parser/validator error ladder, the XBRL config
//! environment loader, the structured-document generation guard arms and the
//! approve/submit state-machine refusals.
//!
//! Skips unless TEST_DATABASE_URL is set (workspace convention).

use compliance::annual_report::{
    approve_annual_report, generate_annual_report, get_annual_report,
    record_annual_report_submission, AnnualReportStatus, ReportSlot, TaxonomyBinding,
    ANNUAL_REPORT_XBRL_MAX_DEPTH_ENV, ANNUAL_REPORT_XBRL_MAX_DOCUMENTS_ENV,
    ANNUAL_REPORT_XBRL_TAXONOMY_BINDING_ENV, ANNUAL_REPORT_XBRL_TAXONOMY_ENV,
};
use compliance::xbrl_taxonomy::{load_taxonomy, TaxonomyLimits, TaxonomySource};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::path::PathBuf;
use uuid::Uuid;

// ── Canonical fixture (same shape as annual_report_xbrl_db_tests) ──────────

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    let suffix = format!("annual_res_{}", test_name);
    match migrator::test_support::fresh_canonical_pool(test_name, &suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn d(year: i32, month: u32, day: u32) -> chrono::NaiveDate {
    chrono::NaiveDate::from_ymd_opt(year, month, day).expect("test date")
}

fn fixture_entry_point() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ee_annual_report/entry.xsd")
}

async fn seed_entity_with_accounts(pool: &PgPool, registry_code: &str) -> (Uuid, Uuid, Uuid) {
    let entity_id: Uuid = sqlx::query_scalar(
        "INSERT INTO legal_entities (legal_name, registry_code, country_code) \
         VALUES ($1, $2, 'EE') RETURNING id",
    )
    .bind(format!("Test OÜ {registry_code}"))
    .bind(registry_code)
    .fetch_one(pool)
    .await
    .expect("insert legal entity");

    let bank: Uuid = sqlx::query_scalar(
        "INSERT INTO chart_of_accounts (legal_entity_id, code, name, account_type, normal_balance, account_role) \
         VALUES ($1, '1020', 'Bank', 'asset', 'debit', 'bank') RETURNING id",
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .expect("insert bank account");

    let revenue: Uuid = sqlx::query_scalar(
        "INSERT INTO chart_of_accounts (legal_entity_id, code, name, account_type, normal_balance, account_role) \
         VALUES ($1, '4000', 'Revenue', 'revenue', 'credit', 'revenue') RETURNING id",
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .expect("insert revenue account");

    (entity_id, bank, revenue)
}

async fn close_period(pool: &PgPool, period_id: Uuid) {
    sqlx::query("UPDATE fiscal_periods SET status = 'closed' WHERE id = $1")
        .bind(period_id)
        .execute(pool)
        .await
        .expect("close fiscal period");
}

async fn create_closed_period(pool: &PgPool, entity_id: Uuid, year: i32) -> Uuid {
    let period_id: Uuid = sqlx::query_scalar(
        "INSERT INTO fiscal_periods (legal_entity_id, period_type, label, start_date, end_date) \
         VALUES ($1, 'year', $2, $3, $4) RETURNING id",
    )
    .bind(entity_id)
    .bind(format!("FY {year}"))
    .bind(d(year, 1, 1))
    .bind(d(year, 12, 31))
    .fetch_one(pool)
    .await
    .expect("insert fiscal period");
    sqlx::query("UPDATE fiscal_periods SET status = 'closed' WHERE id = $1")
        .bind(period_id)
        .execute(pool)
        .await
        .expect("close fiscal period");
    period_id
}

// ── Slot naming ────────────────────────────────────────────────────────────

#[test]
fn report_slot_names_round_trip_and_reject_unknown() {
    for name in [
        "assets",
        "liabilities",
        "equity",
        "revenue",
        "expenses",
        "period_profit",
        "net_profit",
        "company_name",
    ] {
        let slot = ReportSlot::from_name(name).unwrap_or_else(|| panic!("{name} parses"));
        assert_eq!(slot.as_str(), name);
        assert_eq!(ReportSlot::from_name(&format!("  {name} ")), Some(slot));
    }
    assert_eq!(
        ReportSlot::from_name("liabilities "),
        Some(ReportSlot::Liabilities)
    );
    assert_eq!(ReportSlot::from_name("no-such-slot"), None);
}

// ── Taxonomy binding parser/validator ──────────────────────────────────────

#[test]
fn binding_json_rejects_non_object_and_unknown_slots() {
    let err = TaxonomyBinding::from_json_str("[]").expect_err("non-object binding refused");
    assert!(err.contains("not a JSON object"), "{err}");

    let err = TaxonomyBinding::from_json_str(r#"{"assets": "ee:Assets", "bogus": "ee:B"}"#)
        .expect_err("unknown slot refused");
    assert!(
        err.contains("unknown annual-report slot") && err.contains("company_name"),
        "{err}"
    );
}

#[test]
fn binding_file_loader_reads_a_file_and_reports_missing_files() {
    let missing =
        TaxonomyBinding::from_json_file(std::path::Path::new("/nonexistent/binding.json"));
    let err = missing.expect_err("missing file refused");
    assert!(err.contains("cannot read taxonomy binding"), "{err}");

    let dir = std::env::temp_dir().join(format!("annual_res_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(format!("binding-{}.json", Uuid::new_v4().simple()));
    std::fs::write(&path, r#"{"assets": "ee:Assets"}"#).expect("write binding");
    let binding = TaxonomyBinding::from_json_file(&path).expect("file binding parses");
    assert_eq!(binding.reference(ReportSlot::Assets), Some("ee:Assets"));
    assert!(!binding.is_empty());
    let mut binding = binding;
    binding.insert(ReportSlot::NetProfit, "ee:NetProfit");
    assert_eq!(
        binding.reference(ReportSlot::NetProfit),
        Some("ee:NetProfit")
    );
}

#[test]
fn xbrl_config_source_and_env_loader_arms() {
    // Empty source string fails at PARSE time with the env var named.
    let err = compliance::annual_report::AnnualReportXbrlConfig::from_source("   ", None)
        .expect_err("empty source refused");
    assert!(err.contains("APEXMAIL_EE_ANNUAL_REPORT_TAXONOMY"), "{err}");

    // A source that parses but fails to LOAD names the configured value.
    let err = compliance::annual_report::AnnualReportXbrlConfig::from_source("::bogus::", None)
        .expect_err("unreadable source refused");
    assert!(
        err.contains("failed to load the configured XBRL taxonomy"),
        "{err}"
    );

    // File source with a binding file loads and validates.
    let dir = std::env::temp_dir().join(format!("annual_res_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let binding_path = dir.join(format!("binding-{}.json", Uuid::new_v4().simple()));
    std::fs::write(&binding_path, r#"{"assets": "ee:Assets"}"#).expect("write binding");
    let cfg = compliance::annual_report::AnnualReportXbrlConfig::from_source(
        fixture_entry_point().to_str().expect("path"),
        Some(binding_path.as_path()),
    )
    .expect("config from file source");
    assert!(cfg.binding.is_some());

    // Env loading: unset -> None.
    std::env::remove_var(ANNUAL_REPORT_XBRL_TAXONOMY_ENV);
    assert!(
        compliance::annual_report::AnnualReportXbrlConfig::from_env()
            .expect("unset env loads")
            .is_none()
    );

    // Env loading: valid file source + limits.
    std::env::set_var(
        ANNUAL_REPORT_XBRL_TAXONOMY_ENV,
        fixture_entry_point().to_str().unwrap(),
    );
    std::env::set_var(
        ANNUAL_REPORT_XBRL_TAXONOMY_BINDING_ENV,
        binding_path.to_str().unwrap(),
    );
    std::env::set_var(ANNUAL_REPORT_XBRL_MAX_DOCUMENTS_ENV, "50");
    std::env::set_var(ANNUAL_REPORT_XBRL_MAX_DEPTH_ENV, "9");
    let loaded = compliance::annual_report::AnnualReportXbrlConfig::from_env()
        .expect("env loads")
        .expect("config present");
    assert!(loaded.binding.is_some());

    // Env loading: a bad limit value fails with the variable named.
    std::env::set_var(ANNUAL_REPORT_XBRL_MAX_DOCUMENTS_ENV, "many");
    let err = compliance::annual_report::AnnualReportXbrlConfig::from_env()
        .expect_err("bad limit refused");
    assert!(err.contains(ANNUAL_REPORT_XBRL_MAX_DOCUMENTS_ENV), "{err}");

    std::env::remove_var(ANNUAL_REPORT_XBRL_TAXONOMY_ENV);
    std::env::remove_var(ANNUAL_REPORT_XBRL_TAXONOMY_BINDING_ENV);
    std::env::remove_var(ANNUAL_REPORT_XBRL_MAX_DOCUMENTS_ENV);
    std::env::remove_var(ANNUAL_REPORT_XBRL_MAX_DEPTH_ENV);
}

#[test]
fn a_binding_to_a_non_item_concept_is_refused() {
    // A concept declared with substitutionGroup="xbrli:tuple" (not an item)
    // parses into the taxonomy but must fail slot validation with an
    // explicit FAIL_BINDING_INVALID refusal — items are the only concepts
    // that can carry a reported fact.
    let dir = std::env::temp_dir().join(format!("annual_res_tuple_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ee_annual_report");
    let dst = dir.join("tax");
    copy_dir_recursive(&src, &dst).expect("copy fixture taxonomy");

    let concepts = dst.join("concepts.xsd");
    let text = std::fs::read_to_string(&concepts).expect("read concepts");
    let patched = text.replace(
        "substitutionGroup=\"xbrli:item\" xbrli:periodType=\"instant\"",
        "substitutionGroup=\"xbrli:tuple\" xbrli:periodType=\"instant\"",
    );
    std::fs::write(&concepts, patched).expect("patch concepts");

    let taxonomy = load_taxonomy(
        &TaxonomySource::File(dst.join("entry.xsd")),
        &TaxonomyLimits::default(),
    )
    .expect("patched taxonomy loads");

    // The FIRST concept of the fixture is now a tuple: binding to it is
    // refused as a non-item.
    let binding =
        TaxonomyBinding::from_json_str(r#"{"assets": "ee:Assets"}"#).expect("binding parses");
    let config = compliance::annual_report::AnnualReportXbrlConfig {
        taxonomy,
        binding: Some(binding),
    };

    let balance_sheet = compliance::annual_report::BalanceSheet {
        assets_cents: 100,
        liabilities_cents: 0,
        equity_cents: 100,
        period_profit_cents: 0,
        total_liabilities_and_equity_cents: 100,
        balance_difference_cents: 0,
        balance_check_ok: true,
    };
    let income_statement = compliance::annual_report::IncomeStatement {
        revenue_cents: 0,
        expenses_cents: 0,
        net_profit_cents: 0,
    };
    let xbrl = compliance::annual_report::build_annual_report_xbrl(
        &compliance::annual_report::CompanyIdentity {
            legal_name: "Test".into(),
            registry_code: "55990033".into(),
            vat_number: None,
            country_code: "EE".into(),
            currency: "EUR".into(),
        },
        2025,
        d(2025, 1, 1),
        d(2025, 12, 31),
        &balance_sheet,
        &income_statement,
        &[],
        Some(&config),
    );
    let rendered = format!("{:?}", xbrl.readiness.validation_failures);
    assert!(
        rendered.contains("xbrli:item"),
        "the tuple concept must be refused as a non-item: {rendered}"
    );
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

// ── DB-backed generation + lifecycle error arms ────────────────────────────

#[tokio::test]
async fn generation_validates_actor_period_and_existence() {
    let Some(pool) = canonical_pool("generation_arms").await else {
        return;
    };
    let (entity_id, _bank, _revenue) = seed_entity_with_accounts(&pool, "55990011").await;
    let period_id = create_closed_period(&pool, entity_id, 2025).await;

    // Blank actor refused.
    let err = generate_annual_report(&pool, entity_id, period_id, "   ")
        .await
        .expect_err("blank actor refused");
    assert!(err.contains("authenticated actor"), "{err}");

    // Unknown fiscal period refused with the identity named.
    let missing = Uuid::new_v4();
    let err = generate_annual_report(&pool, entity_id, missing, "tester")
        .await
        .expect_err("unknown period refused");
    assert!(err.contains("not found for legal entity"), "{err}");

    // Happy path: the report is generated and reachable through get_annual_report.
    let report = generate_annual_report(&pool, entity_id, period_id, "tester")
        .await
        .expect("report generates from a closed period");
    let stored = get_annual_report(&pool, report.id)
        .await
        .expect("report loads");
    assert!(stored.is_some(), "the generated report is retrievable");
}

#[tokio::test]
async fn approve_and_submit_state_machine_refusals() {
    let Some(pool) = canonical_pool("lifecycle_arms").await else {
        return;
    };
    let (entity_id, bank, revenue) = seed_entity_with_accounts(&pool, "55990022").await;
    // The period must still be OPEN while the entries are posted (the
    // accounting triggers refuse postings into closed periods); it is
    // closed right after, which is the state the report generator needs.
    let open_period_id: Uuid = sqlx::query_scalar(
        "INSERT INTO fiscal_periods (legal_entity_id, period_type, label, start_date, end_date) \
         VALUES ($1, 'year', 'FY 2025', $2, $3) RETURNING id",
    )
    .bind(entity_id)
    .bind(d(2025, 1, 1))
    .bind(d(2025, 12, 31))
    .fetch_one(&pool)
    .await
    .expect("insert open period");

    // Post a balanced pair so the report has real values.
    let entry_id: Uuid = sqlx::query_scalar(
        "INSERT INTO journal_entries \
            (legal_entity_id, fiscal_period_id, entry_date, entry_type, memo, source_hash, idempotency_key) \
         VALUES ($1, $2, $3, 'standard', $4, $5, $6) RETURNING id",
    )
    .bind(entity_id)
    .bind(open_period_id)
    .bind(d(2025, 3, 1))
    .bind("seed")
    .bind(hex::encode(Sha256::digest(b"seed")))
    .bind(format!("seed-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("insert entry");
    for (line_no, (account, debit, credit)) in [(bank, 100_000i64, 0i64), (revenue, 0, 100_000)]
        .iter()
        .enumerate()
    {
        sqlx::query(
            "INSERT INTO journal_lines (entry_id, line_no, account_id, debit_cents, credit_cents) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(entry_id)
        .bind(line_no as i32 + 1)
        .bind(account)
        .bind(debit)
        .bind(credit)
        .execute(&pool)
        .await
        .expect("insert line");
    }
    sqlx::query("UPDATE journal_entries SET posted_at = NOW(), posted_by = 't' WHERE id = $1")
        .bind(entry_id)
        .execute(&pool)
        .await
        .unwrap();
    close_period(&pool, open_period_id).await;
    let period_id = open_period_id;

    let report = generate_annual_report(&pool, entity_id, period_id, "tester")
        .await
        .expect("report generates");
    let report_id = report.id;

    // Submission before approval is refused.
    let err = record_annual_report_submission(&pool, report_id, "tester", "EMTA-AR-1", None)
        .await
        .expect_err("submission before approval refused");
    assert!(err.contains("management_approved"), "{err}");

    // Approve once — then a second approval is an illegal transition.
    approve_annual_report(&pool, report_id, "approver", None)
        .await
        .expect("first approval");
    let err = approve_annual_report(&pool, report_id, "approver-2", Some("second"))
        .await
        .expect_err("second approval is an illegal transition");
    assert!(err.contains("illegal annual report transition"), "{err}");

    // Now submission works (default receipt payload branch).
    record_annual_report_submission(&pool, report_id, "submitter", "EMTA-AR-2", None)
        .await
        .expect("submission with the default receipt payload");

    // Unknown report ids are refused on both calls.
    let missing = Uuid::new_v4();
    let err = approve_annual_report(&pool, missing, "approver", None)
        .await
        .expect_err("unknown report approve refused");
    assert!(err.contains("not found"), "{err}");
    let err = record_annual_report_submission(&pool, missing, "s", "R", None)
        .await
        .expect_err("unknown report submission refused");
    assert!(err.contains("not found"), "{err}");

    // The status column moved on: an already-submitted report refuses
    // another approval via the state machine (its stored status is
    // 'submitted', which cannot transition to management_approved).
    let err = approve_annual_report(&pool, report_id, "approver-3", None)
        .await
        .expect_err("approving a submitted report is illegal");
    assert!(
        err.contains("illegal annual report transition") || err.contains("not found"),
        "{err}"
    );
    let _ = AnnualReportStatus::ManagementApproved;
}
