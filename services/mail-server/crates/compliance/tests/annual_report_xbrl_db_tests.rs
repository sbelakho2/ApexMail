//! DB-backed tests for the taxonomy-driven annual-report XBRL output.
//!
//! These provision throwaway databases carrying the REAL production migration
//! chain through `migrator::test_support` and prove that the readiness claim
//! recorded in `annual_reports.structured_document` is derived: submission
//! ready only with a loaded, bound and validated taxonomy; explicitly not
//! ready (with the reason) otherwise; and the stored instance re-parses.
//!
//! Skips unless TEST_DATABASE_URL is set (workspace convention).

use std::path::PathBuf;

use chrono::NaiveDate;
use compliance::annual_report::{
    generate_annual_report, generate_annual_report_configured, AnnualReportXbrlConfig,
    TaxonomyBinding, XBRL_EXTENSION_NAMESPACE, ANNUAL_REPORT_XBRL_TAXONOMY_BINDING_ENV,
    ANNUAL_REPORT_XBRL_TAXONOMY_ENV,
};
use compliance::xbrl_taxonomy::{
    load_taxonomy, parse_instance, validate_instance, TaxonomyLimits, TaxonomySource,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

const TAXONOMY_NAMESPACE: &str = "http://apexmail.test/xbrl/ee-annual-report/2026-01-01";

// ── Fixture helpers ────────────────────────────────────────────────────────

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    let suffix = format!("xbrl_{}", test_name);
    match migrator::test_support::fresh_canonical_pool(test_name, &suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn d(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("test date")
}

fn fixture_entry_point() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ee_annual_report/entry.xsd")
}

fn fixture_taxonomy() -> compliance::xbrl_taxonomy::XbrlTaxonomy {
    load_taxonomy(
        &TaxonomySource::File(fixture_entry_point()),
        &TaxonomyLimits::default(),
    )
    .expect("fixture taxonomy loads")
}

fn binding_json() -> &'static str {
    r#"{
        "assets": "ee:Assets",
        "liabilities": "ee:Liabilities",
        "equity": "ee:Equity",
        "revenue": "ee:Revenue",
        "expenses": "ee:Expenses",
        "net_profit": "ee:NetProfit",
        "period_profit": "ee:ProfitLossForPeriod",
        "company_name": "ee:CompanyName"
    }"#
}

fn config() -> AnnualReportXbrlConfig {
    AnnualReportXbrlConfig {
        taxonomy: fixture_taxonomy(),
        binding: Some(TaxonomyBinding::from_json_str(binding_json()).expect("binding parses")),
    }
}

fn failing_config() -> AnnualReportXbrlConfig {
    AnnualReportXbrlConfig {
        taxonomy: fixture_taxonomy(),
        binding: Some(
            TaxonomyBinding::from_json_str(
                r#"{
                    "assets": "ee:Assets",
                    "liabilities": "ee:Liabilities",
                    "equity": "ee:Equity",
                    "revenue": "ee:Revenue",
                    "expenses": "ee:Expenses",
                    "net_profit": "ee:NeverDeclaredConcept"
                }"#,
            )
            .expect("binding parses"),
        ),
    }
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

    let _equity: Uuid = sqlx::query_scalar(
        "INSERT INTO chart_of_accounts (legal_entity_id, code, name, account_type, normal_balance, account_role) \
         VALUES ($1, '3000', 'Retained earnings', 'equity', 'credit', 'retained_earnings') RETURNING id",
    )
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .expect("insert equity account");

    (entity_id, bank, revenue)
}

async fn create_period(pool: &PgPool, entity_id: Uuid, year: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO fiscal_periods (legal_entity_id, period_type, label, start_date, end_date) \
         VALUES ($1, 'year', $2, $3, $4) RETURNING id",
    )
    .bind(entity_id)
    .bind(format!("FY {year}"))
    .bind(d(year, 1, 1))
    .bind(d(year, 12, 31))
    .fetch_one(pool)
    .await
    .expect("insert open fiscal period")
}

async fn close_period(pool: &PgPool, period_id: Uuid) {
    sqlx::query("UPDATE fiscal_periods SET status = 'closed' WHERE id = $1")
        .bind(period_id)
        .execute(pool)
        .await
        .expect("close fiscal period");
}

async fn post_entry(
    pool: &PgPool,
    entity_id: Uuid,
    period_id: Uuid,
    entry_date: NaiveDate,
    memo: &str,
    lines: &[(Uuid, i64, i64)],
) {
    let idempotency_key = format!("test-{}-{}", memo, Uuid::new_v4());
    let entry_id: Uuid = sqlx::query_scalar(
        "INSERT INTO journal_entries \
            (legal_entity_id, fiscal_period_id, entry_date, entry_type, memo, source_hash, idempotency_key) \
         VALUES ($1, $2, $3, 'standard', $4, $5, $6) RETURNING id",
    )
    .bind(entity_id)
    .bind(period_id)
    .bind(entry_date)
    .bind(memo)
    .bind(hex::encode(Sha256::digest(memo.as_bytes())))
    .bind(&idempotency_key)
    .fetch_one(pool)
    .await
    .expect("insert draft journal entry");

    for (line_no, (account_id, debit, credit)) in lines.iter().enumerate() {
        sqlx::query(
            "INSERT INTO journal_lines (entry_id, line_no, account_id, debit_cents, credit_cents) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(entry_id)
        .bind(line_no as i32 + 1)
        .bind(account_id)
        .bind(debit)
        .bind(credit)
        .execute(pool)
        .await
        .expect("insert journal line");
    }

    sqlx::query(
        "UPDATE journal_entries SET posted_at = NOW(), posted_by = 'test-post' WHERE id = $1",
    )
    .bind(entry_id)
    .execute(pool)
    .await
    .expect("post journal entry");
}

/// 1 500.00 EUR bank / 1 000.00 equity / 2 000.00 revenue / 1 500.00 expenses.
async fn seed_postings(pool: &PgPool, entity_id: Uuid, period_id: Uuid, bank: Uuid, revenue: Uuid) {
    post_entry(
        pool,
        entity_id,
        period_id,
        d(2025, 3, 1),
        "opening-equity",
        &[(bank, 100_000, 0), (revenue, 0, 100_000)],
    )
    .await;
    post_entry(
        pool,
        entity_id,
        period_id,
        d(2025, 6, 1),
        "sale",
        &[(bank, 200_000, 0), (revenue, 0, 200_000)],
    )
    .await;
    post_entry(
        pool,
        entity_id,
        period_id,
        d(2025, 7, 1),
        "costs",
        &[(revenue, 150_000, 0), (bank, 0, 150_000)],
    )
    .await;
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn annual_report_records_taxonomy_identity_when_validated() {
    let Some(pool) = canonical_pool("annual_report_taxonomy_ready").await else {
        return;
    };
    let (entity_id, bank, revenue) = seed_entity_with_accounts(&pool, "16588751").await;
    let period = create_period(&pool, entity_id, 2025).await;
    seed_postings(&pool, entity_id, period, bank, revenue).await;
    close_period(&pool, period).await;

    let config = config();
    let report =
        generate_annual_report_configured(&pool, entity_id, period, "system:close-run", Some(&config))
            .await
            .expect("generate with a loaded taxonomy");

    let xbrl = &report.structured_document["xbrl"];
    assert_eq!(
        xbrl["submission_ready"],
        json!(true),
        "readiness: {:#?}",
        xbrl["readiness"]
    );
    assert_eq!(xbrl["readiness"]["submission_ready"], json!(true));
    assert_eq!(xbrl["readiness"]["missing"], json!([]));
    assert_eq!(xbrl["readiness"]["validation_failures"], json!([]));
    assert_eq!(
        xbrl["readiness"]["taxonomy"]["target_namespace"],
        json!(TAXONOMY_NAMESPACE)
    );
    assert!(xbrl["readiness"]["taxonomy"]["entry_point"]
        .as_str()
        .unwrap()
        .ends_with("entry.xsd"));
    assert_eq!(
        xbrl["readiness"]["taxonomy"]["digest"].as_str().unwrap().len(),
        64
    );

    // The instance carries official concepts for statement totals and
    // extension concepts (declared in the extension schema) for accounts.
    assert!(report.xbrl_instance.contains("<ee:Assets"), "{}", report.xbrl_instance);
    assert!(report.xbrl_instance.contains("<ee:CompanyName"));
    assert!(!report.xbrl_instance.contains("<apex:Assets"));
    assert!(report.xbrl_instance.contains("<apex:Account_a1020"));
    let extension_schema = xbrl["extension_schema"]["xml"]
        .as_str()
        .expect("extension schema stored");
    assert!(extension_schema.contains("name=\"Account_a1020\""));
    assert_eq!(
        xbrl["extension_schema"]["sha256"].as_str().unwrap().len(),
        64
    );

    // The stored instance re-parses; every fact resolves through the loaded
    // taxonomy or the declared extension concepts.
    let parsed = parse_instance(&report.xbrl_instance).expect("stored instance parses");
    assert!(!parsed.facts.is_empty());
    for fact in &parsed.facts {
        if fact.concept.namespace == TAXONOMY_NAMESPACE {
            assert!(
                config.taxonomy.concept(&fact.concept).is_some(),
                "{} is declared by the taxonomy",
                fact.concept.clark()
            );
        } else if fact.concept.namespace == XBRL_EXTENSION_NAMESPACE {
            assert!(
                extension_schema.contains(&format!("name=\"{}\"", fact.concept.name)),
                "{} is declared by the extension schema",
                fact.concept.name
            );
        } else {
            panic!("unexpected fact namespace {}", fact.concept.namespace);
        }
    }
    assert_eq!(
        xbrl["instance_sha256"],
        json!(hex::encode(Sha256::digest(report.xbrl_instance.as_bytes())))
    );
    // The pre-existing format markers are unchanged.
    assert_eq!(
        report.structured_document["format"],
        json!("apexmail.annual-report/1")
    );
    assert_eq!(xbrl["official_estonian_taxonomy"], json!(false));
    assert_eq!(xbrl["instance_embedded"], json!(true));
    assert_eq!(xbrl["namespace"], json!(XBRL_EXTENSION_NAMESPACE));

    // The validator agrees with the recorded readiness on the parsed facts.
    let mut extension = compliance::xbrl_taxonomy::ExtensionSchema {
        target_namespace: XBRL_EXTENSION_NAMESPACE.to_string(),
        concepts: Default::default(),
    };
    for fact in &parsed.facts {
        if fact.concept.namespace == XBRL_EXTENSION_NAMESPACE {
            let context = parsed
                .contexts
                .iter()
                .find(|context| context.id == fact.context_ref)
                .expect("context");
            extension.insert(compliance::xbrl_taxonomy::DeclaredConcept {
                qname: fact.concept.clone(),
                period_type: Some(context.period.expect("period").period_type()),
                balance: None,
                is_abstract: false,
                is_item: true,
                numeric: Some(compliance::xbrl_taxonomy::NumericKind::Monetary),
                source: "extension schema".to_string(),
            });
        }
    }
    let failures = validate_instance(&config.taxonomy, &extension, &parsed);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[tokio::test]
async fn annual_report_lists_validation_failures_and_stays_not_ready() {
    let Some(pool) = canonical_pool("annual_report_taxonomy_failure").await else {
        return;
    };
    let (entity_id, bank, revenue) = seed_entity_with_accounts(&pool, "16588752").await;
    let period = create_period(&pool, entity_id, 2025).await;
    seed_postings(&pool, entity_id, period, bank, revenue).await;
    close_period(&pool, period).await;

    let report = generate_annual_report_configured(
        &pool,
        entity_id,
        period,
        "system:close-run",
        Some(&failing_config()),
    )
    .await
    .expect("generation still produces a draft");

    let xbrl = &report.structured_document["xbrl"];
    assert_eq!(xbrl["submission_ready"], json!(false));
    let failures = xbrl["readiness"]["validation_failures"]
        .as_array()
        .expect("failures listed");
    assert!(!failures.is_empty());
    assert!(
        failures
            .iter()
            .any(|failure| failure["code"] == json!("binding_invalid")
                && failure["message"]
                    .as_str()
                    .unwrap()
                    .contains("NeverDeclaredConcept")),
        "{failures:#?}"
    );
    assert!(xbrl["readiness"]["taxonomy"]["digest"].as_str().is_some());
    // Nothing invented reaches the instance: no official-namespace elements.
    assert!(!report.xbrl_instance.contains("<ee:"), "{}", report.xbrl_instance);
    let warnings = report.structured_document["warnings"]
        .as_array()
        .expect("warnings");
    assert!(
        warnings
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("NOT submission-ready")),
        "{warnings:#?}"
    );
    // The stored container is still well-formed and parses.
    parse_instance(&report.xbrl_instance).expect("fallback container parses");
}

#[tokio::test]
async fn annual_report_without_a_configured_taxonomy_is_not_ready_and_says_why() {
    let Some(pool) = canonical_pool("annual_report_no_taxonomy").await else {
        return;
    };
    // Deterministic regardless of the caller's environment: this test owns
    // the process environment for the keys it exercises.
    std::env::remove_var(ANNUAL_REPORT_XBRL_TAXONOMY_ENV);
    std::env::remove_var(ANNUAL_REPORT_XBRL_TAXONOMY_BINDING_ENV);

    let (entity_id, bank, revenue) = seed_entity_with_accounts(&pool, "16588753").await;
    let period = create_period(&pool, entity_id, 2025).await;
    seed_postings(&pool, entity_id, period, bank, revenue).await;
    close_period(&pool, period).await;

    let report = generate_annual_report(&pool, entity_id, period, "system:close-run")
        .await
        .expect("generate without a taxonomy");
    let xbrl = &report.structured_document["xbrl"];
    assert_eq!(xbrl["submission_ready"], json!(false));
    assert_eq!(xbrl["readiness"]["taxonomy"], serde_json::Value::Null);
    let missing = xbrl["readiness"]["missing"]
        .as_array()
        .expect("missing list");
    assert_eq!(missing.len(), 1);
    assert!(
        missing[0]
            .as_str()
            .unwrap()
            .contains(ANNUAL_REPORT_XBRL_TAXONOMY_ENV),
        "{missing:#?}"
    );
    assert!(report.xbrl_instance.contains("<apex:Assets"));
    assert!(!report.xbrl_instance.contains("<ee:Assets"));
    parse_instance(&report.xbrl_instance).expect("extension container parses");
}
