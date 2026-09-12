//! Validated filing-package contract and transport-wiring tests.
//!
//! The pure per-form tests exercise the builders (determinism, required
//! fields, named gaps, source-declared insufficiency). The DB-backed tests
//! provision throwaway databases carrying the REAL production migration
//! chain through `migrator::test_support` and exercise the transport:
//! validated-package persistence, the "no trusted timestamp" record, a
//! failing-TSA refusal, payload-mutation refusal, and the VD named-gap
//! refusal. Skips unless TEST_DATABASE_URL is set (workspace convention); a
//! CONFIGURED provisioning failure panics (audit F01).

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use compliance::estonia_ou::{
    DataQualityNote, EmployeeTaxRecord, SocialTaxDeclaration, SocialTaxTotals, VatCategory,
    VatDeclaration, VatInputBreakdown, VatInputLine, VatSummary,
};
use compliance::filing_package::{
    build_kmd_inf_package, build_kmd_package, build_kmd_package_with_vat_number, build_oss_package,
    build_tsd_package, build_vd_package, canonical_json, payload_digest, payload_digest_matches,
    EntityIdentity, FilingForm, KmdInfAnnex, KmdInfLine, OssRegistrationIdentity,
    OssReturnDeclaration, OssSupplyEntryDeclaration, OssTotals, ValidationOutcome,
    VdEntryDeclaration, VdReturnDeclaration, VdTotals, KMD_INF_DERIVATION_GAP, KMD_VAT_NUMBER_GAP,
    TSD_PAYMENT_TYPE_GAP,
};
use compliance::filing_transport::{
    submit_filing_with_policy, verify_package_row, FilingTransport, FilingTransportConfig,
    ReturnKind, SubmissionOutcome, TimestampPolicy, TimestampRecord, TransportMode,
    TransportReceipt, NO_TRUSTED_TIMESTAMP_NOTE, TIMESTAMP_STATUS_FAILED,
    TIMESTAMP_STATUS_NOT_CONFIGURED, TIMESTAMP_STATUS_OBTAINED,
};
use compliance::signing::timestamp::TsaConfig;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

// ── Fixtures ───────────────────────────────────────────────────────────────

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    let suffix = format!("pkg_{}", test_name);
    match migrator::test_support::fresh_canonical_pool(test_name, &suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn d(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("test date")
}

fn sample_kmd() -> VatDeclaration {
    VatDeclaration {
        company_name: "Bel Consulting OÜ".into(),
        registry_code: "16588745".into(),
        tax_year: 2026,
        tax_month: 1,
        generated_at: Utc::now(),
        domestic_sales: VatCategory {
            taxable_amount_cents: 100_000,
            vat_rate: 24,
            vat_amount_cents: 24_000,
            transaction_count: 3,
            description: "domestic".into(),
        },
        intra_eu_supplies: VatCategory {
            taxable_amount_cents: 50_000,
            vat_rate: 0,
            vat_amount_cents: 0,
            transaction_count: 1,
            description: "reverse charge".into(),
        },
        exports: VatCategory {
            taxable_amount_cents: 20_000,
            vat_rate: 0,
            vat_amount_cents: 0,
            transaction_count: 1,
            description: "exports".into(),
        },
        input_vat: VatInputBreakdown {
            domestic_purchases: VatInputLine {
                amount_cents: 10_000,
                vat_amount_cents: 2_400,
                description: "purchases".into(),
            },
            intra_eu_acquisitions: VatInputLine {
                amount_cents: 0,
                vat_amount_cents: 0,
                description: "acquisitions".into(),
            },
            imports: VatInputLine {
                amount_cents: 0,
                vat_amount_cents: 0,
                description: "imports".into(),
            },
            total_deductible_vat_cents: 2_400,
        },
        summary: VatSummary {
            total_output_vat_cents: 24_000,
            total_input_vat_cents: 2_400,
            net_vat_payable_cents: 21_600,
            vat_refund_cents: 0,
            due_date: d(2026, 2, 20),
        },
        data_quality: DataQualityNote {
            has_sufficient_data: true,
            missing_fields: vec![],
            note: "extracted from live invoices".into(),
        },
        ready_for_filing: true,
        incomplete_reasons: vec![],
    }
}

fn sample_employee() -> EmployeeTaxRecord {
    EmployeeTaxRecord {
        employee_name: "Mari Mägi".into(),
        personal_code: "49001010001".into(),
        gross_salary_cents: 200_000,
        social_tax_cents: 66_000,
        unemployment_insurance_employer_cents: 1_600,
        unemployment_insurance_employee_cents: 3_200,
        funded_pension_cents: 4_000,
        funded_pension_rate: Some(0.02),
        income_tax_withheld_cents: 38_560,
        net_salary_cents: 154_240,
    }
}

fn sample_tsd() -> SocialTaxDeclaration {
    let employee = sample_employee();
    SocialTaxDeclaration {
        company_name: "Bel Consulting OÜ".into(),
        registry_code: "16588745".into(),
        tax_year: 2026,
        tax_month: 1,
        generated_at: Utc::now(),
        employees: vec![employee.clone()],
        totals: SocialTaxTotals {
            total_gross_salary_cents: employee.gross_salary_cents,
            total_social_tax_cents: employee.social_tax_cents,
            total_unemployment_employer_cents: employee.unemployment_insurance_employer_cents,
            total_unemployment_employee_cents: employee.unemployment_insurance_employee_cents,
            total_funded_pension_cents: employee.funded_pension_cents,
            total_income_tax_withheld_cents: employee.income_tax_withheld_cents,
            total_employer_cost_cents: employee.gross_salary_cents
                + employee.social_tax_cents
                + employee.unemployment_insurance_employer_cents,
            employee_count: 1,
        },
        due_date: d(2026, 2, 10),
        data_quality: DataQualityNote {
            has_sufficient_data: true,
            missing_fields: vec![],
            note: "posted ledger is complete for the month".into(),
        },
    }
}

fn sample_oss() -> OssReturnDeclaration {
    OssReturnDeclaration {
        period: "2026-01".into(),
        return_payload_hash: Some("oss-return-hash".into()),
        registration: OssRegistrationIdentity {
            scheme: "union".into(),
            registration_country: "EE".into(),
            registration_number: "EE-OSS-1".into(),
        },
        totals: OssTotals {
            total_taxable_cents: 10_000,
            total_vat_cents: 2_400,
            supply_count: 1,
        },
        entries: vec![OssSupplyEntryDeclaration {
            supply_id: "supply-1".into(),
            tenant_id: "tenant-1".into(),
            invoice_id: None,
            customer_country: "DE".into(),
            consumption_country: "DE".into(),
            taxable_amount_cents: 10_000,
            vat_rate: 24.0,
            vat_amount_cents: 2_400,
            currency: "EUR".into(),
        }],
    }
}

fn sample_vd(evidence_id: Uuid, invoice_id: Uuid) -> VdReturnDeclaration {
    VdReturnDeclaration {
        period: "2026-01".into(),
        return_payload_hash: Some("vd-return-hash".into()),
        seller_vat_number: Some("EE101234567".into()),
        totals: VdTotals {
            total_taxable_cents: 50_000,
            line_count: 1,
        },
        entries: vec![VdEntryDeclaration {
            supply_id: "invoice-1".into(),
            invoice_id: Some(invoice_id),
            customer_vat_number: "DE123456789".into(),
            customer_country: "DE".into(),
            vat_evidence_id: Some(evidence_id),
            transaction_nature: "services".into(),
            taxable_amount_cents: 50_000,
            currency: "EUR".into(),
        }],
    }
}

fn sample_annex() -> KmdInfAnnex {
    KmdInfAnnex {
        period: "2026-01".into(),
        entity: EntityIdentity {
            legal_name: Some("Bel Consulting OÜ".into()),
            registry_code: Some("16588745".into()),
            vat_number: Some("EE101234567".into()),
            registration_number: None,
        },
        lines: vec![KmdInfLine {
            invoice_number: "2026-0001".into(),
            invoice_date: d(2026, 1, 15),
            counterparty_name: "Acme GmbH".into(),
            counterparty_registry_code: None,
            counterparty_vat_number: Some("DE123456789".into()),
            taxable_amount_cents: 100_000,
            vat_rate_percent: 24.0,
            vat_amount_cents: 24_000,
        }],
    }
}

// ── Canonical serialisation ────────────────────────────────────────────────

#[test]
fn canonical_json_is_key_order_independent_and_deterministic() {
    let first = json!({"b": 2, "a": {"z": 1, "c": [1, 2, 3]}});
    let second = json!({"a": {"c": [1, 2, 3], "z": 1}, "b": 2});
    assert_eq!(canonical_json(&first), canonical_json(&second));
    assert_eq!(payload_digest(&first), payload_digest(&second));
    assert_eq!(payload_digest(&first).len(), 64);

    assert!(payload_digest_matches(&first, &payload_digest(&first)));
    assert!(!payload_digest_matches(&first, "0".repeat(64).as_str()));
    let mut mutated = first.clone();
    mutated["a"]["z"] = json!(2);
    assert!(!payload_digest_matches(&mutated, &payload_digest(&first)));
}

// ── KMD ────────────────────────────────────────────────────────────────────

#[test]
fn kmd_complete_declaration_is_deterministic_and_records_the_vat_number_gap() {
    let declaration = sample_kmd();
    let first = build_kmd_package(&declaration).expect("complete KMD declaration");
    let second = build_kmd_package(&declaration).expect("complete KMD declaration again");

    assert_eq!(first.form, FilingForm::Kmd);
    assert_eq!(first.period, "2026-01");
    assert_eq!(first.validation.outcome, ValidationOutcome::Valid);
    assert_eq!(
        first.canonical_payload_bytes(),
        second.canonical_payload_bytes(),
        "the same declaration must produce byte-identical package bytes"
    );
    assert_eq!(first.payload_sha256, second.payload_sha256);
    assert_eq!(first.payload_sha256.len(), 64);

    // No VAT number member exists on VatDeclaration: explicit named gap, and
    // therefore not submittable.
    assert_eq!(first.named_gaps.len(), 1);
    assert_eq!(first.named_gaps[0].field, KMD_VAT_NUMBER_GAP);
    assert!(!first.is_submittable());
    let refusal = first.refusal_reason().expect("gap refusal");
    assert!(refusal.contains(KMD_VAT_NUMBER_GAP), "{refusal}");

    // The caller can supply the entity VAT number from the entity record;
    // then the package is clean and submittable.
    let with_vat =
        build_kmd_package_with_vat_number(&declaration, Some("EE101234567")).expect("with VAT");
    assert!(with_vat.named_gaps.is_empty());
    assert!(with_vat.is_submittable());
    assert_eq!(with_vat.entity.vat_number.as_deref(), Some("EE101234567"));
}

#[test]
fn kmd_refuses_missing_entity_identity_and_insufficient_source_data() {
    let mut missing_name = sample_kmd();
    missing_name.company_name = "   ".into();
    let error = build_kmd_package(&missing_name).expect_err("blank entity name must be refused");
    assert!(error.to_string().contains("entity.legal_name"), "{error}");
    assert_eq!(error.fields(), vec!["entity.legal_name"]);

    let mut missing_registry = sample_kmd();
    missing_registry.registry_code = String::new();
    let error =
        build_kmd_package(&missing_registry).expect_err("blank registry code must be refused");
    assert!(error.to_string().contains("entity.registry_code"), "{error}");

    let mut not_ready = sample_kmd();
    not_ready.ready_for_filing = false;
    not_ready.incomplete_reasons = vec!["deductible input VAT is 0".into()];
    let error = build_kmd_package(&not_ready).expect_err("not-ready KMD must be refused");
    assert!(error.to_string().contains("ready_for_filing"), "{error}");
    assert!(
        error.to_string().contains("deductible input VAT is 0"),
        "{error}"
    );

    let mut insufficient = sample_kmd();
    insufficient.data_quality.has_sufficient_data = false;
    insufficient.data_quality.missing_fields = vec!["invoices table".into()];
    let error = build_kmd_package(&insufficient).expect_err("insufficient KMD must be refused");
    assert!(error.to_string().contains("invoices table"), "{error}");
}

#[test]
fn kmd_refuses_a_summary_that_disagrees_with_its_components() {
    let mut tampered = sample_kmd();
    tampered.summary.net_vat_payable_cents += 1;
    let error = build_kmd_package(&tampered).expect_err("inconsistent summary must be refused");
    assert!(
        error.to_string().contains("summary.net_vat_payable_cents"),
        "{error}"
    );
    assert_eq!(error.problems[0].kind, compliance::filing_package::ProblemKind::InvalidValue);
}

// ── KMD INF ────────────────────────────────────────────────────────────────

#[test]
fn kmd_inf_validates_lines_and_records_the_derivation_gap() {
    let package = build_kmd_inf_package(&sample_annex()).expect("complete annex");
    assert_eq!(package.form, FilingForm::KmdInf);
    assert_eq!(package.validation.outcome, ValidationOutcome::Valid);
    assert_eq!(package.named_gaps.len(), 1);
    assert_eq!(package.named_gaps[0].field, KMD_INF_DERIVATION_GAP);
    assert!(
        !package.is_submittable(),
        "the annex has no repository derivation and must stay non-submittable"
    );

    let mut missing_invoice_number = sample_annex();
    missing_invoice_number.lines[0].invoice_number = " ".into();
    let error = build_kmd_inf_package(&missing_invoice_number)
        .expect_err("blank invoice number must be refused");
    assert!(
        error.to_string().contains("lines[0].invoice_number"),
        "{error}"
    );

    let mut no_identity = sample_annex();
    no_identity.lines[0].counterparty_vat_number = None;
    no_identity.lines[0].counterparty_registry_code = Some("  ".into());
    let error =
        build_kmd_inf_package(&no_identity).expect_err("identity-less line must be refused");
    assert!(
        error.to_string().contains("lines[0].counterparty_identity"),
        "{error}"
    );

    let mut empty = sample_annex();
    empty.lines.clear();
    let error = build_kmd_inf_package(&empty).expect_err("empty annex must be refused");
    assert!(error.to_string().contains("lines"), "{error}");
}

// ── TSD ────────────────────────────────────────────────────────────────────

#[test]
fn tsd_complete_declaration_is_deterministic_and_records_the_payment_type_gap() {
    let declaration = sample_tsd();
    let first = build_tsd_package(&declaration).expect("complete TSD");
    let second = build_tsd_package(&declaration).expect("complete TSD again");

    assert_eq!(first.form, FilingForm::Tsd);
    assert_eq!(first.period, "2026-01");
    assert_eq!(first.validation.outcome, ValidationOutcome::Valid);
    assert_eq!(first.canonical_payload_bytes(), second.canonical_payload_bytes());
    assert_eq!(first.payload_sha256, second.payload_sha256);
    assert_eq!(first.named_gaps.len(), 1);
    assert_eq!(first.named_gaps[0].field, TSD_PAYMENT_TYPE_GAP);
    assert!(!first.is_submittable());
}

#[test]
fn tsd_refuses_insufficient_ledger_data_and_missing_person_fields() {
    // Ledger says the month is not complete.
    let mut insufficient = sample_tsd();
    insufficient.data_quality.has_sufficient_data = false;
    insufficient.data_quality.missing_fields =
        vec!["posted payroll postings for 2026-01".into()];
    let error = build_tsd_package(&insufficient).expect_err("insufficient TSD must be refused");
    assert!(
        error
            .to_string()
            .contains("posted payroll postings for 2026-01"),
        "{error}"
    );

    // Even with the flag true, a non-empty missing_fields is a refusal.
    let mut declared_gap = sample_tsd();
    declared_gap.data_quality.missing_fields = vec!["payroll_records (staff costs)".into()];
    let error =
        build_tsd_package(&declared_gap).expect_err("named missing field must be refused");
    assert!(
        error.to_string().contains("payroll_records (staff costs)"),
        "{error}"
    );

    // Unknown II-pillar participation is not zero-filled.
    let mut unknown_pension = sample_tsd();
    unknown_pension.employees[0].funded_pension_rate = None;
    let error = build_tsd_package(&unknown_pension)
        .expect_err("unknown funded-pension participation must be refused");
    assert!(
        error
            .to_string()
            .contains("employees[0].funded_pension_rate"),
        "{error}"
    );

    // A person without a personal code cannot be declared.
    let mut missing_code = sample_tsd();
    missing_code.employees[0].personal_code = String::new();
    let error =
        build_tsd_package(&missing_code).expect_err("missing personal code must be refused");
    assert!(
        error.to_string().contains("employees[0].personal_code"),
        "{error}"
    );

    // Totals that disagree with the person rows are refused.
    let mut bad_totals = sample_tsd();
    bad_totals.totals.total_gross_salary_cents += 1;
    let error = build_tsd_package(&bad_totals).expect_err("bad totals must be refused");
    assert!(
        error
            .to_string()
            .contains("totals.total_gross_salary_cents"),
        "{error}"
    );
}

// ── OSS ────────────────────────────────────────────────────────────────────

#[test]
fn oss_complete_declaration_is_valid_submittable_and_deterministic() {
    let declaration = sample_oss();
    let first = build_oss_package(&declaration).expect("complete OSS return");
    let second = build_oss_package(&declaration).expect("complete OSS return again");

    assert_eq!(first.form, FilingForm::Oss);
    assert_eq!(first.validation.outcome, ValidationOutcome::Valid);
    assert!(first.named_gaps.is_empty(), "OSS has no named gap");
    assert!(first.is_submittable());
    assert_eq!(first.canonical_payload_bytes(), second.canonical_payload_bytes());
    assert_eq!(first.payload_sha256, second.payload_sha256);
    assert_eq!(
        first.entity.registration_number.as_deref(),
        Some("EE-OSS-1")
    );
}

#[test]
fn oss_refuses_missing_registration_entries_and_inconsistent_totals() {
    let mut no_registration = sample_oss();
    no_registration.registration.registration_number = "  ".into();
    let error = build_oss_package(&no_registration)
        .expect_err("missing registration number must be refused");
    assert!(
        error.to_string().contains("registration.registration_number"),
        "{error}"
    );

    let mut wrong_scheme = sample_oss();
    wrong_scheme.registration.scheme = "ioss".into();
    let error = build_oss_package(&wrong_scheme).expect_err("non-union scheme must be refused");
    assert!(error.to_string().contains("registration.scheme"), "{error}");

    let mut empty = sample_oss();
    empty.entries.clear();
    empty.totals = OssTotals {
        total_taxable_cents: 0,
        total_vat_cents: 0,
        supply_count: 0,
    };
    let error = build_oss_package(&empty).expect_err("empty OSS return must be refused");
    assert!(error.to_string().contains("entries"), "{error}");

    let mut bad_total = sample_oss();
    bad_total.totals.total_vat_cents += 1;
    let error = build_oss_package(&bad_total).expect_err("bad total VAT must be refused");
    assert!(error.to_string().contains("totals.total_vat_cents"), "{error}");

    let mut bad_country = sample_oss();
    bad_country.entries[0].consumption_country = "DEU".into();
    let error = build_oss_package(&bad_country).expect_err("bad country must be refused");
    assert!(
        error.to_string().contains("entries[0].consumption_country"),
        "{error}"
    );
}

// ── VD ─────────────────────────────────────────────────────────────────────

#[test]
fn vd_valid_package_is_submittable_and_refuses_bad_lines() {
    let package = build_vd_package(&sample_vd(Uuid::new_v4(), Uuid::new_v4())).expect("complete VD");
    assert_eq!(package.form, FilingForm::Vd);
    assert_eq!(package.validation.outcome, ValidationOutcome::Valid);
    // No named gaps: the VD listing is the intra-Community SUPPLY listing, and
    // acquisitions are declared on KMD (VatInputBreakdown::intra_eu_acquisitions),
    // so a supplies-only return is complete and submittable.
    assert!(package.named_gaps.is_empty(), "{:?}", package.named_gaps);
    assert!(package.is_submittable());

    let mut no_seller = sample_vd(Uuid::new_v4(), Uuid::new_v4());
    no_seller.seller_vat_number = None;
    let error = build_vd_package(&no_seller).expect_err("missing seller VAT number");
    assert!(error.to_string().contains("seller_vat_number"), "{error}");

    let mut no_evidence = sample_vd(Uuid::new_v4(), Uuid::new_v4());
    no_evidence.entries[0].vat_evidence_id = None;
    let error = build_vd_package(&no_evidence).expect_err("missing VIES evidence");
    assert!(
        error.to_string().contains("entries[0].vat_evidence_id"),
        "{error}"
    );
}

// ── DB-backed transport tests ──────────────────────────────────────────────

struct FakeTransport {
    result: Result<TransportReceipt, String>,
}

#[async_trait]
impl FilingTransport for FakeTransport {
    async fn submit(
        &self,
        _package: &compliance::filing_transport::SubmissionPackage,
    ) -> Result<TransportReceipt, String> {
        self.result.clone()
    }
}

fn machine_config() -> FilingTransportConfig {
    FilingTransportConfig {
        mode: TransportMode::Http,
        endpoint: Some("https://filing.test/submit".into()),
        bearer_token: Some("test-credential".into()),
        timeout_secs: 5,
    }
}

async fn seed_oss_registration(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO oss_registrations (scheme, registration_country, registration_number, valid_from) \
         VALUES ('union', 'EE', 'EE-OSS-TEST', $1) RETURNING id",
    )
    .bind(d(2025, 1, 1))
    .fetch_one(pool)
    .await
    .expect("insert OSS registration")
}

async fn seed_oss_return(pool: &PgPool, registration_id: Uuid, period: &str) -> Uuid {
    let return_id: Uuid = sqlx::query_scalar(
        "INSERT INTO oss_returns \
            (registration_id, period, scheme, status, total_taxable_cents, total_vat_cents, supply_count, payload_hash) \
         VALUES ($1, $2, 'union', 'validated', 10000, 2400, 1, 'payload-hash-1') RETURNING id",
    )
    .bind(registration_id)
    .bind(period)
    .fetch_one(pool)
    .await
    .expect("insert OSS return");

    sqlx::query(
        "INSERT INTO oss_supply_entries \
            (registration_id, period, supply_id, tenant_id, customer_country, consumption_country, \
             taxable_amount_cents, vat_rate, vat_amount_cents, currency) \
         VALUES ($1, $2, $3, 'tenant-1', 'DE', 'DE', 10000, 24.0, 2400, 'EUR')",
    )
    .bind(registration_id)
    .bind(period)
    .bind(format!("supply-{period}"))
    .execute(pool)
    .await
    .expect("insert OSS supply entry");

    return_id
}

#[tokio::test]
async fn oss_submission_records_validated_package_and_the_absent_timestamp() {
    let Some(pool) = canonical_pool("oss_package_evidence").await else {
        return;
    };
    let registration_id = seed_oss_registration(&pool).await;
    let return_id = seed_oss_return(&pool, registration_id, "2026-01").await;

    let outcome = submit_filing_with_policy(
        &pool,
        ReturnKind::Oss,
        return_id,
        &FilingTransportConfig::disabled(),
        None,
        TimestampPolicy::Explicit(None),
    )
    .await
    .expect("unconfigured submission opens the mandatory human task");
    let package_id = match outcome {
        SubmissionOutcome::HumanTaskRequired { package_id, .. } => package_id,
        other => panic!("expected HumanTaskRequired, got {other:?}"),
    };

    let row: (
        String,
        String,
        Value,
        Value,
        String,
        Value,
        Value,
        String,
    ) = sqlx::query_as(
        "SELECT form, validation_outcome, validation_report, named_gaps, timestamp_status, \
                timestamp_evidence, payload, payload_sha256 \
         FROM filing_submission_packages WHERE id = $1",
    )
    .bind(package_id)
    .fetch_one(&pool)
    .await
    .expect("package row");

    assert_eq!(row.0, "oss");
    assert_eq!(row.1, "valid");
    assert_eq!(row.2["outcome"], json!("valid"));
    assert_eq!(row.2["ruleset"], json!("apexmail.filing.validation/1"));
    assert_eq!(row.3, json!([]));
    assert_eq!(row.4, TIMESTAMP_STATUS_NOT_CONFIGURED);
    assert_eq!(row.5["status"], json!(TIMESTAMP_STATUS_NOT_CONFIGURED));
    assert_eq!(row.5["note"], json!(NO_TRUSTED_TIMESTAMP_NOTE));
    assert_eq!(
        row.5.get("evidence").and_then(Value::as_object),
        None,
        "no timestamp evidence may be fabricated"
    );

    // The persisted JSONB payload round-trips to the exact digest: the package
    // survives the storage round trip byte-for-byte (canonically).
    assert_eq!(payload_digest(&row.6), row.7);
    assert_eq!(row.6["format"], json!("apexmail.filing.oss/1"));
    verify_package_row(&pool, package_id)
        .await
        .expect("the stored package verifies");

    // The human task guarantee is intact.
    let open_tasks: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM filing_human_tasks WHERE return_id = $1 AND status = 'open'",
    )
    .bind(return_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(open_tasks, 1);
}

#[tokio::test]
async fn machine_submission_without_tsa_proceeds_and_records_no_trusted_timestamp() {
    let Some(pool) = canonical_pool("machine_no_tsa").await else {
        return;
    };
    let registration_id = seed_oss_registration(&pool).await;
    let return_id = seed_oss_return(&pool, registration_id, "2026-02").await;

    let transport = FakeTransport {
        result: Ok(TransportReceipt {
            receipt_reference: "EMTA-SUB-2026-02-7".into(),
            accepted_at: Utc::now(),
            receipt_payload: json!({"status": "received"}),
        }),
    };
    let outcome = submit_filing_with_policy(
        &pool,
        ReturnKind::Oss,
        return_id,
        &machine_config(),
        Some(&transport),
        TimestampPolicy::Explicit(None),
    )
    .await
    .expect("machine submission without a TSA proceeds");
    let package_id = match outcome {
        SubmissionOutcome::Submitted { package_id, .. } => package_id,
        other => panic!("expected Submitted, got {other:?}"),
    };

    let (status, timestamp_status, note, evidence): (String, String, String, Option<Value>) =
        sqlx::query_as(
            "SELECT status, timestamp_status, timestamp_evidence->>'note', \
                    timestamp_evidence->'evidence' \
             FROM filing_submission_packages WHERE id = $1",
        )
        .bind(package_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "sent");
    assert_eq!(timestamp_status, TIMESTAMP_STATUS_NOT_CONFIGURED);
    assert_eq!(note, NO_TRUSTED_TIMESTAMP_NOTE);
    assert!(evidence.is_none(), "never fabricate a timestamp");

    let return_status: String =
        sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1")
            .bind(return_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(return_status, "submitted");
}

#[tokio::test]
async fn machine_submission_with_a_failing_tsa_is_refused_with_the_check_results() {
    let Some(pool) = canonical_pool("machine_failing_tsa").await else {
        return;
    };
    let registration_id = seed_oss_registration(&pool).await;
    let return_id = seed_oss_return(&pool, registration_id, "2026-03").await;

    // A loopback TSA answers with the genuine OpenSSL fixture response, whose
    // embedded nonce cannot match the freshly generated request nonce: the
    // timestamp is granted-shaped but the exchange binding fails, so the
    // verification FAILS with named checks.
    let (url, server) = spawn_tsa_server(|_body| fixture_response()).await;
    let tsa = TsaConfig::new(url)
        .expect("valid TSA URL")
        .with_timeout_secs(5);

    let transport = FakeTransport {
        result: Ok(TransportReceipt {
            receipt_reference: "EMTA-SUB-2026-03-9".into(),
            accepted_at: Utc::now(),
            receipt_payload: json!({"status": "received"}),
        }),
    };
    let error = submit_filing_with_policy(
        &pool,
        ReturnKind::Oss,
        return_id,
        &machine_config(),
        Some(&transport),
        TimestampPolicy::Explicit(Some(&tsa)),
    )
    .await
    .expect_err("a failing timestamp must refuse the submission");
    assert!(error.contains("trusted timestamp"), "{error}");
    assert!(error.contains("nonce_matches_request"), "{error}");
    let _ = server.await.expect("TSA server task");

    // The return stays validated and the refusal is recorded with evidence.
    let return_status: String =
        sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1")
            .bind(return_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(return_status, "validated");

    let (package_status, timestamp_status, failure_checks): (String, String, Value) =
        sqlx::query_as(
            "SELECT status, timestamp_status, timestamp_evidence->'failure_checks' \
             FROM filing_submission_packages WHERE return_id = $1",
        )
        .bind(return_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(package_status, "failed");
    assert_eq!(timestamp_status, TIMESTAMP_STATUS_FAILED);
    let failing: Vec<&str> = failure_checks
        .as_array()
        .expect("failure_checks array")
        .iter()
        .filter_map(|check| check.get("check").and_then(Value::as_str))
        .collect();
    assert!(
        failing.contains(&"nonce_matches_request"),
        "the recorded check results must name the failed exchange binding: {failing:?}"
    );
}

#[tokio::test]
async fn mutated_payload_is_refused_before_manual_submission() {
    let Some(pool) = canonical_pool("mutated_payload").await else {
        return;
    };
    let registration_id = seed_oss_registration(&pool).await;
    let return_id = seed_oss_return(&pool, registration_id, "2026-04").await;

    let outcome = submit_filing_with_policy(
        &pool,
        ReturnKind::Oss,
        return_id,
        &FilingTransportConfig::disabled(),
        None,
        TimestampPolicy::Explicit(None),
    )
    .await
    .expect("human task");
    let (package_id, task_id) = match outcome {
        SubmissionOutcome::HumanTaskRequired { package_id, task_id } => (package_id, task_id),
        other => panic!("expected HumanTaskRequired, got {other:?}"),
    };
    verify_package_row(&pool, package_id).await.expect("clean");

    // Mutate the stored payload after validation; the digest no longer
    // matches and every submission act refuses.
    sqlx::query(
        "UPDATE filing_submission_packages SET payload = payload || '{\"tampered\": true}'::jsonb \
         WHERE id = $1",
    )
    .bind(package_id)
    .execute(&pool)
    .await
    .expect("mutate payload");

    let error = verify_package_row(&pool, package_id)
        .await
        .expect_err("mutated payload must not verify");
    assert!(error.contains("digest"), "{error}");

    let error = compliance::filing_transport::record_manual_submission(
        &pool,
        ReturnKind::Oss,
        return_id,
        task_id,
        "operator:1",
        "EMTA-OSS-2026-04-0001",
        None,
    )
    .await
    .expect_err("manual submission of a mutated package must be refused");
    assert!(error.contains("digest"), "{error}");

    let return_status: String =
        sqlx::query_scalar("SELECT status FROM oss_returns WHERE id = $1")
            .bind(return_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(return_status, "validated");
    let task_status: String =
        sqlx::query_scalar("SELECT status FROM filing_human_tasks WHERE id = $1")
            .bind(task_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(task_status, "open");
}

async fn seed_vd_return(pool: &PgPool, period: &str) -> Uuid {
    let evidence_id: Uuid = sqlx::query_scalar(
        "INSERT INTO vat_validation_evidence \
            (tenant_id, vat_number, country, source, requested_at, valid, response_hash, valid_from) \
         VALUES ('tenant-1', 'DE123456789', 'DE', 'VIES', NOW(), TRUE, 'evidence-hash', $1) \
         RETURNING id",
    )
    .bind(d(2026, 1, 1))
    .fetch_one(pool)
    .await
    .expect("insert VIES evidence");

    let return_id: Uuid = sqlx::query_scalar(
        "INSERT INTO vd_returns \
            (period, seller_vat_number, status, total_taxable_cents, total_vat_cents, line_count, payload_hash) \
         VALUES ($1, 'EE101234567', 'validated', 50000, 0, 1, 'vd-payload-hash') RETURNING id",
    )
    .bind(period)
    .fetch_one(pool)
    .await
    .expect("insert VD return");

    sqlx::query(
        "INSERT INTO vd_entries \
            (return_id, period, supply_id, invoice_id, customer_vat_number, customer_country, \
             vat_evidence_id, transaction_nature, taxable_amount_cents, currency) \
         VALUES ($1, $2, $3, $4, 'DE123456789', 'DE', $5, 'services', 50000, 'EUR')",
    )
    .bind(return_id)
    .bind(period)
    .bind(format!("invoice-{period}"))
    .bind(Uuid::new_v4())
    .bind(evidence_id)
    .execute(pool)
    .await
    .expect("insert VD entry");

    return_id
}

#[tokio::test]
async fn vd_supply_listing_is_submittable_and_persisted_with_its_evidence() {
    let Some(pool) = canonical_pool("vd_supply_listing_submits").await else {
        return;
    };
    let return_id = seed_vd_return(&pool, "2026-05").await;

    let transport = FakeTransport {
        result: Ok(TransportReceipt {
            receipt_reference: "EMTA-VD-2026-05-1".into(),
            accepted_at: Utc::now(),
            receipt_payload: json!({"status": "received"}),
        }),
    };
    let submission = submit_filing_with_policy(
        &pool,
        ReturnKind::Vd,
        return_id,
        &machine_config(),
        Some(&transport),
        TimestampPolicy::Explicit(None),
    )
    .await
    .expect("a complete intra-Community supply listing must be submittable");
    match submission {
        SubmissionOutcome::Submitted {
            receipt_reference, ..
        } => assert_eq!(receipt_reference, "EMTA-VD-2026-05-1"),
        other => panic!("the machine transport must have submitted: {other:?}"),
    }

    // The package is persisted with a validation report, no named gaps, and
    // the explicit no-TSA note (never a fabricated timestamp).
    let row: (String, String, Option<serde_json::Value>, Option<String>) = sqlx::query_as(
        "SELECT form, validation_outcome, named_gaps, timestamp_status \
         FROM filing_submission_packages WHERE return_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(return_id)
    .fetch_one(&pool)
    .await
    .expect("package row");
    assert_eq!(row.0, "vd");
    assert_eq!(row.1, "valid");
    assert_eq!(
        row.2.as_ref().and_then(|gaps| gaps.as_array()).map(Vec::len),
        Some(0),
        "no named gaps: {:?}",
        row.2
    );
    assert_eq!(row.3.as_deref(), Some("not_configured"));

    // The return advanced, so the lawful filing actually happened.
    let return_status: String =
        sqlx::query_scalar("SELECT status FROM vd_returns WHERE id = $1")
            .bind(return_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(return_status, "submitted");
}

// ── Timestamp evidence record ──────────────────────────────────────────────

#[test]
fn obtained_timestamp_record_round_trips_with_the_required_evidence() {
    use compliance::signing::timestamp::{
        verify_response, HashAlgorithm, TimestampVerificationRequest,
    };

    // The fixture response is the genuine granted reply for this document and
    // nonce (`signing_tests.rs`), so all checks pass and the evidence is a
    // real RFC 3161 record — not a placeholder.
    let document: &[u8] =
        b"ApexMail statutory filing fixture document.\nPeriod: 2026-01-01..2026-12-31\n";
    let evidence = verify_response(
        &fixture_response(),
        &TimestampVerificationRequest {
            document,
            nonce: 0xD57F_3EDC_B92F_412D,
            algorithm: HashAlgorithm::Sha256,
            tolerance_secs: 300,
            now: DateTime::parse_from_rfc3339("2026-09-12T21:19:44Z")
                .expect("fixture genTime")
                .with_timezone(&Utc),
            tsa_url: Some("https://tsa.example.test/"),
        },
    )
    .expect("the fixture must verify");
    assert!(evidence.all_passed(), "{:?}", evidence.failing_checks());

    let record = TimestampRecord::obtained(evidence.clone());
    assert!(record.is_obtained());
    let value = serde_json::to_value(&record).expect("record serialises");
    assert_eq!(value["status"], json!(TIMESTAMP_STATUS_OBTAINED));
    assert_eq!(value["schema_version"], json!(1));
    assert_eq!(
        value["evidence"]["policy_oid"],
        json!("1.3.6.1.4.1.57264.1.1"),
        "the TSA policy must be recorded"
    );
    assert_eq!(
        value["evidence"]["gen_time_rfc3339"],
        json!("2026-09-12T21:19:44Z")
    );
    assert!(
        value["evidence"]["signer_certificate"]["subject"].is_string(),
        "the signer certificate summary must be recorded"
    );
    assert!(
        value["evidence"]["checks"].as_array().is_some_and(|checks| !checks.is_empty()),
        "the per-check verdicts must be recorded"
    );
    assert!(value["evidence"]["proven_properties"]
        .as_array()
        .is_some_and(|properties| !properties.is_empty()));
    assert!(!value["evidence"]["not_proven_properties"]
        .as_array()
        .unwrap()
        .is_empty());

    // The evidence survives a JSON round trip (the storage representation).
    let back: TimestampRecord = serde_json::from_value(value).expect("record deserialises");
    let back_evidence = back.evidence.expect("evidence present");
    assert_eq!(back_evidence.request_nonce, evidence.request_nonce);
    assert_eq!(back_evidence.gen_time_rfc3339, evidence.gen_time_rfc3339);
    assert_eq!(back_evidence.policy_oid, evidence.policy_oid);
    assert_eq!(back_evidence.signer_certificate, evidence.signer_certificate);
    assert_eq!(back_evidence.checks, evidence.checks);
}

// ── Loopback TSA fixture ───────────────────────────────────────────────────
//
// The RFC 3161 response below is the genuine OpenSSL fixture used by
// `signing_tests.rs` (a granted reply minted for FIXTURE_DOCUMENT with a
// fixed nonce). Served against a freshly generated request nonce it parses
// and verifies, then fails exactly the `nonce_matches_request` check.

const FIXTURE_RESPONSE_HEX: &str = "30820a09300302010030820a0006092a864886f70d010702a08209f1308209ed020103310f300d06096086480165030402010500308180060b2a864886f70d01\n09100104a071046f306d020101060a2b0601040183bf3001013031300d0609608648016503040201050004206ccbf31f3339b0d03d9aeb7d6321751b79320b85\n41dc53d4b4291c833b4d186f020102180f32303236303931323231313934345a300a020101800201f4810164020900d57f3edcb92f412da082071a3082038930\n820271a00302010202045a504558300d06092a864886f70d01010b0500305a310b3009060355040613024545311e301c060355040a0c15417065784d61696c20\n546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e29301e170d323630\n3931323231313933375a170d3336303930393231313933375a305a310b3009060355040613024545311e301c060355040a0c15417065784d61696c2054657374\n2046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e2930820122300d06092a8648\n86f70d01010105000382010f003082010a0282010100b30a8b1ae3ecf5fb229dc9beb60b613cc02d86b4b9bc8f84d595984399dd8a1afa71521c6d91b6377537\n8ba7bf2ed6d9d543faa71f777dc3c2632c5b4c8ea7d8a7cd26f7462694d721f5aefdbe4ef31878b78bccb9aa1acd89bd73252218420ef3b6fcd27ee010864862\nedacb2dcfe35901c71060284771986f2033c40309e716ca7ad9c7efb5c494b6dfd7a012bb0210b283cccca9e3059cb1a48d03a2bb604ebfce7bd1bd24e30efb9\n9949b3966b09597e46e87483b1afb0b289a73c7bf7df4d489698ff37e223f83b046af65f51454ccdbe9f3442c4705cd5c397d9f2369fb513db37a20955e62384\n892c2bea6388d17583426fdc9284efb1c604d011df150203010001a3573055300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301606\n03551d250101ff040c300a06082b06010505070308301d0603551d0e04160414717afd522d0495d89e78f45d59795d981a0d482a300d06092a864886f70d0101\n0b0500038201010028e4f826146b6240f3f1d13ec21284e1dbe4494cf405cebb211aca3e90c864bd314ba83591120d7dba2cf3b497022b04630a1e1e58d8fdde\na0e36b47bbc91ae357cc9d5fe44e50fba8e476a9850f8017070ef10628e7fa12d41bdb03411e275055c04834419c909f1a4ee683c0e3ce96ecb5334f04398b64\n88bbead7c74771ec913e6d927e54261ebb67dc036762683a573b259643e6370f81e0e87070a556ba33e515738a8a5853840c834a4d53a2d0d40816c99a4b1ca0\n6b8ba847537481be1632fce7d5ff1ea419d8bd47e9ab779beaabb5de7068a2f869befb2f43c0f34f4ef92c385630cc655f0b5e8de49c4bd43a8585a5af92dd7e\n4b3730fb785f9b853082038930820271a00302010202045a504558300d06092a864886f70d01010b0500305a310b3009060355040613024545311e301c060355\n040a0c15417065784d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f4455\n4354494f4e29301e170d3236303931323231313933375a170d3336303930393231313933375a305a310b3009060355040613024545311e301c060355040a0c15\n417065784d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f\n4e2930820122300d06092a864886f70d01010105000382010f003082010a0282010100b30a8b1ae3ecf5fb229dc9beb60b613cc02d86b4b9bc8f84d595984399\ndd8a1afa71521c6d91b63775378ba7bf2ed6d9d543faa71f777dc3c2632c5b4c8ea7d8a7cd26f7462694d721f5aefdbe4ef31878b78bccb9aa1acd89bd732522\n18420ef3b6fcd27ee010864862edacb2dcfe35901c71060284771986f2033c40309e716ca7ad9c7efb5c494b6dfd7a012bb0210b283cccca9e3059cb1a48d03a\n2bb604ebfce7bd1bd24e30efb99949b3966b09597e46e87483b1afb0b289a73c7bf7df4d489698ff37e223f83b046af65f51454ccdbe9f3442c4705cd5c397d9\nf2369fb513db37a20955e62384892c2bea6388d17583426fdc9284efb1c604d011df150203010001a3573055300c0603551d130101ff04023000300e0603551d\n0f0101ff04040302078030160603551d250101ff040c300a06082b06010505070308301d0603551d0e04160414717afd522d0495d89e78f45d59795d981a0d48\n2a300d06092a864886f70d01010b0500038201010028e4f826146b6240f3f1d13ec21284e1dbe4494cf405cebb211aca3e90c864bd314ba83591120d7dba2cf3\nb497022b04630a1e1e58d8fddea0e36b47bbc91ae357cc9d5fe44e50fba8e476a9850f8017070ef10628e7fa12d41bdb03411e275055c04834419c909f1a4ee6\n83c0e3ce96ecb5334f04398b6488bbead7c74771ec913e6d927e54261ebb67dc036762683a573b259643e6370f81e0e87070a556ba33e515738a8a5853840c83\n4a4d53a2d0d40816c99a4b1ca06b8ba847537481be1632fce7d5ff1ea419d8bd47e9ab779beaabb5de7068a2f869befb2f43c0f34f4ef92c385630cc655f0b5e\n8de49c4bd43a8585a5af92dd7e4b3730fb785f9b8531820234308202300201013062305a310b3009060355040613024545311e301c060355040a0c1541706578\n4d61696c20546573742046697874757265312b302906035504030c22417065784d61696c20546573742054534120284e4f542050524f44554354494f4e290204\n5a504558300d06096086480165030402010500a081a4301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d01090531\n0f170d3236303931323231313934345a302f06092a864886f70d01090431220420913999fbeb8574d89dc21976957fa88672ce1ab714601fb77fbb19ca535002\n063037060b2a864886f70d010910022f312830263024302204201d2e89363dc0ae22976e4abc010efc985b63eccac2d87c0b00ebfc46b55e0912300d06092a86\n4886f70d01010105000482010001bd2755b82cfbabbdb4d42b087a12fd3d2e74bc4cb71e8912f4eef14dd1d654bc30100171dbf89827e281e4f116113a4be7ed\nc7c29b191f988574e4a35f6adea0e8e45be8466ef73fe1001f6b0f782949d024d946fa1fabe82be84c37d30f67aad777c4b9e1f310872955b84d285c0cb742ee\nebc6f5a57196e3ba2c69d0f0ad0d51725515f74e9f8bbef774f72d160b4b56ff94630933952c4cc9e69eefeace75bcbe8efe3af97887d452c280107a5bb2b23a\nf5b0999afe42fe123a355ddf20a779fd1b700057540752675cef8e5d4460d991daaac961140cbce358bcdaad1a609748ee687e1e4346a8e0f5ab886eae761016\n24bde8637973f453bf37a86e07";

fn strip_whitespace(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn fixture_response() -> Vec<u8> {
    hex::decode(strip_whitespace(FIXTURE_RESPONSE_HEX)).expect("fixture hex")
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    })
}

/// A one-shot HTTP/1.1 server that answers one TSA request.
async fn spawn_tsa_server<F>(make_response: F) -> (String, tokio::task::JoinHandle<Vec<u8>>)
where
    F: FnOnce(&[u8]) -> Vec<u8> + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = socket.read(&mut chunk).await.expect("read");
            if read == 0 {
                return buffer;
            }
            buffer.extend_from_slice(&chunk[..read]);
            let Some(header_end) = find_header_end(&buffer) else {
                continue;
            };
            let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
            let Some(length) = content_length(&head) else {
                continue;
            };
            if buffer.len() < header_end + length {
                continue;
            }
            let body = buffer[header_end..header_end + length].to_vec();
            let response = make_response(&body);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            );
            socket.write_all(head.as_bytes()).await.expect("write head");
            socket.write_all(&response).await.expect("write body");
            socket.shutdown().await.ok();
            return body;
        }
    });
    (format!("http://127.0.0.1:{port}/tsa"), handle)
}
