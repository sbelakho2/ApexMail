//! Taxonomy-driven XBRL tests against a genuine (test-namespace) XBRL 2.1
//! taxonomy fixture.
//!
//! The fixture under `tests/fixtures/ee_annual_report/` is a real
//! entry-point schema with imports, an include, a presentation linkbase, a
//! label linkbase and a calculation linkbase — not a stub. Nothing here
//! claims to be the official Estonian e-aruande taksonoomia (the target
//! namespace is `apexmail.test`); the point is that the loader, the emitter
//! and the validator depend on a taxonomy rather than on invented names.

use std::path::PathBuf;

use compliance::annual_report::{
    build_annual_report_xbrl, derive_statements, AnnualReportXbrl, AnnualReportXbrlConfig,
    BalanceSheet, CompanyIdentity, IncomeStatement, LedgerBalanceLine, ReportSlot,
    TaxonomyBinding, XBRL_EXTENSION_NAMESPACE, XBRL_EXTENSION_SCHEMA_NAME,
};
use compliance::xbrl_taxonomy::{
    load_taxonomy, load_taxonomy_with, parse_instance, validate_instance, Context, ContextPeriod,
    DecimalAmount, Decimals, ExtensionSchema, Fact, FactValue, InstanceDocument, MemoryResolver,
    NumericKind, PeriodType, QName, TaxonomyError, TaxonomyLimits, TaxonomySource, Unit,
    FAIL_ABSTRACT_CONCEPT, FAIL_BINDING_INVALID, FAIL_BINDING_MISSING, FAIL_CALCULATION_MISMATCH,
    FAIL_CONCEPT_UNDECLARED, FAIL_MISSING_DECIMALS, FAIL_MISSING_ENTITY_IDENTIFIER,
    FAIL_MISSING_ENTITY_SCHEME, FAIL_MISSING_UNIT, FAIL_MISSING_UNIT_MEASURE,
    FAIL_NON_NUMERIC_VALUE, FAIL_PERIOD_TYPE_MISMATCH, FAIL_UNEXPECTED_UNIT, FAIL_UNKNOWN_CONTEXT,
};
use chrono::NaiveDate;

// ── Fixtures ───────────────────────────────────────────────────────────────

const TAXONOMY_NAMESPACE: &str = "http://apexmail.test/xbrl/ee-annual-report/2026-01-01";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ee_annual_report")
}

fn fixture_entry_point() -> PathBuf {
    fixture_dir().join("entry.xsd")
}

fn load_fixture() -> compliance::xbrl_taxonomy::XbrlTaxonomy {
    load_taxonomy(
        &TaxonomySource::File(fixture_entry_point()),
        &TaxonomyLimits::default(),
    )
    .expect("the fixture taxonomy must load")
}

fn binding() -> TaxonomyBinding {
    TaxonomyBinding::from_json_str(
        r#"{
            "assets": "ee:Assets",
            "liabilities": "ee:Liabilities",
            "equity": "ee:Equity",
            "revenue": "ee:Revenue",
            "expenses": "ee:Expenses",
            "net_profit": "ee:NetProfit",
            "period_profit": "ee:ProfitLossForPeriod",
            "company_name": "ee:CompanyName"
        }"#,
    )
    .expect("binding parses")
}

fn config() -> AnnualReportXbrlConfig {
    AnnualReportXbrlConfig {
        taxonomy: load_fixture(),
        binding: Some(binding()),
    }
}

fn d(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("test date")
}

fn company() -> CompanyIdentity {
    CompanyIdentity {
        legal_name: "Fixture OÜ & Partners <test>".into(),
        registry_code: "16588745".into(),
        vat_number: Some("EE102400000".into()),
        country_code: "EE".into(),
        currency: "EUR".into(),
    }
}

fn account_lines() -> Vec<LedgerBalanceLine> {
    vec![
        LedgerBalanceLine {
            account_id: uuid::Uuid::new_v4(),
            account_code: "1020".into(),
            account_name: "Bank".into(),
            account_type: "asset".into(),
            account_role: Some("bank".into()),
            debit_cents: 150_000,
            credit_cents: 0,
            balance_debit_positive: 150_000,
        },
        LedgerBalanceLine {
            account_id: uuid::Uuid::new_v4(),
            account_code: "3000".into(),
            account_name: "Retained earnings".into(),
            account_type: "equity".into(),
            account_role: Some("retained_earnings".into()),
            debit_cents: 0,
            credit_cents: 100_000,
            balance_debit_positive: -100_000,
        },
        LedgerBalanceLine {
            account_id: uuid::Uuid::new_v4(),
            account_code: "4000".into(),
            account_name: "Revenue".into(),
            account_type: "revenue".into(),
            account_role: Some("revenue".into()),
            debit_cents: 0,
            credit_cents: 200_000,
            balance_debit_positive: -200_000,
        },
        LedgerBalanceLine {
            account_id: uuid::Uuid::new_v4(),
            account_code: "5000".into(),
            account_name: "Expenses".into(),
            account_type: "expense".into(),
            account_role: Some("expense".into()),
            debit_cents: 150_000,
            credit_cents: 0,
            balance_debit_positive: 150_000,
        },
    ]
}

fn statements() -> (BalanceSheet, IncomeStatement) {
    derive_statements(&account_lines())
}

fn emit(config: Option<&AnnualReportXbrlConfig>) -> AnnualReportXbrl {
    let (balance_sheet, income_statement) = statements();
    build_annual_report_xbrl(
        &company(),
        2025,
        d(2025, 1, 1),
        d(2025, 12, 31),
        &balance_sheet,
        &income_statement,
        &account_lines(),
        config,
    )
}

/// Parse a taxonomy in memory (hostile-input tests never touch the disk).
fn memory_source(uri: &str) -> TaxonomySource {
    TaxonomySource::parse(uri).expect("memory source parses")
}

fn schema_document(target_namespace: &str, references: &[(&str, &str)]) -> String {
    let mut body = String::new();
    for (namespace, location) in references {
        body.push_str(&format!(
            "<xs:import namespace=\"{namespace}\" schemaLocation=\"{location}\"/>"
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" \
         targetNamespace=\"{target_namespace}\">{body}</xs:schema>"
    )
}

// ── 1. The taxonomy loads ──────────────────────────────────────────────────

#[test]
fn taxonomy_fixture_loads_elements_arcs_and_labels() {
    let taxonomy = load_fixture();
    assert_eq!(taxonomy.target_namespace, TAXONOMY_NAMESPACE);
    assert!(
        taxonomy.entry_point.ends_with("entry.xsd"),
        "entry point recorded: {}",
        taxonomy.entry_point
    );

    // Element declarations, including a custom type derived from xbrli.
    let assets = taxonomy.resolve_qname("ee:Assets").expect("prefix resolves");
    let concept = taxonomy.concept(&assets).expect("Assets is declared");
    assert_eq!(concept.period_type, Some(PeriodType::Instant));
    assert_eq!(concept.balance, Some(compliance::xbrl_taxonomy::Balance::Debit));
    assert!(!concept.is_abstract);
    assert!(concept.is_item());
    assert_eq!(
        taxonomy.numeric_kind(&assets),
        Some(NumericKind::Monetary),
        "custom type chain must reach xbrli:monetaryItemType"
    );

    let net_profit = taxonomy.resolve_qname("ee:NetProfit").expect("resolves");
    assert_eq!(
        taxonomy.concept(&net_profit).unwrap().period_type,
        Some(PeriodType::Duration)
    );
    let company_name = taxonomy.resolve_qname("ee:CompanyName").unwrap();
    assert_eq!(taxonomy.numeric_kind(&company_name), None);
    let abstract_heading = taxonomy.resolve_qname("ee:StatementAbstract").unwrap();
    assert!(taxonomy.concept(&abstract_heading).unwrap().is_abstract);
    assert_eq!(taxonomy.concepts.len(), 9, "8 items + 1 abstract heading");

    // Presentation arcs resolved through link:loc hrefs across documents.
    assert!(taxonomy
        .presentation_arcs
        .iter()
        .any(|arc| arc.parent == assets && arc.child == taxonomy.resolve_qname("ee:Liabilities").unwrap()));
    assert!(taxonomy
        .presentation_children(&net_profit)
        .iter()
        .any(|child| **child == taxonomy.resolve_qname("ee:Revenue").unwrap()));
    assert!(!taxonomy.presentation_arcs[0].role.is_empty());

    // Calculation arcs with exact weights.
    assert_eq!(taxonomy.calculation_arcs.len(), 2);
    let revenue_arc = taxonomy
        .calculation_arcs
        .iter()
        .find(|arc| arc.child == taxonomy.resolve_qname("ee:Revenue").unwrap())
        .expect("NetProfit -> Revenue arc");
    assert_eq!(revenue_arc.parent, net_profit);
    assert_eq!(revenue_arc.weight, DecimalAmount::parse("1").unwrap());
    let expenses_arc = taxonomy
        .calculation_arcs
        .iter()
        .find(|arc| arc.child == taxonomy.resolve_qname("ee:Expenses").unwrap())
        .expect("NetProfit -> Expenses arc");
    assert_eq!(expenses_arc.weight, DecimalAmount::parse("-1").unwrap());

    // Labels, including the terse role.
    assert_eq!(taxonomy.standard_label(&assets), Some("Total assets"));
    assert_eq!(
        taxonomy.label(&assets, "http://www.xbrl.org/2003/role/terseLabel"),
        Some("Assets")
    );
    assert_eq!(
        taxonomy.standard_label(&net_profit),
        Some("Net profit for the period")
    );

    // A digest of the loaded documents, and the whole multi-file package.
    assert_eq!(taxonomy.documents.len(), 5, "entry, concepts, 3 linkbases");
    assert_eq!(taxonomy.digest.len(), 64);
    assert_eq!(
        taxonomy.prefix_for_namespace(TAXONOMY_NAMESPACE),
        Some("ee")
    );
}

// ── 2. Emission through the model, re-parse, re-validate ───────────────────

#[test]
fn emitted_instance_reparses_and_every_fact_validates() {
    let config = config();
    let output = emit(Some(&config));
    assert!(
        output.readiness.submission_ready,
        "expected submission-ready, got: {:#?}",
        output.readiness
    );
    assert!(output.readiness.missing.is_empty());
    assert!(output.readiness.validation_failures.is_empty());
    let identity = output
        .readiness
        .taxonomy
        .as_ref()
        .expect("taxonomy identity recorded");
    assert_eq!(identity.target_namespace, TAXONOMY_NAMESPACE);
    assert!(identity.entry_point.ends_with("entry.xsd"));
    assert_eq!(identity.digest.len(), 64);
    assert_eq!(identity.document_count, 5);

    // Official statement facts use taxonomy concepts, extension account facts
    // stay in the extension namespace.
    assert!(output.instance_xml.contains("<ee:Assets"), "{}", output.instance_xml);
    assert!(output.instance_xml.contains("<ee:CompanyName"));
    assert!(!output.instance_xml.contains("<apex:Assets"));
    assert!(output
        .instance_xml
        .contains(&format!("href=\"{XBRL_EXTENSION_SCHEMA_NAME}\"")));
    assert!(output.instance_xml.contains("entry.xsd"), "taxonomy entry point referenced");

    // Every emitted fact resolves through the taxonomy or the extension
    // schema — nothing is invented.
    for fact in &output.document.facts {
        assert!(
            config.taxonomy.concept(&fact.concept).is_some()
                || output.extension.declare(&fact.concept).is_some(),
            "fact {} resolves",
            fact.concept.clark()
        );
    }

    // The emitted instance re-parses and re-validates as a document.
    let parsed = parse_instance(&output.instance_xml).expect("emitted instance parses");
    assert_eq!(parsed.facts.len(), output.document.facts.len());
    assert_eq!(parsed.contexts.len(), 2);
    assert_eq!(parsed.units.len(), 1);
    assert_eq!(parsed.schema_refs.len(), 2);
    let failures = validate_instance(&config.taxonomy, &output.extension, &parsed);
    assert!(failures.is_empty(), "re-validation failures: {failures:#?}");

    // The extension schema is a real schema document declaring every
    // extension fact, including the account-level ones.
    assert!(output
        .extension_schema_xml
        .contains("name=\"Account_a1020\""));
    assert!(output
        .extension_schema_xml
        .contains(&format!("targetNamespace=\"{XBRL_EXTENSION_NAMESPACE}\"")));
    let mut reader = quick_xml::Reader::from_str(&output.extension_schema_xml);
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            Err(error) => panic!("extension schema is not well-formed XML: {error}"),
        }
    }
    for fact in &parsed.facts {
        if fact.concept.namespace == XBRL_EXTENSION_NAMESPACE {
            assert!(
                output
                    .extension_schema_xml
                    .contains(&format!("name=\"{}\"", fact.concept.name)),
                "extension fact {} is declared in the extension schema",
                fact.concept.name
            );
        }
    }
}

#[test]
fn extension_only_instance_is_declared_and_validates() {
    let output = emit(None);
    assert!(!output.readiness.submission_ready);
    let parsed = parse_instance(&output.instance_xml).expect("extension-only instance parses");
    assert!(!parsed.facts.is_empty());
    for fact in &parsed.facts {
        assert_eq!(fact.concept.namespace, XBRL_EXTENSION_NAMESPACE);
        assert!(
            output.extension.declare(&fact.concept).is_some(),
            "extension fact {} declared",
            fact.concept.clark()
        );
    }
    // The container validates against the extension declarations alone.
    let failures = validate_instance(&load_fixture(), &output.extension, &parsed);
    assert!(failures.is_empty(), "{failures:#?}");
}

// ── 3. Period-type mismatches are refused ──────────────────────────────────

#[test]
fn instant_concept_with_duration_context_is_refused() {
    let config = config();
    let output = emit(Some(&config));
    let assets = config.taxonomy.resolve_qname("ee:Assets").unwrap();
    let duration_context = output
        .document
        .contexts
        .iter()
        .find(|context| matches!(context.period, Some(ContextPeriod::Duration { .. })))
        .expect("duration context")
        .id
        .clone();

    let mut document = output.document.clone();
    let fact = document
        .facts
        .iter_mut()
        .find(|fact| fact.concept == assets)
        .expect("Assets fact");
    fact.context_ref = duration_context.clone();

    let failures = validate_instance(&config.taxonomy, &output.extension, &document);
    let mismatch = failures
        .iter()
        .find(|failure| failure.code == FAIL_PERIOD_TYPE_MISMATCH)
        .unwrap_or_else(|| panic!("expected a period-type mismatch, got {failures:#?}"));
    assert!(
        mismatch.message.contains("ee:Assets"),
        "message names the concept: {}",
        mismatch.message
    );
    assert!(
        mismatch.message.contains(&duration_context),
        "message names the context: {}",
        mismatch.message
    );

    // And the reverse: a duration concept with an instant context.
    let revenue = config.taxonomy.resolve_qname("ee:Revenue").unwrap();
    let instant_context = document
        .contexts
        .iter()
        .find(|context| matches!(context.period, Some(ContextPeriod::Instant { .. })))
        .unwrap()
        .id
        .clone();
    let mut reversed = output.document.clone();
    let fact = reversed
        .facts
        .iter_mut()
        .find(|fact| fact.concept == revenue)
        .expect("Revenue fact");
    fact.context_ref = instant_context;
    let failures = validate_instance(&config.taxonomy, &output.extension, &reversed);
    assert!(
        failures
            .iter()
            .any(|failure| failure.code == FAIL_PERIOD_TYPE_MISMATCH),
        "{failures:#?}"
    );
}

// ── 4. The anti-invention tests ────────────────────────────────────────────

#[test]
fn undeclared_concept_is_refused_by_validator() {
    let config = config();
    let output = emit(Some(&config));
    let mut document = output.document.clone();
    document.facts.push(Fact {
        concept: QName::new(TAXONOMY_NAMESPACE, "InventedConcept"),
        context_ref: document.contexts[0].id.clone(),
        unit_ref: Some("EUR".to_string()),
        value: FactValue::Numeric(DecimalAmount::from_cents(100)),
        decimals: Some(Decimals::Finite(2)),
        id: None,
    });
    let failures = validate_instance(&config.taxonomy, &output.extension, &document);
    let undeclared = failures
        .iter()
        .find(|failure| failure.code == FAIL_CONCEPT_UNDECLARED)
        .unwrap_or_else(|| panic!("expected concept_undeclared, got {failures:#?}"));
    assert!(undeclared.message.contains("InventedConcept"));
}

#[test]
fn undeclared_binding_concept_is_refused_and_nothing_is_emitted() {
    let taxonomy = load_fixture();
    let bad_binding = TaxonomyBinding::from_json_str(
        r#"{
            "assets": "ee:Assets",
            "liabilities": "ee:Liabilities",
            "equity": "ee:Equity",
            "revenue": "ee:Revenue",
            "expenses": "ee:Expenses",
            "net_profit": "ee:NotDeclaredAnywhere"
        }"#,
    )
    .unwrap();
    let config = AnnualReportXbrlConfig {
        taxonomy,
        binding: Some(bad_binding),
    };
    let output = emit(Some(&config));
    assert!(!output.readiness.submission_ready);
    assert!(
        output
            .readiness
            .validation_failures
            .iter()
            .any(|failure| failure.code == FAIL_BINDING_INVALID
                && failure.message.contains("NotDeclaredAnywhere")),
        "{:#?}",
        output.readiness.validation_failures
    );
    // No invented official-namespace fact reaches the instance.
    assert!(!output.instance_xml.contains("<ee:"), "{}", output.instance_xml);
    assert!(!output.instance_xml.contains("<ee:NotDeclaredAnywhere"));
    let parsed = parse_instance(&output.instance_xml).unwrap();
    assert!(parsed
        .facts
        .iter()
        .all(|fact| fact.concept.namespace == XBRL_EXTENSION_NAMESPACE));
}

#[test]
fn abstract_and_missing_binding_slots_are_refused() {
    let taxonomy = load_fixture();
    let abstract_binding = TaxonomyBinding::from_json_str(
        r#"{
            "assets": "ee:StatementAbstract",
            "liabilities": "ee:Liabilities",
            "equity": "ee:Equity",
            "revenue": "ee:Revenue",
            "expenses": "ee:Expenses",
            "net_profit": "ee:NetProfit"
        }"#,
    )
    .unwrap();
    let output = emit(Some(&AnnualReportXbrlConfig {
        taxonomy: load_fixture(),
        binding: Some(abstract_binding),
    }));
    assert!(!output.readiness.submission_ready);
    assert!(output
        .readiness
        .validation_failures
        .iter()
        .any(|failure| failure.code == FAIL_BINDING_INVALID
            && failure.message.contains("abstract")));

    // A validator-level fact on an abstract concept is refused too.
    let mut document = output.document.clone();
    let mut fact = document.facts[0].clone();
    fact.concept = taxonomy.resolve_qname("ee:StatementAbstract").unwrap();
    document.facts = vec![fact];
    let failures = validate_instance(&taxonomy, &output.extension, &document);
    assert!(
        failures
            .iter()
            .any(|failure| failure.code == FAIL_ABSTRACT_CONCEPT),
        "{failures:#?}"
    );

    // A binding that omits a required slot is incomplete, not silently
    // defaulted.
    let incomplete = TaxonomyBinding::from_json_str(
        r#"{"assets": "ee:Assets"}"#,
    )
    .unwrap();
    let output = emit(Some(&AnnualReportXbrlConfig {
        taxonomy: load_fixture(),
        binding: Some(incomplete),
    }));
    assert!(!output.readiness.submission_ready);
    assert_eq!(
        output
            .readiness
            .validation_failures
            .iter()
            .filter(|failure| failure.code == FAIL_BINDING_MISSING)
            .count(),
        5,
        "one missing failure per unbound required slot: {:#?}",
        output.readiness.validation_failures
    );
    let _ = ReportSlot::REQUIRED;
}

// ── 5. Calculation mismatches are reported, not fixed ──────────────────────

#[test]
fn calculation_mismatch_is_reported_with_concepts_and_amounts() {
    let config = config();
    let output = emit(Some(&config));
    let net_profit = config.taxonomy.resolve_qname("ee:NetProfit").unwrap();

    let mut document = output.document.clone();
    let fact = document
        .facts
        .iter_mut()
        .find(|fact| fact.concept == net_profit)
        .expect("NetProfit fact");
    fact.value = FactValue::Numeric(DecimalAmount::parse("600.00").unwrap());

    let failures = validate_instance(&config.taxonomy, &output.extension, &document);
    let mismatch = failures
        .iter()
        .find(|failure| failure.code == FAIL_CALCULATION_MISMATCH)
        .unwrap_or_else(|| panic!("expected calculation_mismatch, got {failures:#?}"));
    assert!(mismatch.message.contains("ee:NetProfit"), "{}", mismatch.message);
    assert!(mismatch.message.contains("ee:Revenue"), "{}", mismatch.message);
    assert!(mismatch.message.contains("ee:Expenses"), "{}", mismatch.message);
    assert!(mismatch.message.contains("600.00"), "{}", mismatch.message);
    assert!(mismatch.message.contains("500.00"), "{}", mismatch.message);
    assert_eq!(
        mismatch.amounts,
        vec!["600.00".to_string(), "500.00".to_string()]
    );
    assert!(mismatch.concepts.contains(&"ee:NetProfit".to_string()));

    // The validator reports; it does not silently fix the value.
    assert_eq!(
        document
            .facts
            .iter()
            .find(|fact| fact.concept == net_profit)
            .unwrap()
            .value,
        FactValue::Numeric(DecimalAmount::parse("600.00").unwrap())
    );
}

// ── 6. Unit / decimals / structural rules ──────────────────────────────────

#[test]
fn monetary_unit_and_decimals_rules_are_enforced() {
    let config = config();
    let output = emit(Some(&config));
    let assets = config.taxonomy.resolve_qname("ee:Assets").unwrap();

    // Monetary fact without a unit.
    let mut document = output.document.clone();
    document
        .facts
        .iter_mut()
        .find(|fact| fact.concept == assets)
        .unwrap()
        .unit_ref = None;
    let failures = validate_instance(&config.taxonomy, &output.extension, &document);
    assert!(failures.iter().any(|failure| failure.code == FAIL_MISSING_UNIT));

    // Monetary fact without decimals.
    let mut document = output.document.clone();
    document
        .facts
        .iter_mut()
        .find(|fact| fact.concept == assets)
        .unwrap()
        .decimals = None;
    let failures = validate_instance(&config.taxonomy, &output.extension, &document);
    assert!(failures
        .iter()
        .any(|failure| failure.code == FAIL_MISSING_DECIMALS));

    // Numeric concept carrying a non-numeric value.
    let mut document = output.document.clone();
    document
        .facts
        .iter_mut()
        .find(|fact| fact.concept == assets)
        .unwrap()
        .value = FactValue::Text("not-a-number".to_string());
    let failures = validate_instance(&config.taxonomy, &output.extension, &document);
    assert!(failures
        .iter()
        .any(|failure| failure.code == FAIL_NON_NUMERIC_VALUE));

    // Non-monetary fact carrying a unit.
    let company_name = config.taxonomy.resolve_qname("ee:CompanyName").unwrap();
    let mut document = output.document.clone();
    document
        .facts
        .iter_mut()
        .find(|fact| fact.concept == company_name)
        .unwrap()
        .unit_ref = Some("EUR".to_string());
    let failures = validate_instance(&config.taxonomy, &output.extension, &document);
    assert!(failures
        .iter()
        .any(|failure| failure.code == FAIL_UNEXPECTED_UNIT));
}

#[test]
fn structural_context_requirements_are_enforced() {
    let config = config();
    let output = emit(Some(&config));
    let mut document = output.document.clone();
    for context in &mut document.contexts {
        context.entity_identifier = None;
        context.entity_scheme = None;
    }
    let failures = validate_instance(&config.taxonomy, &output.extension, &document);
    assert!(failures
        .iter()
        .any(|failure| failure.code == FAIL_MISSING_ENTITY_IDENTIFIER));
    assert!(failures
        .iter()
        .any(|failure| failure.code == FAIL_MISSING_ENTITY_SCHEME));

    // A fact referencing an unknown context.
    let mut document = output.document.clone();
    document.facts[0].context_ref = "does-not-exist".to_string();
    let failures = validate_instance(&config.taxonomy, &output.extension, &document);
    assert!(failures
        .iter()
        .any(|failure| failure.code == FAIL_UNKNOWN_CONTEXT));

    // A unit without a measure.
    let mut document = output.document.clone();
    document.units[0].measures.clear();
    let failures = validate_instance(&config.taxonomy, &output.extension, &document);
    assert!(failures
        .iter()
        .any(|failure| failure.code == FAIL_MISSING_UNIT_MEASURE));
}

// ── 7. No taxonomy configured ──────────────────────────────────────────────

#[test]
fn no_taxonomy_is_not_submission_ready_and_names_what_is_missing() {
    let output = emit(None);
    assert!(!output.readiness.submission_ready);
    assert_eq!(output.readiness.taxonomy, None);
    assert_eq!(output.readiness.missing.len(), 1);
    assert!(
        output.readiness.missing[0].contains("APEXMAIL_EE_ANNUAL_REPORT_TAXONOMY"),
        "missing entry names the configuration variable: {}",
        output.readiness.missing[0]
    );
    assert!(output.readiness.validation_failures.is_empty());
    assert!(output
        .instance_xml
        .contains("not submission-ready: the Estonian annual-report taxonomy entry point is not \
                   configured"));
}

#[test]
fn configured_taxonomy_without_binding_is_not_submission_ready() {
    let output = emit(Some(&AnnualReportXbrlConfig {
        taxonomy: load_fixture(),
        binding: None,
    }));
    assert!(!output.readiness.submission_ready);
    assert!(output
        .readiness
        .missing
        .iter()
        .any(|missing| missing.contains("APEXMAIL_EE_ANNUAL_REPORT_TAXONOMY_BINDING")));
    assert!(output.readiness.taxonomy.is_some());
}

// ── 8. Typed errors: missing imports, cycles, hostile bounds ───────────────

#[test]
fn missing_import_is_a_typed_error_not_a_panic() {
    let mut resolver = MemoryResolver::new();
    resolver.insert(
        "memory://tax/entry.xsd",
        schema_document("urn:test:entry", &[("urn:test:missing", "missing.xsd")]),
    );
    let error = load_taxonomy_with(
        &memory_source("memory://tax/entry.xsd"),
        &resolver,
        &TaxonomyLimits::default(),
    )
    .expect_err("a missing import must be refused");
    match error {
        TaxonomyError::MissingImport {
            reference, location, ..
        } => {
            assert!(reference.contains("missing.xsd"), "{reference}");
            assert!(location.contains("missing.xsd"), "{location}");
        }
        other => panic!("expected MissingImport, got {other:?}"),
    }

    // A missing entry point file is an Io error.
    let error = load_taxonomy(
        &TaxonomySource::File("/nonexistent/taxonomy/entry.xsd".into()),
        &TaxonomyLimits::default(),
    )
    .expect_err("missing entry point");
    assert!(matches!(error, TaxonomyError::Io { .. }), "{error:?}");
}

#[test]
fn import_cycles_are_typed_errors_not_panics() {
    let mut resolver = MemoryResolver::new();
    resolver.insert(
        "memory://cycle/entry.xsd",
        schema_document("urn:test:cycle", &[("urn:test:cycle", "a.xsd")]),
    );
    resolver.insert(
        "memory://cycle/a.xsd",
        schema_document("urn:test:cycle", &[("urn:test:cycle", "entry.xsd")]),
    );
    let error = load_taxonomy_with(
        &memory_source("memory://cycle/entry.xsd"),
        &resolver,
        &TaxonomyLimits::default(),
    )
    .expect_err("an import cycle must be refused");
    match error {
        TaxonomyError::ImportCycle { chain } => {
            assert!(chain.contains("entry.xsd"), "{chain}");
            assert!(chain.contains("a.xsd"), "{chain}");
        }
        other => panic!("expected ImportCycle, got {other:?}"),
    }

    // Self-import is a cycle too.
    let mut self_resolver = MemoryResolver::new();
    self_resolver.insert(
        "memory://self/entry.xsd",
        schema_document("urn:test:self", &[("urn:test:self", "entry.xsd")]),
    );
    let error = load_taxonomy_with(
        &memory_source("memory://self/entry.xsd"),
        &self_resolver,
        &TaxonomyLimits::default(),
    )
    .expect_err("self-import must be refused");
    assert!(matches!(error, TaxonomyError::ImportCycle { .. }), "{error:?}");
}

#[test]
fn hostile_taxonomy_bounds_refuse_quickly() {
    // Too many documents: a chain of 5 imports with a bound of 3.
    let mut resolver = MemoryResolver::new();
    for index in 0..5 {
        let reference = format!("doc{}.xsd", index + 1);
        resolver.insert(
            &format!("memory://many/doc{index}.xsd"),
            schema_document("urn:test:many", &[("urn:test:many", &reference)]),
        );
    }
    let error = load_taxonomy_with(
        &memory_source("memory://many/doc0.xsd"),
        &resolver,
        &TaxonomyLimits {
            max_documents: 3,
            ..TaxonomyLimits::default()
        },
    )
    .expect_err("the document bound must be enforced");
    assert!(matches!(error, TaxonomyError::TooManyDocuments { limit: 3 }), "{error:?}");

    // Depth bound: the same chain with max_depth = 1.
    let error = load_taxonomy_with(
        &memory_source("memory://many/doc0.xsd"),
        &resolver,
        &TaxonomyLimits {
            max_depth: 1,
            ..TaxonomyLimits::default()
        },
    )
    .expect_err("the depth bound must be enforced");
    assert!(
        matches!(error, TaxonomyError::MaxDepthExceeded { limit: 1, .. }),
        "{error:?}"
    );

    // Per-document byte bound.
    let mut small = MemoryResolver::new();
    small.insert(
        "memory://large/entry.xsd",
        schema_document("urn:test:large", &[]),
    );
    let error = load_taxonomy_with(
        &memory_source("memory://large/entry.xsd"),
        &small,
        &TaxonomyLimits {
            max_document_bytes: 16,
            ..TaxonomyLimits::default()
        },
    )
    .expect_err("the document size bound must be enforced");
    assert!(
        matches!(error, TaxonomyError::DocumentTooLarge { limit: 16, .. }),
        "{error:?}"
    );
}

// ── 9. Malformed instances / instances that are not XBRL ───────────────────

#[test]
fn instance_parsing_errors_are_typed() {
    let error = parse_instance("<not-xbrl/>").expect_err("non-XBRL root");
    assert!(matches!(error, compliance::xbrl_taxonomy::InstanceError::NotAnInstance { .. }));

    let error = parse_instance("<xbrli:xbrl").expect_err("unclosed");
    assert!(matches!(
        error,
        compliance::xbrl_taxonomy::InstanceError::MalformedXml { .. }
    ));
}

// ── 10. Legacy extension-only build stays well-formed and declared ─────────

#[test]
fn legacy_instance_builder_is_taxonomy_free_but_declared() {
    let (balance_sheet, income_statement) = statements();
    let xml = compliance::annual_report::build_xbrl_instance(
        &company(),
        2025,
        d(2025, 1, 1),
        d(2025, 12, 31),
        &balance_sheet,
        &income_statement,
        &account_lines(),
    );
    let parsed = parse_instance(&xml).expect("legacy instance parses");
    assert!(parsed
        .facts
        .iter()
        .all(|fact| fact.concept.namespace == XBRL_EXTENSION_NAMESPACE));
    let mut extension = ExtensionSchema {
        target_namespace: XBRL_EXTENSION_NAMESPACE.to_string(),
        concepts: Default::default(),
    };
    for fact in &parsed.facts {
        extension.insert(compliance::xbrl_taxonomy::DeclaredConcept {
            qname: fact.concept.clone(),
            period_type: Some(fact_period_type(&parsed, fact)),
            balance: None,
            is_abstract: false,
            is_item: true,
            numeric: Some(NumericKind::Monetary),
            source: "test".to_string(),
        });
    }
    let failures = validate_instance(&load_fixture(), &extension, &parsed);
    assert!(failures.is_empty(), "{failures:#?}");
    // Contexts and units are real XBRL structure.
    assert_eq!(parsed.contexts.len(), 2);
    assert!(parsed.units[0].measures[0].starts_with("iso4217:"));
    let _ = Unit {
        id: "unused".into(),
        measures: vec![],
    };
}

fn fact_period_type(document: &InstanceDocument, fact: &Fact) -> PeriodType {
    let context: &Context = document
        .contexts
        .iter()
        .find(|context| context.id == fact.context_ref)
        .expect("context");
    context.period.expect("period").period_type()
}
