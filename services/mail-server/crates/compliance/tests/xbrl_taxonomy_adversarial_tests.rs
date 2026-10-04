//! Adversarial tests for the taxonomy-driven XBRL machinery
//! ([`compliance::xbrl_taxonomy`]).
//!
//! Coverage targets the hostile edges: every typed loader error arm, QName
//! resolution abuse, exact-decimal overflow/cycle degradation, namespace
//! confusion, locator/label/arc malformed linkbases, and the instance
//! validator's full failure matrix (duplicate ids, unknown references,
//! calculation overflow, tuple/non-item concepts, extension declarations).
//!
//! Every test pins behavior that could plausibly regress: loaders that panic
//! on hostile input, bounds that can be crossed, or validators that silently
//! accept what the taxonomy never declared.

use std::collections::BTreeMap;

use compliance::xbrl_taxonomy::{
    declared_concept, numeric_kind_of, parse_instance, validate_instance, Balance, Concept,
    Context, ContextPeriod, DecimalAmount, Decimals, DeclaredConcept, ExtensionSchema, Fact,
    FactValue, InstanceDocument, InstanceError, MemoryResolver, NumericKind, PeriodType, QName,
    TaxonomyError, TaxonomyLimits, TaxonomyLocation, TaxonomyResolver, TaxonomySource,
    XbrlReadiness, XbrlTaxonomy, FAIL_ABSTRACT_CONCEPT, FAIL_CALCULATION_OVERFLOW,
    FAIL_CONCEPT_NOT_ITEM, FAIL_CONTEXT_PERIOD_INVALID, FAIL_DUPLICATE_CONTEXT,
    FAIL_DUPLICATE_FACT, FAIL_DUPLICATE_UNIT, FAIL_EMPTY_CONTEXT_ID, FAIL_MISSING_CONTEXT_PERIOD,
    FAIL_MISSING_DECIMALS, FAIL_MISSING_PERIOD_TYPE, FAIL_MISSING_UNIT_MEASURE,
    FAIL_UNEXPECTED_DECIMALS, FAIL_UNKNOWN_UNIT,
};
use compliance::xbrl_taxonomy::{
    FAIL_CONCEPT_UNDECLARED, FAIL_MISSING_ENTITY_IDENTIFIER, FAIL_MISSING_ENTITY_SCHEME,
    FAIL_MISSING_UNIT, FAIL_NON_NUMERIC_VALUE, FAIL_PERIOD_TYPE_MISMATCH, FAIL_UNEXPECTED_UNIT,
    FAIL_UNKNOWN_CONTEXT,
};

// ── Shared fixture helpers ─────────────────────────────────────────────────

const NS: &str = "urn:apexmail:test:hostile";
const XBRLI: &str = "http://www.xbrl.org/2003/instance";
const LINK: &str = "http://www.xbrl.org/2003/linkbase";
const XLINK: &str = "http://www.w3.org/1999/xlink";
const XSD: &str = "http://www.w3.org/2001/XMLSchema";

/// A schema document with an explicit body (the caller owns the hostility).
fn schema(target: Option<&str>, body: &str) -> String {
    let target_attr = match target {
        Some(ns) => format!(" targetNamespace=\"{ns}\""),
        None => String::new(),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <xs:schema xmlns:xs=\"{XSD}\" xmlns:xbrli=\"{XBRLI}\"{target_attr}>{body}</xs:schema>"
    )
}

/// A linkbase document with an explicit body.
fn linkbase(body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <link:linkbase xmlns:link=\"{LINK}\" xmlns:xlink=\"{XLINK}\" \
         xmlns:xs=\"{XSD}\">{body}</link:linkbase>"
    )
}

fn concept_element(name: &str, extra: &str) -> String {
    format!(
        "<xs:element name=\"{name}\" id=\"el-{name}\" \
         substitutionGroup=\"xbrli:item\" xbrli:periodType=\"instant\" xbrli:balance=\"debit\" \
         type=\"xbrli:monetaryItemType\" {extra}/>"
    )
}

/// Load a single in-memory schema and return the taxonomy.
fn load_one(body: &str) -> Result<XbrlTaxonomy, TaxonomyError> {
    load_memory(
        "memory://hostile/entry.xsd",
        schema(Some(NS), body),
        &TaxonomyLimits::default(),
    )
}

/// Load `entry` plus arbitrary companion documents.
fn load_memory(
    entry: &str,
    entry_doc: String,
    limits: &TaxonomyLimits,
) -> Result<XbrlTaxonomy, TaxonomyError> {
    let mut resolver = MemoryResolver::new();
    resolver.insert(entry, entry_doc);
    compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse(entry).expect("entry parses"),
        &resolver,
        limits,
    )
}

fn load_memory_many(entry: &str, docs: &[(&str, String)], limits: &TaxonomyLimits) -> XbrlTaxonomy {
    let mut resolver = MemoryResolver::new();
    for (location, doc) in docs {
        resolver.insert(location, doc.clone());
    }
    compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse(entry).expect("entry parses"),
        &resolver,
        limits,
    )
    .expect("package must load")
}

fn expect_error(result: Result<XbrlTaxonomy, TaxonomyError>) -> TaxonomyError {
    result.expect_err("hostile package must be refused")
}

// ── 1. DecimalAmount: hostile lexical forms and overflow degradation ───────

#[test]
fn decimal_amount_parse_rejects_hostile_lexical_forms() {
    let parse = |s: &str| DecimalAmount::parse(s);
    // Whitespace is trimmed; an explicit plus is accepted.
    assert_eq!(parse("  12.50  "), Some(DecimalAmount::from_cents(1250)));
    assert_eq!(parse("+3.25"), parse("3.25"));
    // Signs alone, bare dot, empty, exponent, thousands separator: refused.
    assert_eq!(parse("-"), None);
    assert_eq!(parse("+"), None);
    assert_eq!(parse("."), None);
    assert_eq!(parse(""), None);
    assert_eq!(parse("   "), None);
    assert_eq!(parse("1e5"), None);
    assert_eq!(parse("12,50"), None);
    assert_eq!(parse("1 2"), None);
    assert_eq!(parse("--1"), None);
    assert_eq!(parse("+-1"), None);
    // Fraction-only and integer-only forms are valid.
    assert_eq!(
        parse(".5"),
        Some(DecimalAmount {
            unscaled: 5,
            scale: 1
        })
    );
    assert_eq!(
        parse("1."),
        Some(DecimalAmount {
            unscaled: 1,
            scale: 0
        })
    );
    // A fraction wider than 18 digits is refused (excess precision).
    assert_eq!(parse("1.0000000000000000000"), None);
    assert_eq!(parse("1.000000000000000000").unwrap().scale, 18);
    // Values beyond the i128 magnitude are degraded to None, never wrapped.
    assert_eq!(parse("9".repeat(40).as_str()), None);
    assert_eq!(parse("9".repeat(39).as_str()), None);
    let max = "170141183460469231731687303715884105727";
    assert_eq!(parse(max).map(|d| d.unscaled), Some(i128::MAX));
    assert_eq!(
        parse(&format!("-{max}")).map(|d| d.unscaled),
        Some(-i128::MAX)
    );
    // i128::MIN is NOT representable: the magnitude would exceed i128::MAX.
    assert_eq!(parse("-170141183460469231731687303715884105728"), None);
    // Exact display: sign, padding, no exponent.
    assert_eq!(parse("-0.05").unwrap().to_display(), "-0.05");
    assert_eq!(parse("-5").unwrap().to_display(), "-5");
    assert_eq!(parse("0.05").unwrap().to_display(), "0.05");
    assert_eq!(DecimalAmount::zero().to_display(), "0");
    assert_eq!(parse("-123.45").unwrap().to_display(), "-123.45");
    assert!(DecimalAmount::zero().is_zero());
    assert!(parse("-0.00").unwrap().is_zero(), "zero magnitude");
    assert!(!parse("0.01").unwrap().is_zero());
}

#[test]
fn decimal_amount_checked_arithmetic_never_panics_or_wraps() {
    let max = DecimalAmount::parse("170141183460469231731687303715884105727").unwrap();
    let half = DecimalAmount::parse("0.5").unwrap();
    // Addition overflow (same scale) and rescale overflow (mixed scale).
    assert_eq!(max.checked_add(DecimalAmount::from_cents(1)), None);
    assert_eq!(max.checked_add(half), None, "rescaling MAX by 10 overflows");
    // Mixed scales add exactly when they fit.
    assert_eq!(
        half.checked_add(DecimalAmount::parse("2.25").unwrap()),
        DecimalAmount::parse("2.75")
    );
    assert_eq!(
        DecimalAmount::from_cents(100).checked_add(DecimalAmount::parse("1").unwrap()),
        DecimalAmount::parse("2.00") // scale widens to the max
    );
    // Multiplication: exact, scale bound, magnitude bound.
    assert_eq!(
        DecimalAmount::parse("1.5")
            .unwrap()
            .checked_mul(DecimalAmount::parse("2.25").unwrap()),
        DecimalAmount::parse("3.375")
    );
    let tenth_power = |n: u32| DecimalAmount {
        unscaled: 1,
        scale: n,
    };
    assert_eq!(
        tenth_power(10).checked_mul(tenth_power(10)),
        None,
        "scale 20 > 18"
    );
    assert_eq!(
        tenth_power(9).checked_mul(tenth_power(9)).unwrap().scale,
        18
    );
    assert_eq!(
        max.checked_mul(max),
        None,
        "magnitude overflow degrades to None"
    );
    assert_eq!(
        max.checked_mul(DecimalAmount::from_cents(-1)),
        Some(DecimalAmount {
            unscaled: -i128::MAX,
            scale: 2
        }),
        "MAX * -1 cent is exact: -1 unscaled at scale 2"
    );
}

// ── 2. Typed error codes are stable machine identifiers ───────────────────

#[test]
fn taxonomy_error_codes_are_stable_and_exhaustive() {
    let err = |e: TaxonomyError| (e.code().to_string(), e.to_string());
    let cases = vec![
        TaxonomyError::NotConfigured,
        TaxonomyError::InvalidSource {
            value: "v".into(),
            reason: "r".into(),
        },
        TaxonomyError::Io {
            location: "l".into(),
            detail: "d".into(),
        },
        TaxonomyError::UnsupportedLocation {
            location: "l".into(),
            detail: "d".into(),
        },
        TaxonomyError::UnresolvableReference {
            from: "f".into(),
            reference: "r".into(),
            detail: "d".into(),
        },
        TaxonomyError::DocumentTooLarge {
            location: "l".into(),
            limit: 1,
        },
        TaxonomyError::TotalBytesExceeded { limit: 1 },
        TaxonomyError::TooManyDocuments { limit: 1 },
        TaxonomyError::MaxDepthExceeded {
            location: "l".into(),
            limit: 1,
        },
        TaxonomyError::ImportCycle {
            chain: "a -> b".into(),
        },
        TaxonomyError::MissingImport {
            from: "f".into(),
            reference: "r".into(),
            location: "l".into(),
        },
        TaxonomyError::MalformedXml {
            location: "l".into(),
            detail: "d".into(),
        },
        TaxonomyError::UnsupportedDocument {
            location: "l".into(),
            detail: "d".into(),
        },
        TaxonomyError::MissingTargetNamespace {
            location: "l".into(),
        },
        TaxonomyError::Malformed {
            location: "l".into(),
            detail: "d".into(),
        },
        TaxonomyError::DuplicateElementId {
            id: "i".into(),
            location: "l".into(),
        },
        TaxonomyError::DuplicateConcept {
            concept: "c".into(),
            location: "l".into(),
        },
        TaxonomyError::UnresolvedLocator {
            location: "l".into(),
            href: "h".into(),
            detail: "d".into(),
        },
        TaxonomyError::InvalidWeight {
            value: "w".into(),
            location: "l".into(),
        },
        TaxonomyError::UnknownConcept {
            concept: "c".into(),
            target_namespace: "t".into(),
        },
        TaxonomyError::AbstractConcept {
            concept: "c".into(),
        },
        TaxonomyError::NotAnItemConcept {
            concept: "c".into(),
        },
        TaxonomyError::BadQName {
            value: "v".into(),
            detail: "d".into(),
        },
        TaxonomyError::UnknownPrefix {
            value: "v".into(),
            prefix: "p".into(),
        },
    ];
    let expected = [
        "not_configured",
        "invalid_source",
        "io",
        "unsupported_location",
        "unresolvable_reference",
        "document_too_large",
        "total_bytes_exceeded",
        "too_many_documents",
        "max_depth_exceeded",
        "import_cycle",
        "missing_import",
        "malformed_xml",
        "unsupported_document",
        "missing_target_namespace",
        "malformed",
        "duplicate_element_id",
        "duplicate_concept",
        "unresolved_locator",
        "invalid_weight",
        "concept_undeclared",
        "concept_abstract",
        "concept_not_item",
        "bad_qname",
        "unknown_prefix",
    ];
    assert_eq!(
        cases.len(),
        expected.len(),
        "every variant needs a pinned code"
    );
    for (case, code) in cases.into_iter().zip(expected) {
        let (actual, message) = err(case);
        assert_eq!(
            actual, code,
            "code drifted for {code}: message was {message}"
        );
        assert!(!message.is_empty());
    }
}

// ── 3. QName model and concept classification ─────────────────────────────

#[test]
fn qname_clark_notation_and_display_roundtrip() {
    let qname = QName::new("urn:a", "Assets");
    assert_eq!(qname.clark(), "{urn:a}Assets");
    assert_eq!(format!("{qname}"), "{urn:a}Assets");
    assert_eq!(QName::new("", "x").clark(), "{}x");
}

#[test]
fn concept_item_and_tuple_classification_follows_substitution_group() {
    let item = Concept {
        qname: QName::new(NS, "A"),
        type_qname: None,
        period_type: Some(PeriodType::Instant),
        balance: None,
        is_abstract: false,
        substitution_group: None,
        id: None,
        source: "t".into(),
    };
    assert!(item.is_item());
    assert!(!item.is_tuple());

    // A substitution group other than xbrli:item is not an item.
    let tuple = Concept {
        substitution_group: Some(QName::new(XBRLI, "tuple")),
        ..item.clone()
    };
    assert!(!tuple.is_item());
    assert!(tuple.is_tuple());

    // A bound-but-foreign group is neither.
    let foreign = Concept {
        substitution_group: Some(QName::new("urn:other", "item")),
        ..item.clone()
    };
    assert!(!foreign.is_item());
    assert!(!foreign.is_tuple());

    // Without a group, an item requires a period type.
    let no_period = Concept {
        period_type: None,
        ..item
    };
    assert!(!no_period.is_item());
}

// ── 4. Configured concept references resolve under strict rules ───────────

fn taxonomy_for_resolution() -> XbrlTaxonomy {
    let mut concepts = BTreeMap::new();
    concepts.insert(
        QName::new(NS, "Assets"),
        Concept {
            qname: QName::new(NS, "Assets"),
            type_qname: Some(QName::new(XBRLI, "monetaryItemType")),
            period_type: Some(PeriodType::Instant),
            balance: Some(Balance::Debit),
            is_abstract: false,
            substitution_group: None,
            id: Some("el-Assets".into()),
            source: "t".into(),
        },
    );
    XbrlTaxonomy {
        entry_point: "entry.xsd".into(),
        target_namespace: NS.into(),
        concepts,
        type_bases: BTreeMap::new(),
        presentation_arcs: Vec::new(),
        calculation_arcs: Vec::new(),
        labels: BTreeMap::new(),
        prefixes: BTreeMap::from([("ee".into(), NS.into())]),
        documents: Vec::new(),
        digest: "0".repeat(64),
    }
}

#[test]
fn resolve_qname_accepts_only_wellformed_references() {
    let taxonomy = taxonomy_for_resolution();
    // Clark notation.
    assert_eq!(
        taxonomy.resolve_qname(&format!("{{{NS}}}Assets")).unwrap(),
        QName::new(NS, "Assets")
    );
    // Prefixed.
    assert_eq!(
        taxonomy.resolve_qname("ee:Assets").unwrap(),
        QName::new(NS, "Assets")
    );
    // Bare local name lands in the taxonomy target namespace.
    assert_eq!(
        taxonomy.resolve_qname("Assets").unwrap(),
        QName::new(NS, "Assets")
    );
    assert_eq!(
        taxonomy.resolve_qname("  Assets  ").unwrap(),
        QName::new(NS, "Assets")
    );

    // Hostile references are typed errors, never guesses.
    for bad in ["", "   "] {
        assert!(matches!(
            taxonomy.resolve_qname(bad),
            Err(TaxonomyError::BadQName { .. })
        ));
    }
    assert!(matches!(
        taxonomy.resolve_qname("{ns}"),
        Err(TaxonomyError::BadQName { .. })
    ));
    assert!(matches!(
        taxonomy.resolve_qname("{}x"),
        Err(TaxonomyError::BadQName { .. })
    ));
    assert!(matches!(
        taxonomy.resolve_qname("{ns"),
        Err(TaxonomyError::BadQName { .. })
    ));
    assert!(matches!(
        taxonomy.resolve_qname(":name"),
        Err(TaxonomyError::BadQName { .. })
    ));
    assert!(matches!(
        taxonomy.resolve_qname("name:"),
        Err(TaxonomyError::BadQName { .. })
    ));
    match taxonomy.resolve_qname("nosuch:Assets") {
        Err(TaxonomyError::UnknownPrefix { prefix, .. }) => assert_eq!(prefix, "nosuch"),
        other => panic!("expected UnknownPrefix, got {other:?}"),
    }
}

// ── 5. Numeric-kind derivation is bounded against hostile type graphs ─────

fn concept_of_type(name: &str, type_qname: QName) -> (QName, Concept) {
    let qname = QName::new(NS, name);
    (
        qname.clone(),
        Concept {
            qname,
            type_qname: Some(type_qname),
            period_type: Some(PeriodType::Instant),
            balance: None,
            is_abstract: false,
            substitution_group: None,
            id: None,
            source: "t".into(),
        },
    )
}

#[test]
fn numeric_kind_survives_type_cycles_and_deep_chains() {
    let monetary = QName::new(XBRLI, "monetaryItemType");
    let string = QName::new(XBRLI, "stringItemType");
    let a = QName::new(NS, "typeA");
    let b = QName::new(NS, "typeB");

    // Cyclic custom types degrade to None instead of hanging.
    let cycle = XbrlTaxonomy {
        concepts: BTreeMap::from([concept_of_type("C", a.clone())]),
        type_bases: BTreeMap::from([(a.clone(), b.clone()), (b.clone(), a.clone())]),
        ..taxonomy_for_resolution()
    };
    assert_eq!(
        cycle.numeric_kind(&QName::new(NS, "C")),
        None,
        "cycle must abort"
    );

    // A chain that leaves the loaded package is None, never a guess.
    let dangling = XbrlTaxonomy {
        concepts: BTreeMap::from([concept_of_type("C", QName::new(NS, "nowhere"))]),
        ..taxonomy_for_resolution()
    };
    assert_eq!(dangling.numeric_kind(&QName::new(NS, "C")), None);

    // A concept with no declared type at all is not numeric.
    let mut untyped = taxonomy_for_resolution();
    let qname = QName::new(NS, "Plain");
    untyped.concepts.insert(
        qname.clone(),
        Concept {
            qname: qname.clone(),
            type_qname: None,
            period_type: Some(PeriodType::Instant),
            balance: None,
            is_abstract: false,
            substitution_group: None,
            id: None,
            source: "t".into(),
        },
    );
    assert_eq!(untyped.numeric_kind(&qname), None);

    // Non-numeric XBRL built-ins are explicitly not numeric.
    let non_numeric = XbrlTaxonomy {
        concepts: BTreeMap::from([concept_of_type("C", string.clone())]),
        ..taxonomy_for_resolution()
    };
    assert_eq!(non_numeric.numeric_kind(&QName::new(NS, "C")), None);

    // The walk allows exactly 32 iterations, so a derivation chain whose
    // monetary root is reached ON iteration 32 still resolves; one more hop
    // exceeds the bound and degrades to None.
    let chain = |length: usize| -> Vec<(QName, QName)> {
        (0..length)
            .map(|i| {
                let from = QName::new(NS, format!("t{i}"));
                let to = if i + 1 == length {
                    monetary.clone()
                } else {
                    QName::new(NS, format!("t{}", i + 1))
                };
                (from, to)
            })
            .collect()
    };
    let mut deep_taxonomy = taxonomy_for_resolution();
    // 31 arcs: monetary becomes `current` exactly on iteration 32.
    deep_taxonomy.type_bases = chain(31).into_iter().collect();
    deep_taxonomy.concepts = BTreeMap::from([concept_of_type("C", QName::new(NS, "t0"))]);
    assert_eq!(
        deep_taxonomy.numeric_kind(&QName::new(NS, "C")),
        Some(NumericKind::Monetary),
        "31-hop derivation chain must still resolve"
    );

    deep_taxonomy.type_bases = chain(32).into_iter().collect();
    assert_eq!(
        deep_taxonomy.numeric_kind(&QName::new(NS, "C")),
        None,
        "a chain needing more than the walk bound degrades to None"
    );

    // The validator's declare() view carries the numeric kind and item-ness.
    let monetary_concept = XbrlTaxonomy {
        concepts: BTreeMap::from([concept_of_type("C", monetary)]),
        ..taxonomy_for_resolution()
    };
    let declared = monetary_concept
        .declare(&QName::new(NS, "C"))
        .expect("declared");
    assert_eq!(declared.numeric, Some(NumericKind::Monetary));
    assert!(declared.is_item);
    assert_eq!(declared.period_type, Some(PeriodType::Instant));
    assert!(monetary_concept
        .declare(&QName::new(NS, "Missing"))
        .is_none());
    // Test-only helpers mirror the methods.
    assert_eq!(
        numeric_kind_of(&monetary_concept, &QName::new(NS, "C")),
        Some(NumericKind::Monetary)
    );
    assert_eq!(
        declared_concept(&monetary_concept, &QName::new(NS, "C")),
        Some(declared)
    );
}

// ── 6. Sources and resolvers ───────────────────────────────────────────────

#[test]
fn taxonomy_source_parsing_is_strict() {
    assert!(matches!(
        TaxonomySource::parse(""),
        Err(TaxonomyError::NotConfigured)
    ));
    assert!(matches!(
        TaxonomySource::parse("   "),
        Err(TaxonomyError::NotConfigured)
    ));
    let uri = TaxonomySource::parse(" https://example.test/tax.xsd ").expect("uri");
    assert!(matches!(uri, TaxonomySource::Uri(_)));
    assert!(matches!(uri.location(), TaxonomyLocation::Uri(_)));
    assert_eq!(uri.as_str(), "https://example.test/tax.xsd");

    let file = TaxonomySource::parse("/opt/tax/entry.xsd").expect("file");
    assert!(matches!(file, TaxonomySource::File(_)));
    assert!(matches!(file.location(), TaxonomyLocation::File(_)));
    assert_eq!(file.as_str(), "/opt/tax/entry.xsd");
}

#[test]
fn taxonomy_location_display_uses_the_plain_string() {
    let file = TaxonomyLocation::File("/a/b.xsd".into());
    assert_eq!(file.to_string(), "/a/b.xsd");
    assert_eq!(file.as_string(), "/a/b.xsd");
    let uri = TaxonomyLocation::Uri("memory://a/b.xsd".into());
    assert_eq!(uri.to_string(), "memory://a/b.xsd");
}

#[test]
fn filesystem_resolver_rules() {
    use compliance::xbrl_taxonomy::FileSystemResolver;
    let resolver = FileSystemResolver;
    let base = TaxonomyLocation::File("/opt/tax/entry.xsd".into());

    // Empty references are refused.
    assert!(matches!(
        resolver.resolve(&base, "   "),
        Err(TaxonomyError::UnresolvableReference { .. })
    ));

    // Remote references become Uri locations (the loader refuses them later).
    assert_eq!(
        resolver
            .resolve(&base, "https://evil.example/x.xsd")
            .unwrap(),
        TaxonomyLocation::Uri("https://evil.example/x.xsd".into())
    );

    // Absolute references replace the base entirely.
    assert_eq!(
        resolver.resolve(&base, "/etc/evil.xsd").unwrap(),
        TaxonomyLocation::File("/etc/evil.xsd".into())
    );

    // Relative references normalize lexically: .. climbs, . vanishes.
    assert_eq!(
        resolver.resolve(&base, "../shared/x.xsd").unwrap(),
        TaxonomyLocation::File("/opt/shared/x.xsd".into())
    );
    assert_eq!(
        resolver.resolve(&base, "./sub/../y.xsd").unwrap(),
        TaxonomyLocation::File("/opt/tax/y.xsd".into())
    );
    // Climbing past a relative root keeps the leading ..
    let relative_base = TaxonomyLocation::File("tax/entry.xsd".into());
    assert_eq!(
        resolver.resolve(&relative_base, "../../up.xsd").unwrap(),
        TaxonomyLocation::File("../up.xsd".into())
    );

    // Loading a missing file is a typed Io error naming the location.
    match resolver.load(&TaxonomyLocation::File("/nonexistent/entry.xsd".into())) {
        Err(TaxonomyError::Io { location, .. }) => {
            assert_eq!(location, "/nonexistent/entry.xsd")
        }
        other => panic!("expected Io, got {other:?}"),
    }
    // The filesystem resolver never fetches remotes.
    assert!(matches!(
        resolver.load(&TaxonomyLocation::Uri("https://x/y.xsd".into())),
        Err(TaxonomyError::UnsupportedLocation { .. })
    ));
    // A remote BASE cannot resolve relative references either.
    let uri_base = TaxonomyLocation::Uri("https://x/y.xsd".into());
    assert!(matches!(
        resolver.resolve(&uri_base, "z.xsd"),
        Err(TaxonomyError::UnsupportedLocation { .. })
    ));
}

#[test]
fn memory_resolver_rules() {
    let mut resolver = MemoryResolver::new();
    resolver.insert("memory://m/entry.xsd", schema(Some(NS), ""));
    assert!(resolver.contains("memory://m/entry.xsd"));
    assert!(!resolver.contains("memory://m/other.xsd"));

    let base = TaxonomyLocation::Uri("memory://m/entry.xsd".into());
    // Relative references join onto the base URI.
    assert_eq!(
        resolver.resolve(&base, "sub/a.xsd").unwrap(),
        TaxonomyLocation::Uri("memory://m/sub/a.xsd".into())
    );
    // Absolute remote references pass through.
    assert_eq!(
        resolver.resolve(&base, "http://other/x.xsd").unwrap(),
        TaxonomyLocation::Uri("http://other/x.xsd".into())
    );
    // Empty references and broken base URIs are typed errors.
    assert!(matches!(
        resolver.resolve(&base, ""),
        Err(TaxonomyError::UnresolvableReference { .. })
    ));
    let bad_base = TaxonomyLocation::Uri("not a uri at all".into());
    assert!(matches!(
        resolver.resolve(&bad_base, "a.xsd"),
        Err(TaxonomyError::UnresolvableReference { .. })
    ));
    // The in-memory resolver refuses file-backed locations in both ops.
    let file = TaxonomyLocation::File("/x.y".into());
    assert!(matches!(
        resolver.resolve(&file, "a.xsd"),
        Err(TaxonomyError::UnsupportedLocation { .. })
    ));
    match resolver.load(&TaxonomyLocation::Uri("memory://m/missing.xsd".into())) {
        Err(TaxonomyError::Io { detail, .. }) => {
            assert!(detail.contains("not present"), "{detail}")
        }
        other => panic!("expected Io, got {other:?}"),
    }
    // A file location is just another lookup key for LOAD (nothing was
    // registered under it); only RESOLVE refuses file bases outright.
    match resolver.load(&TaxonomyLocation::File("/missing.xsd".into())) {
        Err(TaxonomyError::Io { location, .. }) => assert_eq!(location, "/missing.xsd"),
        other => panic!("expected Io, got {other:?}"),
    }
}

/// A resolver that loads fine but refuses every cross-reference — proves the
/// loader maps `UnsupportedLocation` from RESOLVE to `UnresolvableReference`.
struct RefusingResolver;

impl TaxonomyResolver for RefusingResolver {
    fn load(&self, _location: &TaxonomyLocation) -> Result<Vec<u8>, TaxonomyError> {
        Ok(schema(
            Some(NS),
            "<xs:import namespace=\"urn:out\" schemaLocation=\"out.xsd\"/>",
        )
        .into_bytes())
    }

    fn resolve(
        &self,
        _base: &TaxonomyLocation,
        reference: &str,
    ) -> Result<TaxonomyLocation, TaxonomyError> {
        Err(TaxonomyError::UnsupportedLocation {
            location: reference.to_string(),
            detail: "resolver refuses to resolve".into(),
        })
    }
}

#[test]
fn custom_resolver_unsupported_location_becomes_unresolvable_reference() {
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://refusing/entry.xsd").unwrap(),
        &RefusingResolver,
        &TaxonomyLimits::default(),
    )
    .expect_err("the refusing resolver must fail the import");
    match error {
        TaxonomyError::UnresolvableReference {
            reference, detail, ..
        } => {
            assert_eq!(reference, "out.xsd");
            assert_eq!(detail, "resolver refuses to resolve");
        }
        other => panic!("expected UnresolvableReference, got {other:?}"),
    }
}

// ── 7. Loader bounds and reference resolution ──────────────────────────────

#[test]
fn total_bytes_bound_refuses_the_package_before_it_finishes() {
    let entry = schema(
        Some(NS),
        "<xs:import namespace=\"urn:two\" schemaLocation=\"two.xsd\"/>",
    );
    let two = schema(Some("urn:two"), "");
    let limits = TaxonomyLimits {
        // Each document fits; the PAIR does not.
        max_document_bytes: 8 * 1024 * 1024,
        max_total_bytes: entry.len() + two.len() - 1,
        ..TaxonomyLimits::default()
    };
    let mut resolver = MemoryResolver::new();
    resolver.insert("memory://bytes/entry.xsd", entry.clone());
    resolver.insert("memory://bytes/two.xsd", two.clone());
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://bytes/entry.xsd").unwrap(),
        &resolver,
        &limits,
    )
    .expect_err("the total-byte bound must trip");
    match error {
        TaxonomyError::TotalBytesExceeded { limit } => {
            assert_eq!(limit, entry.len() + two.len() - 1)
        }
        other => panic!("expected TotalBytesExceeded, got {other:?}"),
    }
}

#[test]
fn diamond_imports_load_the_shared_document_exactly_once() {
    let entry = schema(
        Some(NS),
        "<xs:import namespace=\"urn:a\" schemaLocation=\"a.xsd\"/>\
         <xs:import namespace=\"urn:b\" schemaLocation=\"b.xsd\"/>",
    );
    let a = schema(
        Some("urn:a"),
        "<xs:import namespace=\"urn:c\" schemaLocation=\"common.xsd\"/>",
    );
    let b = schema(
        Some("urn:b"),
        "<xs:import namespace=\"urn:c\" schemaLocation=\"common.xsd\"/>",
    );
    let common = schema(Some("urn:c"), "");
    let taxonomy = load_memory_many(
        "memory://diamond/entry.xsd",
        &[
            ("memory://diamond/entry.xsd", entry),
            ("memory://diamond/a.xsd", a),
            ("memory://diamond/b.xsd", b),
            ("memory://diamond/common.xsd", common),
        ],
        &TaxonomyLimits::default(),
    );
    assert_eq!(
        taxonomy.documents.len(),
        4,
        "the diamond's shared document must load once, not twice"
    );
}

#[test]
fn locationless_imports_skip_known_namespaces_and_refuse_unknown_ones() {
    // xbrli is known: the import carries nothing to fetch and is skipped.
    let known = schema(Some(NS), &format!("<xs:import namespace=\"{XBRLI}\"/>"));
    let taxonomy = load_memory(
        "memory://known/entry.xsd",
        known,
        &TaxonomyLimits::default(),
    )
    .expect("known-namespace import without a location is skippable");
    assert_eq!(taxonomy.documents.len(), 1);

    // An unknown namespace without a schemaLocation is a typed missing import.
    let unknown = schema(Some(NS), "<xs:import namespace=\"urn:ghost\"/>");
    let error = expect_error(load_memory(
        "memory://known/ghost.xsd",
        unknown,
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::MissingImport {
            reference,
            location,
            ..
        } => {
            assert!(reference.contains("urn:ghost"), "{reference}");
            assert_eq!(location, "unresolvable reference without a location");
        }
        other => panic!("expected MissingImport, got {other:?}"),
    }
}

#[test]
fn missing_include_and_missing_linkbase_describe_their_reference_kind() {
    // xs:include to a document that is not in the fixture set.
    let entry = schema(
        Some(NS),
        "<xs:include schemaLocation=\"ghost-include.xsd\"/>",
    );
    let error = expect_error(load_memory(
        "memory://desc/entry.xsd",
        entry,
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::MissingImport { reference, .. } => {
            assert!(
                reference.contains("xs:include schemaLocation")
                    && reference.contains("ghost-include.xsd"),
                "describe must name the include: {reference}"
            );
        }
        other => panic!("expected MissingImport, got {other:?}"),
    }

    // link:linkbaseRef to a missing document (the entry itself is a
    // linkbase — a valid root).
    let entry = linkbase("<link:linkbaseRef xlink:href=\"ghost-lb.xml\"/>");
    let error = expect_error(load_memory(
        "memory://desc/lb.xml",
        entry,
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::MissingImport { reference, .. } => {
            assert!(
                reference.contains("link:linkbaseRef href") && reference.contains("ghost-lb.xml"),
                "describe must name the linkbaseRef: {reference}"
            );
        }
        other => panic!("expected MissingImport, got {other:?}"),
    }
}

// ── 8. Hostile document content is refused with typed errors ───────────────

#[test]
fn unsupported_root_elements_are_refused() {
    let mut resolver = MemoryResolver::new();
    resolver.insert(
        "memory://roots/entry.xsd",
        "<html xmlns=\"http://www.w3.org/1999/xhtml\"/>",
    );
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://roots/entry.xsd").unwrap(),
        &resolver,
        &TaxonomyLimits::default(),
    )
    .expect_err("an HTML root is not a taxonomy");
    match error {
        TaxonomyError::UnsupportedDocument { detail, .. } => {
            assert!(detail.contains("html"), "{detail}")
        }
        other => panic!("expected UnsupportedDocument, got {other:?}"),
    }
}

#[test]
fn malformed_xml_and_unbound_prefixes_never_panic() {
    // Truncated XML.
    let error = expect_error(load_memory(
        "memory://bad/entry.xsd",
        "<xs:schema xmlns:xs=".to_string(),
        &TaxonomyLimits::default(),
    ));
    assert!(
        matches!(error, TaxonomyError::MalformedXml { .. }),
        "{error:?}"
    );

    // An element whose prefix is never bound.
    let error = expect_error(load_memory(
        "memory://bad/prefix.xsd",
        "<zzz:schema/>".to_string(),
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::MalformedXml { detail, .. } => {
            assert!(detail.contains("zzz"), "{detail}")
        }
        other => panic!("expected MalformedXml, got {other:?}"),
    }

    // An ATTRIBUTE with an unbound prefix.
    let error = expect_error(load_memory(
        "memory://bad/attr.xsd",
        schema(Some(NS), "<xs:element xlink:href=\"x\"/>"),
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::Malformed { detail, .. } => {
            assert!(detail.contains("unbound prefix"), "{detail}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn named_types_before_target_namespace_are_refused() {
    let error = expect_error(load_memory(
        "memory://tns/entry.xsd",
        "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\
           <xs:simpleType name=\"Money\"/>\
         </xs:schema>"
            .to_string(),
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::Malformed { detail, .. } => {
            assert!(detail.contains("targetNamespace"), "{detail}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn entry_without_target_namespace_is_refused_at_finish() {
    let error = expect_error(load_memory(
        "memory://tns/none.xsd",
        schema(None, "").to_string(),
        &TaxonomyLimits::default(),
    ));
    assert!(
        matches!(error, TaxonomyError::MissingTargetNamespace { .. }),
        "{error:?}"
    );
}

#[test]
fn restriction_base_with_unknown_prefix_is_refused() {
    let body = "<xs:simpleType name=\"Money\">\
                  <xs:restriction base=\"ghost:monetaryItemType\"/>\
                </xs:simpleType>";
    let error = expect_error(load_memory(
        "memory://base/entry.xsd",
        schema(Some(NS), body).to_string(),
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::UnknownPrefix { prefix, .. } => assert_eq!(prefix, "ghost"),
        other => panic!("expected UnknownPrefix, got {other:?}"),
    }
}

#[test]
fn include_without_schema_location_is_refused() {
    let error = expect_error(load_memory(
        "memory://inc/entry.xsd",
        schema(Some(NS), "<xs:include/>").to_string(),
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::Malformed { detail, .. } => {
            assert!(detail.contains("schemaLocation"), "{detail}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn linkbase_ref_without_xlink_href_is_refused() {
    // The entry itself is a linkbase (a valid root) whose linkbaseRef lacks
    // the required xlink:href.
    let error = expect_error(load_memory(
        "memory://lbr/entry.xml",
        linkbase("<link:linkbaseRef/>"),
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::Malformed { detail, .. } => {
            assert!(detail.contains("xlink:href"), "{detail}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn arcs_without_from_or_to_are_refused() {
    let no_from = linkbase(
        "<link:presentationLink xlink:type=\"extended\" xlink:role=\"http://r/1\">\
           <link:presentationArc xlink:type=\"arc\" xlink:to=\"b\" \
            xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/parent-child\"/>\
         </link:presentationLink>",
    );
    let error = expect_error(load_memory(
        "memory://arcs/a.xsd",
        no_from,
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::Malformed { detail, .. } => assert!(detail.contains("from"), "{detail}"),
        other => panic!("expected Malformed, got {other:?}"),
    }

    let no_to = linkbase(
        "<link:presentationLink xlink:type=\"extended\" xlink:role=\"http://r/1\">\
           <link:presentationArc xlink:type=\"arc\" xlink:from=\"a\" \
            xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/parent-child\"/>\
         </link:presentationLink>",
    );
    let error = expect_error(load_memory(
        "memory://arcs/b.xsd",
        no_to,
        &TaxonomyLimits::default(),
    ));
    match error {
        TaxonomyError::Malformed { detail, .. } => assert!(detail.contains("to"), "{detail}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

// ── 9. Hostile element declarations ────────────────────────────────────────

#[test]
fn element_declaration_hostility_is_refused_with_typed_errors() {
    // Unknown periodType.
    let error = expect_error(load_one(
        "<xs:element name=\"X\" substitutionGroup=\"xbrli:item\" \
         xbrli:periodType=\"forever\"/>",
    ));
    match error {
        TaxonomyError::Malformed { detail, .. } => {
            assert!(
                detail.contains("periodType") && detail.contains("forever"),
                "{detail}"
            )
        }
        other => panic!("expected Malformed, got {other:?}"),
    }

    // Unknown balance.
    let error = expect_error(load_one(
        "<xs:element name=\"X\" substitutionGroup=\"xbrli:item\" \
         xbrli:periodType=\"instant\" xbrli:balance=\"sideways\"/>",
    ));
    match error {
        TaxonomyError::Malformed { detail, .. } => {
            assert!(
                detail.contains("balance") && detail.contains("sideways"),
                "{detail}"
            )
        }
        other => panic!("expected Malformed, got {other:?}"),
    }

    // A non-abstract item without a period type can never be validated.
    let error = expect_error(load_one(
        "<xs:element name=\"X\" substitutionGroup=\"xbrli:item\" \
         type=\"xbrli:monetaryItemType\"/>",
    ));
    match error {
        TaxonomyError::Malformed { detail, .. } => {
            assert!(detail.contains("periodType"), "{detail}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }

    // An abstract heading MAY omit the period type (it carries no facts).
    let taxonomy = load_one(
        "<xs:element name=\"Heading\" abstract=\"true\" substitutionGroup=\"xbrli:item\" \
         type=\"xbrli:monetaryItemType\"/>",
    )
    .expect("abstract concept without periodType is loadable");
    let heading = taxonomy
        .concept(&QName::new(NS, "Heading"))
        .expect("declared");
    assert!(heading.is_abstract);
    assert_eq!(heading.period_type, None);
}

#[test]
fn element_type_attribute_qname_forms_are_handled_strictly() {
    // Unbound prefix in the type attribute.
    let error = expect_error(load_one(
        "<xs:element name=\"X\" type=\"ghost:stringItemType\"/>",
    ));
    match error {
        TaxonomyError::UnknownPrefix { prefix, .. } => assert_eq!(prefix, "ghost"),
        other => panic!("expected UnknownPrefix, got {other:?}"),
    }

    // Empty local name.
    let error = expect_error(load_one("<xs:element name=\"X\" type=\"ee:\"/>"));
    match error {
        TaxonomyError::BadQName { detail, .. } => assert!(detail.contains("empty"), "{detail}"),
        other => panic!("expected BadQName, got {other:?}"),
    }

    // Malformed Clark notation.
    let error = expect_error(load_one("<xs:element name=\"X\" type=\"{urnonly\"/>"));
    assert!(matches!(error, TaxonomyError::BadQName { .. }), "{error:?}");

    // Empty attribute value.
    let error = expect_error(load_one("<xs:element name=\"X\" type=\"\"/>"));
    match error {
        TaxonomyError::Malformed { detail, .. } => {
            assert!(detail.contains("empty QName"), "{detail}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }

    // Clark notation and default-namespace forms resolve when bound.
    let taxonomy = load_one(&format!(
        "<xs:element name=\"A\" type=\"{{{XSD}}}string\"/>\
         <xs:element name=\"B\" type=\"string\"/>"
    ))
    .expect("type QNames resolve");
    assert_eq!(
        taxonomy
            .concept(&QName::new(NS, "A"))
            .unwrap()
            .type_qname
            .as_ref()
            .unwrap()
            .namespace,
        XSD
    );
    // No default namespace is bound, so the bare name resolves to "".
    assert_eq!(
        taxonomy
            .concept(&QName::new(NS, "B"))
            .unwrap()
            .type_qname
            .as_ref()
            .unwrap()
            .namespace,
        ""
    );
}

#[test]
fn global_elements_without_names_are_skipped() {
    let taxonomy = load_one("<xs:element abstract=\"true\"/>").expect("loads");
    assert!(
        taxonomy.concepts.is_empty(),
        "a nameless global element is not a concept"
    );
}

#[test]
fn duplicate_element_ids_and_duplicate_concepts_are_refused() {
    // Same element id in two documents.
    let entry = schema(
        Some(NS),
        "<xs:import namespace=\"urn:d1\" schemaLocation=\"d1.xsd\"/>\
             <xs:import namespace=\"urn:d2\" schemaLocation=\"d2.xsd\"/>",
    );
    let item_decl = |ns: &str, name: &str| {
        format!(
            "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" \
             xmlns:xbrli=\"http://www.xbrl.org/2003/instance\" targetNamespace=\"{ns}\">\
             <xs:element name=\"{name}\" id=\"dup\" substitutionGroup=\"xbrli:item\" \
              xbrli:periodType=\"instant\" type=\"xbrli:monetaryItemType\"/>\
             </xs:schema>"
        )
    };
    let d1 = item_decl("urn:d1", "X");
    let d2 = item_decl("urn:d2", "Y");
    let mut resolver = MemoryResolver::new();
    resolver.insert("memory://dup/entry.xsd", entry);
    resolver.insert("memory://dup/d1.xsd", d1);
    resolver.insert("memory://dup/d2.xsd", d2);
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://dup/entry.xsd").unwrap(),
        &resolver,
        &TaxonomyLimits::default(),
    )
    .expect_err("duplicate ids must be refused");
    match error {
        TaxonomyError::DuplicateElementId { id, .. } => assert_eq!(id, "dup"),
        other => panic!("expected DuplicateElementId, got {other:?}"),
    }

    // The same concept QName in two documents.
    let entry = schema(
        Some(NS),
        "<xs:include schemaLocation=\"c1.xsd\"/>\
         <xs:include schemaLocation=\"c2.xsd\"/>",
    );
    let concept_doc = |id: &str| {
        schema(
            Some(NS),
            &format!(
                "<xs:element name=\"Same\" id=\"{id}\" substitutionGroup=\"xbrli:item\" \
                 xbrli:periodType=\"instant\" type=\"xbrli:monetaryItemType\"/>"
            ),
        )
    };
    let mut resolver = MemoryResolver::new();
    resolver.insert("memory://dupc/entry.xsd", entry);
    resolver.insert("memory://dupc/c1.xsd", concept_doc("c1"));
    resolver.insert("memory://dupc/c2.xsd", concept_doc("c2"));
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://dupc/entry.xsd").unwrap(),
        &resolver,
        &TaxonomyLimits::default(),
    )
    .expect_err("duplicate concepts must be refused");
    match error {
        TaxonomyError::DuplicateConcept { concept, .. } => {
            assert!(concept.contains("Same"), "{concept}")
        }
        other => panic!("expected DuplicateConcept, got {other:?}"),
    }
}

// ── 10. Linkbase resolution: locators, weights, labels ─────────────────────

fn concepts_schema() -> String {
    concepts_schema_with("pres.xml")
}

/// The concepts schema plus a linkbaseRef to `href` — the loader only loads
/// documents the entry point actually references.
fn concepts_schema_with(href: &str) -> String {
    let mut body = format!("<link:linkbaseRef xlink:href=\"{href}\"/>");
    body.push_str(&concept_element("Assets", ""));
    body.push_str(&concept_element("Liabilities", ""));
    body.push_str(&concept_element("Cash", ""));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <xs:schema xmlns:xs=\"{XSD}\" xmlns:xbrli=\"{XBRLI}\" \
         xmlns:link=\"{LINK}\" xmlns:xlink=\"{XLINK}\" targetNamespace=\"{NS}\">{body}</xs:schema>"
    )
}

#[test]
fn locator_hrefs_must_carry_a_known_fragment() {
    let loc = |href: &str| {
        linkbase(&format!(
            "<link:presentationLink xlink:type=\"extended\" xlink:role=\"http://r/1\">\
               <link:loc xlink:type=\"locator\" xlink:href=\"{href}\" xlink:label=\"a\"/>\
               <link:loc xlink:type=\"locator\" xlink:href=\"#el-Assets\" xlink:label=\"b\"/>\
               <link:presentationArc xlink:type=\"arc\" xlink:from=\"a\" xlink:to=\"b\" \
                xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/parent-child\"/>\
             </link:presentationLink>"
        ))
    };

    let docs = |href: &str| {
        vec![
            ("memory://loc/entry.xsd", concepts_schema()),
            ("memory://loc/pres.xml", loc(href)),
        ]
    };
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://loc/entry.xsd").unwrap(),
        &{
            let mut r = MemoryResolver::new();
            for (k, v) in docs("plain-no-fragment.xml") {
                r.insert(k, v);
            }
            r
        },
        &TaxonomyLimits::default(),
    )
    .expect_err("a fragment-less locator href must be refused");
    match error {
        TaxonomyError::UnresolvedLocator { detail, href, .. } => {
            assert!(detail.contains("no fragment"), "{detail}");
            assert!(href.contains("plain-no-fragment.xml"), "{href}");
        }
        other => panic!("expected UnresolvedLocator, got {other:?}"),
    }

    // A fragment naming an unknown element id.
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://loc/entry.xsd").unwrap(),
        &{
            let mut r = MemoryResolver::new();
            for (k, v) in docs("#no-such-id") {
                r.insert(k, v);
            }
            r
        },
        &TaxonomyLimits::default(),
    )
    .expect_err("an unknown fragment id must be refused");
    match error {
        TaxonomyError::UnresolvedLocator { detail, .. } => {
            assert!(detail.contains("no-such-id"), "{detail}")
        }
        other => panic!("expected UnresolvedLocator, got {other:?}"),
    }

    // An arc endpoint whose xlink:label has no matching link:loc.
    let orphan = linkbase(
        "<link:presentationLink xlink:type=\"extended\" xlink:role=\"http://r/1\">\
           <link:loc xlink:type=\"locator\" xlink:href=\"#el-Assets\" xlink:label=\"b\"/>\
           <link:presentationArc xlink:type=\"arc\" xlink:from=\"ghost-label\" xlink:to=\"b\" \
            xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/parent-child\"/>\
         </link:presentationLink>",
    );
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://loc/entry.xsd").unwrap(),
        &{
            let mut r = MemoryResolver::new();
            r.insert("memory://loc/entry.xsd", concepts_schema_with("pres.xml"));
            r.insert("memory://loc/pres.xml", orphan);
            r
        },
        &TaxonomyLimits::default(),
    )
    .expect_err("an arc endpoint without a locator must be refused");
    match error {
        TaxonomyError::UnresolvedLocator { detail, .. } => {
            assert!(detail.contains("ghost-label"), "{detail}")
        }
        other => panic!("expected UnresolvedLocator, got {other:?}"),
    }
}

#[test]
fn calculation_arcs_require_a_parseable_weight() {
    // Missing weight: the attribute is entirely absent.
    let no_weight_attr = |extra: &str| {
        linkbase(&format!(
            "<link:calculationLink xlink:type=\"extended\" xlink:role=\"http://r/calc\">\
               <link:loc xlink:type=\"locator\" xlink:href=\"#el-Assets\" xlink:label=\"p\"/>\
               <link:loc xlink:type=\"locator\" xlink:href=\"#el-Cash\" xlink:label=\"c\"/>\
               <link:calculationArc xlink:type=\"arc\" xlink:from=\"p\" xlink:to=\"c\" \
                xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/summation-item\" {extra}/>\
             </link:calculationLink>"
        ))
    };
    let mut resolver = MemoryResolver::new();
    resolver.insert("memory://calc/entry.xsd", concepts_schema_with("calc.xml"));
    resolver.insert("memory://calc/calc.xml", no_weight_attr(""));
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://calc/entry.xsd").unwrap(),
        &resolver,
        &TaxonomyLimits::default(),
    )
    .expect_err("summation arcs need a weight");
    match error {
        TaxonomyError::Malformed { detail, .. } => {
            assert!(detail.contains("weight"), "{detail}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }

    // Unparseable weight.
    let mut resolver = MemoryResolver::new();
    resolver.insert("memory://calc/entry.xsd", concepts_schema_with("calc.xml"));
    resolver.insert("memory://calc/calc.xml", no_weight_attr("weight=\"one\""));
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://calc/entry.xsd").unwrap(),
        &resolver,
        &TaxonomyLimits::default(),
    )
    .expect_err("weights must parse as decimals");
    match error {
        TaxonomyError::InvalidWeight { value, .. } => assert_eq!(value, "one"),
        other => panic!("expected InvalidWeight, got {other:?}"),
    }
}

#[test]
fn labels_resolve_through_label_arcs_with_roles_and_cdata() {
    let labels = linkbase(
        "<link:labelLink xlink:type=\"extended\" xlink:role=\"http://r/labels\">\
           <link:loc xlink:type=\"locator\" xlink:href=\"#el-Assets\" xlink:label=\"a\"/>\
           <link:label xlink:type=\"resource\" xlink:label=\"std\" \
            xlink:role=\"http://www.xbrl.org/2003/role/label\">Total &amp; assets</link:label>\
           <link:label xlink:type=\"resource\" xlink:label=\"terse\" \
            xlink:role=\"http://www.xbrl.org/2003/role/terseLabel\"><![CDATA[Assets <raw>]]></link:label>\
           <link:labelArc xlink:type=\"arc\" xlink:from=\"a\" xlink:to=\"std\" \
            xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/concept-label\"/>\
           <link:labelArc xlink:type=\"arc\" xlink:from=\"a\" xlink:to=\"terse\" \
            xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/concept-label\"/>\
         </link:labelLink>\
         <link:labelLink xlink:type=\"extended\" xlink:role=\"http://r/labels2\">\
           <link:loc xlink:type=\"locator\" xlink:href=\"#el-Cash\" xlink:label=\"c\"/>\
           <link:labelArc xlink:type=\"arc\" xlink:from=\"c\" xlink:to=\"nowhere\" \
            xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/concept-label\"/>\
         </link:labelLink>",
    );
    let taxonomy = load_memory_many(
        "memory://labels/entry.xsd",
        &[
            (
                "memory://labels/entry.xsd",
                concepts_schema_with("labels.xml"),
            ),
            ("memory://labels/labels.xml", labels),
        ],
        &TaxonomyLimits::default(),
    );
    let assets = QName::new(NS, "Assets");
    assert_eq!(taxonomy.standard_label(&assets), Some("Total & assets"));
    assert_eq!(
        taxonomy.label(&assets, "http://www.xbrl.org/2003/role/terseLabel"),
        Some("Assets <raw>"),
        "CDATA text is decoded verbatim"
    );
    // A labelArc to a missing resource is silently ignored — no crash, no
    // fabricated label.
    assert_eq!(
        taxonomy.label(&QName::new(NS, "Cash"), "http://r/labels2"),
        None
    );
    // Unrelated roles return nothing.
    assert_eq!(taxonomy.label(&assets, "http://no-such/role"), None);
}

#[test]
fn presentation_arcs_sort_by_role_parent_child_then_order() {
    let concepts = concepts_schema();
    let pres = linkbase(
        "<link:presentationLink xlink:type=\"extended\" xlink:role=\"http://r/p\">\
           <link:loc xlink:type=\"locator\" xlink:href=\"#el-Assets\" xlink:label=\"p\"/>\
           <link:loc xlink:type=\"locator\" xlink:href=\"#el-Cash\" xlink:label=\"c1\"/>\
           <link:loc xlink:type=\"locator\" xlink:href=\"#el-Liabilities\" xlink:label=\"c2\"/>\
           <link:presentationArc xlink:type=\"arc\" xlink:from=\"p\" xlink:to=\"c1\" \
            xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/parent-child\" order=\"2\"/>\
           <link:presentationArc xlink:type=\"arc\" xlink:from=\"p\" xlink:to=\"c1\" \
            xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/parent-child\" order=\"1\"/>\
           <link:presentationArc xlink:type=\"arc\" xlink:from=\"p\" xlink:to=\"c2\" \
            xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/parent-child\" order=\"nonsense\"/>\
         </link:presentationLink>\
         <link:definitionLink xlink:type=\"extended\" xlink:role=\"http://r/d\">\
           <link:loc xlink:type=\"locator\" xlink:href=\"#el-Assets\" xlink:label=\"dp\"/>\
           <link:loc xlink:type=\"locator\" xlink:href=\"#el-Cash\" xlink:label=\"dc\"/>\
           <link:definitionArc xlink:type=\"arc\" xlink:from=\"dp\" xlink:to=\"dc\" \
            xlink:arcrole=\"http://x/dimensionally-required\"/>\
         </link:definitionLink>",
    );
    let taxonomy = load_memory_many(
        "memory://order/entry.xsd",
        &[
            ("memory://order/entry.xsd", concepts),
            ("memory://order/pres.xml", pres),
        ],
        &TaxonomyLimits::default(),
    );
    let parent = QName::new(NS, "Assets");
    let children = taxonomy.presentation_children(&parent);
    assert_eq!(
        children.len(),
        3,
        "all presentation arcs are present (c1 twice): {children:?}"
    );
    // Identical (role, parent, child) pairs sort by numeric order, and an
    // unparseable order degrades to +infinity (sorts last).
    let orders: Vec<Option<f64>> = taxonomy
        .presentation_arcs
        .iter()
        .map(|arc| arc.order)
        .collect();
    assert_eq!(orders, vec![Some(1.0), Some(2.0), None]);
    assert!(!taxonomy.presentation_arcs.is_empty());
    // The definitionArc (non presentation/summation arcrole) is ignored.
    assert!(taxonomy.calculation_arcs.is_empty());
}

#[test]
fn locators_and_labels_are_scoped_to_their_own_extended_link() {
    // label "a" exists only in link 1; an arc in link 2 must NOT resolve
    // against link 1's locators (link-scoped keys).
    let doc = linkbase(
        "<link:presentationLink xlink:type=\"extended\" xlink:role=\"http://r/1\">\
           <link:loc xlink:type=\"locator\" xlink:href=\"#el-Assets\" xlink:label=\"a\"/>\
         </link:presentationLink>\
         <link:presentationLink xlink:type=\"extended\" xlink:role=\"http://r/2\">\
           <link:loc xlink:type=\"locator\" xlink:href=\"#el-Cash\" xlink:label=\"b\"/>\
           <link:presentationArc xlink:type=\"arc\" xlink:from=\"a\" xlink:to=\"b\" \
            xlink:arcrole=\"http://www.xbrl.org/2003/arcrole/parent-child\"/>\
         </link:presentationLink>",
    );
    let error = compliance::xbrl_taxonomy::load_taxonomy_with(
        &TaxonomySource::parse("memory://scope/entry.xsd").unwrap(),
        &{
            let mut r = MemoryResolver::new();
            r.insert("memory://scope/entry.xsd", concepts_schema_with("pres.xml"));
            r.insert("memory://scope/pres.xml", doc);
            r
        },
        &TaxonomyLimits::default(),
    )
    .expect_err("a locator from another extended link must not resolve");
    match error {
        TaxonomyError::UnresolvedLocator { detail, .. } => {
            assert!(detail.contains("\"a\""), "{detail}")
        }
        other => panic!("expected UnresolvedLocator, got {other:?}"),
    }
}

// ── 11. Instance parsing: hostile shapes never panic ───────────────────────

fn instance(body: &str) -> String {
    format!(
        "<xbrli:xbrl xmlns:xbrli=\"{XBRLI}\" xmlns:link=\"{LINK}\" \
         xmlns:xlink=\"{XLINK}\" xmlns:ee=\"{NS}\">{body}</xbrli:xbrl>"
    )
}

fn good_context(id: &str) -> String {
    format!(
        "<xbrli:context id=\"{id}\">\
           <xbrli:entity><xbrli:identifier scheme=\"http://reg.test\">16588745</xbrli:identifier></xbrli:entity>\
           <xbrli:period><xbrli:instant>2025-12-31</xbrli:instant></xbrli:period>\
         </xbrli:context>"
    )
}

#[test]
fn parse_instance_reads_the_full_document_shape() {
    let xml = instance(&format!(
        "<link:schemaRef xlink:href=\"entry.xsd\"/>\
         {}\
         <xbrli:context id=\"c-dur\">\
           <xbrli:entity><xbrli:identifier scheme=\"http://reg.test\">16588745</xbrli:identifier></xbrli:entity>\
           <xbrli:period><xbrli:startDate>2025-01-01</xbrli:startDate><xbrli:endDate>2025-12-31</xbrli:endDate></xbrli:period>\
         </xbrli:context>\
         <xbrli:unit id=\"EUR\"><xbrli:measure>iso4217:EUR</xbrli:measure></xbrli:unit>\
         <ee:Assets contextRef=\"c-ins\" unitRef=\"EUR\" decimals=\"2\" id=\"f1\">123.45</ee:Assets>\
         <ee:Revenue contextRef=\"c-dur\" unitRef=\"EUR\" decimals=\"INF\">200</ee:Revenue>\
         <ee:Note contextRef=\"c-ins\">hello</ee:Note>",
        good_context("c-ins")
    ));
    let document = parse_instance(&xml).expect("well-formed instance parses");
    assert_eq!(document.contexts.len(), 2);
    assert_eq!(document.units.len(), 1);
    assert_eq!(document.facts.len(), 3);
    assert_eq!(document.schema_refs, vec!["entry.xsd".to_string()]);
    assert_eq!(document.namespaces.get("ee").map(String::as_str), Some(NS));

    let instant = &document.contexts[0];
    assert_eq!(instant.id, "c-ins");
    assert_eq!(instant.entity_identifier.as_deref(), Some("16588745"));
    assert_eq!(instant.entity_scheme.as_deref(), Some("http://reg.test"));
    assert_eq!(
        instant.period,
        Some(ContextPeriod::Instant {
            date: chrono::NaiveDate::from_ymd_opt(2025, 12, 31).unwrap()
        })
    );
    assert_eq!(
        document.contexts[1].period,
        Some(ContextPeriod::Duration {
            start: chrono::NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
            end: chrono::NaiveDate::from_ymd_opt(2025, 12, 31).unwrap(),
        })
    );
    // Period descriptions feed validation messages.
    assert_eq!(instant.period.unwrap().describe(), "instant 2025-12-31");
    assert_eq!(
        document.contexts[1].period.unwrap().describe(),
        "duration 2025-01-01..2025-12-31"
    );
    assert_eq!(instant.period.unwrap().period_type(), PeriodType::Instant);

    // Numeric and text fact values, decimals including INF.
    assert_eq!(
        document.facts[0].value,
        FactValue::Numeric(DecimalAmount::from_cents(12345))
    );
    assert_eq!(document.facts[0].decimals, Some(Decimals::Finite(2)));
    assert_eq!(document.facts[1].decimals, Some(Decimals::Infinite));
    assert_eq!(document.facts[2].value, FactValue::Text("hello".into()));
    assert_eq!(document.facts[0].id.as_deref(), Some("f1"));
}

#[test]
fn parse_instance_survives_hostile_but_wellformed_shapes() {
    // Identifier directly under context (no entity wrapper), whitespace in
    // measures, instant+duration together (instant wins), a tuple fact whose
    // subtree is dropped, a self-closing fact, a schemaRef without href, and
    // other-namespaced children at the root.
    let xml = instance("<xbrli:context id=\"c1\">\
           <xbrli:identifier scheme=\"http://reg.test\">1234</xbrli:identifier>\
           <xbrli:period>\
             <xbrli:instant>2025-12-31</xbrli:instant>\
             <xbrli:startDate>2025-01-01</xbrli:startDate>\
             <xbrli:endDate>2025-12-31</xbrli:endDate>\
           </xbrli:period>\
           <xbrli:scenario/>\
         </xbrli:context>\
         <xbrli:context id=\"c2\">\
           <xbrli:entity>\
             <xbrli:identifier scheme=\"http://reg.test\">1234</xbrli:identifier>\
             <xbrli:segment/>\
           </xbrli:entity>\
           <xbrli:period><xbrli:startDate>2025-01-01</xbrli:startDate></xbrli:period>\
         </xbrli:context>\
         <xbrli:context id=\"c3\">\
           <xbrli:entity><xbrli:identifier scheme=\"http://reg.test\">1234</xbrli:identifier></xbrli:entity>\
           <xbrli:period>\
             <xbrli:instant>2025-12-31</xbrli:instant>\
             <xbrli:instant>2024-12-31</xbrli:instant>\
           </xbrli:period>\
         </xbrli:context>\
         <xbrli:unit id=\"u1\"><xbrli:measure>  </xbrli:measure><xbrli:extra/></xbrli:unit>\
         <link:footnoteLink xlink:type=\"extended\"/>\
         <link:schemaRef/>\
         <ee:TupleThing contextRef=\"c1\"><ee:Assets contextRef=\"c1\">1</ee:Assets></ee:TupleThing>\
         <ee:Empty contextRef=\"c1\"/>\
         <ee:Assets contextRef=\"c1\" unitRef=\"u1\" decimals=\"2\"><![CDATA[42.50]]></ee:Assets>");
    let document = parse_instance(&xml).expect("hostile-but-wellformed parses");
    assert_eq!(document.contexts.len(), 3);
    assert_eq!(
        document.schema_refs.len(),
        0,
        "schemaRef without xlink:href records nothing"
    );

    // Identifier captured even without the entity wrapper.
    assert_eq!(
        document.contexts[0].entity_identifier.as_deref(),
        Some("1234")
    );
    // instant wins over the duration trio.
    assert!(matches!(
        document.contexts[0].period,
        Some(ContextPeriod::Instant { .. })
    ));
    // Missing endDate -> no period at all (the validator flags it later).
    assert_eq!(document.contexts[1].period, None);
    // The LAST instant wins when several are present (each start resets the
    // text buffer).
    assert_eq!(
        document.contexts[2].period,
        Some(ContextPeriod::Instant {
            date: chrono::NaiveDate::from_ymd_opt(2024, 12, 31).unwrap()
        })
    );

    // Whitespace-only measure text is trimmed to the empty string by the
    // parser; the validator judges a unit whose only measure is empty.
    assert_eq!(document.units[0].measures, vec![String::new()]);

    // The tuple's inner element is NOT a fact; the self-closing fact is an
    // empty text value; the CDATA fact parses numerically.
    assert_eq!(document.facts.len(), 2);
    assert_eq!(document.facts[0].value, FactValue::Text(String::new()));
    assert_eq!(
        document.facts[1].value,
        FactValue::Numeric(DecimalAmount::from_cents(4250))
    );
}

#[test]
fn parse_instance_typed_errors_for_genuinely_broken_input() {
    // Not an instance (wrong namespace, wrong root).
    assert!(matches!(
        parse_instance("<html xmlns=\"http://www.w3.org/1999/xhtml\"/>"),
        Err(InstanceError::NotAnInstance { .. })
    ));
    assert!(matches!(
        parse_instance("<xbrli:inst xmlns:xbrli=\"http://www.xbrl.org/2003/instance\"/>"),
        Err(InstanceError::NotAnInstance { .. })
    ));

    // Truncated XML.
    assert!(matches!(
        parse_instance("<xbrli:xbrl xmlns:xbrli=\"http://www.xbrl.org/2003/instance\""),
        Err(InstanceError::MalformedXml { .. })
    ));

    // An element with an unbound prefix.
    let error = parse_instance(instance("<zz:Fact contextRef=\"c\">1</zz:Fact>").as_str())
        .expect_err("unbound prefix must be a typed error");
    match error {
        InstanceError::MalformedXml { detail } => assert!(detail.contains("zz"), "{detail}"),
        other => panic!("expected MalformedXml, got {other:?}"),
    }

    // An unresolvable entity reference inside fact text.
    let xml = instance("<ee:Assets contextRef=\"c\">&no-such-entity;</ee:Assets>");
    let error = parse_instance(&xml).expect_err("unknown entities must be typed errors");
    match error {
        InstanceError::MalformedXml { detail } => {
            assert!(detail.contains("no-such-entity"), "{detail}")
        }
        other => panic!("expected MalformedXml, got {other:?}"),
    }

    // Entity references are DECODED into fact values, never dropped: the
    // five predefined entities plus numeric character references survive.
    let xml = instance(
        "<ee:Note contextRef=\"c\">AT&amp;T &lt;tag&gt; &apos;q&apos; &quot;&#65;&#x42;&quot;</ee:Note>",
    );
    let document = parse_instance(&xml).expect("entity-bearing fact parses");
    assert_eq!(
        document.facts[0].value,
        FactValue::Text("AT&T <tag> 'q' \"AB\"".into()),
        "every entity reference must survive into the fact value"
    );

    // An unparseable period date.
    let xml = instance(
        "<xbrli:context id=\"c9\">\
           <xbrli:entity><xbrli:identifier scheme=\"s\">x</xbrli:identifier></xbrli:entity>\
           <xbrli:period><xbrli:instant>31-12-2025</xbrli:instant></xbrli:period>\
         </xbrli:context>",
    );
    match parse_instance(&xml) {
        Err(InstanceError::MalformedContext { id, detail }) => {
            assert_eq!(id, "c9");
            assert!(detail.contains("31-12-2025"), "{detail}");
        }
        other => panic!("expected MalformedContext, got {other:?}"),
    }
}

#[test]
fn decimals_parse_accepts_only_xbrl_forms() {
    assert_eq!(Decimals::parse("INF"), Some(Decimals::Infinite));
    assert_eq!(Decimals::parse("inf"), Some(Decimals::Infinite));
    assert_eq!(Decimals::parse(" 4 "), Some(Decimals::Finite(4)));
    assert_eq!(Decimals::parse("-1"), Some(Decimals::Finite(-1)));
    assert_eq!(Decimals::parse("abc"), None);
    assert_eq!(Decimals::parse(""), None);
    assert_eq!(Decimals::parse("2147483648"), None, "beyond i32 is refused");
}

#[test]
fn extension_schema_containers_report_their_size() {
    let mut schema = ExtensionSchema::default();
    assert!(schema.is_empty());
    assert_eq!(schema.len(), 0);
    schema.insert(DeclaredConcept {
        qname: QName::new("urn:ext", "X"),
        period_type: Some(PeriodType::Instant),
        balance: None,
        is_abstract: false,
        is_item: true,
        numeric: Some(NumericKind::Monetary),
        source: "t".into(),
    });
    assert!(!schema.is_empty());
    assert_eq!(schema.len(), 1);
    assert!(schema.declare(&QName::new("urn:ext", "X")).is_some());
    assert!(schema.declare(&QName::new("urn:ext", "Y")).is_none());
}

// ── 12. The validator's full failure matrix ────────────────────────────────

/// A hand-built taxonomy with every concept shape the validator distinguishes.
fn hostile_taxonomy() -> XbrlTaxonomy {
    let mut concepts = BTreeMap::new();
    let mut push = |name: &str, concept: Concept| {
        concepts.insert(QName::new(NS, name), concept);
    };
    let item = |name: &str, period: PeriodType, type_qname: QName| Concept {
        qname: QName::new(NS, name),
        type_qname: Some(type_qname),
        period_type: Some(period),
        balance: Some(Balance::Debit),
        is_abstract: false,
        substitution_group: None,
        id: None,
        source: "t".into(),
    };
    let monetary = QName::new(XBRLI, "monetaryItemType");
    let string = QName::new(XBRLI, "stringItemType");
    push(
        "Assets",
        item("Assets", PeriodType::Instant, monetary.clone()),
    );
    push("Cash", item("Cash", PeriodType::Instant, monetary.clone()));
    push(
        "Equity",
        item("Equity", PeriodType::Instant, monetary.clone()),
    );
    push(
        "Revenue",
        item("Revenue", PeriodType::Duration, monetary.clone()),
    );
    push("Note", item("Note", PeriodType::Duration, string));
    push(
        "Heading",
        Concept {
            is_abstract: true,
            ..item("Heading", PeriodType::Instant, monetary.clone())
        },
    );
    // A tuple: declared, but never an item.
    push(
        "TupleThing",
        Concept {
            substitution_group: Some(QName::new(XBRLI, "tuple")),
            period_type: None,
            balance: None,
            ..item("TupleThing", PeriodType::Instant, monetary)
        },
    );
    XbrlTaxonomy {
        entry_point: "entry.xsd".into(),
        target_namespace: NS.into(),
        concepts,
        type_bases: BTreeMap::new(),
        presentation_arcs: Vec::new(),
        calculation_arcs: Vec::new(),
        labels: BTreeMap::new(),
        prefixes: BTreeMap::from([("ee".into(), NS.into())]),
        documents: Vec::new(),
        digest: "0".repeat(64),
    }
}

fn context_instant(id: &str) -> Context {
    Context {
        id: id.into(),
        entity_identifier: Some("16588745".into()),
        entity_scheme: Some("http://reg.test".into()),
        period: Some(ContextPeriod::Instant {
            date: chrono::NaiveDate::from_ymd_opt(2025, 12, 31).unwrap(),
        }),
    }
}

fn fact_numeric(name: &str, context: &str, cents: i64) -> Fact {
    Fact {
        concept: QName::new(NS, name),
        context_ref: context.into(),
        unit_ref: Some("EUR".into()),
        value: FactValue::Numeric(DecimalAmount::from_cents(cents)),
        decimals: Some(Decimals::Finite(2)),
        id: None,
    }
}

fn validate(
    taxonomy: &XbrlTaxonomy,
    document: &InstanceDocument,
) -> Vec<compliance::xbrl_taxonomy::ValidationFailure> {
    validate_instance(taxonomy, &ExtensionSchema::default(), document)
}

#[test]
fn context_and_unit_structural_rules_are_all_enforced() {
    let taxonomy = hostile_taxonomy();
    let mut document = InstanceDocument::empty();
    document.units.push(compliance::xbrl_taxonomy::Unit {
        id: "EUR".into(),
        measures: vec!["iso4217:EUR".into()],
    });

    // Empty context id.
    document.contexts.push(Context {
        id: "   ".into(),
        ..context_instant("x")
    });
    // Duplicate context id (both named dup).
    document.contexts.push(context_instant("dup"));
    document.contexts.push(context_instant("dup"));
    // A context without entity identifier / scheme / period.
    document.contexts.push(Context {
        id: "bare".into(),
        entity_identifier: None,
        entity_scheme: Some("s".into()),
        period: None,
    });
    document.contexts.push(Context {
        id: "noscheme".into(),
        entity_identifier: Some("1".into()),
        entity_scheme: None,
        period: Some(ContextPeriod::Duration {
            start: chrono::NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
            end: chrono::NaiveDate::from_ymd_opt(2024, 12, 31).unwrap(),
        }),
    });
    // Reversed duration on an otherwise-fine context.
    let mut reversed = context_instant("rev");
    reversed.period = Some(ContextPeriod::Duration {
        start: chrono::NaiveDate::from_ymd_opt(2025, 6, 1).unwrap(),
        end: chrono::NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
    });
    document.contexts.push(reversed);

    let failures = validate(&taxonomy, &document);
    let codes = |needle: &str| failures.iter().filter(|f| f.code == needle).count();
    assert_eq!(codes(FAIL_EMPTY_CONTEXT_ID), 1, "{failures:?}");
    assert_eq!(
        codes(FAIL_DUPLICATE_CONTEXT),
        1,
        "exactly one duplicate report for the pair"
    );
    assert_eq!(codes(FAIL_MISSING_ENTITY_IDENTIFIER), 1);
    assert_eq!(codes(FAIL_MISSING_ENTITY_SCHEME), 1);
    assert_eq!(codes(FAIL_MISSING_CONTEXT_PERIOD), 1);
    assert_eq!(
        codes(FAIL_CONTEXT_PERIOD_INVALID),
        2,
        "noscheme and rev both reverse"
    );

    // Duplicate units.
    let mut document = InstanceDocument::empty();
    document.units.push(compliance::xbrl_taxonomy::Unit {
        id: "EUR".into(),
        measures: vec!["m".into()],
    });
    document.units.push(compliance::xbrl_taxonomy::Unit {
        id: "EUR".into(),
        measures: vec!["m".into()],
    });
    document.contexts.push(context_instant("c"));
    let failures = validate(&taxonomy, &document);
    assert!(
        failures.iter().any(|f| f.code == FAIL_DUPLICATE_UNIT),
        "{failures:?}"
    );
    // A unit without any measure is refused.
    let mut document = InstanceDocument::empty();
    document.units.push(compliance::xbrl_taxonomy::Unit {
        id: "u".into(),
        measures: vec![],
    });
    let failures = validate(&taxonomy, &document);
    assert!(failures.iter().any(|f| f.code == FAIL_MISSING_UNIT_MEASURE));
}

#[test]
fn fact_level_failures_name_the_concept_and_context() {
    let taxonomy = hostile_taxonomy();
    let mut document = InstanceDocument::empty();
    document.contexts.push(context_instant("c"));
    document.units.push(compliance::xbrl_taxonomy::Unit {
        id: "EUR".into(),
        measures: vec!["m".into()],
    });

    // Duplicate fact: same concept/context/unit twice — and a third copy so
    // the dedup logic must collapse identical reports.
    document.facts.push(fact_numeric("Assets", "c", 100));
    document.facts.push(fact_numeric("Assets", "c", 100));
    document.facts.push(fact_numeric("Assets", "c", 100));
    // Unknown context.
    document.facts.push(fact_numeric("Cash", "nope", 1));
    // Undeclared concept.
    document.facts.push(Fact {
        concept: QName::new("urn:elsewhere", "Invented"),
        context_ref: "c".into(),
        unit_ref: Some("EUR".into()),
        value: FactValue::Numeric(DecimalAmount::from_cents(1)),
        decimals: Some(Decimals::Finite(2)),
        id: None,
    });
    // Tuple concept carrying a fact.
    document.facts.push(fact_numeric("TupleThing", "c", 1));
    // Abstract concept carrying a fact.
    document.facts.push(fact_numeric("Heading", "c", 1));
    // Unknown unit ref.
    let mut ghost_unit = fact_numeric("Equity", "c", 5);
    ghost_unit.unit_ref = Some("GHOST".into());
    document.facts.push(ghost_unit);
    // Missing unit + missing decimals + non-numeric value on numeric facts.
    let mut no_unit = fact_numeric("Assets", "c", 1);
    no_unit.unit_ref = None;
    document.facts.push(no_unit);
    let mut no_decimals = fact_numeric("Assets", "c", 1);
    no_decimals.decimals = None;
    document.facts.push(no_decimals);
    let mut text_value = fact_numeric("Assets", "c", 1);
    text_value.value = FactValue::Text("N/A".into());
    document.facts.push(text_value);
    // Period-type mismatch: a duration concept in an instant context.
    document.facts.push(fact_numeric("Revenue", "c", 1));
    // Non-numeric concept with a unit and decimals: both unexpected.
    let mut stringy = fact_numeric("Note", "c", 0);
    stringy.value = FactValue::Text("note".into());
    document.facts.push(stringy);

    let failures = validate(&taxonomy, &document);
    let count = |code: &str| failures.iter().filter(|f| f.code == code).count();
    assert_eq!(
        count(FAIL_DUPLICATE_FACT),
        1,
        "identical duplicate reports dedup: {failures:?}"
    );
    assert_eq!(count(FAIL_UNKNOWN_CONTEXT), 1);
    assert_eq!(count(FAIL_CONCEPT_UNDECLARED), 1);
    assert_eq!(count(FAIL_CONCEPT_NOT_ITEM), 1);
    assert_eq!(count(FAIL_ABSTRACT_CONCEPT), 1);
    assert_eq!(count(FAIL_UNKNOWN_UNIT), 1);
    // Assets appears in 6 facts (3 dup + no_unit + no_decimals + text):
    // every rule fires per fact occurrence.
    assert_eq!(count(FAIL_MISSING_UNIT), 1);
    assert_eq!(count(FAIL_MISSING_DECIMALS), 1);
    assert_eq!(count(FAIL_NON_NUMERIC_VALUE), 1);
    // Revenue AND Note are duration concepts reported in an instant context.
    assert_eq!(count(FAIL_PERIOD_TYPE_MISMATCH), 2);
    assert_eq!(count(FAIL_UNEXPECTED_UNIT), 1);
    assert_eq!(count(FAIL_UNEXPECTED_DECIMALS), 1);

    // Messages name the involved names for machine consumers.
    let dup = failures
        .iter()
        .find(|f| f.code == FAIL_DUPLICATE_FACT)
        .unwrap();
    assert!(dup.concepts.iter().any(|c| c.contains("Assets")), "{dup:?}");
    assert!(dup.message.contains("c"), "{dup:?}");
    assert!(
        failures
            .iter()
            .any(|f| f.code == FAIL_PERIOD_TYPE_MISMATCH && f.message.contains("ee:Revenue")),
        "{failures:?}"
    );
    assert!(
        failures
            .iter()
            .any(|f| f.code == FAIL_PERIOD_TYPE_MISMATCH && f.message.contains("duration")),
        "{failures:?}"
    );

    // Deterministic order: sorted, no adjacent duplicates.
    assert!(
        failures.windows(2).all(|w| w[0] <= w[1]),
        "failures must be sorted: {failures:?}"
    );
}

#[test]
fn calculation_overflow_is_reported_not_panicked_on() {
    let max_text = "170141183460469231731687303715884105727";
    let max_value = DecimalAmount::parse(max_text).unwrap();

    // ADD overflow: two children at MAX sum beyond i128.
    let mut taxonomy = hostile_taxonomy();
    taxonomy
        .calculation_arcs
        .push(compliance::xbrl_taxonomy::CalculationArc {
            role: "http://r/calc".into(),
            parent: QName::new(NS, "Assets"),
            child: QName::new(NS, "Cash"),
            weight: DecimalAmount::from_cents(100),
            order: None,
        });
    taxonomy
        .calculation_arcs
        .push(compliance::xbrl_taxonomy::CalculationArc {
            role: "http://r/calc".into(),
            parent: QName::new(NS, "Assets"),
            child: QName::new(NS, "Equity"),
            weight: DecimalAmount::from_cents(100),
            order: None,
        });
    let mut document = InstanceDocument::empty();
    document.contexts.push(context_instant("c"));
    document.units.push(compliance::xbrl_taxonomy::Unit {
        id: "EUR".into(),
        measures: vec!["m".into()],
    });
    let mut parent = fact_numeric("Assets", "c", 0);
    parent.value = FactValue::Numeric(max_value);
    let mut child1 = fact_numeric("Cash", "c", 0);
    child1.value = FactValue::Numeric(max_value);
    let mut child2 = fact_numeric("Equity", "c", 0);
    child2.value = FactValue::Numeric(max_value);
    document.facts.extend([parent, child1, child2]);

    let failures = validate(&taxonomy, &document);
    let overflow = failures
        .iter()
        .find(|f| f.code == FAIL_CALCULATION_OVERFLOW)
        .unwrap_or_else(|| panic!("expected calculation overflow, got {failures:?}"));
    assert!(
        overflow.message.contains("overflows"),
        "{}",
        overflow.message
    );
    assert!(overflow.concepts.iter().any(|c| c.contains("Assets")));

    // MULTIPLY overflow: a hostile weight at MAX times any child at MAX.
    let mut taxonomy = hostile_taxonomy();
    taxonomy
        .calculation_arcs
        .push(compliance::xbrl_taxonomy::CalculationArc {
            role: "http://r/calc".into(),
            parent: QName::new(NS, "Assets"),
            child: QName::new(NS, "Cash"),
            weight: DecimalAmount::parse(max_text).unwrap(),
            order: None,
        });
    let mut document = InstanceDocument::empty();
    document.contexts.push(context_instant("c"));
    document.units.push(compliance::xbrl_taxonomy::Unit {
        id: "EUR".into(),
        measures: vec!["m".into()],
    });
    let mut parent = fact_numeric("Assets", "c", 0);
    parent.value = FactValue::Numeric(max_value);
    let mut child = fact_numeric("Cash", "c", 0);
    child.value = FactValue::Numeric(max_value);
    document.facts.extend([parent, child]);
    let failures = validate(&taxonomy, &document);
    assert!(
        failures.iter().any(|f| f.code == FAIL_CALCULATION_OVERFLOW),
        "weight*value overflow must be reported: {failures:?}"
    );
}

#[test]
fn extension_declarations_participate_like_taxonomy_concepts() {
    let taxonomy = hostile_taxonomy();
    let mut extensions = ExtensionSchema {
        target_namespace: "urn:apex:ext".into(),
        concepts: Default::default(),
    };

    // A well-declared extension concept validates cleanly.
    extensions.insert(DeclaredConcept {
        qname: QName::new("urn:apex:ext", "CustomerCount"),
        period_type: Some(PeriodType::Instant),
        balance: None,
        is_abstract: false,
        is_item: true,
        numeric: None,
        source: "extension".into(),
    });
    // An extension concept with NO period type must be flagged, not excused
    // for being an extension.
    extensions.insert(DeclaredConcept {
        qname: QName::new("urn:apex:ext", "Undated"),
        period_type: None,
        balance: None,
        is_abstract: false,
        is_item: true,
        numeric: None,
        source: "extension".into(),
    });

    let mut document = InstanceDocument::empty();
    document.contexts.push(context_instant("c"));
    let mut good = fact_numeric("Assets", "c", 1);
    good.concept = QName::new("urn:apex:ext", "CustomerCount");
    good.value = FactValue::Text("42".into());
    good.unit_ref = None;
    good.decimals = None;
    let mut bad = fact_numeric("Assets", "c", 1);
    bad.concept = QName::new("urn:apex:ext", "Undated");
    bad.value = FactValue::Text("x".into());
    bad.unit_ref = None;
    bad.decimals = None;
    document.facts.extend([good, bad]);

    let failures = validate_instance(&taxonomy, &extensions, &document);
    assert!(
        failures.iter().any(|f| f.code == FAIL_MISSING_PERIOD_TYPE),
        "extension concepts without periodType are flagged: {failures:?}"
    );
    assert!(
        !failures.iter().any(|f| f.code == FAIL_UNEXPECTED_UNIT),
        "the numeric=None extension fact may carry no judgement about units here"
    );

    // Display names: extension facts read as apex:<name>, taxonomy facts use
    // the bound prefix, and unknown namespaces fall back to Clark notation.
    let undeclared = failures.iter().find(|f| f.code == FAIL_CONCEPT_UNDECLARED);
    assert!(
        undeclared.is_none(),
        "extension facts are declared: {failures:?}"
    );

    let mut document = InstanceDocument::empty();
    document.contexts.push(context_instant("c"));
    document.facts.push(Fact {
        concept: QName::new("urn:apex:ext", "Ghost"),
        context_ref: "c".into(),
        unit_ref: None,
        value: FactValue::Text("x".into()),
        decimals: None,
        id: None,
    });
    let failures = validate_instance(&taxonomy, &extensions, &document);
    let undeclared = failures
        .iter()
        .find(|f| f.code == FAIL_CONCEPT_UNDECLARED)
        .expect("undeclared extension fact");
    assert!(
        undeclared.message.contains("apex:Ghost"),
        "{}",
        undeclared.message
    );

    // A concept in a THIRD namespace displays as Clark notation.
    let mut document = InstanceDocument::empty();
    document.contexts.push(context_instant("c"));
    document.facts.push(Fact {
        concept: QName::new("urn:third", "Mystery"),
        context_ref: "c".into(),
        unit_ref: None,
        value: FactValue::Text("x".into()),
        decimals: None,
        id: None,
    });
    let failures = validate_instance(&taxonomy, &extensions, &document);
    let undeclared = failures
        .iter()
        .find(|f| f.code == FAIL_CONCEPT_UNDECLARED)
        .unwrap();
    assert!(
        undeclared.message.contains("{urn:third}Mystery"),
        "{}",
        undeclared.message
    );

    // Taxonomy concepts display with the bound prefix in messages.
    let mut document = InstanceDocument::empty();
    document.contexts.push(context_instant("c"));
    let mut fact = fact_numeric("Assets", "c", 1);
    fact.unit_ref = None;
    document.facts.push(fact);
    let failures = validate_instance(&taxonomy, &extensions, &document);
    assert!(
        failures[0].message.contains("ee:Assets"),
        "{}",
        failures[0].message
    );
}

#[test]
fn readiness_summary_reports_each_state_honestly() {
    // Ready.
    let ready = XbrlReadiness {
        submission_ready: true,
        taxonomy: None,
        missing: vec![],
        validation_failures: vec![],
    };
    assert_eq!(
        ready.summary(),
        "submission-ready for the configured taxonomy"
    );

    // Missing taxonomy entry point names the first missing item.
    let missing = XbrlReadiness::not_ready(vec!["APEXMAIL_X".into(), "APEXMAIL_Y".into()]);
    assert!(!missing.submission_ready);
    assert_eq!(missing.taxonomy, None);
    assert_eq!(missing.summary(), "not submission-ready: APEXMAIL_X");

    // Validation failures are summarized with the first failure.
    let mut failing = XbrlReadiness::not_ready(vec![]);
    failing.validation_failures = vec![
        compliance::xbrl_taxonomy::ValidationFailure::new("code_x", "first problem"),
        compliance::xbrl_taxonomy::ValidationFailure::new("code_y", "second"),
    ];
    let summary = failing.summary();
    assert!(summary.contains("2 validation failure"), "{summary}");
    assert!(summary.contains("first problem"), "{summary}");
    assert!(summary.contains("code_x"), "{summary}");

    // Nothing at all: the honest default.
    let empty = XbrlReadiness::not_ready(vec![]);
    assert_eq!(
        empty.summary(),
        "not submission-ready: no taxonomy was configured"
    );
}

#[test]
fn taxonomy_identity_and_prefix_preference_are_reported() {
    let mut taxonomy = hostile_taxonomy();
    // The "ee" prefix wins over the insertion-ordered alternative.
    taxonomy.prefixes.insert("alt".into(), NS.into());
    taxonomy.prefixes.insert("ee".into(), NS.into());
    assert_eq!(taxonomy.prefix_for_namespace(NS), Some("ee"));
    // A namespace with only a generic prefix falls back to the first hit.
    taxonomy.prefixes.insert("x1".into(), "urn:other".into());
    taxonomy.prefixes.insert("x2".into(), "urn:other".into());
    assert_eq!(taxonomy.prefix_for_namespace("urn:other"), Some("x1"));
    // An empty prefix never wins.
    taxonomy
        .prefixes
        .insert(String::new(), "urn:empty-only".into());
    assert_eq!(taxonomy.prefix_for_namespace("urn:empty-only"), None);
    assert_eq!(
        taxonomy.display_name(&QName::new("urn:empty-only", "X")),
        "{urn:empty-only}X"
    );
    assert_eq!(
        taxonomy.display_name(&QName::new(NS, "Assets")),
        "ee:Assets"
    );

    let identity = taxonomy.identity();
    assert_eq!(identity.concept_count, taxonomy.concepts.len());
    assert_eq!(identity.document_count, 0);
    assert_eq!(identity.entry_point, "entry.xsd");
    assert_eq!(identity.target_namespace, NS);
}
