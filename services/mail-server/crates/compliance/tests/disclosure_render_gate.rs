//! E16c render gate: the customer-facing compliance documents are rendered
//! through the crate's real template machinery (`compliance::templates::
//! render_preview`, the `{{VAR}}` interpolator in src/templates.rs) and the
//! OUTPUT, never the source, is scanned for the owner's forbidden
//! disclosures, for certification lies ApexMail does not hold, and for
//! unresolved template artifacts (`{{` / `{%` a failed substitution leaves
//! behind, which source scanning cannot see). The gate also asserts the
//! honest anchors survive in the rendered output, so it cannot pass on an
//! empty render.
//!
//! Rendering is pure: `render_preview` is a string interpolator over the
//! template body plus a variable map, no database, no network. The fixture
//! variables are the crate's own legal-identity constants
//! (`compliance::legal_entity`), the same values the deployed documents are
//! filled with.
//!
//! Which templates reach a customer (checked against the serving code):
//!   * `security-measures.md` - DPA Annex 1 (Technical and Organizational
//!     Measures), named by templates/legal/dpa.md section 14 "Annexes".
//!   * `subprocessors.md` - DPA Annex 2, the generated register mirror
//!     (tools/generate_subprocessors.py); the customer DPA names it.
//!   * The remaining templates (`compliance.md`, `data-locations.md`,
//!     `incident-response.md`, `performance-methodology.md`,
//!     `responsible-disclosure.md`, `trust-center.md`) have no serving route
//!     in the codebase today: the compliance server serves DB-backed trust
//!     portal rows only, and the public marketing pages are separate files
//!     under apps/marketing-zola/content. They were scrubbed of provider,
//!     facility and topology disclosures on 2026-10-26 and are now scanned
//!     for those disclosures like everything else — but they stay outside
//!     `CUSTOMER_FACING_ANNEXES` until a serving route actually wires one
//!     to a customer, at which point it joins the annex list (and the
//!     zero-tolerance framework ban).

use chrono::Utc;
use compliance::legal_entity;
use compliance::templates::{
    render_preview, PreviewOutput, TemplateState, TemplateVariable, TemplateVersion,
};
use regex::Regex;
use std::collections::HashMap;
use std::path::PathBuf;

/// Repo-relative location of the template directory, from the crate manifest
/// root (crates/compliance). Used by the inventory test to fail when a new
/// template appears without joining this gate.
const TEMPLATES_DIR_FROM_MANIFEST: &str = "../../../../templates/compliance";

/// Every markdown document under templates/compliance, rendered by this
/// gate. `include_str!` pins the exact bytes the renderer sees.
const ALL_TEMPLATES: &[(&str, &str)] = &[
    (
        "compliance.md",
        include_str!("../../../../../templates/compliance/compliance.md"),
    ),
    (
        "data-locations.md",
        include_str!("../../../../../templates/compliance/data-locations.md"),
    ),
    (
        "incident-response.md",
        include_str!("../../../../../templates/compliance/incident-response.md"),
    ),
    (
        "performance-methodology.md",
        include_str!("../../../../../templates/compliance/performance-methodology.md"),
    ),
    (
        "responsible-disclosure.md",
        include_str!("../../../../../templates/compliance/responsible-disclosure.md"),
    ),
    (
        "security-measures.md",
        include_str!("../../../../../templates/compliance/security-measures.md"),
    ),
    (
        "subprocessors.md",
        include_str!("../../../../../templates/compliance/subprocessors.md"),
    ),
    (
        "trust-center.md",
        include_str!("../../../../../templates/compliance/trust-center.md"),
    ),
];

/// The templates wired to a customer surface: the two DPA annexes (see the
/// module doc). These get the strict owner scan.
const CUSTOMER_FACING_ANNEXES: &[&str] = &["security-measures.md", "subprocessors.md"];

/// The forbidden disclosures (owner directive, third external audit): the
/// infrastructure provider's name, the topology that identifies a single
/// deployment, and any staffing language. Word-boundary regexes, so the
/// honest sentence "a single hostile source cannot lock a victim out" in
/// the TOM is not a "single host" match.
const FORBIDDEN_DISCLOSURES: &[(&str, &str)] = &[
    ("infrastructure provider name", r"(?i)\bhetzner\b"),
    ("single-host topology", r"(?i)\bsingle[- ]hosts?\b"),
    ("single-region topology", r"(?i)\bsingle[- ]regions?\b"),
    ("no standby", r"(?i)\bno standby\b"),
    ("solo operation", r"(?i)\bsolo\b"),
    ("founder", r"(?i)\bfounders?\b"),
    ("sole operator", r"(?i)\bsole operator\b"),
    (
        "one-person staffing",
        r"(?i)\b(one|1)[ -](person|man|woman|operator|developer|engineer)\b",
    ),
];

/// Certification lies: ApexMail holds no SOC 2, no ISO 27001 and no HIPAA
/// attestation. A roadmap or exclusion SENTENCE is honest and may mention a
/// framework; a text scan cannot judge sentence context, so this scans the
/// specific false-claim phrasings the audit named: the framework followed
/// (within one sentence fragment) by a held/attested verb, or a first-person
/// own-claim. The customer-facing annexes get the stricter zero-tolerance
/// scan below (they mention no framework at all today).
const CERTIFICATION_LIES: &[(&str, &str)] = &[
    (
        "SOC 2 held/attested claim",
        r"(?i)\bsoc ?2\b[^.]{0,40}\b(certified|attested|passed|achieved|obtained)\b",
    ),
    (
        "ISO 27001 held/attested claim",
        r"(?i)\biso ?27001\b[^.]{0,40}\b(certified|attested|passed|achieved|obtained)\b",
    ),
    (
        "HIPAA certified/attested claim",
        r"(?i)\bhipaa\b[^.]{0,40}\b(certified|attested)\b",
    ),
    (
        "first-person own-certification claim",
        r"(?i)\bwe (are|have|hold|maintain|passed)\b[^.]{0,40}\b(soc ?2|iso ?27001|hipaa)\b",
    ),
];

/// Zero-tolerance framework scan for the two DPA annexes: the TOM and the
/// subprocessor register mention no framework at all, so any mention of
/// these in the rendered annex output is a regression, context not needed.
const ANNEX_FRAMEWORK_BAN: &[(&str, &str)] = &[
    ("SOC 2", r"(?i)\bsoc ?2\b"),
    ("ISO 27001", r"(?i)\biso ?27001\b"),
    ("HIPAA", r"(?i)\bhipaa\b"),
];

/// Honest anchors that must survive rendering, per annex. Without these the
/// gate could pass on an empty or truncated render.
const SECURITY_MEASURES_ANCHORS: &[&str] = &[
    "AES-256",              // backup encryption claim (TOM storage/backup sections)
    "gate blessing",        // deploy gate-blessing claim (release governance)
    "Finland",              // residency anchor
    "[roadmap]",            // roadmap labels distinguish planned from active
    "Bel Consulting OÜ",    // substituted LEGAL_NAME proves interpolation ran
    "security@apexmail.ee", // substituted SECURITY_EMAIL
];

const SUBPROCESSORS_ANCHORS: &[&str] = &[
    "EU infrastructure provider", // the only approved provider phrasing
    "Finland",
    "Bel Consulting OÜ",
];

/// Every `{{VAR}}` the templates use. Declaring them mirrors how the
/// deployed documents are filled; an undeclared variable would survive into
/// the output and fail the artifact scan.
fn fixture_variables() -> HashMap<String, String> {
    HashMap::from([
        ("LAST_UPDATED".to_string(), "2026-10-25".to_string()),
        ("NEXT_REVIEW_DATE".to_string(), "2027-01-31".to_string()),
        (
            "LEGAL_NAME".to_string(),
            legal_entity::LEGAL_NAME.to_string(),
        ),
        (
            "TRADING_NAME".to_string(),
            legal_entity::TRADING_NAME.to_string(),
        ),
        (
            "REGISTRY_CODE".to_string(),
            legal_entity::REGISTRY_CODE.to_string(),
        ),
        ("ADDRESS".to_string(), legal_entity::ADDRESS.to_string()),
        (
            "SECURITY_EMAIL".to_string(),
            legal_entity::SECURITY_EMAIL.to_string(),
        ),
        (
            "PRIVACY_EMAIL".to_string(),
            legal_entity::PRIVACY_EMAIL.to_string(),
        ),
        (
            "SUPPORT_EMAIL".to_string(),
            legal_entity::SUPPORT_EMAIL.to_string(),
        ),
    ])
}

fn variable_declarations() -> Vec<TemplateVariable> {
    fixture_variables()
        .keys()
        .map(|name| TemplateVariable {
            name: name.clone(),
            required: false,
            default_value: None,
            description: None,
            safe_escape: false,
            raw_html: false,
        })
        .collect()
}

/// Render one compliance document through the real machinery, the same
/// `render_preview` path the template machinery uses for any `{{VAR}}`
/// document body.
fn render_document(source: &str) -> PreviewOutput {
    let version = TemplateVersion {
        version_id: "gate-render".into(),
        template_id: "compliance_document".into(),
        version_number: 1,
        name: "compliance document".into(),
        description: None,
        html_body: None,
        text_body: Some(source.to_string()),
        subject_template: None,
        variables: variable_declarations(),
        defaults: HashMap::new(),
        raw_html: false,
        state: TemplateState::Published,
        locale: None,
        localizations: vec![],
        layout_template_id: None,
        partial_template_ids: vec![],
        max_size_bytes: 1 << 20,
        created_at: Utc::now(),
        created_by: "render-gate".into(),
        updated_at: Utc::now(),
        archived_at: None,
        audit_events: vec![],
    };
    render_preview(&version, &fixture_variables(), None)
}

fn rendered_text(output: &PreviewOutput) -> String {
    let mut text = output.subject.clone().unwrap_or_default();
    text.push('\n');
    text.push_str(output.text_body.as_deref().unwrap_or(""));
    text.push('\n');
    text.push_str(output.html_body.as_deref().unwrap_or(""));
    text
}

fn find_forbidden(rendered: &str, patterns: &[(&str, &str)]) -> Vec<String> {
    let mut hits = Vec::new();
    for (label, pattern) in patterns {
        let re = Regex::new(pattern).expect("gate patterns must compile");
        if let Some(m) = re.find(rendered) {
            let start = rendered[..m.start()]
                .rfind('\n')
                .map(|i| i + 1)
                .unwrap_or(0);
            let end = rendered[m.end()..]
                .find('\n')
                .map(|i| m.end() + i)
                .unwrap_or(rendered.len());
            hits.push(format!(
                "{label}: {:?} in {:?}",
                pattern,
                &rendered[start..end]
            ));
        }
    }
    hits
}

/// Every template under templates/compliance must be listed in
/// ALL_TEMPLATES, so a new customer-facing document cannot ship without
/// joining this gate.
#[test]
fn compliance_template_inventory_is_fully_gated() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(TEMPLATES_DIR_FROM_MANIFEST);
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|entry| {
            let name = entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            name.ends_with(".md").then_some(name)
        })
        .collect();
    on_disk.sort();
    let mut gated: Vec<String> = ALL_TEMPLATES
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect();
    gated.sort();
    assert_eq!(
        on_disk, gated,
        "templates/compliance changed; add the new template to ALL_TEMPLATES so the render gate covers it"
    );
}

/// The rendered DPA Annex 1 (TOM) must carry no forbidden disclosure, no
/// certification lie, no unresolved artifact, and every honest anchor.
#[test]
fn rendered_security_measures_annex_is_clean_and_honest() {
    let source = ALL_TEMPLATES
        .iter()
        .find(|(name, _)| *name == "security-measures.md")
        .expect("security-measures.md must be in the gate list")
        .1;
    let output = render_document(source);
    assert!(
        output.errors.is_empty(),
        "render produced errors: {:?}",
        output.errors
    );
    let rendered = rendered_text(&output);
    assert!(rendered.len() > 4_000, "render is suspiciously short");

    let hits = find_forbidden(&rendered, FORBIDDEN_DISCLOSURES);
    assert!(
        hits.is_empty(),
        "rendered TOM discloses internals: {hits:#?}"
    );

    let hits = find_forbidden(&rendered, CERTIFICATION_LIES);
    assert!(
        hits.is_empty(),
        "rendered TOM carries a certification lie: {hits:#?}"
    );

    let hits = find_forbidden(&rendered, ANNEX_FRAMEWORK_BAN);
    assert!(
        hits.is_empty(),
        "rendered TOM must not mention held certifications at all: {hits:#?}"
    );

    assert!(
        !rendered.contains("{{") && !rendered.contains("{%"),
        "rendered TOM carries unresolved template artifacts"
    );

    for anchor in SECURITY_MEASURES_ANCHORS {
        assert!(
            rendered.contains(anchor),
            "rendered TOM lost the honest anchor {anchor:?}"
        );
    }
}

/// The rendered DPA Annex 2 (subprocessor register) must name the
/// infrastructure provider only as the approved abstraction.
#[test]
fn rendered_subprocessors_annex_names_only_the_eu_provider() {
    let source = ALL_TEMPLATES
        .iter()
        .find(|(name, _)| *name == "subprocessors.md")
        .expect("subprocessors.md must be in the gate list")
        .1;
    let output = render_document(source);
    assert!(
        output.errors.is_empty(),
        "render produced errors: {:?}",
        output.errors
    );
    let rendered = rendered_text(&output);

    let hits = find_forbidden(&rendered, FORBIDDEN_DISCLOSURES);
    assert!(
        hits.is_empty(),
        "rendered subprocessor register discloses internals: {hits:#?}"
    );
    let hits = find_forbidden(&rendered, CERTIFICATION_LIES);
    assert!(
        hits.is_empty(),
        "rendered subprocessor register carries a certification lie: {hits:#?}"
    );
    let hits = find_forbidden(&rendered, ANNEX_FRAMEWORK_BAN);
    assert!(
        hits.is_empty(),
        "rendered subprocessor register must not mention held certifications: {hits:#?}"
    );
    assert!(
        !rendered.contains("{{") && !rendered.contains("{%"),
        "rendered subprocessor register carries unresolved template artifacts"
    );
    for anchor in SUBPROCESSORS_ANCHORS {
        assert!(
            rendered.contains(anchor),
            "rendered subprocessor register lost the honest anchor {anchor:?}"
        );
    }
}

/// Every other template renders purely, resolves every variable, makes
/// no false certification claim (roadmap/exclusion sentences pass; the
/// false-claim phrasings do not), and — since the 2026-10-26 scrub of
/// trust-center/data-locations/compliance/performance-methodology/
/// responsible-disclosure — carries NO provider, topology, staffing or
/// facility disclosure either. The framework zero-tolerance ban stays
/// with the two annexes (their special contractual status).
#[test]
fn every_compliance_template_renders_without_artifacts_or_certification_lies() {
    for (name, source) in ALL_TEMPLATES {
        if CUSTOMER_FACING_ANNEXES.contains(name) {
            continue; // covered by the strict annex tests above
        }
        let output = render_document(source);
        assert!(
            output.errors.is_empty(),
            "{name}: render produced errors: {:?}",
            output.errors
        );
        let rendered = rendered_text(&output);
        assert!(
            !rendered.contains("{{") && !rendered.contains("{%"),
            "{name}: rendered output carries unresolved template artifacts"
        );
        let hits = find_forbidden(&rendered, CERTIFICATION_LIES);
        assert!(
            hits.is_empty(),
            "{name}: rendered output carries a certification lie: {hits:#?}"
        );
        let leaks = find_forbidden(&rendered, FORBIDDEN_DISCLOSURES);
        assert!(
            leaks.is_empty(),
            "{name}: rendered output discloses internal facts: {leaks:#?}"
        );
    }
}

/// Interpolation must actually happen: wherever the source used
/// {{LEGAL_NAME}}, the rendered output carries the constant, proving the
/// gate scans rendered text rather than an unrendered source copy.
#[test]
fn legal_identity_substitution_actually_happens() {
    for (name, source) in ALL_TEMPLATES {
        let output = render_document(source);
        let rendered = rendered_text(&output);
        if source.contains("{{LEGAL_NAME}}") {
            assert!(
                rendered.contains(legal_entity::LEGAL_NAME),
                "{name}: {{LEGAL_NAME}} did not render"
            );
        }
        if source.contains("{{SECURITY_EMAIL}}") {
            assert!(
                rendered.contains(legal_entity::SECURITY_EMAIL),
                "{name}: {{SECURITY_EMAIL}} did not render"
            );
        }
        if source.contains("{{REGISTRY_CODE}}") {
            assert!(
                rendered.contains(legal_entity::REGISTRY_CODE),
                "{name}: {{REGISTRY_CODE}} did not render"
            );
        }
    }
}

/// Regression guard for the scanner itself: the honest TOM sentence about a
/// "single hostile source" must not be read as the forbidden "single host"
/// disclosure, and the forbidden phrases must be caught when present.
#[test]
fn disclosure_scan_word_boundaries_are_sound() {
    let honest = "A lockout requires corroborating failures from at least two \
distinct source IPs, so a single hostile source cannot lock a victim out.";
    assert!(
        find_forbidden(honest, FORBIDDEN_DISCLOSURES).is_empty(),
        "the honest rate-limiting sentence must not trip the disclosure scan"
    );
    for probe in [
        "Production is a single host in one region.",
        "ApexMail is a solo operation run by the founder.",
        "There is no standby and one person approves changes.",
    ] {
        assert!(
            !find_forbidden(probe, FORBIDDEN_DISCLOSURES).is_empty(),
            "the scan missed a forbidden disclosure in {probe:?}"
        );
    }
    assert!(
        !find_forbidden(
            "We are SOC 2 compliant and ISO 27001 certified.",
            CERTIFICATION_LIES
        )
        .is_empty(),
        "the scan missed an own certification claim"
    );
    let roadmap = "**SOC 2 Type II**: Planned, after Type I completion. \
ISO 27001 is on the roadmap but is not the current priority.";
    assert!(
        find_forbidden(roadmap, CERTIFICATION_LIES).is_empty(),
        "honest roadmap sentences must pass the certification-lie scan"
    );
}
