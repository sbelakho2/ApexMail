//! §11 — email-stack signals: ApexMail's own domain expertise as the moat.
//!
//! ApexMail observes DNS and deliverability configuration that a generic CRM
//! enrichment provider does not. This module turns those raw observations
//! (SPF includes, DKIM selectors/CNAMEs, DMARC policies, MX hosts, tracking
//! domains) into **evidence-backed propositions with a confidence** — never
//! facts, never a claim of use from a single weak hint.
//!
//! Design rules (audit §11):
//!
//! * Every analyser is a **pure function** over already-collected
//!   observations, so the inference rules are exhaustively unit-testable
//!   without network access. The `*_at` variants take an explicit
//!   `observed_at`; the short forms stamp `Utc::now()`.
//! * A single weak hint yields `company_may_use_<vendor>` — never
//!   `company_uses_<vendor>`. Two independent hints for the same vendor
//!   corroborate to `company_likely_uses_<vendor>` (still not "uses").
//! * Inference confidence is capped at [`MAX_INFERENCE_CONFIDENCE`] (0.95):
//!   no inference is ever asserted with certainty.
//! * Malformed / non-ASCII / absurdly long records produce low-confidence
//!   evidence or nothing at all — never a confident wrong claim, never a
//!   panic.
//! * A record that was queried and is absent is *observed absence*
//!   ([`CONFIDENCE_OBSERVED_ABSENCE`]) and is a different class of evidence
//!   from a vendor inference. Absence of a DKIM selector is weaker still:
//!   selectors cannot be enumerated, so it is limited absence.
//!
//! The single confidence policy table is [`CONFIDENCE_POLICY`]; every emitted
//! evidence row uses one of its constants.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::SalesError;

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// Provenance vocabulary for `sales_evidence.source_kind`
/// (migration 200_sales_autopilot_v2_unification.sql:316-318).
///
/// The `as_str` values are the exact wire strings accepted by the table's
/// CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceKind {
    DnsObservation,
    HttpFetch,
    ProviderApi,
    FirstParty,
    PublicRegistry,
    Manual,
}

impl EvidenceSourceKind {
    /// Exact wire string for `sales_evidence.source_kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DnsObservation => "dns_observation",
            Self::HttpFetch => "http_fetch",
            Self::ProviderApi => "provider_api",
            Self::FirstParty => "first_party",
            Self::PublicRegistry => "public_registry",
            Self::Manual => "manual",
        }
    }

    /// Parse a persisted value. Unknown values return `None` (callers must
    /// not invent a source kind).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "dns_observation" => Some(Self::DnsObservation),
            "http_fetch" => Some(Self::HttpFetch),
            "provider_api" => Some(Self::ProviderApi),
            "first_party" => Some(Self::FirstParty),
            "public_registry" => Some(Self::PublicRegistry),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

impl std::fmt::Display for EvidenceSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One evidence-backed proposition. `confidence` is always in
/// `0.0..=MAX_INFERENCE_CONFIDENCE` for anything produced by this module, so
/// an inference can never be exactly `1.0`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Machine-readable proposition, e.g. `company_may_use_sendgrid` or
    /// `dmarc_policy_reject`. Never a statement of fact.
    pub proposition: String,
    pub confidence: f32,
    pub source_kind: EvidenceSourceKind,
    /// Where the observation came from (include host, selector name, URL…).
    pub source_ref: Option<String>,
    /// Optional snapshot hash for reproducible re-checking.
    pub source_hash: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Evidence {
    pub fn new(
        proposition: impl Into<String>,
        confidence: f32,
        source_kind: EvidenceSourceKind,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            proposition: proposition.into(),
            confidence: clamp_confidence(confidence),
            source_kind,
            source_ref: None,
            source_hash: None,
            observed_at,
            expires_at: None,
        }
    }

    pub fn with_source_ref(mut self, source_ref: impl Into<String>) -> Self {
        self.source_ref = Some(source_ref.into());
        self
    }

    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Is this evidence still current at `now`? An `expires_at` at or before
    /// `observed_at` is degenerate and therefore already expired (hostile
    /// input must never look fresh).
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(expires_at) => expires_at > self.observed_at && expires_at > now,
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// The one confidence policy table
// ---------------------------------------------------------------------------

/// Hard cap for any inferred proposition. No inference is ever exactly 1.0;
/// `0.95` leaves room for the record itself to be stale or unrepresentative.
pub const MAX_INFERENCE_CONFIDENCE: f32 = 0.95;

/// One weak hint: a single SPF include / MX / tracking host / selector can
/// belong to a reseller, an agency or shared hosting.
pub const CONFIDENCE_WEAK_HINT: f32 = 0.35;

/// Two independent technical hints agree (e.g. SPF include AND DKIM CNAME to
/// the same vendor).
pub const CONFIDENCE_CORROBORATED_HINT: f32 = 0.55;

/// The configuration value itself was read (SPF qualifier, DMARC policy tag,
/// MX list, a resolved selector). Observation of presence, not of usage.
pub const CONFIDENCE_DIRECT_OBSERVATION: f32 = 0.75;

/// A record was queried and is not published. A DNS answer, not a guess.
pub const CONFIDENCE_OBSERVED_ABSENCE: f32 = 0.90;

/// Absence inferred from a finite probe list rather than an authoritative
/// enumeration (DKIM selectors cannot be enumerated).
pub const CONFIDENCE_LIMITED_ABSENCE: f32 = 0.60;

/// Bytes were present but are not a valid record. Claim nothing.
pub const CONFIDENCE_MALFORMED: f32 = 0.20;

/// One row of the documented confidence policy.
#[derive(Debug, Clone, Copy)]
pub struct ConfidenceRule {
    /// Stable class name used in tests and docs.
    pub class: &'static str,
    pub confidence: f32,
    /// When this class applies.
    pub applies_when: &'static str,
}

/// THE confidence policy. Every row emitted by an analyser uses one of these
/// constants; a new class requires a new row here and a test.
pub const CONFIDENCE_POLICY: &[ConfidenceRule] = &[
    ConfidenceRule {
        class: "weak_hint",
        confidence: CONFIDENCE_WEAK_HINT,
        applies_when: "a single technical hint (one SPF include, one MX vendor, one selector, one tracking host)",
    },
    ConfidenceRule {
        class: "corroborated_hint",
        confidence: CONFIDENCE_CORROBORATED_HINT,
        applies_when: "two independent hints agree on the same vendor",
    },
    ConfidenceRule {
        class: "direct_observation",
        confidence: CONFIDENCE_DIRECT_OBSERVATION,
        applies_when: "a configuration value was read directly (qualifier, DMARC policy, MX set, resolved selector)",
    },
    ConfidenceRule {
        class: "observed_absence",
        confidence: CONFIDENCE_OBSERVED_ABSENCE,
        applies_when: "a DNS record was queried and is not published",
    },
    ConfidenceRule {
        class: "limited_absence",
        confidence: CONFIDENCE_LIMITED_ABSENCE,
        applies_when: "absence inferred from a finite probe list (DKIM selectors)",
    },
    ConfidenceRule {
        class: "malformed",
        confidence: CONFIDENCE_MALFORMED,
        applies_when: "bytes were present but unparseable / non-ASCII / absurdly long",
    },
];

/// Clamp any confidence into the policy range. Non-finite input maps to 0.0;
/// the upper bound is [`MAX_INFERENCE_CONFIDENCE`], never 1.0.
pub fn clamp_confidence(confidence: f32) -> f32 {
    if confidence.is_finite() {
        confidence.clamp(0.0, MAX_INFERENCE_CONFIDENCE)
    } else {
        0.0
    }
}

// ---------------------------------------------------------------------------
// Vendor tables
// ---------------------------------------------------------------------------

/// Longest single DNS record string this module will attempt to parse. The
/// SPF spec caps a record at 512 bytes; 2 KB is already far beyond anything
/// legitimate and keeps a 4 KB hostile record from being treated as valid.
pub const MAX_RECORD_BYTES: usize = 2048;

/// Longest host/selector/domain token accepted. DNS names are capped at 253.
const MAX_HOST_BYTES: usize = 253;

/// SPF `include:` suffixes → vendor slug.
const SPF_VENDOR_INCLUDES: &[(&str, &str)] = &[
    ("sendgrid.net", "sendgrid"),
    ("mailgun.org", "mailgun"),
    ("postmarkapp.com", "postmark"),
    ("amazonses.com", "amazon_ses"),
    ("sparkpostmail.com", "sparkpost"),
    ("mandrillapp.com", "mandrill"),
    ("mcsv.net", "mailchimp"),
    ("hubspotemail.net", "hubspot"),
    ("salesforce.com", "salesforce"),
    ("klaviyo.com", "klaviyo"),
    ("protection.outlook.com", "microsoft_365"),
    ("_spf.google.com", "google_workspace"),
    ("zoho.com", "zoho"),
    ("mimecast.com", "mimecast"),
    ("pphosted.com", "proofpoint"),
];

/// MX host suffixes → vendor slug.
const MX_VENDOR_SUFFIXES: &[(&str, &str)] = &[
    ("google.com", "google_workspace"),
    ("googlemail.com", "google_workspace"),
    ("outlook.com", "microsoft_365"),
    ("pphosted.com", "proofpoint"),
    ("mimecast.com", "mimecast"),
    ("barracudanetworks.com", "barracuda"),
    ("amazonaws.com", "amazon"),
    ("zoho.com", "zoho"),
    ("yandex.net", "yandex"),
    ("yandex.ru", "yandex"),
    ("mail.ru", "mail_ru"),
    ("messagingengine.com", "fastmail"),
    ("fastmail.com", "fastmail"),
    ("icloud.com", "apple_icloud"),
];

/// Known default DKIM selector names → vendor slug.
const DKIM_SELECTOR_VENDORS: &[(&str, &str)] = &[
    ("google", "google_workspace"),
    ("s1", "sendgrid"),
    ("s2", "sendgrid"),
    ("smtpapi", "sendgrid"),
    ("mailgun", "mailgun"),
    ("k1", "mailchimp"),
    ("pm", "postmark"),
    ("mandrill", "mandrill"),
    ("sparkpost", "sparkpost"),
    ("ses", "amazon_ses"),
    ("selector1", "microsoft_365"),
    ("selector2", "microsoft_365"),
    ("zoho", "zoho"),
    ("mimecast", "mimecast"),
    ("pp", "proofpoint"),
    ("hubspot", "hubspot"),
    ("klaviyo", "klaviyo"),
];

/// DKIM CNAME target suffixes → vendor slug.
const DKIM_CNAME_VENDORS: &[(&str, &str)] = &[
    ("sendgrid.net", "sendgrid"),
    ("mailgun.org", "mailgun"),
    ("postmarkapp.com", "postmark"),
    ("amazonses.com", "amazon_ses"),
    ("sparkpostmail.com", "sparkpost"),
    ("mandrillapp.com", "mandrill"),
    ("mcsv.net", "mailchimp"),
    ("hubspotemail.net", "hubspot"),
    ("klaviyo.com", "klaviyo"),
    ("protection.outlook.com", "microsoft_365"),
    ("google.com", "google_workspace"),
    ("zoho.com", "zoho"),
];

/// Tracking-domain suffixes → vendor slug.
const TRACKING_VENDOR_SUFFIXES: &[(&str, &str)] = &[
    ("sendgrid.net", "sendgrid"),
    ("mailgun.org", "mailgun"),
    ("list-manage.com", "mailchimp"),
    ("hubspotlinks.com", "hubspot"),
    ("hubspotemail.net", "hubspot"),
    ("klaviyo.com", "klaviyo"),
    ("customeriomail.com", "customerio"),
    ("sparkpostmail.com", "sparkpost"),
    ("mandrillapp.com", "mandrill"),
    ("postmarkapp.com", "postmark"),
    ("exacttarget.com", "salesforce_marketing_cloud"),
    ("mktomail.com", "marketo"),
    ("pardot.com", "pardot"),
    ("braze.com", "braze"),
    ("iterable.com", "iterable"),
    ("constantcontact.com", "constant_contact"),
    ("createsend.com", "campaign_monitor"),
    ("cmail19.com", "campaign_monitor"),
];

/// Conventional click-tracking host prefixes (`click.`, `links.`, …).
const TRACKING_HOST_PREFIXES: &[&str] = &[
    "click.", "clicks.", "links.", "link.", "email.", "mail.", "t.", "trk.", "track.", "mkt.",
    "go.", "ct.", "url.",
];

// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------

/// Normalise a host/token: trim, drop a trailing dot, lowercase. Returns
/// `None` for empty, non-ASCII or absurdly long input — hostile bytes are
/// skipped, never guessed at.
fn normalize_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > MAX_HOST_BYTES || !trimmed.is_ascii() {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

/// Boundary-aware suffix match: `mail.google.com` matches `google.com` but
/// `notgoogle.com` does not.
fn host_has_suffix(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

fn vendor_for_suffix(host: &str, table: &[(&'static str, &'static str)]) -> Option<&'static str> {
    table
        .iter()
        .find(|(suffix, _)| host_has_suffix(host, suffix))
        .map(|(_, vendor)| *vendor)
}

/// A record that is present but cannot be trusted to parse.
fn record_is_suspicious(record: &str) -> bool {
    !record.is_ascii() || record.len() > MAX_RECORD_BYTES || record.contains('\u{0}')
}

/// First syntactically plausible SPF record, or a marker for "present but
/// unparseable".
enum SpfRecord<'a> {
    None,
    Unparseable,
    Valid(&'a str),
}

fn find_spf_record(records: &[String]) -> SpfRecord<'_> {
    let mut saw_non_empty = false;
    for raw in records {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        saw_non_empty = true;
        if record_is_suspicious(trimmed) {
            return SpfRecord::Unparseable;
        }
        if trimmed.to_ascii_lowercase().starts_with("v=spf1") {
            return SpfRecord::Valid(trimmed);
        }
    }
    if saw_non_empty {
        // A TXT answer existed but none of it is an SPF record.
        SpfRecord::Unparseable
    } else {
        SpfRecord::None
    }
}

fn evidence(
    proposition: &str,
    confidence: f32,
    kind: EvidenceSourceKind,
    observed_at: DateTime<Utc>,
) -> Evidence {
    Evidence::new(proposition, confidence, kind, observed_at)
}

fn dedupe(mut rows: Vec<Evidence>) -> Vec<Evidence> {
    rows.sort_by(|a, b| {
        a.proposition
            .cmp(&b.proposition)
            .then_with(|| a.source_ref.cmp(&b.source_ref))
    });
    rows.dedup_by(|a, b| a.proposition == b.proposition && a.source_ref == b.source_ref);
    rows
}

// ---------------------------------------------------------------------------
// SPF
// ---------------------------------------------------------------------------

/// Analyse SPF TXT records. Required signature: stamps `Utc::now()`.
pub fn analyse_spf(records: &[String]) -> Vec<Evidence> {
    analyse_spf_at(records, Utc::now())
}

/// Deterministic SPF analysis at an explicit observation time.
///
/// Emits:
/// * `no_spf_record_published` (observed absence) when no TXT answer exists;
/// * `spf_record_unparseable` (malformed) when bytes exist but are not SPF;
/// * `spf_record_published` plus per-include `company_may_use_<vendor>`
///   (weak hint) and the qualifier observation (`spf_policy_strict` for
///   `-all`, `spf_policy_softfail` for `~all`, `spf_policy_neutral` for
///   `?all`, `spf_policy_permissive_all_pass` for `+all`).
pub fn analyse_spf_at(records: &[String], observed_at: DateTime<Utc>) -> Vec<Evidence> {
    let mut rows = Vec::new();
    let record = match find_spf_record(records) {
        SpfRecord::None => {
            rows.push(evidence(
                "no_spf_record_published",
                CONFIDENCE_OBSERVED_ABSENCE,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            ));
            return rows;
        }
        SpfRecord::Unparseable => {
            rows.push(evidence(
                "spf_record_unparseable",
                CONFIDENCE_MALFORMED,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            ));
            return rows;
        }
        SpfRecord::Valid(record) => record,
    };

    rows.push(evidence(
        "spf_record_published",
        CONFIDENCE_DIRECT_OBSERVATION,
        EvidenceSourceKind::DnsObservation,
        observed_at,
    ));

    let mut vendors: Vec<(&'static str, String)> = Vec::new();
    let mut includes_seen = 0usize;
    let mut external_include_seen = false;

    for token in record.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        // The version marker is not a mechanism.
        if lower.starts_with("v=spf1") {
            continue;
        }
        if let Some(include) = lower.strip_prefix("include:") {
            includes_seen += 1;
            let Some(host) = normalize_host(include) else {
                continue;
            };
            match vendor_for_suffix(&host, SPF_VENDOR_INCLUDES) {
                Some(vendor) => {
                    if !vendors.iter().any(|(known, _)| *known == vendor) {
                        vendors.push((vendor, host));
                    }
                }
                None => external_include_seen = true,
            }
            continue;
        }
        match lower.as_str() {
            "-all" => rows.push(evidence(
                "spf_policy_strict",
                CONFIDENCE_DIRECT_OBSERVATION,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            )),
            "~all" => rows.push(evidence(
                "spf_policy_softfail",
                CONFIDENCE_DIRECT_OBSERVATION,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            )),
            "?all" => rows.push(evidence(
                "spf_policy_neutral",
                CONFIDENCE_DIRECT_OBSERVATION,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            )),
            "+all" => rows.push(evidence(
                "spf_policy_permissive_all_pass",
                CONFIDENCE_DIRECT_OBSERVATION,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            )),
            _ => {}
        }
    }

    // A single include is a WEAK hint: "may use", never "uses".
    for (vendor, host) in &vendors {
        rows.push(
            evidence(
                &format!("company_may_use_{vendor}"),
                CONFIDENCE_WEAK_HINT,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            )
            .with_source_ref(format!("spf include:{host}")),
        );
    }
    if vendors.len() > 1 {
        rows.push(evidence(
            "multiple_email_vendors_in_spf",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
    }
    if external_include_seen {
        rows.push(evidence(
            "spf_authorizes_external_sender",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
    }
    if includes_seen == 0 {
        rows.push(evidence(
            "spf_without_vendor_includes",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
    }

    dedupe(rows)
}

// ---------------------------------------------------------------------------
// DKIM
// ---------------------------------------------------------------------------

/// Analyse DKIM observations. Required signature: stamps `Utc::now()`.
pub fn analyse_dkim(selectors: &[String], cnames: &[String]) -> Vec<Evidence> {
    analyse_dkim_at(selectors, cnames, Utc::now())
}

/// Deterministic DKIM analysis.
///
/// `selectors` are selector names whose DNS record resolved; `cnames` are the
/// observed CNAME targets. Vendor agreement between a selector and a CNAME
/// corroborates (`company_likely_uses_<vendor>`, 0.55); a lone selector or
/// CNAME is only a weak `company_may_use_<vendor>` hint (0.35).
pub fn analyse_dkim_at(
    selectors: &[String],
    cnames: &[String],
    observed_at: DateTime<Utc>,
) -> Vec<Evidence> {
    let mut rows = Vec::new();
    let mut selector_vendors: Vec<(&'static str, String)> = Vec::new();
    let mut cname_vendors: Vec<(&'static str, String)> = Vec::new();
    let mut selector_count = 0usize;
    let mut cname_count = 0usize;

    for raw in selectors {
        let Some(selector) = normalize_host(raw) else {
            continue;
        };
        selector_count += 1;
        if let Some((_, vendor)) = DKIM_SELECTOR_VENDORS
            .iter()
            .find(|(known, _)| selector == *known || selector.starts_with(&format!("{known}-")))
        {
            if !selector_vendors.iter().any(|(v, _)| v == vendor) {
                selector_vendors.push((vendor, selector.clone()));
            }
        }
    }

    for raw in cnames {
        let Some(host) = normalize_host(raw) else {
            continue;
        };
        cname_count += 1;
        if let Some(vendor) = vendor_for_suffix(&host, DKIM_CNAME_VENDORS) {
            if !cname_vendors.iter().any(|(v, _)| *v == vendor) {
                cname_vendors.push((vendor, host.clone()));
            }
        } else {
            rows.push(
                evidence(
                    "custom_dkim_cname_configured",
                    CONFIDENCE_DIRECT_OBSERVATION,
                    EvidenceSourceKind::DnsObservation,
                    observed_at,
                )
                .with_source_ref(format!("cname:{host}")),
            );
        }
    }

    if selector_count == 0 && cname_count == 0 {
        // Selectors cannot be enumerated; this is limited absence, not proof.
        rows.push(evidence(
            "no_dkim_selector_observed",
            CONFIDENCE_LIMITED_ABSENCE,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
        return dedupe(rows);
    }
    if selector_count > 0 {
        rows.push(evidence(
            "dkim_selector_present",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
    }

    for (vendor, selector) in &selector_vendors {
        let corroborated = cname_vendors.iter().any(|(v, _)| v == vendor);
        rows.push(
            evidence(
                if corroborated {
                    format!("company_likely_uses_{vendor}")
                } else {
                    format!("company_may_use_{vendor}")
                }
                .as_str(),
                if corroborated {
                    CONFIDENCE_CORROBORATED_HINT
                } else {
                    CONFIDENCE_WEAK_HINT
                },
                EvidenceSourceKind::DnsObservation,
                observed_at,
            )
            .with_source_ref(format!("dkim-selector:{selector}")),
        );
    }
    for (vendor, host) in &cname_vendors {
        if selector_vendors.iter().any(|(v, _)| v == vendor) {
            continue; // already covered by the corroborated row
        }
        rows.push(
            evidence(
                &format!("company_may_use_{vendor}"),
                CONFIDENCE_WEAK_HINT,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            )
            .with_source_ref(format!("dkim-cname:{host}")),
        );
    }

    dedupe(rows)
}

// ---------------------------------------------------------------------------
// DMARC
// ---------------------------------------------------------------------------

/// Analyse a DMARC TXT record. Required signature: stamps `Utc::now()`.
pub fn analyse_dmarc(record: Option<&str>) -> Vec<Evidence> {
    analyse_dmarc_at(record, Utc::now())
}

/// Deterministic DMARC analysis.
///
/// Emits missing / malformed / `p=none` / `p=quarantine` / `p=reject` rows,
/// plus `dmarc_aggregate_reporting_configured` when `rua` is present and
/// `dmarc_reports_to_multiple_addresses` when more than one address is listed.
pub fn analyse_dmarc_at(record: Option<&str>, observed_at: DateTime<Utc>) -> Vec<Evidence> {
    let mut rows = Vec::new();
    let Some(raw) = record.map(str::trim).filter(|r| !r.is_empty()) else {
        rows.push(evidence(
            "dmarc_record_missing",
            CONFIDENCE_OBSERVED_ABSENCE,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
        return rows;
    };
    if record_is_suspicious(raw) {
        rows.push(evidence(
            "dmarc_record_malformed",
            CONFIDENCE_MALFORMED,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
        return rows;
    }

    let version_ok = raw
        .split(';')
        .filter_map(|part| part.split_once('='))
        .any(|(key, value)| {
            key.trim().eq_ignore_ascii_case("v") && value.trim().eq_ignore_ascii_case("DMARC1")
        });
    if !version_ok {
        rows.push(evidence(
            "dmarc_record_malformed",
            CONFIDENCE_MALFORMED,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
        return rows;
    }

    rows.push(evidence(
        "dmarc_record_published",
        CONFIDENCE_DIRECT_OBSERVATION,
        EvidenceSourceKind::DnsObservation,
        observed_at,
    ));

    let policy = raw
        .split(';')
        .filter_map(|part| part.split_once('='))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case("p"))
        .map(|(_, value)| value.trim().to_ascii_lowercase());

    match policy.as_deref() {
        Some("none") => rows.push(evidence(
            "dmarc_policy_monitoring_only",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        )),
        Some("quarantine") => rows.push(evidence(
            "dmarc_policy_quarantine",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        )),
        Some("reject") => rows.push(evidence(
            "dmarc_policy_reject",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        )),
        Some(_) | None => rows.push(evidence(
            "dmarc_policy_absent_or_invalid",
            CONFIDENCE_MALFORMED,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        )),
    }

    // rua may appear multiple times and/or carry a comma-separated list.
    let rua_addresses: Vec<&str> = raw
        .split(';')
        .filter_map(|part| part.split_once('='))
        .filter(|(key, _)| key.trim().eq_ignore_ascii_case("rua"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    if !rua_addresses.is_empty() {
        rows.push(evidence(
            "dmarc_aggregate_reporting_configured",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
        if rua_addresses.len() > 1 {
            rows.push(evidence(
                "dmarc_reports_to_multiple_addresses",
                CONFIDENCE_DIRECT_OBSERVATION,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            ));
        }
    }

    dedupe(rows)
}

// ---------------------------------------------------------------------------
// MX
// ---------------------------------------------------------------------------

/// Analyse MX hosts. Required signature: stamps `Utc::now()`.
pub fn analyse_mx(hosts: &[String]) -> Vec<Evidence> {
    analyse_mx_at(hosts, Utc::now())
}

/// Deterministic MX analysis. A vendor is only ever `company_may_use_<vendor>`
/// (a mail provider can be shared infrastructure).
pub fn analyse_mx_at(hosts: &[String], observed_at: DateTime<Utc>) -> Vec<Evidence> {
    let mut rows = Vec::new();
    let mut normalised: Vec<String> = hosts.iter().filter_map(|h| normalize_host(h)).collect();
    normalised.sort();
    normalised.dedup();

    if normalised.is_empty() {
        rows.push(evidence(
            "no_mx_hosts",
            CONFIDENCE_OBSERVED_ABSENCE,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
        return rows;
    }

    rows.push(evidence(
        "mx_hosts_observed",
        CONFIDENCE_DIRECT_OBSERVATION,
        EvidenceSourceKind::DnsObservation,
        observed_at,
    ));
    if normalised.len() > 1 {
        rows.push(evidence(
            "multiple_mx_hosts_configured",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
    } else {
        rows.push(evidence(
            "single_mx_host_configured",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
    }

    let mut vendors: Vec<(&'static str, String)> = Vec::new();
    for host in &normalised {
        if let Some(vendor) = vendor_for_suffix(host, MX_VENDOR_SUFFIXES) {
            if !vendors.iter().any(|(v, _)| *v == vendor) {
                vendors.push((vendor, host.clone()));
            }
        }
    }
    for (vendor, host) in &vendors {
        rows.push(
            evidence(
                &format!("company_may_use_{vendor}"),
                CONFIDENCE_WEAK_HINT,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            )
            .with_source_ref(format!("mx:{host}")),
        );
    }

    dedupe(rows)
}

// ---------------------------------------------------------------------------
// Tracking domains
// ---------------------------------------------------------------------------

/// Analyse tracking hosts observed in message links / redirects.
///
/// Required signature shape: `(hosts, account_domain)`. `account_domain` may
/// be empty (hostile input): first-party classification is then skipped and
/// only vendor / convention hints are emitted.
pub fn analyse_tracking_domain(hosts: &[String], account_domain: &str) -> Vec<Evidence> {
    analyse_tracking_domain_at(hosts, account_domain, Utc::now())
}

/// Deterministic tracking-domain analysis.
pub fn analyse_tracking_domain_at(
    hosts: &[String],
    account_domain: &str,
    observed_at: DateTime<Utc>,
) -> Vec<Evidence> {
    let mut rows = Vec::new();
    let account = normalize_host(account_domain);

    let mut normalised: Vec<String> = hosts.iter().filter_map(|h| normalize_host(h)).collect();
    normalised.sort();
    normalised.dedup();

    for host in &normalised {
        if let Some(account) = account.as_deref() {
            if host_has_suffix(host, account) {
                rows.push(
                    evidence(
                        "first_party_tracking_domain_configured",
                        CONFIDENCE_DIRECT_OBSERVATION,
                        EvidenceSourceKind::DnsObservation,
                        observed_at,
                    )
                    .with_source_ref(format!("host:{host}")),
                );
                continue;
            }
        }
        if let Some(vendor) = vendor_for_suffix(host, TRACKING_VENDOR_SUFFIXES) {
            rows.push(
                evidence(
                    &format!("company_may_use_{vendor}_tracking"),
                    CONFIDENCE_WEAK_HINT,
                    EvidenceSourceKind::DnsObservation,
                    observed_at,
                )
                .with_source_ref(format!("host:{host}")),
            );
            continue;
        }
        if TRACKING_HOST_PREFIXES
            .iter()
            .any(|prefix| host.starts_with(prefix))
        {
            // Naming convention only: a weak hint, never a claim of use.
            rows.push(
                evidence(
                    "custom_tracking_domain_configured",
                    CONFIDENCE_WEAK_HINT,
                    EvidenceSourceKind::DnsObservation,
                    observed_at,
                )
                .with_source_ref(format!("host:{host}")),
            );
        }
    }

    dedupe(rows)
}

// ---------------------------------------------------------------------------
// Deliverability configuration quality
// ---------------------------------------------------------------------------

fn dmarc_policy(record: Option<&str>) -> Option<String> {
    let raw = record?.trim();
    if raw.is_empty() || record_is_suspicious(raw) {
        return None;
    }
    let version_ok = raw
        .split(';')
        .filter_map(|part| part.split_once('='))
        .any(|(key, value)| {
            key.trim().eq_ignore_ascii_case("v") && value.trim().eq_ignore_ascii_case("DMARC1")
        });
    if !version_ok {
        return None;
    }
    raw.split(';')
        .filter_map(|part| part.split_once('='))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case("p"))
        .map(|(_, value)| value.trim().to_ascii_lowercase())
}

fn has_valid_spf(spf: &[String]) -> bool {
    matches!(find_spf_record(spf), SpfRecord::Valid(_))
}

/// Pure deliverability quality score in `0.0..=1.0` (this is a *quality*
/// score, not an inference confidence, so 1.0 is reachable by a perfect
/// configuration). Weights: SPF 0.30, enforcing DMARC 0.35 (`p=none` 0.10),
/// DKIM selector 0.20, MX 0.15.
pub fn deliverability_quality(
    spf: &[String],
    dkim_selectors: &[String],
    dmarc: Option<&str>,
    mx: &[String],
) -> f32 {
    let mut quality = 0.0f32;
    if has_valid_spf(spf) {
        quality += 0.30;
    }
    if dkim_selectors.iter().any(|s| normalize_host(s).is_some()) {
        quality += 0.20;
    }
    quality += match dmarc_policy(dmarc).as_deref() {
        Some("quarantine") | Some("reject") => 0.35,
        Some("none") => 0.10,
        _ => 0.0,
    };
    if mx.iter().any(|h| normalize_host(h).is_some()) {
        quality += 0.15;
    }
    quality.clamp(0.0, 1.0)
}

/// Analyse the overall deliverability configuration. Required signature uses
/// `Utc::now()`.
pub fn analyse_deliverability(
    spf: &[String],
    dkim_selectors: &[String],
    dmarc: Option<&str>,
    mx: &[String],
) -> Vec<Evidence> {
    analyse_deliverability_at(spf, dkim_selectors, dmarc, mx, Utc::now())
}

/// Deterministic deliverability analysis.
///
/// Emits one summary proposition (`deliverability_configuration_strong` at
/// quality >= 0.80, `_partial` at >= 0.35, `_deficient` below) plus explicit
/// deficiency propositions for each missing control. The summary confidence
/// tracks the quality band; individual deficiencies are direct observations.
pub fn analyse_deliverability_at(
    spf: &[String],
    dkim_selectors: &[String],
    dmarc: Option<&str>,
    mx: &[String],
    observed_at: DateTime<Utc>,
) -> Vec<Evidence> {
    let quality = deliverability_quality(spf, dkim_selectors, dmarc, mx);
    let mut rows = Vec::new();

    let (summary, confidence) = if quality >= 0.80 {
        (
            "deliverability_configuration_strong",
            CONFIDENCE_DIRECT_OBSERVATION,
        )
    } else if quality >= 0.35 {
        (
            "deliverability_configuration_partial",
            CONFIDENCE_CORROBORATED_HINT,
        )
    } else {
        (
            "deliverability_configuration_deficient",
            CONFIDENCE_CORROBORATED_HINT,
        )
    };
    rows.push(evidence(
        summary,
        confidence,
        EvidenceSourceKind::DnsObservation,
        observed_at,
    ));

    if !has_valid_spf(spf) {
        rows.push(evidence(
            "deficiency_missing_spf",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
    }
    match dmarc_policy(dmarc).as_deref() {
        Some("quarantine") | Some("reject") => {}
        Some("none") => rows.push(evidence(
            "deficiency_dmarc_not_enforcing",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        )),
        _ => rows.push(evidence(
            "deficiency_missing_dmarc",
            CONFIDENCE_DIRECT_OBSERVATION,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        )),
    }
    if !dkim_selectors.iter().any(|s| normalize_host(s).is_some()) {
        rows.push(evidence(
            "deficiency_no_dkim_selector_observed",
            CONFIDENCE_LIMITED_ABSENCE,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
    }
    if !mx.iter().any(|h| normalize_host(h).is_some()) {
        rows.push(evidence(
            "deficiency_no_mx_hosts",
            CONFIDENCE_OBSERVED_ABSENCE,
            EvidenceSourceKind::DnsObservation,
            observed_at,
        ));
    }

    dedupe(rows)
}

// ---------------------------------------------------------------------------
// Composite
// ---------------------------------------------------------------------------

/// Run every email-stack analyser against one raw observation set. Required
/// convenience signature: stamps `Utc::now()`.
#[allow(clippy::too_many_arguments)]
pub fn analyse_email_stack(
    spf_records: &[String],
    dkim_selectors: &[String],
    dkim_cnames: &[String],
    dmarc_record: Option<&str>,
    mx_hosts: &[String],
    tracking_hosts: &[String],
    account_domain: &str,
) -> Vec<Evidence> {
    analyse_email_stack_at(
        spf_records,
        dkim_selectors,
        dkim_cnames,
        dmarc_record,
        mx_hosts,
        tracking_hosts,
        account_domain,
        Utc::now(),
    )
}

/// Deterministic composite analysis.
///
/// In addition to the per-analyser rows, a vendor detected by two or more
/// independent analysers is promoted from `company_may_use_<vendor>` to the
/// corroborated `company_likely_uses_<vendor>` (0.55) — still never "uses".
#[allow(clippy::too_many_arguments)]
pub fn analyse_email_stack_at(
    spf_records: &[String],
    dkim_selectors: &[String],
    dkim_cnames: &[String],
    dmarc_record: Option<&str>,
    mx_hosts: &[String],
    tracking_hosts: &[String],
    account_domain: &str,
    observed_at: DateTime<Utc>,
) -> Vec<Evidence> {
    let mut rows = Vec::new();
    rows.extend(analyse_spf_at(spf_records, observed_at));
    rows.extend(analyse_dkim_at(dkim_selectors, dkim_cnames, observed_at));
    rows.extend(analyse_dmarc_at(dmarc_record, observed_at));
    rows.extend(analyse_mx_at(mx_hosts, observed_at));
    rows.extend(analyse_tracking_domain_at(
        tracking_hosts,
        account_domain,
        observed_at,
    ));

    // Cross-analyser corroboration: count how many distinct analyser rows
    // produced a may-use hint for the same vendor.
    let mut vendor_sources: Vec<(String, usize)> = Vec::new();
    for row in &rows {
        let Some(vendor) = row.proposition.strip_prefix("company_may_use_") else {
            continue;
        };
        let vendor = vendor.to_string();
        match vendor_sources.iter_mut().find(|(v, _)| *v == vendor) {
            Some((_, count)) => *count += 1,
            None => vendor_sources.push((vendor, 1)),
        }
    }
    for (vendor, sources) in vendor_sources {
        if sources < 2 {
            continue;
        }
        let proposition = format!("company_likely_uses_{vendor}");
        if rows.iter().any(|row| row.proposition == proposition) {
            continue;
        }
        rows.push(
            evidence(
                &proposition,
                CONFIDENCE_CORROBORATED_HINT,
                EvidenceSourceKind::DnsObservation,
                observed_at,
            )
            .with_source_ref(format!("corroborated by {sources} analysers")),
        );
    }

    dedupe(rows)
}

/// Direction of an email-stack change between two observation sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StackChangeDirection {
    Added,
    Removed,
}

/// One proposition-level difference between two email-stack snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackChange {
    pub proposition: String,
    pub direction: StackChangeDirection,
}

/// Diff two proposition sets. This is the detector behind the
/// `email_stack_change` signal: it only reports propositions, so a caller can
/// decide whether the change is commercially interesting.
pub fn stack_changes(previous: &[String], current: &[String]) -> Vec<StackChange> {
    let mut changes = Vec::new();
    for proposition in current {
        if !previous.iter().any(|p| p == proposition) {
            changes.push(StackChange {
                proposition: proposition.clone(),
                direction: StackChangeDirection::Added,
            });
        }
    }
    for proposition in previous {
        if !current.iter().any(|p| p == proposition) {
            changes.push(StackChange {
                proposition: proposition.clone(),
                direction: StackChangeDirection::Removed,
            });
        }
    }
    changes.sort_by(|a, b| {
        a.proposition
            .cmp(&b.proposition)
            .then_with(|| format!("{:?}", a.direction).cmp(&format!("{:?}", b.direction)))
    });
    changes
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Persist one evidence row into `sales_evidence`
/// (migration 200_sales_autopilot_v2_unification.sql:308-324).
///
/// Requires at least one subject (account or contact): evidence with no
/// subject cannot be joined back to anything. Confidence is clamped into
/// policy range before storage, so the DB CHECK
/// `confidence >= 0 AND confidence <= 1` always holds.
pub async fn persist_evidence(
    db: &PgPool,
    tenant_id: &str,
    account_id: Option<Uuid>,
    contact_id: Option<Uuid>,
    evidence: &Evidence,
) -> Result<Uuid, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }
    if evidence.proposition.trim().is_empty() {
        return Err(SalesError::InvalidInput(
            "evidence proposition must not be empty".into(),
        ));
    }
    if account_id.is_none() && contact_id.is_none() {
        return Err(SalesError::InvalidInput(
            "evidence requires an account_id or contact_id subject".into(),
        ));
    }

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_evidence (
            id, tenant_id, account_id, contact_id, proposition, confidence,
            source_kind, source_ref, source_hash, observed_at, expires_at, created_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(account_id)
    .bind(contact_id)
    .bind(&evidence.proposition)
    .bind(f64::from(clamp_confidence(evidence.confidence)))
    .bind(evidence.source_kind.as_str())
    .bind(&evidence.source_ref)
    .bind(&evidence.source_hash)
    .bind(evidence.observed_at)
    .bind(evidence.expires_at)
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 11, 12, 0, 0).unwrap()
    }

    fn propositions(rows: &[Evidence]) -> Vec<String> {
        rows.iter().map(|row| row.proposition.clone()).collect()
    }

    fn find<'a>(rows: &'a [Evidence], proposition: &str) -> Option<&'a Evidence> {
        rows.iter().find(|row| row.proposition == proposition)
    }

    // ---- SPF table ---------------------------------------------------------

    #[test]
    fn spf_table_driven_real_world_shapes() {
        let observed = at();

        // v=spf1 -all: a valid record with no vendor include, strict policy.
        let rows = analyse_spf_at(&["v=spf1 -all".to_string()], observed);
        assert!(find(&rows, "spf_record_published").is_some());
        assert!(find(&rows, "spf_policy_strict").is_some());
        assert!(find(&rows, "spf_without_vendor_includes").is_some());
        assert!(rows.iter().all(|row| !row.proposition.contains("may_use")));

        // v=spf1 include:_spf.google.com ~all: a single weak hint.
        let rows = analyse_spf_at(
            &["v=spf1 include:_spf.google.com ~all".to_string()],
            observed,
        );
        let hint = find(&rows, "company_may_use_google_workspace").expect("weak hint");
        assert!((hint.confidence - CONFIDENCE_WEAK_HINT).abs() < 1e-6);
        assert!(find(&rows, "spf_policy_softfail").is_some());

        // No record at all: observed absence, not a guess.
        let rows = analyse_spf_at(&[], observed);
        assert_eq!(propositions(&rows), vec!["no_spf_record_published"]);
        assert!((rows[0].confidence - CONFIDENCE_OBSERVED_ABSENCE).abs() < 1e-6);

        // A 4 KB record is suspicious: low-confidence, never a confident claim.
        let huge = format!("v=spf1 include:sendgrid.net {}", "a".repeat(4096));
        let rows = analyse_spf_at(&[huge], observed);
        assert_eq!(propositions(&rows), vec!["spf_record_unparseable"]);
        assert!(rows[0].confidence <= CONFIDENCE_MALFORMED);

        // Non-ASCII bytes are unparseable, not a confident absence.
        let rows = analyse_spf_at(&["v=spf1 include:séndgrid.net".to_string()], observed);
        assert_eq!(propositions(&rows), vec!["spf_record_unparseable"]);
        assert!(rows[0].confidence <= CONFIDENCE_MALFORMED);

        // Malformed junk is unparseable too.
        let rows = analyse_spf_at(&["not an spf record".to_string()], observed);
        assert_eq!(propositions(&rows), vec!["spf_record_unparseable"]);

        // Multiple vendors: each is still only "may use".
        let rows = analyse_spf_at(
            &["v=spf1 include:sendgrid.net include:mailgun.org -all".to_string()],
            observed,
        );
        assert!(find(&rows, "company_may_use_sendgrid").is_some());
        assert!(find(&rows, "company_may_use_mailgun").is_some());
        assert!(find(&rows, "multiple_email_vendors_in_spf").is_some());
    }

    #[test]
    fn weak_spf_hint_never_asserts_use() {
        let rows = analyse_spf_at(&["v=spf1 include:sendgrid.net ~all".to_string()], at());
        for row in &rows {
            assert!(
                !row.proposition.contains("uses"),
                "weak hint must never assert use: {}",
                row.proposition
            );
        }
        let hint = find(&rows, "company_may_use_sendgrid").expect("may-use hint");
        assert_eq!(hint.confidence, CONFIDENCE_WEAK_HINT);
    }

    // ---- DKIM table --------------------------------------------------------

    #[test]
    fn dkim_table_driven() {
        let observed = at();

        // Empty observations: limited absence (selectors cannot be enumerated).
        let rows = analyse_dkim_at(&[], &[], observed);
        assert_eq!(propositions(&rows), vec!["no_dkim_selector_observed"]);
        assert!((rows[0].confidence - CONFIDENCE_LIMITED_ABSENCE).abs() < 1e-6);

        // A known vendor selector is a weak may-use hint.
        let rows = analyse_dkim_at(&["s1".to_string()], &[], observed);
        let hint = find(&rows, "company_may_use_sendgrid").expect("selector hint");
        assert_eq!(hint.confidence, CONFIDENCE_WEAK_HINT);
        assert!(find(&rows, "dkim_selector_present").is_some());

        // Selector + CNAME agreeing corroborates, still not "uses".
        let rows = analyse_dkim_at(
            &["s1".to_string()],
            &["s1.domainkey.u1234.wl.sendgrid.net".to_string()],
            observed,
        );
        let corroborated = find(&rows, "company_likely_uses_sendgrid").expect("corroborated");
        assert_eq!(corroborated.confidence, CONFIDENCE_CORROBORATED_HINT);
        assert!(find(&rows, "company_may_use_sendgrid").is_none());
        assert!(
            rows.iter()
                .all(|row| !row.proposition.starts_with("company_uses_")),
            "no proposition may assert bare use: {:?}",
            propositions(&rows)
        );

        // A non-vendor CNAME is a custom configuration, not a vendor claim.
        let rows = analyse_dkim_at(&[], &["dkim.example.com".to_string()], observed);
        assert!(find(&rows, "custom_dkim_cname_configured").is_some());

        // Non-ASCII / overlong selectors are skipped without panicking.
        let rows = analyse_dkim_at(
            &["sélecteur".to_string(), "x".repeat(1000)],
            &["".to_string(), " ".to_string()],
            observed,
        );
        assert!(find(&rows, "no_dkim_selector_observed").is_some());
    }

    // ---- DMARC table -------------------------------------------------------

    #[test]
    fn dmarc_table_driven() {
        let observed = at();

        let rows = analyse_dmarc_at(None, observed);
        assert_eq!(propositions(&rows), vec!["dmarc_record_missing"]);
        assert!((rows[0].confidence - CONFIDENCE_OBSERVED_ABSENCE).abs() < 1e-6);

        let rows = analyse_dmarc_at(Some("   "), observed);
        assert_eq!(propositions(&rows), vec!["dmarc_record_missing"]);

        let rows = analyse_dmarc_at(Some("v=DMARC1; p=none;"), observed);
        assert!(find(&rows, "dmarc_policy_monitoring_only").is_some());

        let rows = analyse_dmarc_at(Some("v=DMARC1; p=quarantine;"), observed);
        assert!(find(&rows, "dmarc_policy_quarantine").is_some());

        let rows = analyse_dmarc_at(Some("v=DMARC1; p=reject;"), observed);
        assert!(find(&rows, "dmarc_policy_reject").is_some());

        // Two rua tags: aggregate reporting plus the multi-address note.
        let rows = analyse_dmarc_at(
            Some("v=DMARC1; p=reject; rua=mailto:a@example.com; rua=mailto:b@example.com;"),
            observed,
        );
        assert!(find(&rows, "dmarc_aggregate_reporting_configured").is_some());
        assert!(find(&rows, "dmarc_reports_to_multiple_addresses").is_some());

        // One rua tag with a comma-separated list behaves the same way.
        let rows = analyse_dmarc_at(
            Some("v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com"),
            observed,
        );
        assert!(find(&rows, "dmarc_reports_to_multiple_addresses").is_some());

        // Missing p= is not a confident policy claim.
        let rows = analyse_dmarc_at(Some("v=DMARC1; rua=mailto:a@example.com"), observed);
        let invalid = find(&rows, "dmarc_policy_absent_or_invalid").expect("invalid policy");
        assert!(invalid.confidence <= CONFIDENCE_MALFORMED);

        // Malformed and non-ASCII records never yield a confident wrong claim.
        for malformed in ["", "p=reject", "séndgrid", "v=DMARC1; p="] {
            let rows = analyse_dmarc_at(Some(malformed), observed);
            assert!(rows.iter().all(|row| {
                row.proposition == "dmarc_record_missing"
                    || row.proposition == "dmarc_record_malformed"
                    || row.proposition == "dmarc_record_published"
                    || row.proposition == "dmarc_policy_absent_or_invalid"
            }));
            assert!(rows
                .iter()
                .all(|row| row.confidence <= CONFIDENCE_OBSERVED_ABSENCE));
            assert!(find(&rows, "dmarc_policy_reject").is_none());
        }
    }

    // ---- MX table ----------------------------------------------------------

    #[test]
    fn mx_table_driven() {
        let observed = at();

        let rows = analyse_mx_at(&[], observed);
        assert_eq!(propositions(&rows), vec!["no_mx_hosts"]);
        assert!((rows[0].confidence - CONFIDENCE_OBSERVED_ABSENCE).abs() < 1e-6);

        // Multiple MX hosts: direct observation, plus weak vendor hints.
        let rows = analyse_mx_at(
            &[
                "aspmx.l.google.com".to_string(),
                "alt1.aspmx.l.google.com".to_string(),
            ],
            observed,
        );
        assert!(find(&rows, "multiple_mx_hosts_configured").is_some());
        let hint = find(&rows, "company_may_use_google_workspace").expect("mx hint");
        assert_eq!(hint.confidence, CONFIDENCE_WEAK_HINT);

        // Single MX is a SPOF observation.
        let rows = analyse_mx_at(&["mx.example.com".to_string()], observed);
        assert!(find(&rows, "single_mx_host_configured").is_some());
        assert!(find(&rows, "mx_hosts_observed").is_some());

        // Boundary-aware matching: notgoogle.com is not Google.
        let rows = analyse_mx_at(&["notgoogle.com".to_string()], observed);
        assert!(find(&rows, "company_may_use_google_workspace").is_none());

        // Junk is skipped, not guessed at.
        let rows = analyse_mx_at(&["".to_string(), "  ".to_string()], observed);
        assert_eq!(propositions(&rows), vec!["no_mx_hosts"]);
    }

    // ---- Tracking domains --------------------------------------------------

    #[test]
    fn tracking_domain_table_driven() {
        let observed = at();

        let rows = analyse_tracking_domain_at(&[], "", observed);
        assert!(
            rows.is_empty(),
            "empty input yields no evidence, not a claim"
        );

        let rows = analyse_tracking_domain_at(
            &["click.example.com".to_string(), "example.com".to_string()],
            "example.com",
            observed,
        );
        assert!(find(&rows, "first_party_tracking_domain_configured").is_some());
        assert!(find(&rows, "custom_tracking_domain_configured").is_none());

        let rows = analyse_tracking_domain_at(
            &["url1234.sendgrid.net".to_string()],
            "example.com",
            observed,
        );
        let hint = find(&rows, "company_may_use_sendgrid_tracking").expect("vendor hint");
        assert_eq!(hint.confidence, CONFIDENCE_WEAK_HINT);

        // An empty account domain must not panic or misclassify: nothing is
        // first-party when there is no first party to compare against.
        let rows = analyse_tracking_domain_at(&["links.example.com".to_string()], "", observed);
        assert!(find(&rows, "first_party_tracking_domain_configured").is_none());
        assert!(find(&rows, "custom_tracking_domain_configured").is_some());

        // Non-ASCII host is skipped.
        let rows =
            analyse_tracking_domain_at(&["clïck.example.com".to_string()], "example.com", observed);
        assert!(rows.is_empty());
    }

    // ---- Deliverability ----------------------------------------------------

    #[test]
    fn deliverability_quality_and_analysis() {
        let observed = at();
        let spf = vec!["v=spf1 include:_spf.google.com -all".to_string()];
        let dkim = vec!["google".to_string()];
        let dmarc = Some("v=DMARC1; p=reject; rua=mailto:dmarc@example.com");
        let mx = vec!["aspmx.l.google.com".to_string()];

        assert!((deliverability_quality(&spf, &dkim, dmarc, &mx) - 1.0).abs() < 1e-6);
        let rows = analyse_deliverability_at(&spf, &dkim, dmarc, &mx, observed);
        assert!(find(&rows, "deliverability_configuration_strong").is_some());
        assert!(rows
            .iter()
            .all(|row| !row.proposition.starts_with("deficiency")));

        // Nothing configured: deficient plus every deficiency.
        let rows = analyse_deliverability_at(&[], &[], None, &[], observed);
        assert!(find(&rows, "deliverability_configuration_deficient").is_some());
        assert!(find(&rows, "deficiency_missing_spf").is_some());
        assert!(find(&rows, "deficiency_missing_dmarc").is_some());
        assert!(find(&rows, "deficiency_no_dkim_selector_observed").is_some());
        assert!(find(&rows, "deficiency_no_mx_hosts").is_some());
        assert_eq!(deliverability_quality(&[], &[], None, &[]), 0.0);

        // p=none is partial, not enforcing.
        let rows = analyse_deliverability_at(&spf, &dkim, Some("v=DMARC1; p=none"), &mx, observed);
        assert!(find(&rows, "deficiency_dmarc_not_enforcing").is_some());
    }

    // ---- Composite + change detection -------------------------------------

    #[test]
    fn composite_corroborates_vendor_across_analysers() {
        let observed = at();
        let rows = analyse_email_stack_at(
            &["v=spf1 include:sendgrid.net -all".to_string()],
            &["s1".to_string()],
            &["s1.domainkey.u1.wl.sendgrid.net".to_string()],
            Some("v=DMARC1; p=reject;"),
            &["mx.sendgrid.net".to_string()],
            &["click.example.com".to_string()],
            "example.com",
            observed,
        );
        let corroborated =
            find(&rows, "company_likely_uses_sendgrid").expect("SPF + DKIM + MX corroboration");
        assert_eq!(corroborated.confidence, CONFIDENCE_CORROBORATED_HINT);
        assert!((corroborated.confidence - 1.0).abs() > f32::EPSILON);
    }

    #[test]
    fn stack_changes_detects_added_and_removed() {
        let previous = vec![
            "spf_policy_softfail".to_string(),
            "company_may_use_sendgrid".to_string(),
        ];
        let current = vec![
            "spf_policy_strict".to_string(),
            "company_may_use_sendgrid".to_string(),
        ];
        let changes = stack_changes(&previous, &current);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|change| {
            change.proposition == "spf_policy_strict"
                && change.direction == StackChangeDirection::Added
        }));
        assert!(changes.iter().any(|change| {
            change.proposition == "spf_policy_softfail"
                && change.direction == StackChangeDirection::Removed
        }));
        assert!(stack_changes(&previous, &previous).is_empty());
    }

    // ---- Confidence policy bounds (release gate) --------------------------

    #[test]
    fn every_inference_confidence_is_bounded_and_never_certain() {
        let observed = at();
        let mut corpus = Vec::new();
        corpus.extend(analyse_spf_at(
            &[
                "v=spf1 include:sendgrid.net include:mailgun.org ~all".to_string(),
                "".to_string(),
                "junk".to_string(),
            ],
            observed,
        ));
        corpus.extend(analyse_spf_at(&[], observed));
        corpus.extend(analyse_dkim_at(
            &["s1".to_string(), "".to_string(), "nön-ascii".to_string()],
            &[
                "s1.domainkey.u1.wl.sendgrid.net".to_string(),
                "dkim.example.com".to_string(),
            ],
            observed,
        ));
        corpus.extend(analyse_dmarc_at(None, observed));
        corpus.extend(analyse_dmarc_at(
            Some("v=DMARC1; p=reject; rua=a,b"),
            observed,
        ));
        corpus.extend(analyse_dmarc_at(Some("nonsense"), observed));
        corpus.extend(analyse_mx_at(&["aspmx.l.google.com".to_string()], observed));
        corpus.extend(analyse_mx_at(&[], observed));
        corpus.extend(analyse_tracking_domain_at(
            &["click.example.com".to_string()],
            "example.com",
            observed,
        ));
        corpus.extend(analyse_deliverability_at(&[], &[], None, &[], observed));
        corpus.extend(analyse_deliverability_at(
            &["v=spf1 -all".to_string()],
            &["google".to_string()],
            Some("v=DMARC1; p=reject"),
            &["mx.example.com".to_string()],
            observed,
        ));

        assert!(!corpus.is_empty());
        for row in &corpus {
            assert!(row.confidence.is_finite(), "{} non-finite", row.proposition);
            assert!(
                (0.0..=1.0).contains(&row.confidence),
                "{} confidence {} outside 0..=1",
                row.proposition,
                row.confidence
            );
            assert!(
                row.confidence < 1.0,
                "{} must never be exactly certain",
                row.proposition
            );
            assert!(row.confidence <= MAX_INFERENCE_CONFIDENCE);
            assert!(!row.proposition.trim().is_empty());
        }

        // Policy table sanity: every class is capped, and weak hints are
        // strictly weaker than corroborated hints and observations.
        for rule in CONFIDENCE_POLICY {
            assert!(
                rule.confidence.is_finite()
                    && (0.0..=MAX_INFERENCE_CONFIDENCE).contains(&rule.confidence),
                "policy class {} out of range",
                rule.class
            );
            assert!(!rule.applies_when.is_empty());
        }
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(CONFIDENCE_WEAK_HINT < CONFIDENCE_CORROBORATED_HINT);
            assert!(CONFIDENCE_CORROBORATED_HINT < CONFIDENCE_DIRECT_OBSERVATION);
            assert!(CONFIDENCE_MALFORMED < CONFIDENCE_WEAK_HINT);
        }
    }

    #[test]
    fn clamp_confidence_hostile_inputs() {
        // Non-finite confidence is "no confidence", never a certain claim.
        assert_eq!(clamp_confidence(f32::NAN), 0.0);
        assert_eq!(clamp_confidence(f32::INFINITY), 0.0);
        assert_eq!(clamp_confidence(f32::NEG_INFINITY), 0.0);
        assert_eq!(clamp_confidence(-1.0), 0.0);
        assert_eq!(clamp_confidence(0.5), 0.5);
        assert!(clamp_confidence(1.0) < 1.0);
        assert_eq!(clamp_confidence(1.0), MAX_INFERENCE_CONFIDENCE);
    }

    #[test]
    fn evidence_activity_and_wire_kinds() {
        let observed = at();
        let fresh = Evidence::new(
            "proposition",
            0.5,
            EvidenceSourceKind::DnsObservation,
            observed,
        );
        assert!(fresh.is_active(observed));

        // An expiry before (or at) observation is degenerate and already stale.
        let degenerate = fresh
            .clone()
            .with_expiry(observed - chrono::Duration::hours(1));
        assert!(!degenerate.is_active(observed));

        let expired = fresh
            .clone()
            .with_expiry(observed + chrono::Duration::hours(1));
        assert!(expired.is_active(observed));
        assert!(!expired.is_active(observed + chrono::Duration::hours(2)));

        for kind in [
            EvidenceSourceKind::DnsObservation,
            EvidenceSourceKind::HttpFetch,
            EvidenceSourceKind::ProviderApi,
            EvidenceSourceKind::FirstParty,
            EvidenceSourceKind::PublicRegistry,
            EvidenceSourceKind::Manual,
        ] {
            assert_eq!(
                EvidenceSourceKind::parse(kind.as_str()),
                Some(kind),
                "wire string round-trip for {kind:?}"
            );
        }
        assert_eq!(EvidenceSourceKind::parse("not_a_kind"), None);
        // Exact strings the migration's CHECK constraint accepts.
        assert_eq!(
            EvidenceSourceKind::DnsObservation.as_str(),
            "dns_observation"
        );
        assert_eq!(EvidenceSourceKind::HttpFetch.as_str(), "http_fetch");
        assert_eq!(EvidenceSourceKind::ProviderApi.as_str(), "provider_api");
        assert_eq!(EvidenceSourceKind::FirstParty.as_str(), "first_party");
        assert_eq!(
            EvidenceSourceKind::PublicRegistry.as_str(),
            "public_registry"
        );
        assert_eq!(EvidenceSourceKind::Manual.as_str(), "manual");
    }
}
