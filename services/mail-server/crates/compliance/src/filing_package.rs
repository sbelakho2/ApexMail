//! Schema-checked statutory filing packages (KMD, KMD INF, TSD, VD, OSS).
//!
//! A [`FilingPackage`] is a *validated artefact*: form identity + period, the
//! entity identity, a deterministic payload projection, the payload's SHA-256
//! digest, a per-field validation report, and an explicit list of *named gaps*
//! — legally required fields that no repository model can supply today. The
//! submission transport ([`crate::filing_transport`]) refuses to create a
//! submission from anything that is not a validated, gap-free package, so a
//! package with missing fields or named gaps can never be POSTed or handed to
//! a human operator as if it were filable.
//!
//! # Required fields per form (derived from the existing domain models)
//!
//! | Form | Source declaration | Required content |
//! |---|---|---|
//! | [`FilingForm::Kmd`] | [`crate::estonia_ou::VatDeclaration`] | period, entity name/registry code, taxable base + VAT per rate category (domestic / intra-EU / exports), input VAT total, output VAT total, net VAT payable/refundable, due date |
//! | [`FilingForm::KmdInf`] | caller-supplied [`KmdInfAnnex`] | period, entity identity, ≥1 invoice line: invoice number, invoice date, counterparty identity (name + registry code or VAT number), taxable amount, VAT rate, VAT amount |
//! | [`FilingForm::Tsd`] | [`crate::estonia_ou::SocialTaxDeclaration`] | period, entity name/registry code, ≥1 per-person row: name, personal code, gross salary, income tax withheld, social tax, unemployment (employee + employer), funded pension + rate; totals per column; `data_quality` must declare sufficient data |
//! | [`FilingForm::Vd`] | [`VdReturnDeclaration`] | period, seller VAT number, ≥1 line: supply id, invoice id, customer VAT number, customer country, VIES evidence id, transaction nature, taxable amount, EUR currency; line totals |
//! | [`FilingForm::Oss`] | [`OssReturnDeclaration`] | period, union-scheme registration (scheme/country/number), ≥1 supply line: supply id, customer + consumption country, taxable amount, VAT rate, VAT amount, EUR currency; return totals |
//!
//! # Named gaps (fields the repository cannot supply today)
//!
//! Every gap is recorded in [`FilingPackage::named_gaps`] as
//! `{ field, reason }` and makes the package **not submittable** — it is never
//! silently skipped:
//!
//! * **KMD** — [`KMD_VAT_NUMBER_GAP`]: `VatDeclaration` has no VAT
//!   registration number member; the KMD identity requires it. Callers that
//!   hold the entity record can pass it via
//!   [`build_kmd_package_with_vat_number`]; when absent the gap is recorded.
//! * **KMD INF** — [`KMD_INF_DERIVATION_GAP`]: no repository model or
//!   derivation produces invoice-level KMD INF rows (the only KMD INF builder
//!   in the repository, in the billing service, emits aggregate rate buckets).
//!   Lines can be validated when supplied explicitly, but the package stays
//!   non-submittable until a derivation exists.
//! * **TSD** — [`TSD_PAYMENT_TYPE_GAP`]: TSD Annex 1 requires a payment-type
//!   code per person; `EmployeeTaxRecord` has no member for it and no source
//!   assigns one.
//! * **VD** — no gap. The form is the intra-Community SUPPLY listing this
//!   repository documents (`obligations::StatutoryObligationType::Vd`,
//!   "Intra-Community supply report (VD)"). The acquisition side of
//!   intra-Community trade is declared on KMD, where it IS modelled
//!   (`estonia_ou::VatInputBreakdown::intra_eu_acquisitions`) and is a
//!   required field of the KMD package — so a supplies-only VD listing is the
//!   complete statutory return, not a partial one, and refusing it would have
//!   withheld a lawful filing.
//! * **OSS** — none: the union-scheme return's assessable content is fully
//!   carried by `oss_registrations` + `oss_supply_entries` + `oss_returns`.
//!
//! # Determinism and digest scope
//!
//! [`FilingPackage::payload_sha256`] is SHA-256 over [`canonical_json`] of the
//! package payload: object keys sorted, arrays kept in order, numbers rendered
//! by their canonical shortest form, strings JSON-escaped. The payload
//! projection deliberately excludes every non-deterministic model member
//! (`generated_at` and friends): the generation time lives in the **unhashed**
//! envelope field [`FilingPackage::generated_at`], and the validation report /
//! named gaps are envelope fields too. The same declaration therefore always
//! produces byte-identical package bytes and the same digest. Builders that
//! add clock-dependent warnings (the transport adds "period still open") only
//! touch the envelope, never the digest.
#![deny(unsafe_code)]

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::estonia_ou::{SocialTaxDeclaration, VatDeclaration};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema stamped into every package envelope.
pub const FILING_PACKAGE_SCHEMA: &str = "apexmail.filing.package/1";
/// Validation ruleset version stamped into every report.
pub const FILING_VALIDATION_RULESET: &str = "apexmail.filing.validation/1";
/// What the package digest covers, stated for auditors.
pub const PAYLOAD_DIGEST_SCOPE: &str = "sha256 over the canonical (key-sorted, deterministic) \
     JSON of `payload`; the envelope fields (form, period, entity, validation report, named gaps, \
     generated_at) are deliberately excluded because they are not part of the declaration";

/// KMD named gap: the taxable person's VAT number has no model member.
pub const KMD_VAT_NUMBER_GAP: &str = "entity.vat_number";
/// KMD INF named gap: no invoice-level derivation exists in the repository.
pub const KMD_INF_DERIVATION_GAP: &str = "kmd_inf.invoice_lines_derivation";
/// TSD named gap: no payment-type code member exists on the person rows.
pub const TSD_PAYMENT_TYPE_GAP: &str = "tsd.payment_type_code";

// ---------------------------------------------------------------------------
// Form identity
// ---------------------------------------------------------------------------

/// The statutory forms this module can package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilingForm {
    /// Estonian VAT return (Käibedeklaratsioon).
    Kmd,
    /// Invoice-level annex the KMD references (KMD INF).
    KmdInf,
    /// Payroll/social-tax return (Tulumaksu- ja sotsiaalmaksu deklaratsioon).
    Tsd,
    /// Intra-Community supply (and acquisition) listing (VD).
    Vd,
    /// OSS union-scheme return.
    Oss,
}

impl FilingForm {
    /// Every form, in declaration order.
    pub const ALL: [FilingForm; 5] = [
        FilingForm::Kmd,
        FilingForm::KmdInf,
        FilingForm::Tsd,
        FilingForm::Vd,
        FilingForm::Oss,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kmd => "kmd",
            Self::KmdInf => "kmd_inf",
            Self::Tsd => "tsd",
            Self::Vd => "vd",
            Self::Oss => "oss",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Kmd => "VAT return (KMD)",
            Self::KmdInf => "VAT invoice annex (KMD INF)",
            Self::Tsd => "Social tax declaration (TSD)",
            Self::Vd => "Intra-Community supply listing (VD)",
            Self::Oss => "OSS union-scheme return",
        }
    }

    /// The package format identifier embedded in the payload.
    pub fn payload_format(self) -> &'static str {
        match self {
            Self::Kmd => "apexmail.filing.kmd/1",
            Self::KmdInf => "apexmail.filing.kmd-inf/1",
            Self::Tsd => "apexmail.filing.tsd/1",
            Self::Vd => "apexmail.filing.vd/1",
            Self::Oss => "apexmail.filing.oss/1",
        }
    }

    /// Machine-readable names of the fields this form requires, as they appear
    /// in [`FieldCheck::field`] and [`PackageProblem::field`]. Person rows and
    /// lines are represented once (`employees[i].personal_code`,
    /// `lines[i].invoice_number`) because every row is checked.
    pub fn required_fields(self) -> &'static [&'static str] {
        match self {
            Self::Kmd => &[
                "entity.legal_name",
                "entity.registry_code",
                "period",
                "domestic_sales.taxable_amount_cents",
                "domestic_sales.vat_rate",
                "domestic_sales.vat_amount_cents",
                "intra_eu_supplies.taxable_amount_cents",
                "intra_eu_supplies.vat_amount_cents",
                "exports.taxable_amount_cents",
                "exports.vat_amount_cents",
                "input_vat.total_deductible_vat_cents",
                "summary.total_output_vat_cents",
                "summary.total_input_vat_cents",
                "summary.net_vat_payable_cents",
                "summary.vat_refund_cents",
                "summary.due_date",
            ],
            Self::KmdInf => &[
                "entity.legal_name",
                "entity.registry_code",
                "period",
                "lines",
                "lines[i].invoice_number",
                "lines[i].invoice_date",
                "lines[i].counterparty_name",
                "lines[i].counterparty_identity",
                "lines[i].taxable_amount_cents",
                "lines[i].vat_rate_percent",
                "lines[i].vat_amount_cents",
            ],
            Self::Tsd => &[
                "entity.legal_name",
                "entity.registry_code",
                "period",
                "employees",
                "employees[i].employee_name",
                "employees[i].personal_code",
                "employees[i].gross_salary_cents",
                "employees[i].income_tax_withheld_cents",
                "employees[i].social_tax_cents",
                "employees[i].unemployment_insurance_employee_cents",
                "employees[i].unemployment_insurance_employer_cents",
                "employees[i].funded_pension_cents",
                "employees[i].funded_pension_rate",
                "totals.total_gross_salary_cents",
                "totals.total_social_tax_cents",
                "totals.total_income_tax_withheld_cents",
                "totals.total_unemployment_employee_cents",
                "totals.total_unemployment_employer_cents",
                "totals.total_funded_pension_cents",
                "totals.employee_count",
            ],
            Self::Vd => &[
                "period",
                "seller_vat_number",
                "entries",
                "entries[i].supply_id",
                "entries[i].invoice_id",
                "entries[i].customer_vat_number",
                "entries[i].customer_country",
                "entries[i].vat_evidence_id",
                "entries[i].transaction_nature",
                "entries[i].taxable_amount_cents",
                "entries[i].currency",
                "totals.total_taxable_cents",
                "totals.line_count",
            ],
            Self::Oss => &[
                "period",
                "registration.scheme",
                "registration.registration_country",
                "registration.registration_number",
                "entries",
                "entries[i].supply_id",
                "entries[i].customer_country",
                "entries[i].consumption_country",
                "entries[i].taxable_amount_cents",
                "entries[i].vat_rate",
                "entries[i].vat_amount_cents",
                "entries[i].currency",
                "totals.total_taxable_cents",
                "totals.total_vat_cents",
                "totals.supply_count",
            ],
        }
    }

    #[allow(clippy::should_implement_trait)] // inherent parser kept for API stability
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "kmd" => Some(Self::Kmd),
            "kmd_inf" | "kmd-inf" => Some(Self::KmdInf),
            "tsd" => Some(Self::Tsd),
            "vd" => Some(Self::Vd),
            "oss" => Some(Self::Oss),
            _ => None,
        }
    }
}

impl std::fmt::Display for FilingForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Entity identity
// ---------------------------------------------------------------------------

/// The identity the package attributes the declaration to.
///
/// Which members are legally required depends on the form (see the module
/// docs); absent members are recorded as named gaps or missing fields, never
/// defaulted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vat_number: Option<String>,
    /// OSS scheme registration number (the identifier the OSS return is filed
    /// under); unused for the other forms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_number: Option<String>,
}

// ---------------------------------------------------------------------------
// Validation report
// ---------------------------------------------------------------------------

/// One required/checked field and whether it was present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldCheck {
    /// Stable dotted field path (`entries[i].customer_country`).
    pub field: String,
    /// Whether a filing without this field is legally incomplete.
    pub required: bool,
    /// Whether a value was supplied by the source declaration.
    pub present: bool,
    /// Why the field is absent/invalid, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Why a field made the package invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemKind {
    /// The declaration does not carry the required field at all.
    MissingRequiredField,
    /// The field is present but the value violates the form's contract.
    InvalidValue,
    /// The source declaration itself declares its data insufficient.
    InsufficientSourceData,
}

/// One machine-readable refusal reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageProblem {
    pub field: String,
    pub kind: ProblemKind,
    pub detail: String,
}

impl std::fmt::Display for PackageProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.kind {
            ProblemKind::MissingRequiredField => "missing required field",
            ProblemKind::InvalidValue => "invalid value",
            ProblemKind::InsufficientSourceData => "insufficient source data",
        };
        write!(f, "{} ({}: {})", self.field, kind, self.detail)
    }
}

/// Overall verdict of the field contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    Valid,
    Invalid,
}

impl ValidationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }
}

/// The per-field validation report carried by (and persisted with) the
/// package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Ruleset version ([`FILING_VALIDATION_RULESET`]).
    pub ruleset: String,
    pub form: FilingForm,
    /// Every checked field, in contract order.
    pub fields: Vec<FieldCheck>,
    /// Every refusal reason (empty for a valid package).
    pub problems: Vec<PackageProblem>,
    /// Non-blocking observations (e.g. a source data-quality note).
    pub warnings: Vec<String>,
    pub outcome: ValidationOutcome,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.outcome == ValidationOutcome::Valid
    }

    /// Required fields that were absent, in contract order.
    pub fn absent_required_fields(&self) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|field| field.required && !field.present)
            .map(|field| field.field.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Named gaps
// ---------------------------------------------------------------------------

/// A legally required field the repository cannot supply today. A package
/// carrying any gap is NOT submittable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedGap {
    pub field: String,
    pub reason: String,
}

fn gap(field: &str, reason: &str) -> NamedGap {
    NamedGap {
        field: field.to_string(),
        reason: reason.to_string(),
    }
}

/// The KMD VAT-number gap (recorded when no explicit number is supplied).
pub fn kmd_vat_number_gap() -> NamedGap {
    gap(
        KMD_VAT_NUMBER_GAP,
        "estonia_ou::VatDeclaration has no VAT registration number member; the KMD identity \
         requires the taxable person's VAT number (KMKR). Supply it explicitly via \
         build_kmd_package_with_vat_number (e.g. from legal_entities.vat_number).",
    )
}

/// The KMD INF derivation gap.
pub fn kmd_inf_derivation_gap() -> NamedGap {
    gap(
        KMD_INF_DERIVATION_GAP,
        "No repository model or derivation produces invoice-level KMD INF rows: \
         estonia_ou::VatDeclaration carries rate-category aggregates only, and the repository's \
         only KMD INF builder (billing-service vat_emta) emits aggregate rate buckets, not \
         invoice lines. Caller-supplied lines are validated but cannot be reconciled against \
         repository data, so the package is not submittable.",
    )
}

/// The TSD payment-type gap.
pub fn tsd_payment_type_gap() -> NamedGap {
    gap(
        TSD_PAYMENT_TYPE_GAP,
        "TSD Annex 1 requires the payment-type code for every person row \
         (Tulumaksuseadus §40); estonia_ou::EmployeeTaxRecord has no member for it and no \
         repository source assigns one.",
    )
}


// ---------------------------------------------------------------------------
// Canonical serialisation and digest
// ---------------------------------------------------------------------------

/// Canonical JSON: object keys sorted lexicographically, arrays in order,
/// numbers in their shortest exact form. Independent of the map
/// implementation's insertion order, so the same value always hashes the same
/// bytes.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            let mut out = String::from("{");
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                out.push_str(&canonical_json(&map[*key]));
            }
            out.push('}');
            out
        }
        Value::Array(items) => {
            let mut out = String::from("[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The digest a payload must carry: SHA-256 over its canonical JSON.
pub fn payload_digest(payload: &Value) -> String {
    sha256_hex(canonical_json(payload).as_bytes())
}

/// Whether `recorded` is the digest of `payload`. Used to refuse a package
/// whose stored payload was mutated after validation.
pub fn payload_digest_matches(payload: &Value, recorded: &str) -> bool {
    payload_digest(payload) == recorded.trim().to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Package
// ---------------------------------------------------------------------------

/// A validated filing package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilingPackage {
    pub schema: String,
    pub form: FilingForm,
    pub period: String,
    pub entity: EntityIdentity,
    /// The deterministic declaration payload (the thing that is hashed, shown
    /// to the operator and POSTed to a configured endpoint).
    pub payload: Value,
    /// SHA-256 over [`canonical_json`] of `payload`.
    pub payload_sha256: String,
    /// What the digest covers ([`PAYLOAD_DIGEST_SCOPE`]).
    pub digest_scope: String,
    /// Per-field validation report (unhashed envelope).
    pub validation: ValidationReport,
    /// Legally required fields no repository model can supply (unhashed
    /// envelope). Any gap makes the package non-submittable.
    pub named_gaps: Vec<NamedGap>,
    /// Generation time. **Unhashed envelope field** — excluded from the
    /// digest so the same declaration always produces the same digest.
    pub generated_at: DateTime<Utc>,
}

impl FilingPackage {
    fn assemble(
        form: FilingForm,
        period: String,
        entity: EntityIdentity,
        payload: Value,
        validation: ValidationReport,
        named_gaps: Vec<NamedGap>,
    ) -> Self {
        let payload_sha256 = payload_digest(&payload);
        Self {
            schema: FILING_PACKAGE_SCHEMA.to_string(),
            form,
            period,
            entity,
            payload,
            payload_sha256,
            digest_scope: PAYLOAD_DIGEST_SCOPE.to_string(),
            validation,
            named_gaps,
            generated_at: Utc::now(),
        }
    }

    /// Canonical bytes that are hashed (and RFC 3161 timestamped).
    pub fn canonical_payload_bytes(&self) -> Vec<u8> {
        canonical_json(&self.payload).into_bytes()
    }

    /// True when the payload still hashes to the recorded digest.
    pub fn digest_matches_payload(&self) -> bool {
        payload_digest_matches(&self.payload, &self.payload_sha256)
    }

    /// Valid fields AND no named gaps. Only such a package may be submitted.
    pub fn is_submittable(&self) -> bool {
        self.validation.is_valid() && self.named_gaps.is_empty()
    }

    /// Why this package must not be submitted, naming every offending field.
    pub fn refusal_reason(&self) -> Option<String> {
        if self.is_submittable() {
            return None;
        }
        let mut reasons: Vec<String> = self
            .validation
            .problems
            .iter()
            .map(|problem| problem.to_string())
            .collect();
        for named in &self.named_gaps {
            reasons.push(format!("named gap {}: {}", named.field, named.reason));
        }
        Some(format!(
            "{} filing package is not submittable: {}",
            self.form.as_str(),
            reasons.join("; ")
        ))
    }

    /// Add a non-blocking envelope warning (never part of the digest).
    pub fn push_warning(&mut self, warning: impl Into<String>) {
        self.validation.warnings.push(warning.into());
    }

    /// A short machine-readable summary for logs/API responses.
    pub fn summary(&self) -> Value {
        json!({
            "schema": self.schema,
            "form": self.form.as_str(),
            "period": self.period,
            "payload_sha256": self.payload_sha256,
            "validation_outcome": self.validation.outcome,
            "named_gaps": self.named_gaps.iter().map(|gap| gap.field.as_str()).collect::<Vec<_>>(),
            "submittable": self.is_submittable(),
        })
    }
}

/// A hard refusal: the builder will not produce a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageError {
    pub form: FilingForm,
    pub problems: Vec<PackageProblem>,
}

impl PackageError {
    fn new(form: FilingForm, problems: Vec<PackageProblem>) -> Self {
        Self { form, problems }
    }

    /// Every offending field, in report order.
    pub fn fields(&self) -> Vec<&str> {
        self.problems
            .iter()
            .map(|problem| problem.field.as_str())
            .collect()
    }
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} filing package refused: {}",
            self.form.as_str(),
            self.problems
                .iter()
                .map(|problem| problem.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        )
    }
}

impl std::error::Error for PackageError {}

// ---------------------------------------------------------------------------
// Declaration inputs for the DB-backed forms (OSS / VD)
// ---------------------------------------------------------------------------

/// OSS register identity as persisted in `oss_registrations`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OssRegistrationIdentity {
    pub scheme: String,
    pub registration_country: String,
    pub registration_number: String,
}

/// OSS return totals as persisted in `oss_returns`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct OssTotals {
    pub total_taxable_cents: i64,
    pub total_vat_cents: i64,
    pub supply_count: i64,
}

/// One `oss_supply_entries` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OssSupplyEntryDeclaration {
    pub supply_id: String,
    pub tenant_id: String,
    pub invoice_id: Option<Uuid>,
    pub customer_country: String,
    pub consumption_country: String,
    pub taxable_amount_cents: i64,
    pub vat_rate: f64,
    pub vat_amount_cents: i64,
    pub currency: String,
}

/// Everything the union-scheme return is assessed on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OssReturnDeclaration {
    pub period: String,
    /// The derivation payload hash recorded on `oss_returns` (provenance).
    pub return_payload_hash: Option<String>,
    pub registration: OssRegistrationIdentity,
    pub totals: OssTotals,
    pub entries: Vec<OssSupplyEntryDeclaration>,
}

/// VD return totals as persisted in `vd_returns`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct VdTotals {
    pub total_taxable_cents: i64,
    pub line_count: i64,
}

/// One `vd_entries` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VdEntryDeclaration {
    pub supply_id: String,
    pub invoice_id: Option<Uuid>,
    pub customer_vat_number: String,
    pub customer_country: String,
    pub vat_evidence_id: Option<Uuid>,
    pub transaction_nature: String,
    pub taxable_amount_cents: i64,
    pub currency: String,
}

/// Everything the VD listing is assessed on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VdReturnDeclaration {
    pub period: String,
    pub return_payload_hash: Option<String>,
    pub seller_vat_number: Option<String>,
    pub totals: VdTotals,
    pub entries: Vec<VdEntryDeclaration>,
}

/// One invoice line of a KMD INF annex. The annex has no repository model, so
/// callers supply the lines explicitly (see [`kmd_inf_derivation_gap`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KmdInfLine {
    pub invoice_number: String,
    pub invoice_date: NaiveDate,
    pub counterparty_name: String,
    /// Registry code or personal code of the counterparty, when it has one.
    pub counterparty_registry_code: Option<String>,
    /// VAT number of the counterparty, when it is VAT-registered.
    pub counterparty_vat_number: Option<String>,
    pub taxable_amount_cents: i64,
    pub vat_rate_percent: f64,
    pub vat_amount_cents: i64,
}

/// A KMD INF annex: the period, the taxpayer identity and the invoice lines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KmdInfAnnex {
    pub period: String,
    pub entity: EntityIdentity,
    pub lines: Vec<KmdInfLine>,
}

// ---------------------------------------------------------------------------
// Field checking
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FormCheck {
    form: Option<FilingForm>,
    fields: Vec<FieldCheck>,
    problems: Vec<PackageProblem>,
    warnings: Vec<String>,
}

impl FormCheck {
    fn new(form: FilingForm) -> Self {
        Self {
            form: Some(form),
            ..Self::default()
        }
    }

    fn note(&mut self, field: &str, required: bool, present: bool, detail: Option<String>) {
        self.fields.push(FieldCheck {
            field: field.to_string(),
            required,
            present,
            detail,
        });
    }

    /// A field the type system guarantees (an integer/date member): recorded
    /// as present, still named in the contract.
    fn present(&mut self, field: &str) {
        self.note(field, true, true, None);
    }

    /// A required string member: absent when `None` or blank.
    fn required_opt_text(&mut self, field: &str, value: Option<&str>) {
        match value.map(str::trim) {
            Some(value) if !value.is_empty() => self.note(field, true, true, None),
            _ => {
                self.note(
                    field,
                    true,
                    false,
                    Some("required field is absent or empty".to_string()),
                );
                self.problems.push(PackageProblem {
                    field: field.to_string(),
                    kind: ProblemKind::MissingRequiredField,
                    detail: "required field is absent or empty".to_string(),
                });
            }
        }
    }

    /// A required `&str` member.
    fn required_text(&mut self, field: &str, value: &str) {
        self.required_opt_text(field, Some(value));
    }

    /// A required boolean-style presence (row lists, identity alternatives).
    fn required_present(&mut self, field: &str, present: bool, detail: &str) {
        if present {
            self.note(field, true, true, None);
        } else {
            self.note(field, true, false, Some(detail.to_string()));
            self.problems.push(PackageProblem {
                field: field.to_string(),
                kind: ProblemKind::MissingRequiredField,
                detail: detail.to_string(),
            });
        }
    }

    fn invalid(&mut self, field: &str, detail: impl Into<String>) {
        let detail = detail.into();
        self.note(field, true, true, Some(detail.clone()));
        self.problems.push(PackageProblem {
            field: field.to_string(),
            kind: ProblemKind::InvalidValue,
            detail,
        });
    }

    fn insufficient(&mut self, field: &str, detail: impl Into<String>) {
        let detail = detail.into();
        self.note(field, true, false, Some(detail.clone()));
        self.problems.push(PackageProblem {
            field: field.to_string(),
            kind: ProblemKind::InsufficientSourceData,
            detail,
        });
    }

    fn warn(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    fn finish(self) -> ValidationReport {
        let outcome = if self.problems.is_empty() {
            ValidationOutcome::Valid
        } else {
            ValidationOutcome::Invalid
        };
        ValidationReport {
            ruleset: FILING_VALIDATION_RULESET.to_string(),
            form: self.form.unwrap_or(FilingForm::Kmd),
            fields: self.fields,
            problems: self.problems,
            warnings: self.warnings,
            outcome,
        }
    }
}

fn valid_period(period: &str) -> bool {
    let Some((year, month)) = period.split_once('-') else {
        return false;
    };
    let (Ok(year), Ok(month)) = (year.parse::<i32>(), month.parse::<u32>()) else {
        return false;
    };
    crate::vat_oss::period_key(year, month)
        .map(|key| key == period)
        .unwrap_or(false)
}

fn is_country_code(value: &str) -> bool {
    value.len() == 2 && value.chars().all(|character| character.is_ascii_alphabetic())
}

fn is_finite_non_negative(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

/// Record a required total and refuse a declared total that disagrees with
/// the row sums.
fn check_total(
    check: &mut FormCheck,
    field: &str,
    declared: i64,
    values: impl Iterator<Item = i64>,
) {
    check.present(field);
    let computed: i64 = values.sum();
    if computed != declared {
        check.invalid(
            field,
            format!("declared total {declared} does not equal the row sum {computed}"),
        );
    }
}

/// The deterministic payload projection: the serialised declaration minus the
/// non-deterministic `generated_at` member, stamped with the form format.
fn declaration_payload<T: Serialize>(form: FilingForm, declaration: &T) -> Value {
    let mut payload = serde_json::to_value(declaration).unwrap_or(Value::Null);
    if let Some(object) = payload.as_object_mut() {
        object.remove("generated_at");
        object.insert(
            "format".to_string(),
            Value::String(form.payload_format().to_string()),
        );
    }
    payload
}

// ---------------------------------------------------------------------------
// KMD (VAT return)
// ---------------------------------------------------------------------------

/// Build the KMD package for a VAT declaration.
///
/// The taxable person's VAT number has no member on
/// [`crate::estonia_ou::VatDeclaration`], so this records the
/// [`KMD_VAT_NUMBER_GAP`] named gap and the package is NOT submittable. Use
/// [`build_kmd_package_with_vat_number`] when the entity's VAT number is
/// known.
pub fn build_kmd_package(declaration: &VatDeclaration) -> Result<FilingPackage, PackageError> {
    build_kmd_package_with_vat_number(declaration, None)
}

/// Same as [`build_kmd_package`] with the entity's VAT registration number
/// supplied explicitly (e.g. from `legal_entities.vat_number`). When present,
/// the VAT-number gap is not recorded.
pub fn build_kmd_package_with_vat_number(
    declaration: &VatDeclaration,
    vat_number: Option<&str>,
) -> Result<FilingPackage, PackageError> {
    let form = FilingForm::Kmd;
    let period = crate::vat_oss::period_key(declaration.tax_year, declaration.tax_month)
        .unwrap_or_else(|_| format!("{}-{:02}", declaration.tax_year, declaration.tax_month));

    let mut check = FormCheck::new(form);
    check.required_text("entity.legal_name", &declaration.company_name);
    check.required_text("entity.registry_code", &declaration.registry_code);
    if valid_period(&period) {
        check.note("period", true, true, None);
    } else {
        check.invalid(
            "period",
            format!(
                "tax period {}-{:02} is not a valid YYYY-MM period",
                declaration.tax_year, declaration.tax_month
            ),
        );
    }

    let category = |check: &mut FormCheck, prefix: &str, value: &crate::estonia_ou::VatCategory| {
        check.present(&format!("{prefix}.taxable_amount_cents"));
        check.present(&format!("{prefix}.vat_rate"));
        check.present(&format!("{prefix}.vat_amount_cents"));
        if !(0..=100).contains(&value.vat_rate) {
            check.invalid(
                &format!("{prefix}.vat_rate"),
                format!("VAT rate {} is outside 0..=100", value.vat_rate),
            );
        }
    };
    category(&mut check, "domestic_sales", &declaration.domestic_sales);
    category(
        &mut check,
        "intra_eu_supplies",
        &declaration.intra_eu_supplies,
    );
    category(&mut check, "exports", &declaration.exports);

    check.present("input_vat.total_deductible_vat_cents");
    check.present("summary.total_output_vat_cents");
    check.present("summary.total_input_vat_cents");
    check.present("summary.net_vat_payable_cents");
    check.present("summary.vat_refund_cents");
    check.present("summary.due_date");

    // The summary must be the arithmetic of its own components; a hand-edited
    // declaration whose totals disagree is refused rather than filed.
    let net = declaration
        .summary
        .total_output_vat_cents
        .saturating_sub(declaration.summary.total_input_vat_cents);
    let expected_payable = net.max(0);
    let expected_refund = (-net).max(0);
    if declaration.summary.net_vat_payable_cents != expected_payable
        || declaration.summary.vat_refund_cents != expected_refund
    {
        check.invalid(
            "summary.net_vat_payable_cents",
            format!(
                "summary is inconsistent: output {} - input {} = {net}, but the declaration says \
                 payable {} / refund {}",
                declaration.summary.total_output_vat_cents,
                declaration.summary.total_input_vat_cents,
                declaration.summary.net_vat_payable_cents,
                declaration.summary.vat_refund_cents
            ),
        );
    }

    // The source declaration's own data-quality verdict is binding.
    if !declaration.data_quality.has_sufficient_data {
        if declaration.data_quality.missing_fields.is_empty() {
            check.insufficient(
                "data_quality.has_sufficient_data",
                declaration.data_quality.note.clone(),
            );
        } else {
            for missing in &declaration.data_quality.missing_fields {
                check.insufficient(missing, declaration.data_quality.note.clone());
            }
        }
    } else {
        for missing in &declaration.data_quality.missing_fields {
            check.warn(format!(
                "source data-quality note: {missing} ({})",
                declaration.data_quality.note
            ));
        }
    }
    if !declaration.ready_for_filing {
        check.insufficient(
            "ready_for_filing",
            if declaration.incomplete_reasons.is_empty() {
                "the declaration marks itself not ready for filing".to_string()
            } else {
                declaration.incomplete_reasons.join("; ")
            },
        );
    }

    let report = check.finish();
    if !report.is_valid() {
        return Err(PackageError::new(form, report.problems));
    }

    let vat_number = vat_number
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let entity = EntityIdentity {
        legal_name: Some(declaration.company_name.clone()),
        registry_code: Some(declaration.registry_code.clone()),
        vat_number: vat_number.clone(),
        registration_number: None,
    };

    let mut payload = declaration_payload(form, declaration);
    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "entity".to_string(),
            json!({
                "legal_name": entity.legal_name,
                "registry_code": entity.registry_code,
                "vat_number": entity.vat_number,
            }),
        );
    }

    let mut gaps = Vec::new();
    if vat_number.is_none() {
        gaps.push(kmd_vat_number_gap());
    }

    Ok(FilingPackage::assemble(
        form,
        period,
        entity,
        payload,
        report,
        gaps,
    ))
}

// ---------------------------------------------------------------------------
// KMD INF (invoice annex)
// ---------------------------------------------------------------------------

/// Build a KMD INF package from an explicitly supplied annex. The invoice
/// lines have no repository derivation, so the package always carries
/// [`KMD_INF_DERIVATION_GAP`] and is not submittable.
pub fn build_kmd_inf_package(annex: &KmdInfAnnex) -> Result<FilingPackage, PackageError> {
    let form = FilingForm::KmdInf;
    let mut check = FormCheck::new(form);

    check.required_opt_text("entity.legal_name", annex.entity.legal_name.as_deref());
    check.required_opt_text("entity.registry_code", annex.entity.registry_code.as_deref());
    if valid_period(&annex.period) {
        check.note("period", true, true, None);
    } else {
        check.invalid(
            "period",
            format!("period {:?} is not a valid YYYY-MM period", annex.period),
        );
    }

    check.required_present(
        "lines",
        !annex.lines.is_empty(),
        "a KMD INF annex with no invoice lines has nothing to declare",
    );

    for (index, line) in annex.lines.iter().enumerate() {
        let prefix = format!("lines[{index}]");
        check.required_text(&format!("{prefix}.invoice_number"), &line.invoice_number);
        check.present(&format!("{prefix}.invoice_date"));
        check.required_text(
            &format!("{prefix}.counterparty_name"),
            &line.counterparty_name,
        );
        let has_identity = line
            .counterparty_registry_code
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
            || line
                .counterparty_vat_number
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty());
        check.required_present(
            &format!("{prefix}.counterparty_identity"),
            has_identity,
            "the counterparty needs a registry code or a VAT number",
        );
        check.present(&format!("{prefix}.taxable_amount_cents"));
        check.present(&format!("{prefix}.vat_rate_percent"));
        check.present(&format!("{prefix}.vat_amount_cents"));
        if !(0.0..=100.0).contains(&line.vat_rate_percent) || !line.vat_rate_percent.is_finite() {
            check.invalid(
                &format!("{prefix}.vat_rate_percent"),
                format!("VAT rate {} is outside 0..=100", line.vat_rate_percent),
            );
        }
        if line.taxable_amount_cents < 0 || line.vat_amount_cents < 0 {
            check.invalid(
                &format!("{prefix}.taxable_amount_cents"),
                "KMD INF amounts are non-negative",
            );
        }
    }

    let report = check.finish();
    if !report.is_valid() {
        return Err(PackageError::new(form, report.problems));
    }

    let payload = declaration_payload(form, annex);
    Ok(FilingPackage::assemble(
        form,
        annex.period.clone(),
        annex.entity.clone(),
        payload,
        report,
        vec![kmd_inf_derivation_gap()],
    ))
}

// ---------------------------------------------------------------------------
// TSD (payroll return)
// ---------------------------------------------------------------------------

/// Build the TSD package for a social-tax declaration.
///
/// Refuses when the declaration's `data_quality` says the ledger data is
/// insufficient or names missing fields, and when any required person-row
/// member is absent (never omitting a person, never zero-filling a rate).
/// A valid package still carries [`TSD_PAYMENT_TYPE_GAP`] and is not
/// submittable.
pub fn build_tsd_package(declaration: &SocialTaxDeclaration) -> Result<FilingPackage, PackageError> {
    let form = FilingForm::Tsd;
    let period = crate::vat_oss::period_key(declaration.tax_year, declaration.tax_month)
        .unwrap_or_else(|_| format!("{}-{:02}", declaration.tax_year, declaration.tax_month));

    let mut check = FormCheck::new(form);
    check.required_text("entity.legal_name", &declaration.company_name);
    check.required_text("entity.registry_code", &declaration.registry_code);
    if valid_period(&period) {
        check.note("period", true, true, None);
    } else {
        check.invalid(
            "period",
            format!(
                "tax period {}-{:02} is not a valid YYYY-MM period",
                declaration.tax_year, declaration.tax_month
            ),
        );
    }

    // The source's own verdict is binding: an incomplete ledger month may not
    // be filed, and every named gap must be surfaced, not skipped.
    if !declaration.data_quality.has_sufficient_data {
        if declaration.data_quality.missing_fields.is_empty() {
            check.insufficient(
                "data_quality.has_sufficient_data",
                declaration.data_quality.note.clone(),
            );
        } else {
            for missing in &declaration.data_quality.missing_fields {
                check.insufficient(missing, declaration.data_quality.note.clone());
            }
        }
    } else if !declaration.data_quality.missing_fields.is_empty() {
        for missing in &declaration.data_quality.missing_fields {
            check.insufficient(
                missing,
                "the source declaration names this field as missing",
            );
        }
    }

    check.required_present(
        "employees",
        !declaration.employees.is_empty(),
        "a TSD with no person rows declares no payroll",
    );

    for (index, employee) in declaration.employees.iter().enumerate() {
        let prefix = format!("employees[{index}]");
        check.required_text(&format!("{prefix}.employee_name"), &employee.employee_name);
        check.required_text(&format!("{prefix}.personal_code"), &employee.personal_code);
        check.present(&format!("{prefix}.gross_salary_cents"));
        check.present(&format!("{prefix}.income_tax_withheld_cents"));
        check.present(&format!("{prefix}.social_tax_cents"));
        check.present(&format!(
            "{prefix}.unemployment_insurance_employee_cents"
        ));
        check.present(&format!(
            "{prefix}.unemployment_insurance_employer_cents"
        ));
        check.present(&format!("{prefix}.funded_pension_cents"));
        match employee.funded_pension_rate {
            Some(rate) => {
                if matches!(rate, 0.0 | 0.02 | 0.04 | 0.06) {
                    check.note(&format!("{prefix}.funded_pension_rate"), true, true, None);
                } else {
                    check.invalid(
                        &format!("{prefix}.funded_pension_rate"),
                        format!(
                            "funded-pension rate {rate} is not one of the legal choices 0 / 2% / \
                             4% / 6%"
                        ),
                    );
                }
            }
            None => check.required_opt_text(&format!("{prefix}.funded_pension_rate"), None),
        }
    }

    check_total(
        &mut check,
        "totals.total_gross_salary_cents",
        declaration.totals.total_gross_salary_cents,
        declaration.employees.iter().map(|e| e.gross_salary_cents),
    );
    check_total(
        &mut check,
        "totals.total_income_tax_withheld_cents",
        declaration.totals.total_income_tax_withheld_cents,
        declaration
            .employees
            .iter()
            .map(|e| e.income_tax_withheld_cents),
    );
    check_total(
        &mut check,
        "totals.total_social_tax_cents",
        declaration.totals.total_social_tax_cents,
        declaration.employees.iter().map(|e| e.social_tax_cents),
    );
    check_total(
        &mut check,
        "totals.total_unemployment_employee_cents",
        declaration.totals.total_unemployment_employee_cents,
        declaration
            .employees
            .iter()
            .map(|e| e.unemployment_insurance_employee_cents),
    );
    check_total(
        &mut check,
        "totals.total_unemployment_employer_cents",
        declaration.totals.total_unemployment_employer_cents,
        declaration
            .employees
            .iter()
            .map(|e| e.unemployment_insurance_employer_cents),
    );
    check_total(
        &mut check,
        "totals.total_funded_pension_cents",
        declaration.totals.total_funded_pension_cents,
        declaration.employees.iter().map(|e| e.funded_pension_cents),
    );
    check.present("totals.employee_count");
    let declared_count = declaration.totals.employee_count;
    let actual_count = declaration.employees.len() as i32;
    if declared_count != actual_count {
        check.invalid(
            "totals.employee_count",
            format!(
                "declared employee count {declared_count} does not match the {} person rows",
                declaration.employees.len()
            ),
        );
    }

    let report = check.finish();
    if !report.is_valid() {
        return Err(PackageError::new(form, report.problems));
    }

    let payload = declaration_payload(form, declaration);
    let entity = EntityIdentity {
        legal_name: Some(declaration.company_name.clone()),
        registry_code: Some(declaration.registry_code.clone()),
        vat_number: None,
        registration_number: None,
    };
    Ok(FilingPackage::assemble(
        form,
        period,
        entity,
        payload,
        report,
        vec![tsd_payment_type_gap()],
    ))
}

// ---------------------------------------------------------------------------
// VD (intra-Community listing)
// ---------------------------------------------------------------------------

/// Build the VD package: the intra-Community supply listing. Intra-Community
/// ACQUISITIONS are declared on KMD (`VatInputBreakdown::intra_eu_acquisitions`
/// of the KMD package), not on this listing, so a complete return here is
/// submittable.
pub fn build_vd_package(
    declaration: &VdReturnDeclaration,
) -> Result<FilingPackage, PackageError> {
    let form = FilingForm::Vd;
    let mut check = FormCheck::new(form);

    if valid_period(&declaration.period) {
        check.note("period", true, true, None);
    } else {
        check.invalid(
            "period",
            format!("period {:?} is not a valid YYYY-MM period", declaration.period),
        );
    }
    check.required_opt_text("seller_vat_number", declaration.seller_vat_number.as_deref());

    check.required_present(
        "entries",
        !declaration.entries.is_empty(),
        "a VD return with no lines declares no intra-Community supplies",
    );

    for (index, entry) in declaration.entries.iter().enumerate() {
        let prefix = format!("entries[{index}]");
        check.required_text(&format!("{prefix}.supply_id"), &entry.supply_id);
        check.required_present(
            &format!("{prefix}.invoice_id"),
            entry.invoice_id.is_some(),
            "a VD line must name the invoice it reports",
        );
        check.required_text(
            &format!("{prefix}.customer_vat_number"),
            &entry.customer_vat_number,
        );
        if is_country_code(&entry.customer_country) {
            check.note(&format!("{prefix}.customer_country"), true, true, None);
        } else {
            check.invalid(
                &format!("{prefix}.customer_country"),
                format!(
                    "customer country {:?} is not a two-letter country code",
                    entry.customer_country
                ),
            );
        }
        check.required_present(
            &format!("{prefix}.vat_evidence_id"),
            entry.vat_evidence_id.is_some(),
            "zero-rating requires the VIES evidence row that justified it",
        );
        if matches!(
            entry.transaction_nature.as_str(),
            "goods" | "triangular" | "services"
        ) {
            check.note(&format!("{prefix}.transaction_nature"), true, true, None);
        } else {
            check.invalid(
                &format!("{prefix}.transaction_nature"),
                format!(
                    "transaction nature {:?} is not goods/triangular/services",
                    entry.transaction_nature
                ),
            );
        }
        check.present(&format!("{prefix}.taxable_amount_cents"));
        if entry.taxable_amount_cents < 0 {
            check.invalid(
                &format!("{prefix}.taxable_amount_cents"),
                "VD taxable amounts are non-negative",
            );
        }
        if entry.currency.eq_ignore_ascii_case("EUR") {
            check.note(&format!("{prefix}.currency"), true, true, None);
        } else {
            check.invalid(
                &format!("{prefix}.currency"),
                format!("VD currency {:?} is not EUR", entry.currency),
            );
        }
    }

    check.present("totals.total_taxable_cents");
    check.present("totals.line_count");
    let computed_taxable: i64 = declaration
        .entries
        .iter()
        .map(|entry| entry.taxable_amount_cents)
        .sum();
    if computed_taxable != declaration.totals.total_taxable_cents {
        check.invalid(
            "totals.total_taxable_cents",
            format!(
                "declared total {} does not equal the line sum {computed_taxable}",
                declaration.totals.total_taxable_cents
            ),
        );
    }
    let actual_lines = declaration.entries.len() as i64;
    if declaration.totals.line_count != actual_lines {
        check.invalid(
            "totals.line_count",
            format!(
                "declared line count {} does not match the {} lines",
                declaration.totals.line_count, actual_lines
            ),
        );
    }

    let report = check.finish();
    if !report.is_valid() {
        return Err(PackageError::new(form, report.problems));
    }

    let payload = declaration_payload(form, declaration);
    let entity = EntityIdentity {
        legal_name: None,
        registry_code: None,
        vat_number: declaration.seller_vat_number.clone(),
        registration_number: None,
    };
    Ok(FilingPackage::assemble(
        form,
        declaration.period.clone(),
        entity,
        payload,
        report,
        Vec::new(),
    ))
}

// ---------------------------------------------------------------------------
// OSS (union-scheme return)
// ---------------------------------------------------------------------------

/// Build the OSS union-scheme package. Fully derivable from
/// `oss_registrations` + `oss_supply_entries` + `oss_returns`: no named gaps,
/// so a complete return is submittable.
pub fn build_oss_package(
    declaration: &OssReturnDeclaration,
) -> Result<FilingPackage, PackageError> {
    let form = FilingForm::Oss;
    let mut check = FormCheck::new(form);

    if valid_period(&declaration.period) {
        check.note("period", true, true, None);
    } else {
        check.invalid(
            "period",
            format!("period {:?} is not a valid YYYY-MM period", declaration.period),
        );
    }

    if declaration.registration.scheme == "union" {
        check.note("registration.scheme", true, true, None);
    } else {
        check.invalid(
            "registration.scheme",
            format!(
                "scheme {:?} is not the union scheme",
                declaration.registration.scheme
            ),
        );
    }
    if is_country_code(&declaration.registration.registration_country) {
        check.note(
            "registration.registration_country",
            true,
            true,
            None,
        );
    } else {
        check.invalid(
            "registration.registration_country",
            format!(
                "registration country {:?} is not a two-letter country code",
                declaration.registration.registration_country
            ),
        );
    }
    check.required_text(
        "registration.registration_number",
        &declaration.registration.registration_number,
    );

    check.required_present(
        "entries",
        !declaration.entries.is_empty(),
        "a union-scheme return with no supply rows has nothing to declare",
    );

    for (index, entry) in declaration.entries.iter().enumerate() {
        let prefix = format!("entries[{index}]");
        check.required_text(&format!("{prefix}.supply_id"), &entry.supply_id);
        if is_country_code(&entry.customer_country) {
            check.note(&format!("{prefix}.customer_country"), true, true, None);
        } else {
            check.invalid(
                &format!("{prefix}.customer_country"),
                format!(
                    "customer country {:?} is not a two-letter country code",
                    entry.customer_country
                ),
            );
        }
        if is_country_code(&entry.consumption_country) {
            check.note(&format!("{prefix}.consumption_country"), true, true, None);
        } else {
            check.invalid(
                &format!("{prefix}.consumption_country"),
                format!(
                    "consumption country {:?} is not a two-letter country code",
                    entry.consumption_country
                ),
            );
        }
        check.present(&format!("{prefix}.taxable_amount_cents"));
        check.present(&format!("{prefix}.vat_rate"));
        check.present(&format!("{prefix}.vat_amount_cents"));
        if entry.taxable_amount_cents < 0 || entry.vat_amount_cents < 0 {
            check.invalid(
                &format!("{prefix}.taxable_amount_cents"),
                "OSS amounts are non-negative",
            );
        }
        if !is_finite_non_negative(entry.vat_rate) || entry.vat_rate > 100.0 {
            check.invalid(
                &format!("{prefix}.vat_rate"),
                format!("VAT rate {} is outside 0..=100", entry.vat_rate),
            );
        }
        if entry.currency.eq_ignore_ascii_case("EUR") {
            check.note(&format!("{prefix}.currency"), true, true, None);
        } else {
            check.invalid(
                &format!("{prefix}.currency"),
                format!("OSS currency {:?} is not EUR", entry.currency),
            );
        }
    }

    check.present("totals.total_taxable_cents");
    check.present("totals.total_vat_cents");
    check.present("totals.supply_count");
    let computed_taxable: i64 = declaration
        .entries
        .iter()
        .map(|entry| entry.taxable_amount_cents)
        .sum();
    let computed_vat: i64 = declaration
        .entries
        .iter()
        .map(|entry| entry.vat_amount_cents)
        .sum();
    let actual_count = declaration.entries.len() as i64;
    if computed_taxable != declaration.totals.total_taxable_cents {
        check.invalid(
            "totals.total_taxable_cents",
            format!(
                "declared total {} does not equal the supply sum {computed_taxable}",
                declaration.totals.total_taxable_cents
            ),
        );
    }
    if computed_vat != declaration.totals.total_vat_cents {
        check.invalid(
            "totals.total_vat_cents",
            format!(
                "declared total {} does not equal the supply sum {computed_vat}",
                declaration.totals.total_vat_cents
            ),
        );
    }
    if declaration.totals.supply_count != actual_count {
        check.invalid(
            "totals.supply_count",
            format!(
                "declared supply count {} does not match the {} supply rows",
                declaration.totals.supply_count, actual_count
            ),
        );
    }

    let report = check.finish();
    if !report.is_valid() {
        return Err(PackageError::new(form, report.problems));
    }

    let payload = declaration_payload(form, declaration);
    let entity = EntityIdentity {
        legal_name: None,
        registry_code: None,
        vat_number: None,
        registration_number: Some(declaration.registration.registration_number.clone()),
    };
    Ok(FilingPackage::assemble(
        form,
        declaration.period.clone(),
        entity,
        payload,
        report,
        Vec::new(),
    ))
}
