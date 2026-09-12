//! Estonian annual report (majandusaasta aruanne) derived from the **closed
//! ledger**, with the human legal acts modelled explicitly.
//!
//! # Derivation contract
//!
//! Values come exclusively from migration 220's views restricted to a CLOSED
//! fiscal period:
//!
//! * `v_accounting_trial_balance` — per-account debit/credit/balance (the
//!   account-level snapshot persisted in `annual_report_lines`);
//! * `v_accounting_posted_entries` — the posted-entry count and provenance.
//!
//! The operational tables (`invoices`, `payroll_records`, …) are evidence,
//! not the ledger, and are never read here. This replaces the previous
//! `estonia_ou::generate_annual_report`, which summed paid invoices and
//! estimated Stripe fees, with a hard-coded company identity.
//!
//! # The state machine (human legal acts are not automatic)
//!
//! ```text
//!   generate ──▶ draft ──approve(authenticated approver)──▶ management_approved
//!                                                              │
//!                                    submit(actor + authority receipt reference)
//!                                                              ▼
//!                                                          submitted
//! ```
//!
//! * **Generation never implies approval or submission.** A generated report
//!   is `draft`; the database CHECK constraints refuse approval/submission
//!   fields on a draft row.
//! * **Approval requires an authenticated approver identity and a
//!   timestamp**; an empty approver is refused. The record is an
//!   authenticated-approver attestation, not a qualified electronic
//!   signature (that requires an eID/qualified-trust-service provider,
//!   which this repository does not integrate); `approved_by` must therefore
//!   carry an identity that the caller authenticated upstream.
//! * **Submission requires approval plus an authority receipt reference**
//!   (Äriregister confirmation) and the submitting actor.
//! * An approved/submitted report is frozen: regeneration is only possible
//!   while `draft`.
//!
//! # XBRL / structured output — taxonomy-driven, never invented
//!
//! The repository vendors no Estonian e-aruande (Äriregister) taxonomy, and
//! the official package is not reachable from the build environment. The
//! emitter therefore does **not** guess element names: it is driven by a
//! CONFIGURED taxonomy package ([`AnnualReportXbrlConfig`], loaded from
//! `APEXMAIL_EE_ANNUAL_REPORT_TAXONOMY` plus a slot-to-concept binding in
//! `APEXMAIL_EE_ANNUAL_REPORT_TAXONOMY_BINDING`) and emits facts only through
//! the model in [`crate::xbrl_taxonomy`]. Facts the configured taxonomy has
//! no concept for stay in the documented ApexMail extension namespace
//! ([`XBRL_EXTENSION_NAMESPACE`]) and are declared in an extension schema the
//! emitter writes alongside the instance, so the instance is
//! self-describing.
//!
//! The state of the claim is derived, recorded in
//! `annual_reports.structured_document.xbrl.readiness` and auditable later:
//!
//! * **no taxonomy configured** — the report is NOT submission-ready; the
//!   readiness report names exactly what is missing (the taxonomy entry
//!   point);
//! * **taxonomy loaded, binding resolved, every fact validated** — the report
//!   is submission-ready *for that taxonomy*, and the readiness report
//!   records the taxonomy identity (entry point, target namespace, digest of
//!   the loaded documents);
//! * **any validation failure** — the report is NOT submission-ready and the
//!   failures are listed with the concepts and amounts involved. The emitted
//!   instance then falls back to the extension-only container (still
//!   well-formed, still self-describing) so no invalid official-namespace
//!   fact is ever stored.
//!
//! `official_estonian_taxonomy` stays `false`: this repository still vendors
//! no official package, and nothing here certifies that a configured package
//! is the registrar's official one.

#![deny(unsafe_code)]

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::xbrl_taxonomy::{
    validate_instance, Balance, Context, ContextPeriod, DecimalAmount, Decimals, DeclaredConcept,
    ExtensionSchema, Fact, FactValue, InstanceDocument, NumericKind, PeriodType, QName,
    TaxonomyError, TaxonomyLimits, TaxonomySource, Unit, ValidationFailure, XbrlReadiness,
    XbrlTaxonomy, FAIL_BINDING_INVALID, FAIL_BINDING_MISSING,
};

/// Canonical structured-document format identifier.
pub const ANNUAL_REPORT_FORMAT: &str = "apexmail.annual-report/1";
/// XBRL instance namespace (standard).
pub const XBRL_INSTANCE_NAMESPACE: &str = "http://www.xbrl.org/2003/instance";
/// XBRL linkbase namespace (standard).
pub const XBRL_LINKBASE_NAMESPACE: &str = "http://www.xbrl.org/2003/linkbase";
/// ISO 4217 namespace (standard).
pub const XBRL_ISO4217_NAMESPACE: &str = "http://www.xbrl.org/2003/iso4217";
/// Documented ApexMail extension namespace for annual-report facts. This is
/// NOT the official Estonian e-aruande taksonoomia.
pub const XBRL_EXTENSION_NAMESPACE: &str = "https://apexmail.com/xbrl/ee-annual-report/1";
/// Logical file name of the extension schema the emitter writes (its content
/// is stored in `structured_document.xbrl.extension_schema.xml`).
pub const XBRL_EXTENSION_SCHEMA_NAME: &str = "apex-ee-annual-report-extension.xsd";
/// Configuration: filesystem path or URL of the e-aruande taxonomy entry
/// point. Unset means "no taxonomy", which keeps the report NOT
/// submission-ready and says so.
pub const ANNUAL_REPORT_XBRL_TAXONOMY_ENV: &str = "APEXMAIL_EE_ANNUAL_REPORT_TAXONOMY";
/// Configuration: JSON document mapping annual-report slots to taxonomy
/// concepts (see [`TaxonomyBinding`]).
pub const ANNUAL_REPORT_XBRL_TAXONOMY_BINDING_ENV: &str =
    "APEXMAIL_EE_ANNUAL_REPORT_TAXONOMY_BINDING";
/// Optional override for the taxonomy loader's document bound.
pub const ANNUAL_REPORT_XBRL_MAX_DOCUMENTS_ENV: &str =
    "APEXMAIL_EE_ANNUAL_REPORT_TAXONOMY_MAX_DOCUMENTS";
/// Optional override for the taxonomy loader's import-depth bound.
pub const ANNUAL_REPORT_XBRL_MAX_DEPTH_ENV: &str = "APEXMAIL_EE_ANNUAL_REPORT_TAXONOMY_MAX_DEPTH";

/// The entity identifier scheme used for the Estonian business register; the
/// scheme is part of the context structure, never an element name.
pub const ENTITY_IDENTIFIER_SCHEME: &str = "https://ariregister.rik.ee";

/// Annual report lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnualReportStatus {
    /// Generated from the ledger; no human act yet.
    Draft,
    /// Management approved: authenticated approver + timestamp.
    ManagementApproved,
    /// Submitted: approval + authority receipt.
    Submitted,
}

impl AnnualReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::ManagementApproved => "management_approved",
            Self::Submitted => "submitted",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "draft" => Some(Self::Draft),
            "management_approved" => Some(Self::ManagementApproved),
            "submitted" => Some(Self::Submitted),
            _ => None,
        }
    }

    pub fn can_transition(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Draft, Self::ManagementApproved) | (Self::ManagementApproved, Self::Submitted)
        )
    }
}

/// Account identity/legal data resolved from `legal_entities` (never a
/// hard-coded constant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyIdentity {
    pub legal_name: String,
    pub registry_code: String,
    pub vat_number: Option<String>,
    pub country_code: String,
    pub currency: String,
}

/// One trial-balance line (the derivation input, mapped from
/// `v_accounting_trial_balance`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerBalanceLine {
    pub account_id: Uuid,
    pub account_code: String,
    pub account_name: String,
    pub account_type: String,
    pub account_role: Option<String>,
    pub debit_cents: i64,
    pub credit_cents: i64,
    pub balance_debit_positive: i64,
}

/// Bilanss aggregates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceSheet {
    pub assets_cents: i64,
    pub liabilities_cents: i64,
    pub equity_cents: i64,
    pub period_profit_cents: i64,
    pub total_liabilities_and_equity_cents: i64,
    pub balance_difference_cents: i64,
    pub balance_check_ok: bool,
}

/// Kasumiaruanne aggregates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomeStatement {
    pub revenue_cents: i64,
    pub expenses_cents: i64,
    pub net_profit_cents: i64,
}

/// Persisted annual report row.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AnnualReport {
    pub id: Uuid,
    pub legal_entity_id: Uuid,
    pub fiscal_period_id: Uuid,
    pub fiscal_year: i32,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub status: String,
    pub generated_at: DateTime<Utc>,
    pub generated_by: String,
    pub ledger_entry_count: i64,
    pub ledger_hash: String,
    pub balance_sheet: serde_json::Value,
    pub income_statement: serde_json::Value,
    pub structured_document: serde_json::Value,
    pub xbrl_instance: String,
    pub balance_check_ok: bool,
    pub balance_difference_cents: i64,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub submitted_by: Option<String>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub authority_receipt_reference: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Pure derivation
// ---------------------------------------------------------------------------

/// Validate a fiscal period for annual-report derivation.
///
/// Reversed periods are refused; zero-length periods are structurally legal
/// (end >= start) and derive an empty report rather than panicking.
pub fn validate_period(period_type: &str, start: NaiveDate, end: NaiveDate) -> Result<(), String> {
    if end < start {
        return Err(format!(
            "fiscal period end {end} is before start {start} (reversed period)"
        ));
    }
    if !matches!(period_type, "year" | "custom") {
        return Err(format!(
            "annual report requires a fiscal period of type 'year' (or 'custom'); got \
             {period_type:?}"
        ));
    }
    Ok(())
}

/// Derive the bilanss and kasumiaruanne from posted trial-balance lines.
///
/// Pure and panic-free: an empty input (a period with no postings) yields a
/// zeroed report.
pub fn derive_statements(lines: &[LedgerBalanceLine]) -> (BalanceSheet, IncomeStatement) {
    let mut assets = 0i64;
    let mut liabilities = 0i64;
    let mut equity = 0i64;
    let mut revenue = 0i64;
    let mut expenses = 0i64;

    for line in lines {
        match line.account_type.as_str() {
            // Assets grow on the debit side.
            "asset" => assets = assets.saturating_add(line.balance_debit_positive),
            // Liabilities/equity/revenue grow on the credit side.
            "liability" => liabilities = liabilities.saturating_sub(line.balance_debit_positive),
            "equity" => equity = equity.saturating_sub(line.balance_debit_positive),
            "revenue" => revenue = revenue.saturating_sub(line.balance_debit_positive),
            // Expenses grow on the debit side.
            "expense" => expenses = expenses.saturating_add(line.balance_debit_positive),
            _ => {}
        }
    }

    let period_profit = revenue.saturating_sub(expenses);
    let total_liabilities_and_equity = liabilities
        .saturating_add(equity)
        .saturating_add(period_profit);
    let difference = assets.saturating_sub(total_liabilities_and_equity);

    (
        BalanceSheet {
            assets_cents: assets,
            liabilities_cents: liabilities,
            equity_cents: equity,
            period_profit_cents: period_profit,
            total_liabilities_and_equity_cents: total_liabilities_and_equity,
            balance_difference_cents: difference,
            balance_check_ok: difference == 0,
        },
        IncomeStatement {
            revenue_cents: revenue,
            expenses_cents: expenses,
            net_profit_cents: period_profit,
        },
    )
}

/// Content hash of the exact ledger snapshot the report was derived from.
/// Any change to a posted line in the period changes this hash, so a
/// regeneration is provably a different derivation.
pub fn ledger_hash(
    fiscal_period_id: Uuid,
    entry_count: i64,
    lines: &[LedgerBalanceLine],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(fiscal_period_id.as_bytes());
    hasher.update(entry_count.to_be_bytes());
    for line in lines {
        hasher.update(line.account_code.as_bytes());
        hasher.update(b"|");
        hasher.update(line.account_type.as_bytes());
        hasher.update(b"|");
        hasher.update(line.debit_cents.to_be_bytes());
        hasher.update(b"|");
        hasher.update(line.credit_cents.to_be_bytes());
        hasher.update(b"|");
        hasher.update(line.balance_debit_positive.to_be_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// XBRL emission — taxonomy-driven
// ---------------------------------------------------------------------------

/// Annual-report slots the XBRL emitter can map onto taxonomy concepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReportSlot {
    Assets,
    Liabilities,
    Equity,
    Revenue,
    Expenses,
    PeriodProfit,
    NetProfit,
    CompanyName,
}

impl ReportSlot {
    /// Slots that must be bound for a report to be submission-ready.
    pub const REQUIRED: [ReportSlot; 6] = [
        ReportSlot::Assets,
        ReportSlot::Liabilities,
        ReportSlot::Equity,
        ReportSlot::Revenue,
        ReportSlot::Expenses,
        ReportSlot::NetProfit,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assets => "assets",
            Self::Liabilities => "liabilities",
            Self::Equity => "equity",
            Self::Revenue => "revenue",
            Self::Expenses => "expenses",
            Self::PeriodProfit => "period_profit",
            Self::NetProfit => "net_profit",
            Self::CompanyName => "company_name",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim() {
            "assets" => Some(Self::Assets),
            "liabilities" => Some(Self::Liabilities),
            "equity" => Some(Self::Equity),
            "revenue" => Some(Self::Revenue),
            "expenses" => Some(Self::Expenses),
            "period_profit" => Some(Self::PeriodProfit),
            "net_profit" => Some(Self::NetProfit),
            "company_name" => Some(Self::CompanyName),
            _ => None,
        }
    }
}

/// Maps annual-report slots to concepts of the configured taxonomy. The JSON
/// document is an object of `"slot": "concept reference"` pairs, where a
/// concept reference is `prefix:name` (using a prefix the taxonomy declares),
/// `{namespace}name`, or a bare local name in the taxonomy's target
/// namespace. Nothing is guessed: a slot without a mapping is reported as a
/// missing binding, and a reference to an undeclared concept is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaxonomyBinding {
    entries: BTreeMap<ReportSlot, String>,
}

impl TaxonomyBinding {
    pub fn from_json_str(json: &str) -> Result<Self, String> {
        let raw: BTreeMap<String, String> = serde_json::from_str(json)
            .map_err(|error| format!("taxonomy binding is not a JSON object of slot -> concept: {error}"))?;
        let mut entries = BTreeMap::new();
        for (name, reference) in raw {
            let slot = ReportSlot::from_name(&name).ok_or_else(|| {
                format!(
                    "unknown annual-report slot {name:?} in the taxonomy binding; expected one \
                     of: assets, liabilities, equity, revenue, expenses, period_profit, \
                     net_profit, company_name"
                )
            })?;
            entries.insert(slot, reference);
        }
        Ok(Self { entries })
    }

    pub fn from_json_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|error| {
            format!("cannot read taxonomy binding {}: {error}", path.display())
        })?;
        Self::from_json_str(&content)
    }

    pub fn reference(&self, slot: ReportSlot) -> Option<&str> {
        self.entries.get(&slot).map(String::as_str)
    }

    pub fn insert(&mut self, slot: ReportSlot, reference: impl Into<String>) {
        self.entries.insert(slot, reference.into());
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A CONFIGURED taxonomy package plus its concept binding. Loaded from the
/// environment ([`AnnualReportXbrlConfig::from_env`]) or supplied explicitly
/// (tests, callers that already hold a loaded taxonomy).
#[derive(Debug, Clone)]
pub struct AnnualReportXbrlConfig {
    pub taxonomy: XbrlTaxonomy,
    pub binding: Option<TaxonomyBinding>,
}

impl AnnualReportXbrlConfig {
    /// Load a taxonomy entry point (filesystem path or URI) and an optional
    /// binding document with the default loader bounds.
    pub fn from_source(source: &str, binding_path: Option<&Path>) -> Result<Self, String> {
        Self::from_source_with_limits(source, binding_path, &TaxonomyLimits::default())
    }

    pub fn from_source_with_limits(
        source: &str,
        binding_path: Option<&Path>,
        limits: &TaxonomyLimits,
    ) -> Result<Self, String> {
        let parsed = TaxonomySource::parse(source).map_err(|error| {
            format!("invalid {ANNUAL_REPORT_XBRL_TAXONOMY_ENV} value {source:?}: {error}")
        })?;
        let taxonomy = crate::xbrl_taxonomy::load_taxonomy(&parsed, limits).map_err(|error| {
            format!("failed to load the configured XBRL taxonomy from {source:?}: {error}")
        })?;
        let binding = match binding_path {
            Some(path) => Some(TaxonomyBinding::from_json_file(path)?),
            None => None,
        };
        Ok(Self { taxonomy, binding })
    }

    /// Resolve the configuration from the environment. `Ok(None)` means no
    /// entry point is configured, which keeps the report not submission-ready
    /// (and the readiness report says why). A configured but unloadable
    /// taxonomy is a hard error: an operator who configured a package must
    /// not silently receive an unvalidated document.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(source) = env_value(ANNUAL_REPORT_XBRL_TAXONOMY_ENV) else {
            return Ok(None);
        };
        let binding_path = env_value(ANNUAL_REPORT_XBRL_TAXONOMY_BINDING_ENV).map(PathBuf::from);
        let defaults = TaxonomyLimits::default();
        let limits = TaxonomyLimits {
            max_documents: env_usize(ANNUAL_REPORT_XBRL_MAX_DOCUMENTS_ENV)?
                .unwrap_or(defaults.max_documents),
            max_depth: env_usize(ANNUAL_REPORT_XBRL_MAX_DEPTH_ENV)?.unwrap_or(defaults.max_depth),
            ..defaults
        };
        Self::from_source_with_limits(&source, binding_path.as_deref(), &limits).map(Some)
    }
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_usize(key: &str) -> Result<Option<usize>, String> {
    match env_value(key) {
        None => Ok(None),
        Some(value) => value
            .parse::<usize>()
            .map(Some)
            .map_err(|error| format!("{key} must be a positive integer: {error}")),
    }
}

/// Resolved concept binding: every required slot mapped to a declared,
/// non-abstract taxonomy item.
#[derive(Debug, Clone)]
struct BoundConcepts {
    assets: QName,
    liabilities: QName,
    equity: QName,
    revenue: QName,
    expenses: QName,
    net_profit: QName,
    period_profit: Option<QName>,
    company_name: Option<QName>,
}

fn binding_failure(error: TaxonomyError, reference: &str) -> ValidationFailure {
    ValidationFailure::new(
        error.code(),
        format!("taxonomy binding reference {reference:?} cannot be used: {error}"),
    )
    .with_concepts(vec![reference.to_string()])
}

fn resolve_binding(
    taxonomy: &XbrlTaxonomy,
    binding: &TaxonomyBinding,
) -> Result<BoundConcepts, Vec<ValidationFailure>> {
    let mut failures: Vec<ValidationFailure> = Vec::new();
    let mut resolve = |slot: ReportSlot, required: bool| -> Option<QName> {
        let Some(reference) = binding.reference(slot) else {
            if required {
                failures.push(
                    ValidationFailure::new(
                        FAIL_BINDING_MISSING,
                        format!(
                            "the taxonomy binding does not map the required annual-report slot \
                             {:?}; map it to a declared concept of the taxonomy (target \
                             namespace {})",
                            slot.as_str(),
                            taxonomy.target_namespace
                        ),
                    )
                    .with_concepts(vec![slot.as_str().to_string()]),
                );
            }
            return None;
        };
        let qname = match taxonomy.resolve_qname(reference) {
            Ok(qname) => qname,
            Err(error) => {
                failures.push(binding_failure(error, reference));
                return None;
            }
        };
        match taxonomy.declare(&qname) {
            None => {
                failures.push(
                    ValidationFailure::new(
                        FAIL_BINDING_INVALID,
                        format!(
                            "the taxonomy binding maps {:?} to {reference:?}, which the loaded \
                             taxonomy does not declare (target namespace {})",
                            slot.as_str(),
                            taxonomy.target_namespace
                        ),
                    )
                    .with_concepts(vec![reference.to_string(), qname.clark()]),
                );
                None
            }
            Some(declared) if declared.is_abstract => {
                failures.push(
                    ValidationFailure::new(
                        FAIL_BINDING_INVALID,
                        format!(
                            "the taxonomy binding maps {:?} to abstract concept {reference:?}; \
                             abstract concepts cannot carry facts",
                            slot.as_str()
                        ),
                    )
                    .with_concepts(vec![reference.to_string()]),
                );
                None
            }
            Some(declared) if !declared.is_item => {
                failures.push(
                    ValidationFailure::new(
                        FAIL_BINDING_INVALID,
                        format!(
                            "the taxonomy binding maps {:?} to {reference:?}, which is not an \
                             XBRL item (substitution group xbrli:item)",
                            slot.as_str()
                        ),
                    )
                    .with_concepts(vec![reference.to_string()]),
                );
                None
            }
            Some(_) => Some(qname),
        }
    };

    let assets = resolve(ReportSlot::Assets, true);
    let liabilities = resolve(ReportSlot::Liabilities, true);
    let equity = resolve(ReportSlot::Equity, true);
    let revenue = resolve(ReportSlot::Revenue, true);
    let expenses = resolve(ReportSlot::Expenses, true);
    let net_profit = resolve(ReportSlot::NetProfit, true);
    let period_profit = resolve(ReportSlot::PeriodProfit, false);
    let company_name = resolve(ReportSlot::CompanyName, false);

    match (assets, liabilities, equity, revenue, expenses, net_profit) {
        (
            Some(assets),
            Some(liabilities),
            Some(equity),
            Some(revenue),
            Some(expenses),
            Some(net_profit),
        ) => Ok(BoundConcepts {
            assets,
            liabilities,
            equity,
            revenue,
            expenses,
            net_profit,
            period_profit,
            company_name,
        }),
        _ => Err(failures),
    }
}

/// The emitted XBRL artifacts plus the derived readiness statement. The
/// `document`/`extension` pair is exactly what the instance XML encodes, so a
/// caller (or a test) can re-validate it without re-parsing.
#[derive(Debug, Clone)]
pub struct AnnualReportXbrl {
    pub instance_xml: String,
    pub extension_schema_xml: String,
    pub extension_schema_name: String,
    pub instance_sha256: String,
    pub extension_schema_sha256: String,
    pub readiness: XbrlReadiness,
    pub document: InstanceDocument,
    pub extension: ExtensionSchema,
}

/// Build a well-formed XBRL 2.1 instance container.
///
/// This is the legacy extension-only entry point: without a configured
/// taxonomy every fact lives in the documented ApexMail extension namespace
/// and is declared in the emitted extension schema. See
/// [`build_annual_report_xbrl`] for the taxonomy-driven path; this function
/// returns its instance XML.
pub fn build_xbrl_instance(
    company: &CompanyIdentity,
    fiscal_year: i32,
    period_start: NaiveDate,
    period_end: NaiveDate,
    balance_sheet: &BalanceSheet,
    income_statement: &IncomeStatement,
    lines: &[LedgerBalanceLine],
) -> String {
    build_annual_report_xbrl(
        company,
        fiscal_year,
        period_start,
        period_end,
        balance_sheet,
        income_statement,
        lines,
        None,
    )
    .instance_xml
}

/// Emit the XBRL instance and extension schema for an annual report, driven
/// by the configured taxonomy when one is supplied.
///
/// The numbers come from the caller's ledger derivation; this function only
/// maps them onto concepts and validates the resulting facts. With no
/// taxonomy (or a binding that does not resolve) the emitted instance is the
/// extension-only container, and the readiness statement is NOT
/// submission-ready with the reason recorded.
#[allow(clippy::too_many_arguments)]
pub fn build_annual_report_xbrl(
    company: &CompanyIdentity,
    fiscal_year: i32,
    period_start: NaiveDate,
    period_end: NaiveDate,
    balance_sheet: &BalanceSheet,
    income_statement: &IncomeStatement,
    lines: &[LedgerBalanceLine],
    config: Option<&AnnualReportXbrlConfig>,
) -> AnnualReportXbrl {
    let mut missing: Vec<String> = Vec::new();
    let mut failures: Vec<ValidationFailure> = Vec::new();
    let mut bound: Option<BoundConcepts> = None;
    match config {
        None => missing.push(format!(
            "the Estonian annual-report taxonomy entry point is not configured; set \
             {ANNUAL_REPORT_XBRL_TAXONOMY_ENV} to a vendored e-aruande entry-point schema (a \
             filesystem path or URL) to make the XBRL output submission-ready"
        )),
        Some(config) => match &config.binding {
            None => missing.push(format!(
                "a taxonomy is loaded ({}), but no concept binding is configured; set {} to a \
                 JSON document mapping the annual-report slots to taxonomy concepts",
                config.taxonomy.entry_point, ANNUAL_REPORT_XBRL_TAXONOMY_BINDING_ENV
            )),
            Some(binding) => match resolve_binding(&config.taxonomy, binding) {
                Ok(resolved) => bound = Some(resolved),
                Err(binding_failures) => failures.extend(binding_failures),
            },
        },
    }

    let (mut document, extension) = if let (Some(config), Some(bound)) = (config, bound.as_ref())
    {
        let (candidate, candidate_extension) = build_report_facts(
            company,
            fiscal_year,
            period_start,
            period_end,
            balance_sheet,
            income_statement,
            lines,
            Some(bound),
        );
        let candidate_failures =
            validate_instance(&config.taxonomy, &candidate_extension, &candidate);
        if candidate_failures.is_empty() {
            (candidate, candidate_extension)
        } else {
            // A failing fact set is never stored: fall back to the
            // self-describing extension-only container and report the
            // failures, instead of silently fixing or emitting invalid
            // official-namespace facts.
            failures.extend(candidate_failures);
            build_report_facts(
                company,
                fiscal_year,
                period_start,
                period_end,
                balance_sheet,
                income_statement,
                lines,
                None,
            )
        }
    } else {
        build_report_facts(
            company,
            fiscal_year,
            period_start,
            period_end,
            balance_sheet,
            income_statement,
            lines,
            None,
        )
    };

    document.schema_refs = match config {
        Some(config) => vec![
            config.taxonomy.entry_point.clone(),
            XBRL_EXTENSION_SCHEMA_NAME.to_string(),
        ],
        None => vec![
            "urn:apexmail:xbrl:ee-annual-report:1".to_string(),
            XBRL_EXTENSION_SCHEMA_NAME.to_string(),
        ],
    };

    let readiness = if missing.is_empty() && failures.is_empty() {
        XbrlReadiness {
            submission_ready: true,
            taxonomy: config.map(|config| config.taxonomy.identity()),
            missing: Vec::new(),
            validation_failures: Vec::new(),
        }
    } else {
        XbrlReadiness {
            submission_ready: false,
            taxonomy: config.map(|config| config.taxonomy.identity()),
            missing,
            validation_failures: failures,
        }
    };

    let prefixes = namespace_prefixes(&document, config);
    let instance_xml = render_instance(&document, &prefixes, &readiness);
    let extension_schema_xml =
        render_extension_schema(&extension, config.map(|config| &config.taxonomy));
    let instance_sha256 = hex::encode(Sha256::digest(instance_xml.as_bytes()));
    let extension_schema_sha256 =
        hex::encode(Sha256::digest(extension_schema_xml.as_bytes()));

    AnnualReportXbrl {
        instance_xml,
        extension_schema_xml,
        extension_schema_name: XBRL_EXTENSION_SCHEMA_NAME.to_string(),
        instance_sha256,
        extension_schema_sha256,
        readiness,
        document,
        extension,
    }
}

#[allow(clippy::too_many_arguments)]
fn push_amount(
    facts: &mut Vec<Fact>,
    extension: &mut ExtensionSchema,
    concept: QName,
    context_ref: &str,
    cents: i64,
    period_type: PeriodType,
    balance: Option<Balance>,
    is_extension: bool,
) {
    if is_extension {
        extension.insert(DeclaredConcept {
            qname: concept.clone(),
            period_type: Some(period_type),
            balance,
            is_abstract: false,
            is_item: true,
            numeric: Some(NumericKind::Monetary),
            source: XBRL_EXTENSION_SCHEMA_NAME.to_string(),
        });
    }
    facts.push(Fact {
        concept,
        context_ref: context_ref.to_string(),
        unit_ref: Some("EUR".to_string()),
        value: FactValue::Numeric(DecimalAmount::from_cents(cents)),
        decimals: Some(Decimals::Finite(2)),
        id: None,
    });
}

/// Build the contexts, units and facts for a report. With `bound` the
/// statement totals use the configured taxonomy's concepts; without it every
/// fact is an ApexMail extension concept declared in the returned extension
/// schema.
#[allow(clippy::too_many_arguments)]
fn build_report_facts(
    company: &CompanyIdentity,
    fiscal_year: i32,
    period_start: NaiveDate,
    period_end: NaiveDate,
    balance_sheet: &BalanceSheet,
    income_statement: &IncomeStatement,
    lines: &[LedgerBalanceLine],
    bound: Option<&BoundConcepts>,
) -> (InstanceDocument, ExtensionSchema) {
    let duration_context = format!("duration-FY{fiscal_year}");
    let instant_context = format!("instant-{period_end}");
    let context = |id: String, period: ContextPeriod| Context {
        id,
        entity_identifier: Some(company.registry_code.clone()),
        entity_scheme: Some(ENTITY_IDENTIFIER_SCHEME.to_string()),
        period: Some(period),
    };
    let contexts = vec![
        context(
            duration_context.clone(),
            ContextPeriod::Duration {
                start: period_start,
                end: period_end,
            },
        ),
        context(
            instant_context.clone(),
            ContextPeriod::Instant { date: period_end },
        ),
    ];
    let units = vec![Unit {
        id: "EUR".to_string(),
        measures: vec![format!("iso4217:{}", company.currency)],
    }];

    let mut facts: Vec<Fact> = Vec::new();
    let mut extension = ExtensionSchema {
        target_namespace: XBRL_EXTENSION_NAMESPACE.to_string(),
        concepts: BTreeMap::new(),
    };

    match bound {
        Some(bound) => {
            push_amount(&mut facts, &mut extension, 
                bound.assets.clone(),
                &instant_context,
                balance_sheet.assets_cents,
                PeriodType::Instant,
                None,
                false,
            );
            push_amount(&mut facts, &mut extension, 
                bound.liabilities.clone(),
                &instant_context,
                balance_sheet.liabilities_cents,
                PeriodType::Instant,
                None,
                false,
            );
            push_amount(&mut facts, &mut extension, 
                bound.equity.clone(),
                &instant_context,
                balance_sheet.equity_cents,
                PeriodType::Instant,
                None,
                false,
            );
            push_amount(&mut facts, &mut extension, 
                bound.revenue.clone(),
                &duration_context,
                income_statement.revenue_cents,
                PeriodType::Duration,
                None,
                false,
            );
            push_amount(&mut facts, &mut extension, 
                bound.expenses.clone(),
                &duration_context,
                income_statement.expenses_cents,
                PeriodType::Duration,
                None,
                false,
            );
            push_amount(&mut facts, &mut extension, 
                bound.net_profit.clone(),
                &duration_context,
                income_statement.net_profit_cents,
                PeriodType::Duration,
                None,
                false,
            );
            if let Some(period_profit) = &bound.period_profit {
                push_amount(&mut facts, &mut extension, 
                    period_profit.clone(),
                    &duration_context,
                    balance_sheet.period_profit_cents,
                    PeriodType::Duration,
                    None,
                    false,
                );
            }
            if let Some(company_name) = &bound.company_name {
                facts.push(Fact {
                    concept: company_name.clone(),
                    context_ref: duration_context.clone(),
                    unit_ref: None,
                    value: FactValue::Text(company.legal_name.clone()),
                    decimals: None,
                    id: None,
                });
            }
        }
        None => {
            let extension_concept = |name: &str| QName::new(XBRL_EXTENSION_NAMESPACE, name);
            push_amount(&mut facts, &mut extension, 
                extension_concept("Assets"),
                &instant_context,
                balance_sheet.assets_cents,
                PeriodType::Instant,
                Some(Balance::Debit),
                true,
            );
            push_amount(&mut facts, &mut extension, 
                extension_concept("Liabilities"),
                &instant_context,
                balance_sheet.liabilities_cents,
                PeriodType::Instant,
                Some(Balance::Credit),
                true,
            );
            push_amount(&mut facts, &mut extension, 
                extension_concept("Equity"),
                &instant_context,
                balance_sheet.equity_cents,
                PeriodType::Instant,
                Some(Balance::Credit),
                true,
            );
            push_amount(&mut facts, &mut extension, 
                extension_concept("ProfitLossForPeriod"),
                &duration_context,
                balance_sheet.period_profit_cents,
                PeriodType::Duration,
                Some(Balance::Credit),
                true,
            );
            push_amount(&mut facts, &mut extension, 
                extension_concept("Revenue"),
                &duration_context,
                income_statement.revenue_cents,
                PeriodType::Duration,
                Some(Balance::Credit),
                true,
            );
            push_amount(&mut facts, &mut extension, 
                extension_concept("Expenses"),
                &duration_context,
                income_statement.expenses_cents,
                PeriodType::Duration,
                Some(Balance::Debit),
                true,
            );
            push_amount(&mut facts, &mut extension, 
                extension_concept("NetProfit"),
                &duration_context,
                income_statement.net_profit_cents,
                PeriodType::Duration,
                Some(Balance::Credit),
                true,
            );
        }
    }

    // Account-level facts (traceable to chart-of-accounts codes). The
    // official taxonomy has no concept for an individual ApexMail account, so
    // these are always ApexMail extension elements, visibly in their own
    // namespace and declared in the extension schema.
    let mut used_names: BTreeSet<String> = BTreeSet::new();
    for line in lines {
        let (period_type, context_ref, balance) = match line.account_type.as_str() {
            "revenue" => (
                PeriodType::Duration,
                duration_context.as_str(),
                Balance::Credit,
            ),
            "expense" => (
                PeriodType::Duration,
                duration_context.as_str(),
                Balance::Debit,
            ),
            "liability" | "equity" => (
                PeriodType::Instant,
                instant_context.as_str(),
                Balance::Credit,
            ),
            _ => (
                PeriodType::Instant,
                instant_context.as_str(),
                Balance::Debit,
            ),
        };
        let base = xml_fact_name(&line.account_code);
        let mut name = format!("Account_{base}");
        let mut suffix = 2;
        while !used_names.insert(name.clone()) {
            name = format!("Account_{base}_{suffix}");
            suffix += 1;
        }
        push_amount(&mut facts, &mut extension, 
            QName::new(XBRL_EXTENSION_NAMESPACE, name),
            context_ref,
            line.balance_debit_positive,
            period_type,
            Some(balance),
            true,
        );
    }

    (
        InstanceDocument {
            contexts,
            units,
            facts,
            schema_refs: Vec::new(),
            namespaces: BTreeMap::new(),
        },
        extension,
    )
}

fn namespace_prefixes(
    document: &InstanceDocument,
    config: Option<&AnnualReportXbrlConfig>,
) -> BTreeMap<String, String> {
    let mut prefixes: BTreeMap<String, String> = BTreeMap::new();
    prefixes.insert(
        XBRL_EXTENSION_NAMESPACE.to_string(),
        "apex".to_string(),
    );
    let mut next = 0usize;
    for fact in &document.facts {
        if prefixes.contains_key(&fact.concept.namespace) {
            continue;
        }
        let prefix = match fact.concept.namespace.as_str() {
            XBRL_INSTANCE_NAMESPACE => "xbrli".to_string(),
            XBRL_LINKBASE_NAMESPACE => "link".to_string(),
            namespace => config
                .and_then(|config| config.taxonomy.prefix_for_namespace(namespace))
                .map(str::to_string)
                .unwrap_or_else(|| {
                    next += 1;
                    format!("ns{next}")
                }),
        };
        prefixes.insert(fact.concept.namespace.clone(), prefix);
    }
    prefixes
}

fn render_instance(
    document: &InstanceDocument,
    prefixes: &BTreeMap<String, String>,
    readiness: &XbrlReadiness,
) -> String {
    let mut xml = String::with_capacity(8192);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let comment = format!(
        " Generated by ApexMail from posted journal lines of a CLOSED fiscal period. {} \
         Extension facts use the documented ApexMail namespace {XBRL_EXTENSION_NAMESPACE} and \
         are declared in {XBRL_EXTENSION_SCHEMA_NAME} (stored in \
         structured_document.xbrl.extension_schema). ",
        readiness.summary()
    );
    xml.push_str(&format!("<!--{}-->\n", sanitize_xml_comment(&comment)));
    xml.push_str("<xbrli:xbrl");
    xml.push_str(&format!(
        " xmlns:xbrli=\"{XBRL_INSTANCE_NAMESPACE}\" \
         xmlns:link=\"{XBRL_LINKBASE_NAMESPACE}\" \
         xmlns:xlink=\"http://www.w3.org/1999/xlink\" \
         xmlns:iso4217=\"{XBRL_ISO4217_NAMESPACE}\""
    ));
    for (namespace, prefix) in prefixes {
        if matches!(
            namespace.as_str(),
            XBRL_INSTANCE_NAMESPACE | XBRL_LINKBASE_NAMESPACE
        ) {
            continue;
        }
        xml.push_str(&format!(" xmlns:{prefix}=\"{}\"", xml_escape(namespace)));
    }
    xml.push_str(">\n");

    for schema_ref in &document.schema_refs {
        xml.push_str(&format!(
            "  <link:schemaRef xlink:type=\"simple\" xlink:href=\"{}\"/>\n",
            xml_escape(schema_ref)
        ));
    }

    for context in &document.contexts {
        xml.push_str(&format!(
            "  <xbrli:context id=\"{}\">\n",
            xml_escape(&context.id)
        ));
        xml.push_str(&format!(
            "    <xbrli:entity><xbrli:identifier scheme=\"{}\">{}</xbrli:identifier></xbrli:entity>\n",
            xml_escape(context.entity_scheme.as_deref().unwrap_or("")),
            xml_escape(context.entity_identifier.as_deref().unwrap_or(""))
        ));
        match context.period {
            Some(ContextPeriod::Instant { date }) => {
                xml.push_str(&format!(
                    "    <xbrli:period><xbrli:instant>{date}</xbrli:instant></xbrli:period>\n"
                ));
            }
            Some(ContextPeriod::Duration { start, end }) => {
                xml.push_str(&format!(
                    "    <xbrli:period><xbrli:startDate>{start}</xbrli:startDate>\
                     <xbrli:endDate>{end}</xbrli:endDate></xbrli:period>\n"
                ));
            }
            None => xml.push_str("    <xbrli:period/>\n"),
        }
        xml.push_str("  </xbrli:context>\n");
    }

    for unit in &document.units {
        xml.push_str(&format!(
            "  <xbrli:unit id=\"{}\">",
            xml_escape(&unit.id)
        ));
        for measure in &unit.measures {
            xml.push_str(&format!(
                "<xbrli:measure>{}</xbrli:measure>",
                xml_escape(measure)
            ));
        }
        xml.push_str("</xbrli:unit>\n");
    }

    for fact in &document.facts {
        let prefix = prefixes
            .get(&fact.concept.namespace)
            .map(String::as_str)
            .unwrap_or("apex");
        let element = format!("{prefix}:{}", fact.concept.name);
        let mut attributes = format!(" contextRef=\"{}\"", xml_escape(&fact.context_ref));
        if let Some(unit_ref) = &fact.unit_ref {
            attributes.push_str(&format!(" unitRef=\"{}\"", xml_escape(unit_ref)));
        }
        if let Some(decimals) = fact.decimals {
            let value = match decimals {
                Decimals::Finite(places) => places.to_string(),
                Decimals::Infinite => "INF".to_string(),
            };
            attributes.push_str(&format!(" decimals=\"{value}\""));
        }
        let value = match &fact.value {
            FactValue::Numeric(amount) => amount.to_display(),
            FactValue::Text(text) => xml_escape(text),
        };
        xml.push_str(&format!("  <{element}{attributes}>{value}</{element}>\n"));
    }

    xml.push_str("</xbrli:xbrl>\n");
    xml
}

fn render_extension_schema(
    extension: &ExtensionSchema,
    taxonomy: Option<&XbrlTaxonomy>,
) -> String {
    let mut xml = String::with_capacity(4096);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<!-- ApexMail extension schema: declares every non-taxonomy element the annual-report \
         instance reports. These elements live in their own namespace \
         ({XBRL_EXTENSION_NAMESPACE}) and never masquerade as official concepts. \
         Generated by compliance::annual_report. -->\n",
    ));
    xml.push_str("<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"");
    xml.push_str(&format!(
        " xmlns:xbrli=\"{XBRL_INSTANCE_NAMESPACE}\""
    ));
    xml.push_str(&format!(
        " xmlns:link=\"{XBRL_LINKBASE_NAMESPACE}\""
    ));
    xml.push_str(" xmlns:xlink=\"http://www.w3.org/1999/xlink\"");
    xml.push_str(&format!(
        " xmlns:apex=\"{XBRL_EXTENSION_NAMESPACE}\""
    ));
    xml.push_str(&format!(
        " targetNamespace=\"{XBRL_EXTENSION_NAMESPACE}\" elementFormDefault=\"qualified\" \
         id=\"apex-ee-annual-report-extension\">\n"
    ));
    xml.push_str(&format!(
        "  <xs:import namespace=\"{XBRL_INSTANCE_NAMESPACE}\"/>\n"
    ));
    if let Some(taxonomy) = taxonomy {
        xml.push_str(&format!(
            "  <xs:import namespace=\"{}\" schemaLocation=\"{}\"/>\n",
            xml_escape(&taxonomy.target_namespace),
            xml_escape(&taxonomy.entry_point)
        ));
    }
    for concept in extension.concepts.values() {
        let period_type = concept
            .period_type
            .map(PeriodType::as_str)
            .unwrap_or("duration");
        match concept.numeric {
            Some(_) => {
                let balance = match concept.balance {
                    Some(Balance::Debit) => "debit",
                    Some(Balance::Credit) => "credit",
                    None => "debit",
                };
                xml.push_str(&format!(
                    "  <xs:element name=\"{}\" id=\"apex_{}\" type=\"xbrli:monetaryItemType\" \
                     substitutionGroup=\"xbrli:item\" xbrli:periodType=\"{period_type}\" \
                     xbrli:balance=\"{balance}\"/>\n",
                    concept.qname.name, concept.qname.name
                ));
            }
            None => {
                xml.push_str(&format!(
                    "  <xs:element name=\"{}\" id=\"apex_{}\" type=\"xbrli:stringItemType\" \
                     substitutionGroup=\"xbrli:item\" xbrli:periodType=\"{period_type}\"/>\n",
                    concept.qname.name, concept.qname.name
                ));
            }
        }
    }
    xml.push_str("</xs:schema>\n");
    xml
}

/// XML comments must not contain `--` or end with `-`.
fn sanitize_xml_comment(text: &str) -> String {
    let mut sanitized = text.replace("--", "- -");
    if sanitized.ends_with('-') {
        sanitized.push(' ');
    }
    sanitized
}

/// Format euro cents as a decimal amount (`12345` -> `123.45`), without
/// floating point.
pub fn format_cents(cents: i64) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let absolute = cents.unsigned_abs();
    format!("{sign}{}.{:02}", absolute / 100, absolute % 100)
}

/// Sanitize an account code into an XML element-name fragment (QName rules).
fn xml_fact_name(code: &str) -> String {
    let mut name: String = code
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if name.is_empty() || name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        name.insert(0, 'a');
    }
    name
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ---------------------------------------------------------------------------
// Persistence / orchestration
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct FiscalPeriodRow {
    id: Uuid,
    period_type: String,
    label: String,
    start_date: NaiveDate,
    end_date: NaiveDate,
    status: String,
    legal_name: String,
    registry_code: String,
    vat_number: Option<String>,
    country_code: String,
    default_currency: String,
}

/// Generate (or regenerate, while draft) the annual report for a CLOSED
/// fiscal period.
///
/// `actor` is the authenticated identity performing the machine generation;
/// it is recorded but confers no approval.
///
/// The XBRL taxonomy is resolved from the environment
/// ([`AnnualReportXbrlConfig::from_env`]). Without a configured entry point
/// the report is generated as today and is explicitly NOT submission-ready;
/// a configured but unloadable taxonomy is a hard error.
pub async fn generate_annual_report(
    db: &PgPool,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
    actor: &str,
) -> Result<AnnualReport, String> {
    let config = AnnualReportXbrlConfig::from_env()?;
    generate_annual_report_configured(db, legal_entity_id, fiscal_period_id, actor, config.as_ref())
        .await
}

/// Generate (or regenerate, while draft) the annual report with an explicit
/// taxonomy configuration. `None` keeps the documented extension-only output
/// and the not-submission-ready readiness statement.
pub async fn generate_annual_report_configured(
    db: &PgPool,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
    actor: &str,
    xbrl_config: Option<&AnnualReportXbrlConfig>,
) -> Result<AnnualReport, String> {
    let actor = actor.trim();
    if actor.is_empty() {
        return Err("annual report generation requires an authenticated actor".to_string());
    }

    let period = sqlx::query_as::<_, FiscalPeriodRow>(
        r#"
        SELECT p.id, p.period_type, p.label, p.start_date, p.end_date,
               p.status, le.legal_name, le.registry_code, le.vat_number,
               le.country_code, le.default_currency
        FROM fiscal_periods p
        JOIN legal_entities le ON le.id = p.legal_entity_id
        WHERE p.id = $1 AND p.legal_entity_id = $2
        "#,
    )
    .bind(fiscal_period_id)
    .bind(legal_entity_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load fiscal period: {error}"))?
    .ok_or_else(|| {
        format!("fiscal period {fiscal_period_id} not found for legal entity {legal_entity_id}")
    })?;

    validate_period(&period.period_type, period.start_date, period.end_date)?;

    if !matches!(period.status.as_str(), "closed" | "locked") {
        return Err(format!(
            "fiscal period {} is {}; the annual report must derive from a CLOSED period",
            period.id, period.status
        ));
    }

    let lines = fetch_trial_balance(db, legal_entity_id, fiscal_period_id).await?;
    let entry_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM v_accounting_posted_entries \
         WHERE legal_entity_id = $1 AND fiscal_period_id = $2",
    )
    .bind(legal_entity_id)
    .bind(fiscal_period_id)
    .fetch_one(db)
    .await
    .map_err(|error| format!("failed to count posted entries: {error}"))?;

    let (balance_sheet, income_statement) = derive_statements(&lines);
    let hash = ledger_hash(fiscal_period_id, entry_count, &lines);
    let company = CompanyIdentity {
        legal_name: period.legal_name.clone(),
        registry_code: period.registry_code.clone(),
        vat_number: period.vat_number.clone(),
        country_code: period.country_code.clone(),
        currency: period.default_currency.clone(),
    };
    let xbrl = build_annual_report_xbrl(
        &company,
        period.end_date.year(),
        period.start_date,
        period.end_date,
        &balance_sheet,
        &income_statement,
        &lines,
        xbrl_config,
    );
    let structured = build_structured_document(
        &period,
        &company,
        actor,
        entry_count,
        &hash,
        &balance_sheet,
        &income_statement,
        &lines,
        &xbrl,
    );

    let balance_sheet_json = serde_json::to_value(balance_sheet)
        .map_err(|error| format!("failed to serialize balance sheet: {error}"))?;
    let income_statement_json = serde_json::to_value(income_statement)
        .map_err(|error| format!("failed to serialize income statement: {error}"))?;

    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin annual report generation: {error}"))?;

    let existing: Option<String> = sqlx::query_scalar(
        "SELECT status FROM annual_reports \
         WHERE legal_entity_id = $1 AND fiscal_period_id = $2 FOR UPDATE",
    )
    .bind(legal_entity_id)
    .bind(fiscal_period_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("failed to lock existing annual report: {error}"))?;

    if let Some(status) = existing.as_deref() {
        if status != "draft" {
            return Err(format!(
                "annual report for this period is {status}; an approved/submitted report is a \
                 human legal act and cannot be regenerated"
            ));
        }
    }

    let report_id: Uuid = if existing.is_some() {
        sqlx::query_scalar(
            r#"
            UPDATE annual_reports
            SET fiscal_year = $3,
                period_start = $4,
                period_end = $5,
                generated_at = NOW(),
                generated_by = $6,
                ledger_entry_count = $7,
                ledger_hash = $8,
                balance_sheet = $9,
                income_statement = $10,
                structured_document = $11,
                xbrl_instance = $12,
                balance_check_ok = $13,
                balance_difference_cents = $14,
                updated_at = NOW()
            WHERE legal_entity_id = $1 AND fiscal_period_id = $2 AND status = 'draft'
            RETURNING id
            "#,
        )
        .bind(legal_entity_id)
        .bind(fiscal_period_id)
        .bind(period.end_date.year())
        .bind(period.start_date)
        .bind(period.end_date)
        .bind(actor)
        .bind(entry_count)
        .bind(&hash)
        .bind(&balance_sheet_json)
        .bind(&income_statement_json)
        .bind(&structured)
        .bind(&xbrl.instance_xml)
        .bind(balance_sheet.balance_check_ok)
        .bind(balance_sheet.balance_difference_cents)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| format!("failed to regenerate annual report: {error}"))?
    } else {
        sqlx::query_scalar(
            r#"
            INSERT INTO annual_reports
                (legal_entity_id, fiscal_period_id, fiscal_year, period_start, period_end,
                 generated_by, ledger_entry_count, ledger_hash, balance_sheet,
                 income_statement, structured_document, xbrl_instance, balance_check_ok,
                 balance_difference_cents)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id
            "#,
        )
        .bind(legal_entity_id)
        .bind(fiscal_period_id)
        .bind(period.end_date.year())
        .bind(period.start_date)
        .bind(period.end_date)
        .bind(actor)
        .bind(entry_count)
        .bind(&hash)
        .bind(&balance_sheet_json)
        .bind(&income_statement_json)
        .bind(&structured)
        .bind(&xbrl.instance_xml)
        .bind(balance_sheet.balance_check_ok)
        .bind(balance_sheet.balance_difference_cents)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| format!("failed to insert annual report: {error}"))?
    };

    // Replace the derivation snapshot lines.
    sqlx::query("DELETE FROM annual_report_lines WHERE report_id = $1")
        .bind(report_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("failed to clear annual report lines: {error}"))?;
    for line in &lines {
        let section = match line.account_type.as_str() {
            "asset" => "assets",
            "liability" => "liabilities",
            "equity" => "equity",
            "revenue" => "revenue",
            "expense" => "expenses",
            _ => continue,
        };
        let statement = if matches!(line.account_type.as_str(), "revenue" | "expense") {
            "income_statement"
        } else {
            "balance_sheet"
        };
        sqlx::query(
            r#"
            INSERT INTO annual_report_lines
                (report_id, statement, section, account_id, account_code, account_name,
                 account_type, account_role, debit_cents, credit_cents, balance_cents)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(report_id)
        .bind(statement)
        .bind(section)
        .bind(line.account_id)
        .bind(&line.account_code)
        .bind(&line.account_name)
        .bind(&line.account_type)
        .bind(&line.account_role)
        .bind(line.debit_cents)
        .bind(line.credit_cents)
        .bind(line.balance_debit_positive)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("failed to insert annual report line: {error}"))?;
    }

    sqlx::query(
        "INSERT INTO annual_report_events (report_id, event, actor, detail) \
         VALUES ($1, 'generated', $2, $3)",
    )
    .bind(report_id)
    .bind(actor)
    .bind(serde_json::json!({
        "ledger_hash": hash,
        "ledger_entry_count": entry_count,
        "balance_check_ok": balance_sheet.balance_check_ok,
    }))
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to record generation event: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("failed to commit annual report generation: {error}"))?;

    get_annual_report(db, report_id)
        .await?
        .ok_or_else(|| "annual report missing after generation".to_string())
}

async fn fetch_trial_balance(
    db: &PgPool,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
) -> Result<Vec<LedgerBalanceLine>, String> {
    let rows = sqlx::query_as::<_, TrialBalanceRow>(
        "SELECT account_id, account_code, account_name, account_type, account_role, \
                debit_cents, credit_cents, balance_debit_positive \
         FROM v_accounting_trial_balance \
         WHERE legal_entity_id = $1 AND fiscal_period_id = $2 \
         ORDER BY account_code",
    )
    .bind(legal_entity_id)
    .bind(fiscal_period_id)
    .fetch_all(db)
    .await
    .map_err(|error| format!("failed to read trial balance: {error}"))?;
    Ok(rows
        .into_iter()
        .map(|row| LedgerBalanceLine {
            account_id: row.account_id,
            account_code: row.account_code,
            account_name: row.account_name,
            account_type: row.account_type,
            account_role: row.account_role,
            debit_cents: row.debit_cents,
            credit_cents: row.credit_cents,
            balance_debit_positive: row.balance_debit_positive,
        })
        .collect())
}

#[derive(Debug, sqlx::FromRow)]
struct TrialBalanceRow {
    account_id: Uuid,
    account_code: String,
    account_name: String,
    account_type: String,
    account_role: Option<String>,
    debit_cents: i64,
    credit_cents: i64,
    balance_debit_positive: i64,
}

#[allow(clippy::too_many_arguments)]
fn build_structured_document(
    period: &FiscalPeriodRow,
    company: &CompanyIdentity,
    actor: &str,
    entry_count: i64,
    ledger_hash: &str,
    balance_sheet: &BalanceSheet,
    income_statement: &IncomeStatement,
    lines: &[LedgerBalanceLine],
    xbrl: &AnnualReportXbrl,
) -> serde_json::Value {
    let mut warnings: Vec<String> = Vec::new();
    if !balance_sheet.balance_check_ok {
        warnings.push(format!(
            "the accounting equation does not balance by {} cents; review the ledger before \
             approval",
            balance_sheet.balance_difference_cents
        ));
    }
    if entry_count == 0 {
        warnings.push(
            "the closed period contains no posted journal entries; all statement values are zero"
                .to_string(),
        );
    }
    if !xbrl.readiness.submission_ready {
        warnings.push(format!(
            "the XBRL output is NOT submission-ready: {}",
            xbrl.readiness.summary()
        ));
    }

    serde_json::json!({
        "format": ANNUAL_REPORT_FORMAT,
        "status": AnnualReportStatus::Draft.as_str(),
        "legal_act_notice": "Generation is a machine act and does not approve or submit this \
            report. Approval requires an authenticated approver; submission requires the \
            approval plus an authority receipt reference.",
        "generated_at": Utc::now().to_rfc3339(),
        "generated_by": actor,
        "company": {
            "legal_name": &company.legal_name,
            "registry_code": &company.registry_code,
            "vat_number": &company.vat_number,
            "country_code": &company.country_code,
            "currency": &company.currency,
        },
        "fiscal_year": period.end_date.year(),
        "period": {
            "fiscal_period_id": period.id,
            "label": period.label,
            "start": period.start_date,
            "end": period.end_date,
            "ledger_status": period.status,
        },
        "balance_sheet": balance_sheet,
        "income_statement": income_statement,
        "accounts": lines.iter().map(|line| serde_json::json!({
            "account_id": line.account_id,
            "account_code": line.account_code,
            "account_name": line.account_name,
            "account_type": line.account_type,
            "account_role": line.account_role,
            "debit_cents": line.debit_cents,
            "credit_cents": line.credit_cents,
            "balance_debit_positive_cents": line.balance_debit_positive,
        })).collect::<Vec<_>>(),
        "ledger_provenance": {
            "derivation_views": [
                "v_accounting_trial_balance",
                "v_accounting_posted_entries",
            ],
            "fiscal_period_id": period.id,
            "posted_entry_count": entry_count,
            "ledger_hash": ledger_hash,
        },
        "xbrl": {
            // Existing readers keep these fields unchanged.
            "instance_embedded": true,
            "instance_sha256": &xbrl.instance_sha256,
            "namespace": XBRL_EXTENSION_NAMESPACE,
            "official_estonian_taxonomy": false,
            "note": xbrl_note(&xbrl.readiness),
            // Added for taxonomy-driven readiness (auditable after the fact).
            "submission_ready": xbrl.readiness.submission_ready,
            "readiness": &xbrl.readiness,
            "extension_schema": {
                "name": &xbrl.extension_schema_name,
                "sha256": &xbrl.extension_schema_sha256,
                "xml": &xbrl.extension_schema_xml,
            },
        },
        "warnings": warnings,
    })
}

/// The honest note that travels with the instance: what the readiness claim
/// covers, and what it does not.
fn xbrl_note(readiness: &XbrlReadiness) -> String {
    match (&readiness.taxonomy, readiness.submission_ready) {
        (Some(identity), true) => format!(
            "Well-formed XBRL 2.1 instance emitted through the configured taxonomy {} (target \
             namespace {}, digest {} over {} document(s)) and validated against it: \
             submission-ready for that taxonomy. The official Estonian e-aruande taksonoomia is \
             not vendored by this repository, and nothing here certifies that the configured \
             package is the registrar's official one.",
            identity.entry_point,
            identity.target_namespace,
            identity.digest,
            identity.document_count
        ),
        (Some(identity), false) => format!(
            "Well-formed XBRL 2.1 instance container. A taxonomy is configured ({}) but the \
             report is NOT submission-ready: {}",
            identity.entry_point,
            readiness.summary()
        ),
        (None, _) => format!(
            "Well-formed XBRL 2.1 container in the documented ApexMail extension namespace \
             ({XBRL_EXTENSION_NAMESPACE}), with every extension fact declared in the \
             accompanying extension schema. NOT submission-ready: {}",
            readiness.summary()
        ),
    }
}

/// The documented state transition: draft -> management_approved.
///
/// An authenticated approver identity is mandatory; an empty approver is
/// refused (generation can never approve itself).
pub async fn approve_annual_report(
    db: &PgPool,
    report_id: Uuid,
    approver: &str,
    note: Option<&str>,
) -> Result<(), String> {
    let approver = approver.trim();
    if approver.is_empty() {
        return Err(
            "approval requires an authenticated approver identity; refusal to approve without \
             one"
            .to_string(),
        );
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin approval: {error}"))?;
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM annual_reports WHERE id = $1 FOR UPDATE")
            .bind(report_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| format!("failed to lock annual report: {error}"))?;
    let Some(status) = status else {
        return Err(format!("annual report {report_id} not found"));
    };
    let from = AnnualReportStatus::from_db(&status)
        .ok_or_else(|| format!("unknown annual report status {status:?}"))?;
    if !from.can_transition(AnnualReportStatus::ManagementApproved) {
        return Err(format!(
            "illegal annual report transition {status} -> management_approved"
        ));
    }

    sqlx::query(
        "UPDATE annual_reports SET status = 'management_approved', approved_by = $2, \
         approved_at = NOW(), updated_at = NOW() WHERE id = $1",
    )
    .bind(report_id)
    .bind(approver)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to approve annual report: {error}"))?;

    sqlx::query(
        "INSERT INTO annual_report_events (report_id, event, actor, detail) \
         VALUES ($1, 'management_approved', $2, $3)",
    )
    .bind(report_id)
    .bind(approver)
    .bind(serde_json::json!({ "note": note }))
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to record approval event: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("failed to commit approval: {error}"))?;
    Ok(())
}

/// Record the submission of an approved report.
///
/// Requires the authenticated submitting actor AND a non-empty authority
/// receipt reference; the receipt payload (registration confirmation) is
/// stored as evidence.
pub async fn record_annual_report_submission(
    db: &PgPool,
    report_id: Uuid,
    actor: &str,
    authority_receipt_reference: &str,
    authority_receipt_payload: Option<serde_json::Value>,
) -> Result<(), String> {
    let actor = actor.trim();
    if actor.is_empty() {
        return Err("submission requires an authenticated actor".to_string());
    }
    let reference = authority_receipt_reference.trim();
    if reference.is_empty() {
        return Err(
            "submission requires the authority receipt reference; a report is never marked \
             submitted without evidence that the authority received it"
                .to_string(),
        );
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin submission: {error}"))?;
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM annual_reports WHERE id = $1 FOR UPDATE")
            .bind(report_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| format!("failed to lock annual report: {error}"))?;
    let Some(status) = status else {
        return Err(format!("annual report {report_id} not found"));
    };
    if status != AnnualReportStatus::ManagementApproved.as_str() {
        return Err(format!(
            "annual report must be management_approved before submission (current: {status})"
        ));
    }

    let payload = authority_receipt_payload.unwrap_or_else(|| {
        serde_json::json!({
            "reference": reference,
            "recorded_by": actor,
        })
    });

    sqlx::query(
        "UPDATE annual_reports SET status = 'submitted', submitted_by = $2, \
         submitted_at = NOW(), authority_receipt_reference = $3, \
         authority_receipt_payload = $4, updated_at = NOW() WHERE id = $1",
    )
    .bind(report_id)
    .bind(actor)
    .bind(reference)
    .bind(&payload)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to submit annual report: {error}"))?;

    sqlx::query(
        "INSERT INTO annual_report_events (report_id, event, actor, detail) \
         VALUES ($1, 'submitted', $2, $3)",
    )
    .bind(report_id)
    .bind(actor)
    .bind(serde_json::json!({
        "authority_receipt_reference": reference,
        "receipt_payload": payload,
    }))
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failed to record submission event: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("failed to commit submission: {error}"))?;
    Ok(())
}

/// Load one annual report.
pub async fn get_annual_report(
    db: &PgPool,
    report_id: Uuid,
) -> Result<Option<AnnualReport>, String> {
    sqlx::query_as::<_, AnnualReport>(
        r#"
        SELECT id, legal_entity_id, fiscal_period_id, fiscal_year, period_start, period_end,
               status, generated_at, generated_by, ledger_entry_count, ledger_hash,
               balance_sheet, income_statement, structured_document, xbrl_instance,
               balance_check_ok, balance_difference_cents, approved_by, approved_at,
               submitted_by, submitted_at, authority_receipt_reference, created_at, updated_at
        FROM annual_reports
        WHERE id = $1
        "#,
    )
    .bind(report_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load annual report: {error}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn d(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).expect("test date")
    }

    fn line(
        code: &str,
        account_type: &str,
        debit: i64,
        credit: i64,
        balance: i64,
    ) -> LedgerBalanceLine {
        LedgerBalanceLine {
            account_id: Uuid::new_v4(),
            account_code: code.into(),
            account_name: code.into(),
            account_type: account_type.into(),
            account_role: None,
            debit_cents: debit,
            credit_cents: credit,
            balance_debit_positive: balance,
        }
    }

    #[test]
    fn status_names_round_trip_and_machine_is_one_way() {
        for status in [
            AnnualReportStatus::Draft,
            AnnualReportStatus::ManagementApproved,
            AnnualReportStatus::Submitted,
        ] {
            assert_eq!(AnnualReportStatus::from_db(status.as_str()), Some(status));
        }
        assert!(AnnualReportStatus::Draft.can_transition(AnnualReportStatus::ManagementApproved));
        assert!(
            AnnualReportStatus::ManagementApproved.can_transition(AnnualReportStatus::Submitted)
        );
        // Generation can never be approval, and submitted is terminal.
        assert!(!AnnualReportStatus::Draft.can_transition(AnnualReportStatus::Submitted));
        assert!(!AnnualReportStatus::Submitted.can_transition(AnnualReportStatus::Draft));
    }

    #[test]
    fn derivation_sums_posted_lines_by_account_type() {
        let lines = vec![
            line("1020", "asset", 150_000, 0, 150_000),
            line("3000", "equity", 0, 100_000, -100_000),
            line("4000", "revenue", 0, 200_000, -200_000),
            line("5000", "expense", 150_000, 0, 150_000),
        ];
        let (balance_sheet, income_statement) = derive_statements(&lines);
        assert_eq!(balance_sheet.assets_cents, 150_000);
        assert_eq!(balance_sheet.equity_cents, 100_000);
        assert_eq!(income_statement.revenue_cents, 200_000);
        assert_eq!(income_statement.expenses_cents, 150_000);
        assert_eq!(income_statement.net_profit_cents, 50_000);
        assert_eq!(balance_sheet.period_profit_cents, 50_000);
        // assets 150 000 == equity 100 000 + profit 50 000.
        assert_eq!(balance_sheet.total_liabilities_and_equity_cents, 150_000);
        assert!(balance_sheet.balance_check_ok);
        assert_eq!(balance_sheet.balance_difference_cents, 0);
    }

    #[test]
    fn empty_period_derives_zeros_not_a_panic() {
        let (balance_sheet, income_statement) = derive_statements(&[]);
        assert_eq!(balance_sheet.assets_cents, 0);
        assert_eq!(balance_sheet.balance_difference_cents, 0);
        assert!(balance_sheet.balance_check_ok);
        assert_eq!(income_statement.net_profit_cents, 0);
    }

    #[test]
    fn unbalanced_ledger_is_surfaced_not_hidden() {
        // Assets without a matching liability/equity posting (e.g. missing
        // opening balances) must be flagged, not silently balanced.
        let lines = vec![line("1020", "asset", 100, 0, 100)];
        let (balance_sheet, _) = derive_statements(&lines);
        assert!(!balance_sheet.balance_check_ok);
        assert_eq!(balance_sheet.balance_difference_cents, 100);
    }

    #[test]
    fn ledger_hash_changes_when_a_posting_changes() {
        let period = Uuid::new_v4();
        let first = vec![line("4000", "revenue", 0, 100_000, -100_000)];
        let second = vec![
            line("4000", "revenue", 0, 100_000, -100_000),
            line("4000b", "revenue", 0, 50_000, -50_000),
        ];
        let h1 = ledger_hash(period, 1, &first);
        let h2 = ledger_hash(period, 2, &second);
        assert_ne!(h1, h2);
        assert_eq!(h1, ledger_hash(period, 1, &first));
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn period_validation_rejects_reversed_and_wrong_type() {
        assert!(validate_period("year", d(2025, 1, 1), d(2025, 12, 31)).is_ok());
        assert!(validate_period("custom", d(2025, 6, 1), d(2025, 6, 1)).is_ok());
        assert!(validate_period("year", d(2025, 12, 31), d(2025, 1, 1)).is_err());
        assert!(validate_period("month", d(2025, 1, 1), d(2025, 1, 31)).is_err());
    }

    #[test]
    fn xbrl_instance_is_well_formed_xml() {
        let company = CompanyIdentity {
            legal_name: "Test & Sons <OÜ>".into(),
            registry_code: "16588745".into(),
            vat_number: Some("EE102400000".into()),
            country_code: "EE".into(),
            currency: "EUR".into(),
        };
        let lines = vec![
            line("1020", "asset", 150_000, 0, 150_000),
            line("3000", "equity", 0, 100_000, -100_000),
            line("4000", "revenue", 0, 200_000, -200_000),
            line("5000", "expense", 150_000, 0, 150_000),
        ];
        let (balance_sheet, income_statement) = derive_statements(&lines);
        let xml = build_xbrl_instance(
            &company,
            d(2025, 12, 31).year(),
            d(2025, 1, 1),
            d(2025, 12, 31),
            &balance_sheet,
            &income_statement,
            &lines,
        );

        // Well-formedness is checked with a real XML parser.
        let mut reader = quick_xml::Reader::from_str(&xml);
        let mut saw_root = false;
        let mut depth = 0i32;
        loop {
            match reader.read_event() {
                Ok(quick_xml::events::Event::Start(_)) => {
                    depth += 1;
                    saw_root = true;
                }
                Ok(quick_xml::events::Event::End(_)) => depth -= 1,
                Ok(quick_xml::events::Event::Eof) => break,
                Ok(_) => {}
                Err(error) => panic!("XBRL instance is not well-formed XML: {error}"),
            }
            assert!(depth >= 0, "unbalanced closing tag");
        }
        assert!(saw_root, "instance must have a root element");
        assert_eq!(depth, 0, "all elements must be closed");
        assert!(xml.contains("xbrli:xbrl"));
        assert!(xml.contains("contextRef=\"instant-2025-12-31\""));
        assert!(xml.contains("<apex:Assets"));
        // The special characters in the company name are escaped, not raw.
        assert!(!xml.contains("Test & Sons"));
    }

    #[test]
    fn cents_format_never_uses_floating_point_artifacts() {
        assert_eq!(format_cents(0), "0.00");
        assert_eq!(format_cents(5), "0.05");
        assert_eq!(format_cents(12345), "123.45");
        assert_eq!(format_cents(-1), "-0.01");
        assert_eq!(format_cents(1_000_000_000), "10000000.00");
    }

    #[test]
    fn fact_names_are_valid_xml_names() {
        assert_eq!(xml_fact_name("1020"), "a1020");
        assert_eq!(xml_fact_name("AR-1"), "AR_1");
        assert_eq!(xml_fact_name(""), "a");
    }

    #[test]
    fn migration_carries_the_state_machine_constraints() {
        let migration = include_str!("../../../migrations/221_statutory_filing_completion.sql");
        for needed in [
            "annual_reports_approval_requires_actor",
            "annual_reports_submission_requires_receipt",
            "annual_reports_draft_has_no_human_act",
            "v_accounting_trial_balance",
        ] {
            assert!(
                migration.contains(needed),
                "migration 221 must carry {needed}"
            );
        }
    }
}
