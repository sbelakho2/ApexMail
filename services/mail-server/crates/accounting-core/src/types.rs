//! Shared domain types for the accounting core.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Retention classes (must match migration 220's accounting_retention_classes)
// ---------------------------------------------------------------------------

/// Seven-year statutory retention class (RPS §12 / MKS §25).
pub const RETENTION_LEGAL_7Y: &str = "legal_7y";
/// Ten-year statutory retention class.
pub const RETENTION_LEGAL_10Y: &str = "legal_10y";
/// No statutory floor.
pub const RETENTION_OPERATIONAL: &str = "operational";

// ---------------------------------------------------------------------------
// Chart-of-accounts roles (must match the role CHECK in migration 220)
// ---------------------------------------------------------------------------

pub const ROLE_AR: &str = "ar";
pub const ROLE_AP: &str = "ap";
pub const ROLE_REVENUE: &str = "revenue";
pub const ROLE_REFUNDS: &str = "refunds";
pub const ROLE_VAT_OUTPUT: &str = "vat_output";
pub const ROLE_VAT_INPUT: &str = "vat_input";
pub const ROLE_BANK: &str = "bank";
pub const ROLE_BANK_CLEARING: &str = "bank_clearing";
pub const ROLE_STRIPE_CLEARING: &str = "stripe_clearing";
pub const ROLE_STRIPE_FEES: &str = "stripe_fees";
pub const ROLE_WALLET_LIABILITY: &str = "wallet_liability";
pub const ROLE_EXPENSE_DEFAULT: &str = "expense_default";
pub const ROLE_PAYROLL_EXPENSE: &str = "payroll_expense";
pub const ROLE_NET_WAGES_PAYABLE: &str = "net_wages_payable";
pub const ROLE_INCOME_TAX_PAYABLE: &str = "income_tax_payable";
pub const ROLE_SOCIAL_TAX_PAYABLE: &str = "social_tax_payable";
pub const ROLE_UNEMPLOYMENT_PAYABLE: &str = "unemployment_payable";
pub const ROLE_PENSION_PAYABLE: &str = "pension_payable";
pub const ROLE_FX_GAIN: &str = "fx_gain";
pub const ROLE_FX_LOSS: &str = "fx_loss";
pub const ROLE_DEPRECIATION_EXPENSE: &str = "depreciation_expense";
pub const ROLE_ACCUMULATED_DEPRECIATION: &str = "accumulated_depreciation";
pub const ROLE_RETAINED_EARNINGS: &str = "retained_earnings";
pub const ROLE_SUSPENSE: &str = "suspense";
pub const ROLE_OTHER_INCOME: &str = "other_income";

/// Every role the schema accepts (kept in sync with migration 220's CHECK).
pub const ACCOUNT_ROLES: &[&str] = &[
    ROLE_AR,
    ROLE_AP,
    ROLE_REVENUE,
    ROLE_REFUNDS,
    ROLE_VAT_OUTPUT,
    ROLE_VAT_INPUT,
    ROLE_BANK,
    ROLE_BANK_CLEARING,
    ROLE_STRIPE_CLEARING,
    ROLE_STRIPE_FEES,
    ROLE_WALLET_LIABILITY,
    ROLE_EXPENSE_DEFAULT,
    ROLE_PAYROLL_EXPENSE,
    ROLE_NET_WAGES_PAYABLE,
    ROLE_INCOME_TAX_PAYABLE,
    ROLE_SOCIAL_TAX_PAYABLE,
    ROLE_UNEMPLOYMENT_PAYABLE,
    ROLE_PENSION_PAYABLE,
    ROLE_FX_GAIN,
    ROLE_FX_LOSS,
    ROLE_DEPRECIATION_EXPENSE,
    ROLE_ACCUMULATED_DEPRECIATION,
    ROLE_RETAINED_EARNINGS,
    ROLE_SUSPENSE,
    ROLE_OTHER_INCOME,
];

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// Journal entry classification. Reversal entries MUST reference the entry
/// they reverse (enforced by a CHECK in migration 220).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    Standard,
    Reversal,
    Adjusting,
    Opening,
    Closing,
    Depreciation,
    Payroll,
    Tax,
}

impl EntryType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Reversal => "reversal",
            Self::Adjusting => "adjusting",
            Self::Opening => "opening",
            Self::Closing => "closing",
            Self::Depreciation => "depreciation",
            Self::Payroll => "payroll",
            Self::Tax => "tax",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "standard" => Some(Self::Standard),
            "reversal" => Some(Self::Reversal),
            "adjusting" => Some(Self::Adjusting),
            "opening" => Some(Self::Opening),
            "closing" => Some(Self::Closing),
            "depreciation" => Some(Self::Depreciation),
            "payroll" => Some(Self::Payroll),
            "tax" => Some(Self::Tax),
            _ => None,
        }
    }
}

impl std::fmt::Display for EntryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One journal line. Exactly one of `debit_cents` / `credit_cents` is > 0
/// (a database CHECK enforces the same).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalLine {
    pub account_id: Uuid,
    pub debit_cents: i64,
    pub credit_cents: i64,
    pub currency: String,
    /// Taxable base for VAT lines (KMD derivation).
    pub net_cents: Option<i64>,
    /// Tax amount for VAT lines.
    pub vat_cents: Option<i64>,
    /// Tax rate in basis points (2400 = 24.00%).
    pub vat_rate_bp: Option<i32>,
    pub vat_code: Option<String>,
    pub description: String,
}

impl JournalLine {
    pub fn debit(account_id: Uuid, amount_cents: i64, currency: &str) -> Self {
        Self {
            account_id,
            debit_cents: amount_cents,
            credit_cents: 0,
            currency: currency.to_string(),
            net_cents: None,
            vat_cents: None,
            vat_rate_bp: None,
            vat_code: None,
            description: String::new(),
        }
    }

    pub fn credit(account_id: Uuid, amount_cents: i64, currency: &str) -> Self {
        Self {
            account_id,
            debit_cents: 0,
            credit_cents: amount_cents,
            currency: currency.to_string(),
            net_cents: None,
            vat_cents: None,
            vat_rate_bp: None,
            vat_code: None,
            description: String::new(),
        }
    }

    /// Attach VAT evidence (base, tax, rate, code) to a line.
    pub fn with_vat(
        mut self,
        net_cents: i64,
        vat_cents: i64,
        vat_rate_bp: Option<i32>,
        vat_code: Option<String>,
    ) -> Self {
        self.net_cents = Some(net_cents);
        self.vat_cents = Some(vat_cents);
        self.vat_rate_bp = vat_rate_bp;
        self.vat_code = vat_code;
        self
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    /// Signed amount used by balance computation.
    pub fn delta_cents(&self) -> i128 {
        i128::from(self.debit_cents) - i128::from(self.credit_cents)
    }
}

/// Identity + evidence of the operational row a posting derives from.
///
/// `(source_type, source_table, source_id)` is the idempotency anchor: a
/// replay of the same webhook/second call finds the existing source document
/// and journal entry. `source_hash` is the sha256 hex of the canonical
/// payload; a replay with a different payload is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIdentity {
    pub source_type: String,
    pub source_table: String,
    pub source_id: String,
    pub source_hash: String,
    pub document_date: NaiveDate,
    pub currency: String,
    pub total_cents: i64,
    pub payload: serde_json::Value,
    pub retention_class: String,
}

impl SourceIdentity {
    /// Build a source identity, hashing the canonical JSON payload.
    pub fn new(
        source_type: &str,
        source_table: &str,
        source_id: &str,
        document_date: NaiveDate,
        currency: &str,
        total_cents: i64,
        payload: serde_json::Value,
    ) -> Self {
        // serde_json maps are BTreeMap-backed (no preserve_order feature in
        // this workspace), so to_string() is deterministic for equal values.
        let source_hash = crate::hash::json_evidence_hash(&payload);
        Self {
            source_type: source_type.to_string(),
            source_table: source_table.to_string(),
            source_id: source_id.to_string(),
            source_hash,
            document_date,
            currency: currency.to_uppercase(),
            total_cents,
            payload,
            retention_class: RETENTION_LEGAL_7Y.to_string(),
        }
    }
}

/// A posting request. The posting API validates balance before writing and
/// the database re-asserts it at commit (deferred constraint trigger).
#[derive(Debug, Clone)]
pub struct PostJournalRequest {
    pub legal_entity_id: Uuid,
    pub fiscal_period_id: Uuid,
    pub entry_date: NaiveDate,
    pub entry_type: EntryType,
    pub memo: String,
    pub posted_by: String,
    /// Unique per economic event. Adapters derive it from the source
    /// identity (e.g. `invoice:<uuid>:issued`).
    pub idempotency_key: String,
    /// `None` for manual/adjusting entries; an evidence hash over the entry
    /// content is still generated.
    pub source: Option<SourceIdentity>,
    pub reversal_of_entry_id: Option<Uuid>,
    pub lines: Vec<JournalLine>,
}

/// Whether a post call created the entry or found it already posted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostStatus {
    Posted,
    AlreadyPosted,
    /// Nothing to post (e.g. zero-value invoice, credit-note source handled
    /// by another entry).
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostOutcome {
    pub entry_id: Option<Uuid>,
    pub status: PostStatus,
}

impl PostOutcome {
    pub fn posted(entry_id: Uuid) -> Self {
        Self {
            entry_id: Some(entry_id),
            status: PostStatus::Posted,
        }
    }

    pub fn already_posted(entry_id: Uuid) -> Self {
        Self {
            entry_id: Some(entry_id),
            status: PostStatus::AlreadyPosted,
        }
    }

    pub fn skipped() -> Self {
        Self {
            entry_id: None,
            status: PostStatus::Skipped,
        }
    }
}

/// Payroll tax amounts for one payroll record (TSD inputs). The caller
/// computes them through the date-effective tax policy; the adapter only
/// validates and posts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayrollAmounts {
    pub income_tax_cents: i64,
    pub social_tax_cents: i64,
    pub unemployment_employee_cents: i64,
    pub unemployment_employer_cents: i64,
    pub pension_cents: i64,
    pub net_cents: i64,
}
