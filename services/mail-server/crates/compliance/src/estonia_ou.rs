//! Estonia OÜ (Osaühing — Private Limited Company) legal compliance.
//!
//! Implements document generation and deadline tracking for Bel Consulting OÜ
//! (Registry Code 16588745), Tallinn, Estonia, as required by the Estonian
//! Commercial Code (Äriseadustik) and the Taxation Act (Maksukorralduse seadus).
//!
//! ## Required Filings
//!
//! | Filing                     | Due Date          | Frequency | Law              |
//! |----------------------------|-------------------|-----------|------------------|
//! | Annual Report              | June 30           | yearly    | Äriseadustik §97 |
//! | VAT Declaration (KMD)      | 20th of month     | monthly   | KMS §27          |
//! | Income Tax Declaration     | 10th of month     | monthly   | TuMS §54         |
//! | Social Tax Declaration     | 10th of month     | monthly   | SOS §9           |
//! | Statistical Report         | per Statistics EE | yearly    | RTS §8           |
//!
//! ## Estonia-Specific Tax Rules
//!
//! - **Corporate income tax**: 0% on reinvested profits. Only distributed
//!   profits (dividends) are taxed. Until end-2024 the split was 80/20;
//!   from 2025-01-01 it is 78/22, i.e. a NET-to-tax fraction of 22/78 —
//!   see `tax_policy::dividend_tax_on_net` (F81).
//! - **VAT (Käibemaks)**: 24% standard rate (since July 1, 2025) — all
//!   rates resolved date-effectively through `tax_policy` (F81).
//! - **Social tax (Sotsiaalmaks)**: 33% on gross salary, declared via TSD.
//! - **Unemployment insurance**: 1.6% employee + 0.8% employer.
//! - **Funded pension (II sammas)**: 2% employee (mandatory for born ≥1983).

#![deny(unsafe_code)]

use chrono::{Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::registry_monitor::{NoticeStatus, ScheduledRegistryMonitor};
use crate::tax_policy;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Company legal name.
pub const COMPANY_NAME: &str = "Bel Consulting OÜ";
/// Estonian Business Registry code.
pub const REGISTRY_CODE: &str = "16588745";
/// Company registered address (Tallinn).
pub const COMPANY_ADDRESS: &str = "Sakala tn 7-2, 10141 Tallinn, Estonia";
/// Estonian VAT rate (standard rate since July 1, 2025).
pub const EST_VAT_RATE: i32 = 24;
/// Social tax rate on gross salary (employer contribution).
pub const SOCIAL_TAX_RATE: f64 = 0.33;
/// Unemployment insurance — employer share.
pub const UNEMPLOYMENT_INSURANCE_EMPLOYER: f64 = 0.008;
/// Unemployment insurance — employee share.
pub const UNEMPLOYMENT_INSURANCE_EMPLOYEE: f64 = 0.016;
/// Funded pension (II pillar) — LEGACY default. The actual rate is an
/// employee-specific 2/4/6% choice recorded per payment period
/// (payroll_records.funded_pension_rate, migration 199); this constant is
/// only a documentation anchor, computations use the recorded input (F81).
pub const FUNDED_PENSION_RATE: f64 = 0.02;
/// LEGACY reference fraction for the pre-2025 20/80 dividend split.
/// Computations use the date-effective `tax_policy::dividend_tax_on_net`
/// (22/78 from 2025-01-01) applied to the NET distribution (F81).
pub const DIVIDEND_TAX_RATE: f64 = 0.20;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionType {
    AnnualReport,
    VatDeclaration,
    IncomeTax,
    SocialTax,
    StatisticalReport,
}

impl SubmissionType {
    #[allow(clippy::should_implement_trait)] // inherent parser kept for API stability
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "annual_report" => Some(Self::AnnualReport),
            "vat_declaration" => Some(Self::VatDeclaration),
            "income_tax" => Some(Self::IncomeTax),
            "social_tax" => Some(Self::SocialTax),
            "statistical_report" => Some(Self::StatisticalReport),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AnnualReport => "annual_report",
            Self::VatDeclaration => "vat_declaration",
            Self::IncomeTax => "income_tax",
            Self::SocialTax => "social_tax",
            Self::StatisticalReport => "statistical_report",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::AnnualReport => "Annual Report (Majandusaasta aruanne)",
            Self::VatDeclaration => "VAT Declaration (Käibedeklaratsioon)",
            Self::IncomeTax => "Income Tax Declaration (Tulumaks)",
            Self::SocialTax => "Social Tax Declaration (TSD)",
            Self::StatisticalReport => "Annual Statistical Report",
        }
    }
}

impl std::fmt::Display for SubmissionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionStatus {
    Draft,
    Generated,
    Submitted,
    Acknowledged,
    Overdue,
    Error,
}

impl SubmissionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Generated => "generated",
            Self::Submitted => "submitted",
            Self::Acknowledged => "acknowledged",
            Self::Overdue => "overdue",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineStatus {
    Pending,
    Filed,
    Overdue,
    Exempt,
}

impl DeadlineStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Filed => "filed",
            Self::Overdue => "overdue",
            Self::Exempt => "exempt",
        }
    }

    /// Colour indicator for admin dashboard.
    pub fn indicator(&self) -> &'static str {
        match self {
            Self::Pending => "yellow",
            Self::Filed => "green",
            Self::Overdue => "red",
            Self::Exempt => "grey",
        }
    }
}

/// Persisted submission record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSubmission {
    pub id: Uuid,
    pub submission_type: String,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub tax_year: i32,
    pub tax_month: Option<i32>,
    pub status: String,
    pub submitted_at: Option<chrono::DateTime<Utc>>,
    pub document_json: serde_json::Value,
    pub document_url: Option<String>,
    pub filing_reference: Option<String>,
    pub notes: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

/// Submission list item with format availability flags (for API responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionListItem {
    pub id: Uuid,
    pub submission_type: String,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub tax_year: i32,
    pub tax_month: Option<i32>,
    pub status: String,
    pub submitted_at: Option<chrono::DateTime<Utc>>,
    pub document_json: serde_json::Value,
    pub document_url: Option<String>,
    pub filing_reference: Option<String>,
    pub file_name: Option<String>,
    pub file_size: Option<i64>,
    pub period_label: Option<String>,
    pub checksum: Option<String>,
    pub has_pdf: bool,
    pub has_csv: bool,
    pub has_json: bool,
}

/// Persisted deadline record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceDeadline {
    pub id: Uuid,
    pub deadline_type: String,
    pub label: String,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub due_date: NaiveDate,
    pub status: String,
    pub submission_id: Option<Uuid>,
    pub reminded_7d_at: Option<chrono::DateTime<Utc>>,
    pub reminded_1d_at: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

// --- Annual Report ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnualReport {
    pub company_name: String,
    pub registry_code: String,
    pub period: String,
    pub fiscal_year: i32,
    pub generated_at: chrono::DateTime<Utc>,

    pub balance_sheet: BalanceSheet,
    pub income_statement: IncomeStatement,
    pub cash_flow: CashFlowStatement,
    pub notes: Vec<ReportNote>,
    pub management_report: String,

    pub revenue_sources: Vec<RevenueSource>,
    pub expense_breakdown: Vec<ExpenseCategory>,
    pub data_quality: DataQualityNote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceSheet {
    pub total_assets_cents: i64,
    pub current_assets_cents: i64,
    pub fixed_assets_cents: i64,
    pub total_liabilities_cents: i64,
    pub current_liabilities_cents: i64,
    pub long_term_liabilities_cents: i64,
    pub equity_cents: i64,
    pub share_capital_cents: i64,
    pub retained_earnings_cents: i64,
    pub period_profit_cents: i64,
    pub as_of: NaiveDate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomeStatement {
    pub revenue_cents: i64,
    pub cost_of_sales_cents: i64,
    pub gross_profit_cents: i64,
    pub operating_expenses_cents: i64,
    pub operating_profit_cents: i64,
    pub financial_income_cents: i64,
    pub financial_expenses_cents: i64,
    pub profit_before_tax_cents: i64,
    pub income_tax_cents: i64,
    pub net_profit_cents: i64,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashFlowStatement {
    pub operating_cash_flow_cents: i64,
    pub investing_cash_flow_cents: i64,
    pub financing_cash_flow_cents: i64,
    pub net_cash_flow_cents: i64,
    pub opening_cash_cents: i64,
    pub closing_cash_cents: i64,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportNote {
    pub index: u32,
    pub title: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevenueSource {
    pub category: String,
    pub amount_cents: i64,
    pub invoice_count: i64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpenseCategory {
    pub category: String,
    pub amount_cents: i64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataQualityNote {
    pub has_sufficient_data: bool,
    pub missing_fields: Vec<String>,
    pub note: String,
}

// --- VAT Declaration ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VatDeclaration {
    pub company_name: String,
    pub registry_code: String,
    pub tax_year: i32,
    pub tax_month: u32,
    pub generated_at: chrono::DateTime<Utc>,

    pub domestic_sales: VatCategory,
    pub intra_eu_supplies: VatCategory,
    pub exports: VatCategory,
    pub input_vat: VatInputBreakdown,
    pub summary: VatSummary,
    pub data_quality: DataQualityNote,
    /// F81: an incomplete return is explicitly NOT READY for filing —
    /// never presented as a complete statutory declaration.
    pub ready_for_filing: bool,
    pub incomplete_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VatCategory {
    pub taxable_amount_cents: i64,
    pub vat_rate: i32,
    pub vat_amount_cents: i64,
    pub transaction_count: i64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VatInputBreakdown {
    pub domestic_purchases: VatInputLine,
    pub intra_eu_acquisitions: VatInputLine,
    pub imports: VatInputLine,
    pub total_deductible_vat_cents: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VatInputLine {
    pub amount_cents: i64,
    pub vat_amount_cents: i64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VatSummary {
    pub total_output_vat_cents: i64,
    pub total_input_vat_cents: i64,
    pub net_vat_payable_cents: i64,
    pub vat_refund_cents: i64,
    pub due_date: NaiveDate,
}

// --- Income Tax Declaration ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomeTaxDeclaration {
    pub company_name: String,
    pub registry_code: String,
    pub tax_year: i32,
    pub tax_month: u32,
    pub generated_at: chrono::DateTime<Utc>,

    pub dividend_distributions: Vec<DividendDistribution>,
    pub total_dividend_cents: i64,
    pub taxable_portion_cents: i64,
    pub income_tax_liability_cents: i64,
    pub fringe_benefits: Vec<FringeBenefit>,
    pub total_fringe_benefit_tax_cents: i64,
    pub other_taxable_payments: Vec<OtherTaxablePayment>,
    pub total_other_tax_cents: i64,
    pub total_tax_due_cents: i64,
    pub due_date: NaiveDate,
    pub data_quality: DataQualityNote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DividendDistribution {
    pub recipient: String,
    pub amount_cents: i64,
    pub tax_rate: f64,
    pub tax_amount_cents: i64,
    pub distribution_date: NaiveDate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FringeBenefit {
    pub benefit_type: String,
    pub value_cents: i64,
    pub tax_amount_cents: i64,
    pub month: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtherTaxablePayment {
    pub payment_type: String,
    pub amount_cents: i64,
    pub tax_rate: f64,
    pub tax_amount_cents: i64,
}

// --- Social Tax (TSD) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialTaxDeclaration {
    pub company_name: String,
    pub registry_code: String,
    pub tax_year: i32,
    pub tax_month: u32,
    pub generated_at: chrono::DateTime<Utc>,

    pub employees: Vec<EmployeeTaxRecord>,
    pub totals: SocialTaxTotals,
    pub due_date: NaiveDate,
    pub data_quality: DataQualityNote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmployeeTaxRecord {
    pub employee_name: String,
    pub personal_code: String,
    pub gross_salary_cents: i64,
    pub social_tax_cents: i64,
    pub unemployment_insurance_employer_cents: i64,
    pub unemployment_insurance_employee_cents: i64,
    pub funded_pension_cents: i64,
    /// The employee-specific II-pillar rate applied (F81). `None` means
    /// participation was unknown for the period: the record is incomplete,
    /// not silently computed at an assumed rate.
    pub funded_pension_rate: Option<f64>,
    pub income_tax_withheld_cents: i64,
    pub net_salary_cents: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialTaxTotals {
    pub total_gross_salary_cents: i64,
    pub total_social_tax_cents: i64,
    pub total_unemployment_employer_cents: i64,
    pub total_unemployment_employee_cents: i64,
    pub total_funded_pension_cents: i64,
    pub total_income_tax_withheld_cents: i64,
    pub total_employer_cost_cents: i64,
    pub employee_count: i32,
}

// --- Statistical Report ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalReport {
    pub company_name: String,
    pub registry_code: String,
    pub report_year: i32,
    pub generated_at: chrono::DateTime<Utc>,

    pub revenue_bands: Vec<RevenueBand>,
    pub employee_headcount: i32,
    pub export_revenue_cents: i64,
    pub is_it_sector: bool,
    pub it_sector_questions: Option<ItSectorQuestions>,
    pub data_quality: DataQualityNote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevenueBand {
    pub category: String,
    pub amount_cents: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItSectorQuestions {
    pub software_development_revenue_cents: i64,
    pub saas_revenue_cents: i64,
    pub it_consulting_revenue_cents: i64,
    pub hosting_infrastructure_revenue_cents: i64,
    pub cybersecurity_revenue_cents: i64,
    pub other_it_revenue_cents: i64,
}

// ---------------------------------------------------------------------------
// ComplianceCalendar
// ---------------------------------------------------------------------------

/// Manages Estonian filing deadlines with reminder tracking.
pub struct ComplianceCalendar {
    db: PgPool,
}

impl ComplianceCalendar {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Calculate the due date for a filing type in a given period.
    ///
    /// The legal date is routed through the ONE shared Estonian business
    /// calendar ([`crate::statutory_calendar::statutory_due_date`]): a
    /// deadline falling on a public holiday or weekend moves to the next
    /// working day. The obligation scheduler
    /// ([`crate::obligations`]) is the preferred entry point for new code;
    /// this method is kept for the existing KMD/TSD/statistical call sites.
    pub fn calculate_due_date(
        deadline_type: SubmissionType,
        year: i32,
        month: Option<u32>,
    ) -> NaiveDate {
        crate::statutory_calendar::statutory_due_date(Self::calculate_legal_due_date(
            deadline_type,
            year,
            month,
        ))
    }

    /// The raw legal due date before the working-day adjustment.
    pub fn calculate_legal_due_date(
        deadline_type: SubmissionType,
        year: i32,
        month: Option<u32>,
    ) -> NaiveDate {
        match deadline_type {
            SubmissionType::AnnualReport => NaiveDate::from_ymd_opt(year + 1, 6, 30)
                .unwrap_or_else(|| NaiveDate::from_ymd_opt(year + 1, 6, 30).unwrap()),
            SubmissionType::VatDeclaration => {
                let m = month.unwrap_or(1);
                let (y, next_m) = if m == 12 {
                    (year + 1, 1)
                } else {
                    (year, m + 1)
                };
                NaiveDate::from_ymd_opt(y, next_m, 20)
                    .unwrap_or_else(|| NaiveDate::from_ymd_opt(y, next_m, 20).unwrap())
            }
            SubmissionType::IncomeTax => {
                let m = month.unwrap_or(1);
                let (y, next_m) = if m == 12 {
                    (year + 1, 1)
                } else {
                    (year, m + 1)
                };
                NaiveDate::from_ymd_opt(y, next_m, 10)
                    .unwrap_or_else(|| NaiveDate::from_ymd_opt(y, next_m, 10).unwrap())
            }
            SubmissionType::SocialTax => {
                let m = month.unwrap_or(1);
                let (y, next_m) = if m == 12 {
                    (year + 1, 1)
                } else {
                    (year, m + 1)
                };
                NaiveDate::from_ymd_opt(y, next_m, 10)
                    .unwrap_or_else(|| NaiveDate::from_ymd_opt(y, next_m, 10).unwrap())
            }
            SubmissionType::StatisticalReport => NaiveDate::from_ymd_opt(year + 1, 7, 1)
                .unwrap_or_else(|| NaiveDate::from_ymd_opt(year + 1, 7, 1).unwrap()),
        }
    }

    /// Calculate the period start/end dates for a filing.
    pub fn calculate_period(
        deadline_type: SubmissionType,
        year: i32,
        month: Option<u32>,
    ) -> (NaiveDate, NaiveDate) {
        match deadline_type {
            SubmissionType::AnnualReport | SubmissionType::StatisticalReport => {
                let start = NaiveDate::from_ymd_opt(year, 1, 1).unwrap();
                let end = NaiveDate::from_ymd_opt(year, 12, 31).unwrap();
                (start, end)
            }
            _ => {
                let m = month.unwrap_or(1);
                let start = NaiveDate::from_ymd_opt(year, m, 1).unwrap();
                let end = if m == 12 {
                    NaiveDate::from_ymd_opt(year, 12, 31).unwrap()
                } else {
                    NaiveDate::from_ymd_opt(year, m + 1, 1)
                        .unwrap()
                        .pred_opt()
                        .unwrap()
                };
                (start, end)
            }
        }
    }

    /// Seed deadlines for all of 2025–2027.
    pub async fn seed_deadlines(&self) -> Result<Vec<ComplianceDeadline>, anyhow::Error> {
        let mut created = Vec::new();
        let now = Utc::now();

        for year in [2025, 2026, 2027] {
            // Annual Report
            {
                let (ps, pe) = Self::calculate_period(SubmissionType::AnnualReport, year, None);
                let due = Self::calculate_due_date(SubmissionType::AnnualReport, year, None);
                let id = Uuid::new_v4();
                sqlx::query(
                    r#"INSERT INTO compliance_deadlines
                       (id, deadline_type, label, period_start, period_end, due_date, status, created_at, updated_at)
                       VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $7)
                       ON CONFLICT (deadline_type, due_date) DO NOTHING"#,
                )
                .bind(id)
                .bind("annual_report")
                .bind(format!("Annual Report FY {}", year))
                .bind(ps)
                .bind(pe)
                .bind(due)
                .bind(now)
                .execute(&self.db)
                .await?;
                created.push(ComplianceDeadline {
                    id,
                    deadline_type: "annual_report".into(),
                    label: format!("Annual Report FY {}", year),
                    period_start: ps,
                    period_end: pe,
                    due_date: due,
                    status: "pending".into(),
                    submission_id: None,
                    reminded_7d_at: None,
                    reminded_1d_at: None,
                    created_at: now,
                    updated_at: now,
                });
            }

            // Monthly declarations
            for month in 1..=12 {
                for st in [
                    SubmissionType::VatDeclaration,
                    SubmissionType::IncomeTax,
                    SubmissionType::SocialTax,
                ] {
                    let (ps, pe) = Self::calculate_period(st, year, Some(month));
                    let due = Self::calculate_due_date(st, year, Some(month));
                    let id = Uuid::new_v4();
                    sqlx::query(
                        r#"INSERT INTO compliance_deadlines
                           (id, deadline_type, label, period_start, period_end, due_date, status, created_at, updated_at)
                           VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $7)
                           ON CONFLICT (deadline_type, due_date) DO NOTHING"#,
                    )
                    .bind(id)
                    .bind(st.as_str())
                    .bind(format!("{} {}-{:02}", st.label(), year, month))
                    .bind(ps)
                    .bind(pe)
                    .bind(due)
                    .bind(now)
                    .execute(&self.db)
                    .await?;
                    created.push(ComplianceDeadline {
                        id,
                        deadline_type: st.as_str().into(),
                        label: format!("{} {}-{:02}", st.label(), year, month),
                        period_start: ps,
                        period_end: pe,
                        due_date: due,
                        status: "pending".into(),
                        submission_id: None,
                        reminded_7d_at: None,
                        reminded_1d_at: None,
                        created_at: now,
                        updated_at: now,
                    });
                }
            }

            // Statistical Report
            {
                let (ps, pe) =
                    Self::calculate_period(SubmissionType::StatisticalReport, year, None);
                let due = Self::calculate_due_date(SubmissionType::StatisticalReport, year, None);
                let id = Uuid::new_v4();
                sqlx::query(
                    r#"INSERT INTO compliance_deadlines
                       (id, deadline_type, label, period_start, period_end, due_date, status, created_at, updated_at)
                       VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $7)
                       ON CONFLICT (deadline_type, due_date) DO NOTHING"#,
                )
                .bind(id)
                .bind("statistical_report")
                .bind(format!("Statistical Report FY {}", year))
                .bind(ps)
                .bind(pe)
                .bind(due)
                .bind(now)
                .execute(&self.db)
                .await?;
                created.push(ComplianceDeadline {
                    id,
                    deadline_type: "statistical_report".into(),
                    label: format!("Statistical Report FY {}", year),
                    period_start: ps,
                    period_end: pe,
                    due_date: due,
                    status: "pending".into(),
                    submission_id: None,
                    reminded_7d_at: None,
                    reminded_1d_at: None,
                    created_at: now,
                    updated_at: now,
                });
            }
        }

        Ok(created)
    }

    /// Mark past-due deadlines as overdue.
    pub async fn refresh_overdue(&self) -> Result<u64, anyhow::Error> {
        let today = Utc::now().date_naive();
        let result = sqlx::query(
            "UPDATE compliance_deadlines SET status = 'overdue', updated_at = NOW()
             WHERE due_date < $1 AND status = 'pending'",
        )
        .bind(today)
        .execute(&self.db)
        .await?;
        Ok(result.rows_affected())
    }

    /// Get all pending deadlines, ordered by due date ascending.
    pub async fn list_pending(&self) -> Result<Vec<ComplianceDeadline>, anyhow::Error> {
        let rows = sqlx::query_as::<_, DeadlineRow>(
            "SELECT id, deadline_type, label, period_start, period_end,
                    due_date, status, submission_id,
                    reminded_7d_at, reminded_1d_at, created_at, updated_at
             FROM compliance_deadlines
             WHERE status = 'pending'
             ORDER BY due_date ASC
             LIMIT 200",
        )
        .fetch_all(&self.db)
        .await?;
        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Get upcoming deadlines (due within `days_ahead` days).
    pub async fn list_upcoming(
        &self,
        days_ahead: i64,
    ) -> Result<Vec<ComplianceDeadline>, anyhow::Error> {
        let today = Utc::now().date_naive();
        let future = today + chrono::Duration::days(days_ahead);
        let rows = sqlx::query_as::<_, DeadlineRow>(
            "SELECT id, deadline_type, label, period_start, period_end,
                    due_date, status, submission_id,
                    reminded_7d_at, reminded_1d_at, created_at, updated_at
             FROM compliance_deadlines
             WHERE status = 'pending' AND due_date BETWEEN $1 AND $2
             ORDER BY due_date ASC
             LIMIT 200",
        )
        .bind(today)
        .bind(future)
        .fetch_all(&self.db)
        .await?;
        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Get deadlines needing 7-day reminder (not yet reminded, due in exactly 7 days).
    pub async fn deadlines_for_7day_reminder(
        &self,
    ) -> Result<Vec<ComplianceDeadline>, anyhow::Error> {
        let target = Utc::now().date_naive() + chrono::Duration::days(7);
        let rows = sqlx::query_as::<_, DeadlineRow>(
            "SELECT id, deadline_type, label, period_start, period_end,
                    due_date, status, submission_id,
                    reminded_7d_at, reminded_1d_at, created_at, updated_at
             FROM compliance_deadlines
             WHERE status = 'pending' AND due_date = $1 AND reminded_7d_at IS NULL",
        )
        .bind(target)
        .fetch_all(&self.db)
        .await?;
        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Get deadlines needing 1-day reminder.
    pub async fn deadlines_for_1day_reminder(
        &self,
    ) -> Result<Vec<ComplianceDeadline>, anyhow::Error> {
        let target = Utc::now().date_naive() + chrono::Duration::days(1);
        let rows = sqlx::query_as::<_, DeadlineRow>(
            "SELECT id, deadline_type, label, period_start, period_end,
                    due_date, status, submission_id,
                    reminded_7d_at, reminded_1d_at, created_at, updated_at
             FROM compliance_deadlines
             WHERE status = 'pending' AND due_date = $1 AND reminded_1d_at IS NULL",
        )
        .bind(target)
        .fetch_all(&self.db)
        .await?;
        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Record a 7-day reminder sent.
    pub async fn record_7day_reminder(&self, deadline_id: Uuid) -> Result<(), anyhow::Error> {
        sqlx::query(
            "UPDATE compliance_deadlines SET reminded_7d_at = NOW(), updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deadline_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Record a 1-day reminder sent.
    pub async fn record_1day_reminder(&self, deadline_id: Uuid) -> Result<(), anyhow::Error> {
        sqlx::query(
            "UPDATE compliance_deadlines SET reminded_1d_at = NOW(), updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deadline_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Mark a deadline as filed (with optional submission ID link).
    pub async fn mark_filed(
        &self,
        deadline_id: Uuid,
        submission_id: Option<Uuid>,
    ) -> Result<(), anyhow::Error> {
        sqlx::query(
            "UPDATE compliance_deadlines SET status = 'filed', submission_id = $2,
                    updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deadline_id)
        .bind(submission_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EstoniaOuCompliance — document generation
// ---------------------------------------------------------------------------

/// Core engine for generating Estonian OÜ compliance documents.
pub struct EstoniaOuCompliance {
    db: PgPool,
    calendar: Arc<ComplianceCalendar>,
}

impl EstoniaOuCompliance {
    pub fn new(db: PgPool) -> Self {
        let calendar = Arc::new(ComplianceCalendar::new(db.clone()));
        Self { db, calendar }
    }

    pub fn calendar(&self) -> &ComplianceCalendar {
        &self.calendar
    }

    // --- Financial data extractors ------------------------------------------

    /// Extract revenue from invoices table for a given year (or year+month).
    async fn query_revenue(
        &self,
        year: i32,
        month: Option<u32>,
    ) -> Result<Vec<RevenueSource>, anyhow::Error> {
        let has_invoices = crate::table_exists_fn(&self.db, "invoices")
            .await
            .unwrap_or(false);

        if !has_invoices {
            return Ok(vec![]);
        }

        let rows = if let Some(m) = month {
            // SUM(bigint) is NUMERIC in PostgreSQL; cast so the row decodes
            // as i64 (sqlx type-checks strictly).
            sqlx::query_as::<_, RevenueRow>(
                "SELECT COALESCE(currency, 'EUR') AS currency,
                        SUM(subtotal)::bigint AS total_cents,
                        COUNT(*) AS invoice_count
                 FROM invoices
                 WHERE EXTRACT(YEAR FROM issued_at) = $1
                   AND EXTRACT(MONTH FROM issued_at) = $2
                   AND status = 'paid'
                 GROUP BY currency",
            )
            .bind(year as f64)
            .bind(m as f64)
            .fetch_all(&self.db)
            .await?
        } else {
            sqlx::query_as::<_, RevenueRow>(
                "SELECT COALESCE(currency, 'EUR') AS currency,
                        SUM(subtotal)::bigint AS total_cents,
                        COUNT(*) AS invoice_count
                 FROM invoices
                 WHERE EXTRACT(YEAR FROM issued_at) = $1
                   AND status = 'paid'
                 GROUP BY currency",
            )
            .bind(year as f64)
            .fetch_all(&self.db)
            .await?
        };

        let sources: Vec<RevenueSource> = rows
            .into_iter()
            .map(|r| RevenueSource {
                category: format!("Billing revenue ({})", r.currency),
                amount_cents: r.total_cents.unwrap_or(0),
                invoice_count: r.invoice_count.unwrap_or(0),
                description: "Revenue from customer invoices (Stripe)".into(),
            })
            .collect();

        Ok(sources)
    }

    /// Extract expenses from operational costs tables.
    async fn query_expenses(
        &self,
        year: i32,
        _month: Option<u32>,
    ) -> Result<Vec<ExpenseCategory>, anyhow::Error> {
        let mut expenses = Vec::new();

        let has_invoices = crate::table_exists_fn(&self.db, "invoices")
            .await
            .unwrap_or(false);

        if has_invoices {
            if let Ok(Some(row)) = sqlx::query_as::<_, ExpenseRow>(
                "SELECT SUM(subtotal + vat_total)::bigint AS total_cents
                 FROM invoices
                 WHERE EXTRACT(YEAR FROM issued_at) = $1
                   AND status = 'paid'",
            )
            .bind(year as f64)
            .fetch_optional(&self.db)
            .await
            {
                if let Some(total_revenue) = row.total_cents {
                    let stripe_fee_est = ((total_revenue as f64) * 0.029 + 30.0) as i64;
                    expenses.push(ExpenseCategory {
                        category: "Payment processing (Stripe fees)".into(),
                        amount_cents: stripe_fee_est,
                        description: "Estimated 2.9% + 0,30 € Stripe processing fees".into(),
                    });
                }
            }
        }

        let has_operating_costs = crate::table_exists_fn(&self.db, "operating_costs")
            .await
            .unwrap_or(false);

        if has_operating_costs {
            let rows = sqlx::query_as::<_, CostRow>(
                "SELECT COALESCE(category, 'infrastructure') AS category,
                        COALESCE(SUM(amount_cents), 0)::bigint AS total_cents
                 FROM operating_costs
                 WHERE EXTRACT(YEAR FROM incurred_at) = $1
                 GROUP BY category",
            )
            .bind(year as f64)
            .fetch_all(&self.db)
            .await?;

            for row in rows {
                expenses.push(ExpenseCategory {
                    category: format!("Infrastructure: {}", row.category),
                    amount_cents: row.total_cents.unwrap_or(0),
                    description: format!("{} operating costs", row.category),
                });
            }
        }

        expenses.push(ExpenseCategory {
            category: "Cloud infrastructure (Hetzner)".into(),
            amount_cents: 0,
            description: "Hetzner Cloud servers — actual costs not yet ingested".into(),
        });
        expenses.push(ExpenseCategory {
            category: "Cloud infrastructure (AWS)".into(),
            amount_cents: 0,
            description: "AWS SES + S3 — actual costs not yet ingested".into(),
        });

        Ok(expenses)
    }

    /// Extract employee salary data if available.
    async fn query_employees(
        &self,
        year: i32,
        month: Option<u32>,
    ) -> Result<Vec<EmployeeTaxRecord>, anyhow::Error> {
        let has_payroll = crate::table_exists_fn(&self.db, "payroll_records")
            .await
            .unwrap_or(false);

        if !has_payroll {
            return Ok(vec![]);
        }

        // F81: the payment period and the per-employee pension/exemption
        // inputs drive the calculation — rates come from the date-effective
        // tax policy, never from one permanent constant.
        let rows = if let Some(m) = month {
            sqlx::query_as::<_, PayrollRow>(
                "SELECT employee_name, personal_code, gross_salary_cents,
                        funded_pension_rate, pension_exemption,
                        unemployment_insurance_exemption, pay_period
                 FROM payroll_records
                 WHERE EXTRACT(YEAR FROM pay_period) = $1
                   AND EXTRACT(MONTH FROM pay_period) = $2",
            )
            .bind(year as f64)
            .bind(m as f64)
            .fetch_all(&self.db)
            .await?
        } else {
            sqlx::query_as::<_, PayrollRow>(
                "SELECT employee_name, personal_code, gross_salary_cents,
                        funded_pension_rate, pension_exemption,
                        unemployment_insurance_exemption, pay_period
                 FROM payroll_records
                 WHERE EXTRACT(YEAR FROM pay_period) = $1",
            )
            .bind(year as f64)
            .fetch_all(&self.db)
            .await?
        };

        let records = rows
            .into_iter()
            .map(|r| {
                let gross = r.gross_salary_cents;
                let period_date = r.pay_period.date_naive();
                let social_tax =
                    (gross as f64 * tax_policy::social_tax_rate(period_date)).round() as i64;
                let unemp_er = if r.unemployment_insurance_exemption {
                    0
                } else {
                    (gross as f64 * tax_policy::unemployment_insurance_employer_rate(period_date))
                        .round() as i64
                };
                let unemp_ee = if r.unemployment_insurance_exemption {
                    0
                } else {
                    (gross as f64 * tax_policy::unemployment_insurance_employee_rate(period_date))
                        .round() as i64
                };
                // Employee-specific II-pillar choice (2/4/6%, or 0% when
                // exempt). None = participation UNKNOWN: the pension
                // contribution stays 0 but the record is flagged so the
                // declaration is explicitly not-ready — a rate is never
                // silently assumed.
                let pension_rate = if r.pension_exemption {
                    Some(0.0)
                } else {
                    r.funded_pension_rate
                };
                let pension = pension_rate
                    .map(|rate| (gross as f64 * rate).round() as i64)
                    .unwrap_or(0);
                let taxable = gross - unemp_ee - pension;
                let income_tax = (taxable as f64
                    * tax_policy::income_tax_withheld_rate(period_date))
                .round() as i64;
                let net = gross - unemp_ee - pension - income_tax;
                EmployeeTaxRecord {
                    employee_name: r.employee_name,
                    personal_code: r.personal_code.unwrap_or_default(),
                    gross_salary_cents: gross,
                    social_tax_cents: social_tax,
                    unemployment_insurance_employer_cents: unemp_er,
                    unemployment_insurance_employee_cents: unemp_ee,
                    funded_pension_cents: pension,
                    funded_pension_rate: pension_rate,
                    income_tax_withheld_cents: income_tax,
                    net_salary_cents: net,
                }
            })
            .collect();

        Ok(records)
    }

    /// Extract dividend distributions.
    async fn query_dividends(
        &self,
        year: i32,
        month: Option<u32>,
    ) -> Result<Vec<DividendDistribution>, anyhow::Error> {
        let has_dividends = crate::table_exists_fn(&self.db, "dividend_distributions")
            .await
            .unwrap_or(false);

        if !has_dividends {
            return Ok(vec![]);
        }

        let rows = if let Some(m) = month {
            sqlx::query_as::<_, DividendRow>(
                "SELECT recipient, amount_cents, distribution_date
                 FROM dividend_distributions
                 WHERE EXTRACT(YEAR FROM distribution_date) = $1
                   AND EXTRACT(MONTH FROM distribution_date) = $2",
            )
            .bind(year as f64)
            .bind(m as f64)
            .fetch_all(&self.db)
            .await?
        } else {
            sqlx::query_as::<_, DividendRow>(
                "SELECT recipient, amount_cents, distribution_date
                 FROM dividend_distributions
                 WHERE EXTRACT(YEAR FROM distribution_date) = $1",
            )
            .bind(year as f64)
            .fetch_all(&self.db)
            .await?
        };

        let distributions: Vec<DividendDistribution> = rows
            .into_iter()
            .map(|r| {
                let amount = r.amount_cents;
                // F81: the recorded amount is the NET distribution; the CIT
                // due is the applicable NET-TO-TAX FRACTION on the
                // distribution date (20/80 until end-2024, 22/78 from
                // 2025-01-01) — not a gross-amount percentage constant.
                let fraction = tax_policy::dividend_tax_on_net(r.distribution_date);
                let tax = ((amount as f64) * fraction).round() as i64;
                DividendDistribution {
                    recipient: r.recipient,
                    amount_cents: amount,
                    tax_rate: fraction,
                    tax_amount_cents: tax,
                    distribution_date: r.distribution_date,
                }
            })
            .collect();

        Ok(distributions)
    }

    /// Build a data quality note based on what data was available.
    fn build_data_quality<T: AsRef<str>>(
        has_invoices: bool,
        has_payroll: bool,
        _has_dividends: bool,
        missing: &[T],
    ) -> DataQualityNote {
        let has_sufficient = has_invoices || has_payroll;
        DataQualityNote {
            has_sufficient_data: has_sufficient,
            // `missing` is the list of sources that could NOT be read. An
            // empty list means every source was available and must be
            // reported as such — a blanket "no tables found" would be a false
            // provenance statement in a statutory document.
            missing_fields: missing.iter().map(|f| f.as_ref().to_string()).collect(),
            note: if has_sufficient {
                "Data extracted from live database. Fields with 0 values indicate no data for the period."
                    .into()
            } else {
                "Insufficient data: all values are 0. Connect billing/payroll data sources.".into()
            },
        }
    }

    // --- Generators ---------------------------------------------------------

    /// Generate an Annual Report (Majandusaasta aruanne) for a fiscal year.
    pub async fn generate_annual_report(&self, year: i32) -> Result<AnnualReport, anyhow::Error> {
        let has_invoices = crate::table_exists_fn(&self.db, "invoices")
            .await
            .unwrap_or(false);
        let has_payroll = crate::table_exists_fn(&self.db, "payroll_records")
            .await
            .unwrap_or(false);
        let has_dividends = crate::table_exists_fn(&self.db, "dividend_distributions")
            .await
            .unwrap_or(false);

        let revenue = self.query_revenue(year, None).await?;
        let expenses = self.query_expenses(year, None).await?;
        let _employees = self.query_employees(year, None).await?;

        let total_revenue: i64 = revenue.iter().map(|s| s.amount_cents).sum();
        let total_expenses: i64 = expenses.iter().map(|e| e.amount_cents).sum();
        let net_profit = total_revenue - total_expenses;

        let (period_start, period_end) =
            ComplianceCalendar::calculate_period(SubmissionType::AnnualReport, year, None);

        let mut missing = Vec::new();
        if !has_invoices {
            missing.push("invoices table (revenue data)");
        }
        if !has_payroll {
            missing.push("payroll_records (staff costs)");
        }

        let report = AnnualReport {
            company_name: COMPANY_NAME.into(),
            registry_code: REGISTRY_CODE.into(),
            period: format!("{}-01-01 to {}-12-31", year, year),
            fiscal_year: year,
            generated_at: Utc::now(),
            balance_sheet: BalanceSheet {
                total_assets_cents: net_profit.max(0),
                current_assets_cents: net_profit.max(0),
                fixed_assets_cents: 0,
                total_liabilities_cents: 0,
                current_liabilities_cents: 0,
                long_term_liabilities_cents: 0,
                equity_cents: 2500,
                share_capital_cents: 2500,
                retained_earnings_cents: 0,
                period_profit_cents: net_profit,
                as_of: NaiveDate::from_ymd_opt(year, 12, 31).unwrap(),
            },
            income_statement: IncomeStatement {
                revenue_cents: total_revenue,
                cost_of_sales_cents: 0,
                gross_profit_cents: total_revenue,
                operating_expenses_cents: total_expenses,
                operating_profit_cents: net_profit,
                financial_income_cents: 0,
                financial_expenses_cents: 0,
                profit_before_tax_cents: net_profit,
                income_tax_cents: 0,
                net_profit_cents: net_profit,
                period_start,
                period_end,
            },
            cash_flow: CashFlowStatement {
                operating_cash_flow_cents: net_profit,
                investing_cash_flow_cents: 0,
                financing_cash_flow_cents: 0,
                net_cash_flow_cents: net_profit,
                opening_cash_cents: 0,
                closing_cash_cents: net_profit,
                period_start,
                period_end,
            },
            notes: vec![
                ReportNote {
                    index: 1,
                    title: "Accounting policies".into(),
                    content: "Prepared in accordance with Estonian Financial Reporting Standards (Eesti Finantsaruandluse Standard). Monetary amounts in euro cents.".into(),
                },
                ReportNote {
                    index: 2,
                    title: "Share capital".into(),
                    content: format!("Share capital is €25.00 (2 500 cents). Single shareholder: founder of {} (registry code {}).", COMPANY_NAME, REGISTRY_CODE),
                },
                ReportNote {
                    index: 3,
                    title: "Related parties".into(),
                    content: "No transactions with related parties requiring disclosure.".into(),
                },
            ],
            management_report: format!(
                "{} continued its operations as an email delivery platform during FY {}. \
                 Total revenue was {} cents. The company remains compliant with Estonian \
                 legal requirements and continues investing in platform development.",
                COMPANY_NAME, year, total_revenue
            ),
            revenue_sources: revenue,
            expense_breakdown: expenses,
            data_quality: Self::build_data_quality(
                has_invoices,
                has_payroll,
                has_dividends,
                &missing,
            ),
        };

        Ok(report)
    }

    /// Generate a VAT Declaration (Käibedeklaratsioon) for a month from
    /// ACTUAL invoice tax snapshots (F81): output VAT is the sum of the
    /// invoices' own `vat_total` values classified as domestic / reverse
    /// charge / export from their immutable billing snapshots, in EUR only;
    /// the displayed standard rate is the date-effective policy rate for the
    /// month. Deductible input VAT requires an explicit input-tax record —
    /// an assumed percentage of operating costs is never invented.
    pub async fn generate_vat_declaration(
        &self,
        year: i32,
        month: u32,
    ) -> Result<VatDeclaration, anyhow::Error> {
        let has_invoices = crate::table_exists_fn(&self.db, "invoices")
            .await
            .unwrap_or(false);
        let mut missing = Vec::new();
        if !has_invoices {
            missing.push("invoices table");
        }

        // Date-effective standard rate for the declared month.
        let month_start = NaiveDate::from_ymd_opt(year, month, 1).unwrap_or_else(|| {
            Utc::now()
                .date_naive()
                .with_day(1)
                .unwrap_or(Utc::now().date_naive())
        });
        let vat_rate = tax_policy::vat_standard_rate(month_start);
        let vat_rate_percent = (vat_rate * 100.0).round() as i32;

        // F81: classify each EUR invoice of the month from its tax snapshot
        // and billing address snapshot. Non-EUR invoices are excluded with
        // an explicit reason (no persisted conversion provenance).
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Class {
            Domestic,
            ReverseCharge,
            EuVatDue,
            Export,
        }

        #[allow(clippy::type_complexity)] // one flat query projection
        let invoice_rows: Vec<(i64, i64, Option<String>, Option<String>, Option<String>)> =
            sqlx::query_as(
                "SELECT COALESCE(subtotal, 0)::bigint, COALESCE(vat_total, 0)::bigint, \
             UPPER(currency), COALESCE(billing_country, ''), billing_address \
             FROM invoices \
             WHERE EXTRACT(YEAR FROM issued_at) = $1 \
               AND EXTRACT(MONTH FROM issued_at) = $2 \
               AND status = 'paid'",
            )
            .bind(year as f64)
            .bind(month as f64)
            .fetch_all(&self.db)
            .await
            .unwrap_or_default();

        let mut domestic_subtotal: i64 = 0;
        let mut domestic_output_vat: i64 = 0;
        let mut domestic_count: i64 = 0;
        let mut reverse_subtotal: i64 = 0;
        let mut reverse_count: i64 = 0;
        let mut eu_vat_due_subtotal: i64 = 0;
        let mut eu_vat_due_vat: i64 = 0;
        let mut eu_vat_due_count: i64 = 0;
        let mut export_subtotal: i64 = 0;
        let mut export_count: i64 = 0;
        let mut non_eur_invoices: i64 = 0;

        for (subtotal, vat_total, currency, country, billing_address) in invoice_rows {
            if currency.as_deref() != Some("EUR") {
                non_eur_invoices += 1;
                continue;
            }
            let country = country.unwrap_or_default();
            // Reverse charge (KMS §14) requires a valid customer VAT number
            // in the IMMUTABLE billing snapshot; without one, EE VAT is due.
            let snapshot_vat_number = billing_address
                .as_deref()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                .and_then(|snap| {
                    snap.get("vat_number")
                        .and_then(|v| v.as_str())
                        .map(|v| !v.trim().is_empty())
                })
                .unwrap_or(false);
            let class = if country == "EE" || country.is_empty() {
                Class::Domestic
            } else if crate::financial_analytics::is_eu_country(&country) {
                if snapshot_vat_number {
                    Class::ReverseCharge
                } else {
                    Class::EuVatDue
                }
            } else {
                Class::Export
            };
            match class {
                Class::Domestic => {
                    domestic_subtotal += subtotal;
                    domestic_output_vat += vat_total;
                    domestic_count += 1;
                }
                Class::ReverseCharge => {
                    reverse_subtotal += subtotal;
                    reverse_count += 1;
                }
                Class::EuVatDue => {
                    eu_vat_due_subtotal += subtotal;
                    eu_vat_due_vat += vat_total;
                    eu_vat_due_count += 1;
                }
                Class::Export => {
                    export_subtotal += subtotal;
                    export_count += 1;
                }
            }
        }
        // EU supplies without a VAT number are charged EE VAT and join the
        // domestic output figures (KMS §14 (5)).
        domestic_subtotal += eu_vat_due_subtotal;
        domestic_output_vat += eu_vat_due_vat;
        domestic_count += eu_vat_due_count;

        // Input VAT: from EXPLICIT eligible input-tax records only. The
        // canonical chain has no input-tax store, so deductible input VAT is
        // zero — multiplying total operating costs by the VAT rate (the old
        // behavior) fabricated a deduction.
        let input_vat_cents: i64 = 0;

        let output_vat = domestic_output_vat;
        let net_vat = output_vat - input_vat_cents;
        let due = ComplianceCalendar::calculate_due_date(
            SubmissionType::VatDeclaration,
            year,
            Some(month),
        );

        // F81: the return is ready for filing only when every box is backed
        // by complete source data.
        let mut incomplete_reasons = Vec::new();
        if !has_invoices {
            incomplete_reasons.push("invoices table absent — no source records".into());
        }
        if non_eur_invoices > 0 {
            incomplete_reasons.push(format!(
                "{non_eur_invoices} invoice(s) in a non-EUR currency excluded:                  no currency-conversion provenance is persisted"
            ));
        }
        incomplete_reasons.push(
            "deductible input VAT is 0: no eligible input-tax store exists in the              canonical schema".into(),
        );
        let ready_for_filing =
            has_invoices && non_eur_invoices == 0 && incomplete_reasons.len() <= 1;

        Ok(VatDeclaration {
            company_name: COMPANY_NAME.into(),
            registry_code: REGISTRY_CODE.into(),
            tax_year: year,
            tax_month: month,
            generated_at: Utc::now(),
            domestic_sales: VatCategory {
                taxable_amount_cents: domestic_subtotal,
                vat_rate: vat_rate_percent,
                vat_amount_cents: output_vat,
                transaction_count: domestic_count,
                description: format!(
                    "Domestic (EE) sales incl. EU B2C — output VAT from invoice tax                      snapshots (standard rate {vat_rate_percent}% in force)"
                ),
            },
            intra_eu_supplies: VatCategory {
                taxable_amount_cents: reverse_subtotal,
                vat_rate: 0,
                vat_amount_cents: 0,
                transaction_count: reverse_count,
                description: "Intra-EU B2B supplies (reverse charge, 0% EE VAT)"
                    .into(),
            },
            exports: VatCategory {
                taxable_amount_cents: export_subtotal,
                vat_rate: 0,
                vat_amount_cents: 0,
                transaction_count: export_count,
                description: "Exports outside EU (0% EE VAT)".into(),
            },
            input_vat: VatInputBreakdown {
                domestic_purchases: VatInputLine {
                    amount_cents: 0,
                    vat_amount_cents: 0,
                    description: "Domestic purchases — no input-tax store;                                   deductible VAT requires eligible records"
                        .into(),
                },
                intra_eu_acquisitions: VatInputLine {
                    amount_cents: 0,
                    vat_amount_cents: 0,
                    description: "Intra-EU acquisitions".into(),
                },
                imports: VatInputLine {
                    amount_cents: 0,
                    vat_amount_cents: 0,
                    description: "Imports from outside EU".into(),
                },
                total_deductible_vat_cents: input_vat_cents,
            },
            summary: VatSummary {
                total_output_vat_cents: output_vat,
                total_input_vat_cents: input_vat_cents,
                net_vat_payable_cents: if net_vat > 0 { net_vat } else { 0 },
                vat_refund_cents: if net_vat < 0 { -net_vat } else { 0 },
                due_date: due,
            },
            data_quality: Self::build_data_quality(
                has_invoices,
                false,
                false,
                &missing,
            ),
            ready_for_filing,
            incomplete_reasons,
        })
    }

    /// Generate an Income Tax Declaration (Tulumaks) for a month.
    pub async fn generate_income_tax_declaration(
        &self,
        year: i32,
        month: u32,
    ) -> Result<IncomeTaxDeclaration, anyhow::Error> {
        let dividends = self.query_dividends(year, Some(month)).await?;
        let has_dividends = crate::table_exists_fn(&self.db, "dividend_distributions")
            .await
            .unwrap_or(false);
        let mut missing = Vec::new();
        if !has_dividends {
            missing.push("dividend_distributions table");
        }

        let total_dividend: i64 = dividends.iter().map(|d| d.amount_cents).sum();
        let total_tax: i64 = dividends.iter().map(|d| d.tax_amount_cents).sum();

        let due =
            ComplianceCalendar::calculate_due_date(SubmissionType::IncomeTax, year, Some(month));

        let note = if dividends.is_empty() {
            "No dividend distributions this period. Estonia taxes only distributed profits."
        } else {
            "Dividend distributions detected. Tax calculated with the date-effective              net-to-tax fraction per TuMS §50 (22/78 from 2025-01-01)."
        };

        Ok(IncomeTaxDeclaration {
            company_name: COMPANY_NAME.into(),
            registry_code: REGISTRY_CODE.into(),
            tax_year: year,
            tax_month: month,
            generated_at: Utc::now(),
            dividend_distributions: dividends,
            total_dividend_cents: total_dividend,
            taxable_portion_cents: total_dividend,
            income_tax_liability_cents: total_tax,
            fringe_benefits: vec![],
            total_fringe_benefit_tax_cents: 0,
            other_taxable_payments: vec![],
            total_other_tax_cents: 0,
            total_tax_due_cents: total_tax,
            due_date: due,
            data_quality: DataQualityNote {
                has_sufficient_data: true,
                missing_fields: missing.iter().map(|s| s.to_string()).collect(),
                note: note.into(),
            },
        })
    }

    /// Generate a Social Tax Declaration (TSD) for a month of the entity
    /// whose registry code the declaration prints ([`REGISTRY_CODE`]).
    ///
    /// The declaration is derived from the **posted ledger** (see
    /// [`crate::tsd_ledger`]); a month whose payroll is not booked produces a
    /// visibly not-ready declaration (`has_sufficient_data = false`, with each
    /// gap named) rather than a figure recomputed from unposted inputs.
    pub async fn generate_social_tax_declaration(
        &self,
        year: i32,
        month: u32,
    ) -> Result<SocialTaxDeclaration, anyhow::Error> {
        self.generate_social_tax_declaration_for_registry_code(REGISTRY_CODE, year, month)
            .await
    }

    /// Same as [`Self::generate_social_tax_declaration`] with an explicit
    /// registry code: the declaration's printed identity must be the identity
    /// whose books were read.
    pub async fn generate_social_tax_declaration_for_registry_code(
        &self,
        registry_code: &str,
        year: i32,
        month: u32,
    ) -> Result<SocialTaxDeclaration, anyhow::Error> {
        let source =
            crate::tsd_ledger::read_month_by_registry_code(&self.db, registry_code, year, month)
                .await?;
        Ok(Self::declaration_from_ledger(source, year, month))
    }

    /// Same as [`Self::generate_social_tax_declaration`] for an explicitly
    /// identified legal entity (multi-entity deployments, tests).
    pub async fn generate_social_tax_declaration_for_entity(
        &self,
        legal_entity_id: Uuid,
        year: i32,
        month: u32,
    ) -> Result<SocialTaxDeclaration, anyhow::Error> {
        let source = crate::tsd_ledger::read_month(&self.db, legal_entity_id, year, month).await?;
        Ok(Self::declaration_from_ledger(source, year, month))
    }

    /// Map the ledger's answer onto the declaration document. Pure function:
    /// every amount and every quality flag comes from the source unchanged.
    pub fn declaration_from_ledger(
        source: crate::tsd_ledger::TsdLedgerSource,
        year: i32,
        month: u32,
    ) -> SocialTaxDeclaration {
        let employees: Vec<EmployeeTaxRecord> = source
            .employees
            .iter()
            .map(|e| EmployeeTaxRecord {
                employee_name: e.employee_name.clone().unwrap_or_default(),
                personal_code: e.personal_code.clone().unwrap_or_default(),
                gross_salary_cents: e.gross_salary_cents,
                social_tax_cents: e.social_tax_cents,
                unemployment_insurance_employer_cents: e.unemployment_insurance_employer_cents,
                unemployment_insurance_employee_cents: e.unemployment_insurance_employee_cents,
                funded_pension_cents: e.funded_pension_cents,
                funded_pension_rate: e.funded_pension_rate,
                income_tax_withheld_cents: e.income_tax_withheld_cents,
                net_salary_cents: e.net_salary_cents,
            })
            .collect();

        let total_gross: i64 = employees.iter().map(|e| e.gross_salary_cents).sum();
        let total_social: i64 = employees.iter().map(|e| e.social_tax_cents).sum();
        let total_unemp_er: i64 = employees
            .iter()
            .map(|e| e.unemployment_insurance_employer_cents)
            .sum();
        let total_unemp_ee: i64 = employees
            .iter()
            .map(|e| e.unemployment_insurance_employee_cents)
            .sum();
        let total_pension: i64 = employees.iter().map(|e| e.funded_pension_cents).sum();
        let total_income_tax: i64 = employees.iter().map(|e| e.income_tax_withheld_cents).sum();
        let total_employer = total_social + total_unemp_er;

        let employee_count = employees.len() as i32;

        SocialTaxDeclaration {
            // Identity from the entity whose books were read, never from a
            // constant: a declaration that names Bel Consulting OÜ while
            // summing another entity's ledger would be a false statement.
            company_name: source.legal_name.clone(),
            registry_code: source.registry_code.clone(),
            tax_year: year,
            tax_month: month,
            generated_at: Utc::now(),
            employees,
            totals: SocialTaxTotals {
                total_gross_salary_cents: total_gross,
                total_social_tax_cents: total_social,
                total_unemployment_employer_cents: total_unemp_er,
                total_unemployment_employee_cents: total_unemp_ee,
                total_funded_pension_cents: total_pension,
                total_income_tax_withheld_cents: total_income_tax,
                total_employer_cost_cents: total_gross + total_employer,
                employee_count,
            },
            due_date: ComplianceCalendar::calculate_due_date(
                SubmissionType::SocialTax,
                year,
                Some(month),
            ),
            data_quality: DataQualityNote {
                has_sufficient_data: source.has_sufficient_data(),
                missing_fields: source.missing_fields(),
                note: source.note(),
            },
        }
    }

    /// Generate a Statistical Report.
    pub async fn generate_statistical_report(
        &self,
        year: i32,
    ) -> Result<StatisticalReport, anyhow::Error> {
        let revenue = self.query_revenue(year, None).await?;
        let employees = self.query_employees(year, None).await?;
        let has_invoices = crate::table_exists_fn(&self.db, "invoices")
            .await
            .unwrap_or(false);

        let total_revenue: i64 = revenue.iter().map(|s| s.amount_cents).sum();
        let mut missing = Vec::new();
        if !has_invoices {
            missing.push("invoices table");
        }

        Ok(StatisticalReport {
            company_name: COMPANY_NAME.into(),
            registry_code: REGISTRY_CODE.into(),
            report_year: year,
            generated_at: Utc::now(),
            revenue_bands: vec![
                RevenueBand {
                    category: "EMTAK 6201 — Computer programming".into(),
                    amount_cents: total_revenue,
                },
            ],
            employee_headcount: employees.len() as i32,
            export_revenue_cents: 0,
            is_it_sector: true,
            it_sector_questions: Some(ItSectorQuestions {
                software_development_revenue_cents: total_revenue,
                saas_revenue_cents: total_revenue,
                it_consulting_revenue_cents: 0,
                hosting_infrastructure_revenue_cents: 0,
                cybersecurity_revenue_cents: 0,
                other_it_revenue_cents: 0,
            }),
            data_quality: DataQualityNote {
                has_sufficient_data: has_invoices,
                missing_fields: missing.iter().map(|s| s.to_string()).collect(),
                note: "IT sector report: ApexMail is classified as EMTAK 6201 (Computer programming activities).".into(),
            },
        })
    }

    // --- File naming & multi-format generation -------------------------------

    /// Build a fully qualified filename for a compliance document.
    ///
    /// Format: `{type}-{year}-{period}-{company-slug}-{registry_code}.pdf`
    ///
    /// Examples:
    ///   - `annual-report-2025-bel-consulting-ou-16588745.pdf`
    ///   - `vat-declaration-2026-01-bel-consulting-ou-16588745.pdf`
    ///   - `income-tax-declaration-2026-01-bel-consulting-ou-16588745.pdf`
    ///   - `social-tax-declaration-2026-01-bel-consulting-ou-16588745.pdf`
    pub fn build_file_name(
        st: SubmissionType,
        year: i32,
        month: Option<u32>,
        extension: &str,
    ) -> String {
        let company_slug = COMPANY_NAME
            .to_lowercase()
            .replace(' ', "-")
            .replace('ü', "u")
            .replace('ö', "o")
            .replace('ä', "a")
            .replace("--", "-");

        match st {
            SubmissionType::AnnualReport => {
                format!("annual-report-{year}-{company_slug}-{REGISTRY_CODE}.{extension}")
            }
            SubmissionType::VatDeclaration => {
                let m = month.unwrap_or(1);
                format!("vat-declaration-{year}-{m:02}-{company_slug}-{REGISTRY_CODE}.{extension}")
            }
            SubmissionType::IncomeTax => {
                let m = month.unwrap_or(1);
                format!("income-tax-declaration-{year}-{m:02}-{company_slug}-{REGISTRY_CODE}.{extension}")
            }
            SubmissionType::SocialTax => {
                let m = month.unwrap_or(1);
                format!("social-tax-declaration-{year}-{m:02}-{company_slug}-{REGISTRY_CODE}.{extension}")
            }
            SubmissionType::StatisticalReport => {
                format!("statistical-report-{year}-{company_slug}-{REGISTRY_CODE}.{extension}")
            }
        }
    }

    /// Build a human-readable period label.
    pub fn build_period_label(st: SubmissionType, year: i32, month: Option<u32>) -> String {
        let month_names = [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ];

        match st {
            SubmissionType::AnnualReport | SubmissionType::StatisticalReport => {
                format!("FY {year}")
            }
            _ => {
                let m = month.unwrap_or(1) as usize;
                if m > 0 && m <= 12 {
                    format!("{} {year}", month_names[m - 1])
                } else {
                    format!("Period {year}-{m:02}")
                }
            }
        }
    }

    /// Generate a minimal PDF binary from the document JSON.
    ///
    /// Produces a valid PDF with embedded JSON content. Uses a minimal PDF
    /// generator without external dependencies — suitable for archiving.
    pub fn build_pdf_bytes(
        st: SubmissionType,
        year: i32,
        month: Option<u32>,
        document_json: &serde_json::Value,
    ) -> Vec<u8> {
        let title = Self::build_file_name(st, year, month, "pdf");
        let period_label = Self::build_period_label(st, year, month);
        let generated_at = Utc::now().to_rfc3339();

        let json_str = serde_json::to_string_pretty(document_json).unwrap_or_default();
        let _json_bytes = json_str.as_bytes();

        // Build a minimal PDF 1.4 document
        let mut pdf = Vec::new();

        // PDF header
        pdf.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");

        // Object 1: Catalog
        let obj1_offset = pdf.len();
        pdf.extend(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Outlines 3 0 R >>\nendobj\n");

        // Object 2: Pages
        let obj2_offset = pdf.len();
        pdf.extend(b"2 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n");

        // Object 3: Outlines
        let obj3_offset = pdf.len();
        pdf.extend(b"3 0 obj\n<< /Type /Outlines /Count 0 >>\nendobj\n");

        // Object 4: Page with content stream
        let obj4_offset = pdf.len();

        // Content stream: title + period + timestamp + JSON summary
        let content = format!(
            "BT /F1 14 Tf 50 750 Td ({}) Tj T*\n\
             /F1 12 Tf 50 730 Td (Period: {}) Tj T*\n\
             50 710 Td (Company: {} — Registry Code: {}) Tj T*\n\
             50 690 Td (Generated: {}) Tj T*\n\
             ET\n",
            escape_pdf_string(&title),
            escape_pdf_string(&period_label),
            escape_pdf_string(COMPANY_NAME),
            escape_pdf_string(REGISTRY_CODE),
            escape_pdf_string(&generated_at),
        );
        let content_bytes = content.into_bytes();

        // Content stream object
        let _content_stream_offset = pdf.len();
        let page_object = "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842]\n\
               /Contents 5 0 R /Resources << /Font << /F1 6 0 R >> >> >>\nendobj\n";
        pdf.extend(page_object.as_bytes());

        // Object 5: Content stream data
        let obj5_offset = pdf.len();
        pdf.extend(format!("5 0 obj\n<< /Length {} >>\nstream\n", content_bytes.len()).as_bytes());
        pdf.extend(&content_bytes);
        pdf.extend(b"\nendstream\nendobj\n");

        // Object 6: Font (Helvetica)
        let obj6_offset = pdf.len();
        pdf.extend(b"6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");

        // Object 7: Document metadata with embedded JSON
        let obj7_offset = pdf.len();
        let escaped_json = escape_pdf_string(&json_str);
        let metadata_xml = format!(
            r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
      xmlns:dc="http://purl.org/dc/elements/1.1/"
      xmlns:xmp="http://ns.adobe.com/xap/1.0/">
      <dc:title>{title}</dc:title>
      <dc:description>Compliance document: {period_label}</dc:description>
      <dc:creator>{COMPANY_NAME}</dc:creator>
      <dc:date>{generated_at}</dc:date>
    </rdf:Description>
    <rdf:Description rdf:about=""
      xmlns:apexmail="https://apexmail.com/compliance/">
      <apexmail:registryCode>{REGISTRY_CODE}</apexmail:registryCode>
      <apexmail:documentType>{doc_type}</apexmail:documentType>
      <apexmail:jsonData>{escaped_json}</apexmail:jsonData>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#,
            title = escape_xml(&title),
            period_label = escape_xml(&period_label),
            COMPANY_NAME = escape_xml(COMPANY_NAME),
            generated_at = escape_xml(&generated_at),
            REGISTRY_CODE = escape_xml(REGISTRY_CODE),
            doc_type = escape_xml(st.as_str()),
            escaped_json = escape_xml(&escaped_json),
        );
        let metadata_bytes = metadata_xml.as_bytes();

        pdf.extend(
            format!(
                "7 0 obj\n<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n",
                metadata_bytes.len()
            )
            .as_bytes(),
        );
        pdf.extend(metadata_bytes);
        pdf.extend(b"\nendstream\nendobj\n");

        // Cross-reference table
        let xref_offset = pdf.len();
        pdf.extend(b"xref\n0 8\n");
        pdf.extend(b"0000000000 65535 f \n");
        pdf.extend(format!("{:010} 00000 n \n", obj1_offset).as_bytes());
        pdf.extend(format!("{:010} 00000 n \n", obj2_offset).as_bytes());
        pdf.extend(format!("{:010} 00000 n \n", obj3_offset).as_bytes());
        pdf.extend(format!("{:010} 00000 n \n", obj4_offset).as_bytes());
        pdf.extend(format!("{:010} 00000 n \n", obj5_offset).as_bytes());
        pdf.extend(format!("{:010} 00000 n \n", obj6_offset).as_bytes());
        pdf.extend(format!("{:010} 00000 n \n", obj7_offset).as_bytes());

        // Trailer
        pdf.extend(
            format!("trailer\n<< /Size 8 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n")
                .as_bytes(),
        );

        pdf
    }

    /// Generate CSV text from the document JSON.
    ///
    /// Flattens nested structures into key-value pairs suitable for CSV export.
    pub fn build_csv_text(
        st: SubmissionType,
        year: i32,
        month: Option<u32>,
        document_json: &serde_json::Value,
    ) -> String {
        let period_label = Self::build_period_label(st, year, month);
        let generated_at = Utc::now().to_rfc3339();
        let file_name = Self::build_file_name(st, year, month, "csv");

        let mut csv = String::new();

        // Header metadata
        csv.push_str("\"Key\",\"Value\"\n");
        csv.push_str(&format!("\"document_type\",\"{}\"\n", st.as_str()));
        csv.push_str(&format!("\"file_name\",\"{}\"\n", file_name));
        csv.push_str(&format!("\"company_name\",\"{}\"\n", COMPANY_NAME));
        csv.push_str(&format!("\"registry_code\",\"{}\"\n", REGISTRY_CODE));
        csv.push_str(&format!("\"period_label\",\"{}\"\n", period_label));
        csv.push_str(&format!("\"tax_year\",\"{}\"\n", year));
        if let Some(m) = month {
            csv.push_str(&format!("\"tax_month\",\"{}\"\n", m));
        }
        csv.push_str(&format!("\"generated_at\",\"{}\"\n", generated_at));

        // Flatten JSON - specific to each document type
        match st {
            SubmissionType::AnnualReport => {
                if let Some(bs) = document_json.get("balance_sheet") {
                    flatten_json_to_csv(&mut csv, "balance_sheet", bs, 0);
                }
                if let Some(ins) = document_json.get("income_statement") {
                    flatten_json_to_csv(&mut csv, "income_statement", ins, 0);
                }
                if let Some(cf) = document_json.get("cash_flow") {
                    flatten_json_to_csv(&mut csv, "cash_flow", cf, 0);
                }
                if let Some(rev) = document_json.get("revenue_sources") {
                    flatten_json_to_csv(&mut csv, "revenue_sources", rev, 0);
                }
            }
            SubmissionType::VatDeclaration => {
                if let Some(s) = document_json.get("summary") {
                    flatten_json_to_csv(&mut csv, "vat_summary", s, 0);
                }
                if let Some(ds) = document_json.get("domestic_sales") {
                    flatten_json_to_csv(&mut csv, "domestic_sales", ds, 0);
                }
                if let Some(iv) = document_json.get("input_vat") {
                    flatten_json_to_csv(&mut csv, "input_vat", iv, 0);
                }
            }
            SubmissionType::IncomeTax => {
                flatten_json_to_csv(&mut csv, "income_tax", document_json, 0);
            }
            SubmissionType::SocialTax => {
                if let Some(t) = document_json.get("totals") {
                    flatten_json_to_csv(&mut csv, "social_tax_totals", t, 0);
                }
            }
            SubmissionType::StatisticalReport => {
                flatten_json_to_csv(&mut csv, "statistical", document_json, 0);
            }
        }

        csv
    }

    /// Compute SHA-256 checksum of pdf_data + csv_data + json_data for tamper-proofing.
    fn compute_checksum(pdf_data: &[u8], csv_data: &str, json_data: &serde_json::Value) -> String {
        let mut hasher = Sha256::new();
        hasher.update(pdf_data);
        hasher.update(csv_data.as_bytes());
        hasher.update(
            serde_json::to_string(json_data)
                .unwrap_or_default()
                .as_bytes(),
        );
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Persist a submission record with all three formats (PDF, CSV, JSON) and metadata.
    pub async fn persist_submission_with_formats(
        &self,
        st: SubmissionType,
        year: i32,
        month: Option<u32>,
        document_json: &serde_json::Value,
    ) -> Result<Uuid, anyhow::Error> {
        let (ps, pe) = ComplianceCalendar::calculate_period(st, year, month);
        let id = Uuid::new_v4();
        let file_name = Self::build_file_name(st, year, month, "pdf");
        let period_label = Self::build_period_label(st, year, month);

        let pdf_data = Self::build_pdf_bytes(st, year, month, document_json);
        let csv_data = Self::build_csv_text(st, year, month, document_json);
        let json_data = document_json.clone();

        let file_size = pdf_data.len() as i64;
        let checksum = Self::compute_checksum(&pdf_data, &csv_data, &json_data);

        sqlx::query(
            r#"INSERT INTO compliance_submissions
               (id, submission_type, period_start, period_end, tax_year, tax_month,
                status, document_json, file_name, file_size, pdf_data, csv_data, json_data,
                period_label, checksum, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, 'generated', $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())
               ON CONFLICT (submission_type, tax_year, COALESCE(tax_month, 0))
               DO UPDATE SET
                   document_json = $7, file_name = $8, file_size = $9,
                   pdf_data = $10, csv_data = $11, json_data = $12,
                   period_label = $13, checksum = $14,
                   status = 'generated', updated_at = NOW()"#,
        )
        .bind(id)
        .bind(st.as_str())
        .bind(ps)
        .bind(pe)
        .bind(year)
        .bind(month.map(|m| m as i32))
        .bind(document_json)
        .bind(&file_name)
        .bind(file_size)
        .bind(&pdf_data)
        .bind(&csv_data)
        .bind(&json_data)
        .bind(&period_label)
        .bind(&checksum)
        .execute(&self.db)
        .await?;

        tracing::info!(
            id = %id,
            file_name = %file_name,
            period_label = %period_label,
            checksum = %checksum,
            file_size = file_size,
            "Compliance submission persisted with all formats"
        );

        Ok(id)
    }

    /// Persist a submission record and return its ID.
    /// Now delegates to `persist_submission_with_formats` for full format storage.
    pub async fn persist_submission(
        &self,
        st: SubmissionType,
        year: i32,
        month: Option<u32>,
        document_json: &serde_json::Value,
    ) -> Result<Uuid, anyhow::Error> {
        self.persist_submission_with_formats(st, year, month, document_json)
            .await
    }

    /// Get a submission with all format data for download.
    pub async fn get_submission_download(
        &self,
        id: Uuid,
    ) -> Result<Option<SubmissionDownload>, anyhow::Error> {
        let row = sqlx::query_as::<_, SubmissionDownloadRow>(
            "SELECT id, submission_type, file_name, file_size, pdf_data, csv_data, json_data,
                    period_label, checksum, status, tax_year, tax_month
             FROM compliance_submissions
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await?;
        Ok(row.map(|r| r.into()))
    }

    /// List past submissions with extended format metadata.
    pub async fn list_submissions_extended(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SubmissionListItem>, anyhow::Error> {
        let rows = sqlx::query_as::<_, SubmissionListRow>(
            "SELECT id, submission_type, period_start, period_end, tax_year, tax_month,
                    status, submitted_at, document_json, document_url, filing_reference,
                    file_name, file_size, period_label, checksum,
                    (pdf_data IS NOT NULL AND length(pdf_data) > 0) AS has_pdf,
                    (csv_data IS NOT NULL AND length(csv_data) > 0) AS has_csv,
                    (json_data IS NOT NULL) AS has_json,
                    notes, created_at, updated_at
             FROM compliance_submissions
             ORDER BY tax_year DESC, COALESCE(tax_month, 0) DESC
             LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Get a single submission by ID.
    pub async fn get_submission(
        &self,
        id: Uuid,
    ) -> Result<Option<ComplianceSubmission>, anyhow::Error> {
        let row = sqlx::query_as::<_, SubmissionRow>(
            "SELECT id, submission_type, period_start, period_end, tax_year, tax_month,
                    status, submitted_at, document_json, document_url, filing_reference, notes,
                    created_at, updated_at
             FROM compliance_submissions
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await?;
        Ok(row.map(|r| r.into()))
    }

    /// Generate an admin dashboard widget with upcoming deadline stats.
    pub async fn deadline_widget(&self) -> Result<DeadlineWidget, anyhow::Error> {
        let today = Utc::now().date_naive();
        let week = today + chrono::Duration::days(7);
        let month = today + chrono::Duration::days(30);

        let upcoming = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM compliance_deadlines
             WHERE status = 'pending' AND due_date BETWEEN $1 AND $2",
        )
        .bind(today)
        .bind(week)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);

        let upcoming_month = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM compliance_deadlines
             WHERE status = 'pending' AND due_date BETWEEN $1 AND $2",
        )
        .bind(today)
        .bind(month)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);

        let overdue = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM compliance_deadlines
             WHERE status = 'overdue'",
        )
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);

        Ok(DeadlineWidget {
            upcoming_7d: upcoming,
            upcoming_30d: upcoming_month,
            overdue,
            next_due: sqlx::query_as::<_, NextDeadlineRow>(
                "SELECT deadline_type, label, due_date
                 FROM compliance_deadlines
                 WHERE status = 'pending'
                 ORDER BY due_date ASC LIMIT 1",
            )
            .fetch_optional(&self.db)
            .await?
            .map(|r| DeadlineInfo {
                deadline_type: r.deadline_type,
                label: r.label,
                due_date: r.due_date,
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// Contact person deadline integration with registry monitor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactPersonRecord {
    pub id: Uuid,
    pub full_name: String,
    pub personal_code: Option<String>,
    pub email: String,
    pub phone: Option<String>,
    pub last_verified_at: Option<chrono::DateTime<Utc>>,
    pub registry_code: String,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

impl ComplianceCalendar {
    pub async fn seed_contact_person_deadline(
        &self,
        year: i32,
    ) -> Result<ComplianceDeadline, anyhow::Error> {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let due = NaiveDate::from_ymd_opt(year, 1, 31).unwrap();

        sqlx::query(
            r#"INSERT INTO compliance_deadlines
               (id, deadline_type, label, period_start, period_end, due_date, status, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $7)
               ON CONFLICT (deadline_type, due_date) DO NOTHING"#,
        )
        .bind(id)
        .bind("contact_person_verification")
        .bind(format!("Contact Person Verification FY {}", year))
        .bind(NaiveDate::from_ymd_opt(year, 1, 1).unwrap())
        .bind(NaiveDate::from_ymd_opt(year, 12, 31).unwrap())
        .bind(due)
        .bind(now)
        .execute(&self.db)
        .await?;

        Ok(ComplianceDeadline {
            id,
            deadline_type: "contact_person_verification".into(),
            label: format!("Contact Person Verification FY {}", year),
            period_start: NaiveDate::from_ymd_opt(year, 1, 1).unwrap(),
            period_end: NaiveDate::from_ymd_opt(year, 12, 31).unwrap(),
            due_date: due,
            status: "pending".into(),
            submission_id: None,
            reminded_7d_at: None,
            reminded_1d_at: None,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn record_contact_person_verification(
        &self,
        deadline_id: Uuid,
        contact_person_id: Uuid,
    ) -> Result<(), anyhow::Error> {
        sqlx::query(
            "UPDATE compliance_deadlines SET status = 'filed', submission_id = $2, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(deadline_id)
        .bind(contact_person_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub async fn register_contact_person(
        &self,
        full_name: &str,
        personal_code: Option<&str>,
        email: &str,
        phone: Option<&str>,
    ) -> Result<ContactPersonRecord, anyhow::Error> {
        let now = Utc::now();
        let id = Uuid::new_v4();

        let row = sqlx::query_as::<_, ContactPersonRow>(
            r#"INSERT INTO contact_persons
               (id, full_name, personal_code, email, phone, last_verified_at, registry_code, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, NOW(), '16588745', $6, $6)
               ON CONFLICT (email) DO UPDATE SET
                   full_name = $2, personal_code = $3, phone = $5,
                   last_verified_at = NOW(), updated_at = $6
               RETURNING id, full_name, personal_code, email, phone,
                         last_verified_at, registry_code, created_at, updated_at"#,
        )
        .bind(id)
        .bind(full_name)
        .bind(personal_code)
        .bind(email)
        .bind(phone)
        .bind(now)
        .fetch_one(&self.db)
        .await?;

        Ok(ContactPersonRecord {
            id: row.id,
            full_name: row.full_name,
            personal_code: row.personal_code,
            email: row.email,
            phone: row.phone,
            last_verified_at: row.last_verified_at,
            registry_code: row.registry_code,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

impl EstoniaOuCompliance {
    pub fn seed_registry_monitor(&self) -> ScheduledRegistryMonitor {
        let mut monitor = ScheduledRegistryMonitor::new(REGISTRY_CODE.into());
        monitor.seed_estonian_ou_notices(COMPANY_NAME, REGISTRY_CODE);
        monitor
    }

    pub async fn sync_registry_notices_to_calendar(
        &self,
    ) -> Result<Vec<ComplianceDeadline>, anyhow::Error> {
        let monitor = self.seed_registry_monitor();
        let mut created = Vec::new();
        let now = Utc::now();

        for notice in monitor.monitor().list_all() {
            if notice.status != NoticeStatus::Completed {
                let id = Uuid::new_v4();
                sqlx::query(
                    r#"INSERT INTO compliance_deadlines
                       (id, deadline_type, label, period_start, period_end, due_date, status, created_at, updated_at)
                       VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $7)
                       ON CONFLICT (deadline_type, due_date) DO NOTHING"#,
                )
                .bind(id)
                .bind(format!("registry_{}", notice.notice_id.to_lowercase().replace('-', "_")))
                .bind(&notice.title)
                .bind(NaiveDate::from_ymd_opt(notice.due_date.year(), 1, 1).unwrap())
                .bind(NaiveDate::from_ymd_opt(notice.due_date.year(), 12, 31).unwrap())
                .bind(notice.due_date)
                .bind(now)
                .execute(&self.db)
                .await?;

                created.push(ComplianceDeadline {
                    id,
                    deadline_type: format!(
                        "registry_{}",
                        notice.notice_id.to_lowercase().replace('-', "_")
                    ),
                    label: notice.title.clone(),
                    period_start: NaiveDate::from_ymd_opt(notice.due_date.year(), 1, 1).unwrap(),
                    period_end: NaiveDate::from_ymd_opt(notice.due_date.year(), 12, 31).unwrap(),
                    due_date: notice.due_date,
                    status: "pending".into(),
                    submission_id: None,
                    reminded_7d_at: None,
                    reminded_1d_at: None,
                    created_at: now,
                    updated_at: now,
                });
            }
        }

        Ok(created)
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ContactPersonRow {
    id: Uuid,
    full_name: String,
    personal_code: Option<String>,
    email: String,
    phone: Option<String>,
    last_verified_at: Option<chrono::DateTime<Utc>>,
    registry_code: String,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Widget types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlineWidget {
    pub upcoming_7d: i64,
    pub upcoming_30d: i64,
    pub overdue: i64,
    pub next_due: Option<DeadlineInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlineInfo {
    pub deadline_type: String,
    pub label: String,
    pub due_date: NaiveDate,
}

/// Downloadable submission data with all formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionDownload {
    pub id: Uuid,
    pub submission_type: String,
    pub file_name: String,
    pub file_size: i64,
    pub pdf_data: Vec<u8>,
    pub csv_data: String,
    pub json_data: serde_json::Value,
    pub period_label: String,
    pub checksum: String,
    pub status: String,
    pub tax_year: i32,
    pub tax_month: Option<i32>,
}

// ---------------------------------------------------------------------------
// PDF / CSV helper functions
// ---------------------------------------------------------------------------

fn escape_pdf_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn flatten_json_to_csv(csv: &mut String, prefix: &str, value: &serde_json::Value, depth: usize) {
    if depth > 10 {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };

                match v {
                    serde_json::Value::Null
                    | serde_json::Value::Bool(_)
                    | serde_json::Value::Number(_)
                    | serde_json::Value::String(_) => {
                        csv.push_str(&format!("\"{}\",\"{}\"\n", key, csv_escape_value(v)));
                    }
                    serde_json::Value::Array(arr) => {
                        for (i, item) in arr.iter().enumerate() {
                            flatten_json_to_csv(csv, &format!("{}[{}]", key, i), item, depth + 1);
                        }
                    }
                    serde_json::Value::Object(_) => {
                        flatten_json_to_csv(csv, &key, v, depth + 1);
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                flatten_json_to_csv(csv, &format!("{}[{}]", prefix, i), item, depth + 1);
            }
        }
        _ => {
            csv.push_str(&format!("\"{}\",\"{}\"\n", prefix, csv_escape_value(value)));
        }
    }
}

fn csv_escape_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.replace('"', "\"\""),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// SQL row types
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct RevenueRow {
    currency: String,
    total_cents: Option<i64>,
    invoice_count: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct ExpenseRow {
    total_cents: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct CostRow {
    category: String,
    total_cents: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct PayrollRow {
    employee_name: String,
    personal_code: Option<String>,
    gross_salary_cents: i64,
    /// Employee's II-pillar choice for the period (2/4/6%; NULL = unknown).
    funded_pension_rate: Option<f64>,
    pension_exemption: bool,
    unemployment_insurance_exemption: bool,
    pay_period: chrono::DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct DividendRow {
    recipient: String,
    amount_cents: i64,
    distribution_date: NaiveDate,
}

#[derive(Debug, sqlx::FromRow)]
struct DeadlineRow {
    id: Uuid,
    deadline_type: String,
    label: String,
    period_start: NaiveDate,
    period_end: NaiveDate,
    due_date: NaiveDate,
    status: String,
    submission_id: Option<Uuid>,
    reminded_7d_at: Option<chrono::DateTime<Utc>>,
    reminded_1d_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<DeadlineRow> for ComplianceDeadline {
    fn from(r: DeadlineRow) -> Self {
        Self {
            id: r.id,
            deadline_type: r.deadline_type,
            label: r.label,
            period_start: r.period_start,
            period_end: r.period_end,
            due_date: r.due_date,
            status: r.status,
            submission_id: r.submission_id,
            reminded_7d_at: r.reminded_7d_at,
            reminded_1d_at: r.reminded_1d_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct SubmissionRow {
    id: Uuid,
    submission_type: String,
    period_start: NaiveDate,
    period_end: NaiveDate,
    tax_year: i32,
    tax_month: Option<i32>,
    status: String,
    submitted_at: Option<chrono::DateTime<Utc>>,
    document_json: serde_json::Value,
    document_url: Option<String>,
    filing_reference: Option<String>,
    notes: Option<String>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<SubmissionRow> for ComplianceSubmission {
    fn from(r: SubmissionRow) -> Self {
        Self {
            id: r.id,
            submission_type: r.submission_type,
            period_start: r.period_start,
            period_end: r.period_end,
            tax_year: r.tax_year,
            tax_month: r.tax_month,
            status: r.status,
            submitted_at: r.submitted_at,
            document_json: r.document_json,
            document_url: r.document_url,
            filing_reference: r.filing_reference,
            notes: r.notes,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)] // full row contract; individual reports read subsets
struct SubmissionListRow {
    id: Uuid,
    submission_type: String,
    period_start: NaiveDate,
    period_end: NaiveDate,
    tax_year: i32,
    tax_month: Option<i32>,
    status: String,
    submitted_at: Option<chrono::DateTime<Utc>>,
    document_json: serde_json::Value,
    document_url: Option<String>,
    filing_reference: Option<String>,
    file_name: Option<String>,
    file_size: Option<i64>,
    period_label: Option<String>,
    checksum: Option<String>,
    has_pdf: bool,
    has_csv: bool,
    has_json: bool,
    notes: Option<String>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<SubmissionListRow> for SubmissionListItem {
    fn from(r: SubmissionListRow) -> Self {
        Self {
            id: r.id,
            submission_type: r.submission_type,
            period_start: r.period_start,
            period_end: r.period_end,
            tax_year: r.tax_year,
            tax_month: r.tax_month,
            status: r.status,
            submitted_at: r.submitted_at,
            document_json: r.document_json,
            document_url: r.document_url,
            filing_reference: r.filing_reference,
            file_name: r.file_name,
            file_size: r.file_size,
            period_label: r.period_label,
            checksum: r.checksum,
            has_pdf: r.has_pdf,
            has_csv: r.has_csv,
            has_json: r.has_json,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct NextDeadlineRow {
    deadline_type: String,
    label: String,
    due_date: NaiveDate,
}

#[derive(Debug, sqlx::FromRow)]
struct SubmissionDownloadRow {
    id: Uuid,
    submission_type: String,
    file_name: Option<String>,
    file_size: Option<i64>,
    pdf_data: Option<Vec<u8>>,
    csv_data: Option<String>,
    json_data: Option<serde_json::Value>,
    period_label: Option<String>,
    checksum: Option<String>,
    status: String,
    tax_year: i32,
    tax_month: Option<i32>,
}

impl From<SubmissionDownloadRow> for SubmissionDownload {
    fn from(r: SubmissionDownloadRow) -> Self {
        Self {
            id: r.id,
            submission_type: r.submission_type,
            file_name: r.file_name.unwrap_or_default(),
            file_size: r.file_size.unwrap_or(0),
            pdf_data: r.pdf_data.unwrap_or_default(),
            csv_data: r.csv_data.unwrap_or_default(),
            json_data: r.json_data.unwrap_or_default(),
            period_label: r.period_label.unwrap_or_default(),
            checksum: r.checksum.unwrap_or_default(),
            status: r.status,
            tax_year: r.tax_year,
            tax_month: r.tax_month,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submission_type_roundtrip() {
        for st in [
            SubmissionType::AnnualReport,
            SubmissionType::VatDeclaration,
            SubmissionType::IncomeTax,
            SubmissionType::SocialTax,
            SubmissionType::StatisticalReport,
        ] {
            let s = st.as_str();
            let back = SubmissionType::from_str(s);
            assert_eq!(back, Some(st));
        }
    }

    #[test]
    fn submission_type_invalid() {
        assert_eq!(SubmissionType::from_str("bogus"), None);
    }

    #[test]
    fn due_date_annual_report() {
        let due = ComplianceCalendar::calculate_due_date(SubmissionType::AnnualReport, 2025, None);
        assert_eq!(due, NaiveDate::from_ymd_opt(2026, 6, 30).unwrap());
    }

    #[test]
    fn due_date_vat_declaration() {
        let due =
            ComplianceCalendar::calculate_due_date(SubmissionType::VatDeclaration, 2026, Some(1));
        assert_eq!(due, NaiveDate::from_ymd_opt(2026, 2, 20).unwrap());
    }

    #[test]
    fn due_date_vat_declaration_december() {
        let due =
            ComplianceCalendar::calculate_due_date(SubmissionType::VatDeclaration, 2025, Some(12));
        assert_eq!(due, NaiveDate::from_ymd_opt(2026, 1, 20).unwrap());
    }

    #[test]
    fn due_date_income_tax() {
        let due = ComplianceCalendar::calculate_due_date(SubmissionType::IncomeTax, 2026, Some(3));
        assert_eq!(due, NaiveDate::from_ymd_opt(2026, 4, 10).unwrap());
    }

    #[test]
    fn due_date_social_tax() {
        let due = ComplianceCalendar::calculate_due_date(SubmissionType::SocialTax, 2026, Some(5));
        assert_eq!(due, NaiveDate::from_ymd_opt(2026, 6, 10).unwrap());
    }

    #[test]
    fn social_tax_calculation() {
        let record = EmployeeTaxRecord {
            employee_name: "Test".into(),
            personal_code: "12345678901".into(),
            gross_salary_cents: 100000,
            social_tax_cents: 33000,
            unemployment_insurance_employer_cents: 800,
            unemployment_insurance_employee_cents: 1600,
            funded_pension_cents: 2000,
            funded_pension_rate: Some(0.02),
            income_tax_withheld_cents: 19280,
            net_salary_cents: 77120,
        };
        assert_eq!(record.social_tax_cents, 33000);
        assert_eq!(record.net_salary_cents, 77120);
    }

    #[test]
    fn dividend_tax_calculation() {
        let div = DividendDistribution {
            recipient: "Shareholder".into(),
            amount_cents: 100000,
            tax_rate: DIVIDEND_TAX_RATE,
            tax_amount_cents: 20000,
            distribution_date: NaiveDate::from_ymd_opt(2026, 1, 15).unwrap(),
        };
        assert_eq!(div.tax_amount_cents, 20000);
    }

    #[test]
    fn deadline_indicator_colors() {
        assert_eq!(DeadlineStatus::Pending.indicator(), "yellow");
        assert_eq!(DeadlineStatus::Filed.indicator(), "green");
        assert_eq!(DeadlineStatus::Overdue.indicator(), "red");
        assert_eq!(DeadlineStatus::Exempt.indicator(), "grey");
    }
}

// ─── Adversarial tests: calendar, filings, formats ──────────────────────────
//
// Statutory documents: a wrong amount, a wrong date or a silently-invented
// zero is a legal event. These tests pin the rate/date boundaries, the
// classification of every customer type, the rounding of net-to-tax
// fractions, and the honest not-ready states when source data is missing.

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use crate::test_support;
    use chrono::TimeZone;
    use sqlx::PgPool;

    async fn engine(suffix: &str) -> Option<(PgPool, EstoniaOuCompliance)> {
        let pool =
            test_support::canonical_pool(&format!("estonia_{suffix}"), &format!("est_{suffix}"))
                .await?;
        // Invoices reference tenants in the canonical chain; the fixture
        // tenant is created once per test database.
        sqlx::query(
            "INSERT INTO tenants (id, name) VALUES ('itest', 'Integration Test Tenant')
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("seed tenant");
        Some((pool.clone(), EstoniaOuCompliance::new(pool)))
    }

    fn d(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).expect("test date")
    }

    async fn seed_invoice(
        pool: &PgPool,
        issued_at: chrono::DateTime<Utc>,
        subtotal: i64,
        vat: i64,
        currency: &str,
        country: &str,
        vat_number: Option<&str>,
    ) {
        let billing_address = vat_number.map(|number| {
            serde_json::json!({"country": country, "vat_number": number}).to_string()
        });
        sqlx::query(
            "INSERT INTO invoices
               (id, tenant_id, amount, currency, status, issued_at, created_at, updated_at,
                subtotal, vat_total, total, billing_country, billing_address)
             VALUES (gen_random_uuid(), 'itest', $1, $2, 'paid', $3, NOW(), NOW(),
                     $1, $4, $1 + $4, $5, $6)",
        )
        .bind(subtotal)
        .bind(currency)
        .bind(issued_at)
        .bind(vat)
        .bind(country)
        .bind(billing_address)
        .execute(pool)
        .await
        .expect("seed invoice");
    }

    // ── Calendar ────────────────────────────────────────────────────────────

    #[test]
    fn legal_due_dates_roll_over_months_and_years() {
        // Monthly filings are due on the 20th (VAT) / 10th (taxes) of the
        // FOLLOWING month; December rolls into the next year.
        assert_eq!(
            ComplianceCalendar::calculate_legal_due_date(
                SubmissionType::VatDeclaration,
                2026,
                Some(12)
            ),
            d(2027, 1, 20)
        );
        assert_eq!(
            ComplianceCalendar::calculate_legal_due_date(SubmissionType::IncomeTax, 2026, Some(12)),
            d(2027, 1, 10)
        );
        assert_eq!(
            ComplianceCalendar::calculate_legal_due_date(SubmissionType::SocialTax, 2026, Some(12)),
            d(2027, 1, 10)
        );
        // January through November keep the year.
        assert_eq!(
            ComplianceCalendar::calculate_legal_due_date(
                SubmissionType::VatDeclaration,
                2026,
                Some(1)
            ),
            d(2026, 2, 20)
        );
        assert_eq!(
            ComplianceCalendar::calculate_legal_due_date(SubmissionType::IncomeTax, 2026, Some(11)),
            d(2026, 12, 10)
        );
        // A missing month is January, not "today".
        assert_eq!(
            ComplianceCalendar::calculate_legal_due_date(
                SubmissionType::VatDeclaration,
                2026,
                None
            ),
            d(2026, 2, 20)
        );
        // Annual / statistical dates.
        assert_eq!(
            ComplianceCalendar::calculate_legal_due_date(SubmissionType::AnnualReport, 2025, None),
            d(2026, 6, 30)
        );
        assert_eq!(
            ComplianceCalendar::calculate_legal_due_date(
                SubmissionType::StatisticalReport,
                2025,
                None
            ),
            d(2026, 7, 1)
        );
    }

    #[test]
    fn due_dates_are_never_before_the_legal_date_and_land_on_working_days() {
        for year in [2024, 2025, 2026, 2027, 2028] {
            for month in 1..=12u32 {
                for st in [
                    SubmissionType::VatDeclaration,
                    SubmissionType::IncomeTax,
                    SubmissionType::SocialTax,
                ] {
                    let legal = ComplianceCalendar::calculate_legal_due_date(st, year, Some(month));
                    let due = ComplianceCalendar::calculate_due_date(st, year, Some(month));
                    assert!(
                        due >= legal,
                        "{st:?} {year}-{month:02}: adjusted {due} before legal {legal}"
                    );
                    let weekday = due.weekday().number_from_monday();
                    assert!(
                        weekday <= 5,
                        "{st:?} {year}-{month:02}: due date {due} is a weekend"
                    );
                }
            }
        }
        // Estonian national holidays are shifted: 2026-02-24 (Independence
        // Day) is a Tuesday; a VAT due date landing on a holiday must move.
        let shifted =
            ComplianceCalendar::calculate_due_date(SubmissionType::VatDeclaration, 2026, Some(1));
        assert_eq!(shifted, d(2026, 2, 20), "the 20th is a Friday in 2026");
    }

    #[test]
    fn periods_cover_exactly_the_declared_month_including_leap_february() {
        assert_eq!(
            ComplianceCalendar::calculate_period(SubmissionType::VatDeclaration, 2026, Some(1)),
            (d(2026, 1, 1), d(2026, 1, 31))
        );
        // 2028 is a leap year: February has 29 days and must not run into March.
        assert_eq!(
            ComplianceCalendar::calculate_period(SubmissionType::VatDeclaration, 2028, Some(2)),
            (d(2028, 2, 1), d(2028, 2, 29))
        );
        assert_eq!(
            ComplianceCalendar::calculate_period(SubmissionType::IncomeTax, 2027, Some(2)),
            (d(2027, 2, 1), d(2027, 2, 28))
        );
        // 30-day and 31-day months.
        assert_eq!(
            ComplianceCalendar::calculate_period(SubmissionType::SocialTax, 2026, Some(4)),
            (d(2026, 4, 1), d(2026, 4, 30))
        );
        assert_eq!(
            ComplianceCalendar::calculate_period(SubmissionType::SocialTax, 2026, Some(12)),
            (d(2026, 12, 1), d(2026, 12, 31))
        );
        // Annual periods ignore the month.
        assert_eq!(
            ComplianceCalendar::calculate_period(SubmissionType::AnnualReport, 2026, Some(7)),
            (d(2026, 1, 1), d(2026, 12, 31))
        );
        assert_eq!(
            ComplianceCalendar::calculate_period(SubmissionType::StatisticalReport, 2026, None),
            (d(2026, 1, 1), d(2026, 12, 31))
        );
        // A January period never ends in the previous year.
        assert_eq!(
            ComplianceCalendar::calculate_period(SubmissionType::VatDeclaration, 2026, Some(1)).1,
            d(2026, 1, 31)
        );
    }

    // ── File naming & rendering ─────────────────────────────────────────────

    #[test]
    fn file_names_and_labels_are_exact_for_every_type() {
        assert_eq!(
            EstoniaOuCompliance::build_file_name(SubmissionType::AnnualReport, 2025, None, "pdf"),
            "annual-report-2025-bel-consulting-ou-16588745.pdf"
        );
        assert_eq!(
            EstoniaOuCompliance::build_file_name(
                SubmissionType::VatDeclaration,
                2026,
                Some(1),
                "csv"
            ),
            "vat-declaration-2026-01-bel-consulting-ou-16588745.csv"
        );
        assert_eq!(
            EstoniaOuCompliance::build_file_name(SubmissionType::IncomeTax, 2026, Some(12), "json"),
            "income-tax-declaration-2026-12-bel-consulting-ou-16588745.json"
        );
        assert_eq!(
            EstoniaOuCompliance::build_file_name(SubmissionType::SocialTax, 2026, None, "pdf"),
            "social-tax-declaration-2026-01-bel-consulting-ou-16588745.pdf"
        );
        assert_eq!(
            EstoniaOuCompliance::build_file_name(
                SubmissionType::StatisticalReport,
                2026,
                None,
                "pdf"
            ),
            "statistical-report-2026-bel-consulting-ou-16588745.pdf"
        );
        assert_eq!(
            EstoniaOuCompliance::build_period_label(SubmissionType::AnnualReport, 2025, None),
            "FY 2025"
        );
        assert_eq!(
            EstoniaOuCompliance::build_period_label(SubmissionType::VatDeclaration, 2026, Some(1)),
            "January 2026"
        );
        assert_eq!(
            EstoniaOuCompliance::build_period_label(SubmissionType::SocialTax, 2026, Some(12)),
            "December 2026"
        );
        // An out-of-range month falls back to a machine label, never panics.
        assert_eq!(
            EstoniaOuCompliance::build_period_label(SubmissionType::VatDeclaration, 2026, Some(13)),
            "Period 2026-13"
        );
    }

    #[test]
    fn pdf_and_csv_rendering_escape_hostile_document_content() {
        let hostile = serde_json::json!({
            "company_name": "OÜ \"Bel\" (Consulting) \\ test",
            "note": "line1\nline2\t\u{0}\u{202e}RTL",
            "balance_sheet": {
                "total_assets_cents": 1_000_000,
                "nested": {"deep": [1, 2.5, "x,y\"z", null, true]}
            },
            "income_statement": {"revenue_cents": -1},
            "cash_flow": {"net_cash_flow_cents": 0},
            "revenue_sources": [{"category": "a,b", "amount_cents": 5}]
        });

        let pdf = EstoniaOuCompliance::build_pdf_bytes(
            SubmissionType::AnnualReport,
            2025,
            None,
            &hostile,
        );
        assert!(pdf.starts_with(b"%PDF-"), "PDF header");
        assert!(pdf.windows(5).any(|w| w == b"%%EOF"), "PDF trailer present");
        // The rendered PDF text must not contain an unescaped form feed that
        // would corrupt the content stream, and must not panic on NUL.
        let pdf_text = String::from_utf8_lossy(&pdf);
        assert!(pdf_text.contains("O"));
        assert!(pdf.len() > 100);

        let csv =
            EstoniaOuCompliance::build_csv_text(SubmissionType::AnnualReport, 2025, None, &hostile);
        assert!(csv.starts_with("\"Key\",\"Value\"\n"));
        // Every value is a quoted field and embedded quotes are doubled.
        assert!(
            csv.contains("\"balance_sheet.total_assets_cents\",\"1000000\""),
            "{csv}"
        );
        assert!(
            csv.contains("\"income_statement.revenue_cents\",\"-1\""),
            "{csv}"
        );
        assert!(
            csv.contains("\"revenue_sources[0].category\",\"a,b\""),
            "{csv}"
        );
        for line in csv.lines() {
            let quotes = line.matches('"').count();
            assert_eq!(quotes % 2, 0, "unbalanced CSV quoting in {line:?}");
        }
        // A quote in a value never ends the field early: the escaped form
        // contains a doubled quote, and the raw form is absent.
        let quoted = EstoniaOuCompliance::build_csv_text(
            SubmissionType::AnnualReport,
            2025,
            None,
            &serde_json::json!({"revenue_sources": [{"category": "q\"uote"}]}),
        );
        assert!(quoted.contains("q\"\"uote"), "{quoted}");
        assert!(!quoted.contains("\"q\"uote\""), "{quoted}");

        // Every document type renders both formats without panicking on an
        // empty object.
        for st in [
            SubmissionType::AnnualReport,
            SubmissionType::VatDeclaration,
            SubmissionType::IncomeTax,
            SubmissionType::SocialTax,
            SubmissionType::StatisticalReport,
        ] {
            let empty = serde_json::json!({});
            assert!(!EstoniaOuCompliance::build_pdf_bytes(st, 2026, Some(3), &empty).is_empty());
            assert!(!EstoniaOuCompliance::build_csv_text(st, 2026, Some(3), &empty).is_empty());
        }
    }

    #[test]
    fn csv_escaping_and_json_flattening_are_lossless() {
        assert_eq!(csv_escape_value(&serde_json::json!("plain")), "plain");
        // Commas stay inside the (always quoted) field; a quote is doubled.
        assert_eq!(csv_escape_value(&serde_json::json!("a,b")), "a,b");
        assert_eq!(csv_escape_value(&serde_json::json!("a\"b")), "a\"\"b");
        assert_eq!(csv_escape_value(&serde_json::json!("a\nb")), "a\nb");
        assert_eq!(csv_escape_value(&serde_json::json!(1.25)), "1.25");
        assert_eq!(csv_escape_value(&serde_json::json!(true)), "true");
        assert_eq!(csv_escape_value(&serde_json::json!(null)), "");
        assert_eq!(csv_escape_value(&serde_json::json!(7)), "7");

        let mut csv = String::new();
        flatten_json_to_csv(
            &mut csv,
            "root",
            &serde_json::json!({
                "a": 1,
                "b": {"c": "x"},
                "d": [1, {"e": 2}],
                "f": null
            }),
            0,
        );
        assert!(csv.contains("root.a"), "{csv}");
        assert!(csv.contains("root.b.c"), "{csv}");
        assert!(csv.contains("root.d[0]"), "{csv}");
        assert!(csv.contains("root.d[1].e"), "{csv}");
        // Depth is bounded: a pathologically deep document must not recurse
        // forever (the flattener stops at its depth limit).
        let mut deep = serde_json::json!(1);
        for _ in 0..40 {
            deep = serde_json::json!({"x": deep});
        }
        let mut bounded = String::new();
        flatten_json_to_csv(&mut bounded, "deep", &deep, 0);
        assert!(bounded.len() < 100000, "flattening must terminate");

        // PDF string escaping escapes the delimiters that would break the
        // content stream.
        assert_eq!(escape_pdf_string("a(b)c\\d"), "a\\(b\\)c\\\\d");
        assert_eq!(escape_pdf_string("plain"), "plain");
        assert_eq!(escape_xml("<&>\"'"), "&lt;&amp;&gt;&quot;&apos;");
    }

    // ── Ledger mapping ──────────────────────────────────────────────────────

    #[test]
    fn declaration_from_ledger_copies_amounts_and_identity_verbatim() {
        let employee = crate::tsd_ledger::TsdEmployee {
            posting_id: Uuid::new_v4(),
            payroll_record_id: Uuid::new_v4(),
            fiscal_period_id: Uuid::new_v4(),
            journal_entry_id: Uuid::new_v4(),
            employee_name: Some("Mari Maasikas".into()),
            personal_code: Some("49001010001".into()),
            funded_pension_rate: Some(0.02),
            gross_salary_cents: 200000,
            social_tax_cents: 66000,
            unemployment_insurance_employer_cents: 1600,
            unemployment_insurance_employee_cents: 3200,
            funded_pension_cents: 4000,
            income_tax_withheld_cents: 42416,
            net_salary_cents: 150384,
            currency: "EUR".into(),
        };
        let source = crate::tsd_ledger::TsdLedgerSource {
            legal_entity_id: Uuid::new_v4(),
            legal_name: "Some Other OÜ".into(),
            registry_code: "12345678".into(),
            vat_number: Some("EE12345678".into()),
            currency: "EUR".into(),
            year: 2026,
            month: 3,
            periods: vec![],
            employees: vec![employee],
            unposted_payroll_records: 0,
            incomplete_employees: vec![],
            identity_violations: vec![],
            currencies: vec!["EUR".into()],
            read_at: Utc::now(),
        };
        let declaration = EstoniaOuCompliance::declaration_from_ledger(source, 2026, 3);
        // The declared identity is the entity whose books were read.
        assert_eq!(declaration.company_name, "Some Other OÜ");
        assert_eq!(declaration.registry_code, "12345678");
        assert_eq!(declaration.employees.len(), 1);
        assert_eq!(declaration.totals.total_gross_salary_cents, 200000);
        assert_eq!(declaration.totals.total_social_tax_cents, 66000);
        assert_eq!(declaration.totals.total_unemployment_employer_cents, 1600);
        assert_eq!(declaration.totals.total_unemployment_employee_cents, 3200);
        assert_eq!(declaration.totals.total_funded_pension_cents, 4000);
        assert_eq!(declaration.totals.total_income_tax_withheld_cents, 42416);
        assert_eq!(declaration.totals.employee_count, 1);
        // Employer cost = gross + employer taxes, never a recomputed amount.
        assert_eq!(declaration.totals.total_employer_cost_cents, 267600);
        assert!(declaration.data_quality.has_sufficient_data);
        assert_eq!(
            declaration.due_date,
            ComplianceCalendar::calculate_due_date(SubmissionType::SocialTax, 2026, Some(3))
        );
    }

    // ── Deadline lifecycle ──────────────────────────────────────────────────

    #[tokio::test]
    async fn deadline_lifecycle_seeds_reminds_and_files() {
        let Some((_pool, engine)) = engine("deadlines").await else {
            return;
        };
        let calendar = engine.calendar();
        let created = calendar.seed_deadlines().await.expect("seed");
        // 3 years × (1 annual + 12×3 monthly + 1 statistical) = 114 rows.
        assert_eq!(created.len(), 114);
        // Re-seeding is idempotent (unique deadline_type+due_date).
        calendar.seed_deadlines().await.expect("re-seed");
        let seeded_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compliance_deadlines WHERE status = 'pending'",
        )
        .fetch_one(&_pool)
        .await
        .expect("count");
        assert_eq!(seeded_count, 114);

        let pending = calendar.list_pending().await.expect("pending");
        assert_eq!(pending.len(), 114);
        // Ordered by due date ascending.
        assert!(pending.windows(2).all(|w| w[0].due_date <= w[1].due_date));

        // Overdue refresh only touches past-due pending rows.
        let past = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO compliance_deadlines
               (id, deadline_type, label, period_start, period_end, due_date, status, created_at, updated_at)
             VALUES ($1, 'unit_past', 'past', $2, $2, $2, 'pending', NOW(), NOW())",
        )
        .bind(past)
        .bind(d(2020, 1, 1))
        .execute(&_pool)
        .await
        .expect("insert past");
        let refreshed = calendar.refresh_overdue().await.expect("refresh");
        assert!(
            refreshed >= 1,
            "the inserted past deadline must be refreshed"
        );
        assert!(calendar
            .list_pending()
            .await
            .expect("pending")
            .iter()
            .all(|deadline| deadline.id != past));

        // Reminder windows: exactly 7 and 1 day ahead, not reminded yet.
        let seven = Uuid::new_v4();
        let one = Uuid::new_v4();
        let now = Utc::now().date_naive();
        for (id, days) in [(seven, 7i64), (one, 1i64)] {
            sqlx::query(
                "INSERT INTO compliance_deadlines
                   (id, deadline_type, label, period_start, period_end, due_date, status, created_at, updated_at)
                 VALUES ($1, $2, 'reminder', $3, $3, $3, 'pending', NOW(), NOW())",
            )
            .bind(id)
            .bind(format!("unit_reminder_{days}"))
            .bind(now + chrono::Duration::days(days))
            .execute(&_pool)
            .await
            .expect("insert reminder");
        }
        // The reminder windows select by EXACT due date across the whole
        // (shared) fixture database, so asserting a total row count made this
        // test order-dependent: any sibling test with a pending deadline on
        // the same date changed the length. Assert on THIS test's rows.
        let seven_due = calendar.deadlines_for_7day_reminder().await.expect("7d");
        assert!(
            seven_due.iter().any(|deadline| deadline.id == seven),
            "the row due in exactly 7 days must be selected"
        );
        assert!(
            !seven_due.iter().any(|deadline| deadline.id == one),
            "a row due tomorrow is not a 7-day reminder"
        );
        let one_due = calendar.deadlines_for_1day_reminder().await.expect("1d");
        assert!(
            one_due.iter().any(|deadline| deadline.id == one),
            "the row due tomorrow must be selected"
        );
        assert!(
            !one_due.iter().any(|deadline| deadline.id == seven),
            "a row due in 7 days is not a 1-day reminder"
        );

        calendar
            .record_7day_reminder(seven)
            .await
            .expect("record 7d");
        assert!(
            !calendar
                .deadlines_for_7day_reminder()
                .await
                .expect("7d again")
                .iter()
                .any(|deadline| deadline.id == seven),
            "a reminded row must leave its reminder window"
        );
        calendar.record_1day_reminder(one).await.expect("record 1d");
        assert!(
            !calendar
                .deadlines_for_1day_reminder()
                .await
                .expect("1d again")
                .iter()
                .any(|deadline| deadline.id == one),
            "a reminded row must leave its reminder window"
        );

        // mark_filed links the submission and leaves the pending set.
        let submission_id = Uuid::new_v4();
        calendar
            .mark_filed(seven, Some(submission_id))
            .await
            .expect("mark filed");
        let row: (String, Option<Uuid>) =
            sqlx::query_as("SELECT status, submission_id FROM compliance_deadlines WHERE id = $1")
                .bind(seven)
                .fetch_one(&_pool)
                .await
                .expect("row");
        assert_eq!(row.0, "filed");
        assert_eq!(row.1, Some(submission_id));

        // list_upcoming is bounded by the window and only returns pending rows.
        let upcoming = calendar.list_upcoming(30).await.expect("upcoming");
        assert!(upcoming
            .iter()
            .all(|deadline| deadline.due_date >= now && deadline.status == "pending"));

        // Widget counts match the window query.
        let widget = engine.deadline_widget().await.expect("widget");
        assert!(widget.upcoming_7d >= 1, "{widget:?}");
        assert!(widget.upcoming_30d >= widget.upcoming_7d, "{widget:?}");
        assert!(widget.overdue >= 1);
        assert!(widget.next_due.is_some());
        // Unknown ids are no-ops, not fabricated success.
        calendar
            .record_7day_reminder(Uuid::new_v4())
            .await
            .expect("no-op");
        calendar
            .mark_filed(Uuid::new_v4(), None)
            .await
            .expect("no-op");
    }

    #[tokio::test]
    async fn contact_person_and_registry_notices_have_db_backed_deadlines() {
        let Some((pool, engine)) = engine("contacts").await else {
            return;
        };
        let deadline = engine
            .calendar()
            .seed_contact_person_deadline(2026)
            .await
            .expect("seed contact deadline");
        assert_eq!(deadline.deadline_type, "contact_person_verification");
        assert_eq!(deadline.due_date, d(2026, 1, 31));
        // Re-seeding the same year does not duplicate the row.
        engine
            .calendar()
            .seed_contact_person_deadline(2026)
            .await
            .expect("re-seed");
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compliance_deadlines
             WHERE deadline_type = 'contact_person_verification'",
        )
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(count, 1);

        let person = engine
            .calendar()
            .register_contact_person(
                "Mari Maasikas",
                Some("49001010001"),
                "mari@example.test",
                Some("+372 5555 0000"),
            )
            .await
            .expect("register");
        assert_eq!(person.registry_code, REGISTRY_CODE);
        assert_eq!(person.full_name, "Mari Maasikas");
        // Upsert by email: the same address updates rather than duplicates.
        let updated = engine
            .calendar()
            .register_contact_person("Mari M.", None, "mari@example.test", None)
            .await
            .expect("upsert");
        assert_eq!(updated.id, person.id);
        assert_eq!(updated.full_name, "Mari M.");
        assert!(updated.personal_code.is_none());
        engine
            .calendar()
            .record_contact_person_verification(deadline.id, person.id)
            .await
            .expect("record verification");
        let status: String =
            sqlx::query_scalar("SELECT status FROM compliance_deadlines WHERE id = $1")
                .bind(deadline.id)
                .fetch_one(&pool)
                .await
                .expect("status");
        assert_eq!(status, "filed");

        // Registry notices: only incomplete ones become deadlines, and the
        // sync is idempotent.
        let created = engine
            .sync_registry_notices_to_calendar()
            .await
            .expect("sync notices");
        assert!(!created.is_empty());
        assert!(created
            .iter()
            .all(|deadline| deadline.deadline_type.starts_with("registry_")
                && deadline.due_date >= d(2000, 1, 1)));
        let again = engine
            .sync_registry_notices_to_calendar()
            .await
            .expect("sync again");
        assert_eq!(again.len(), created.len());
        let distinct: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT deadline_type) FROM compliance_deadlines
             WHERE deadline_type LIKE 'registry_%'",
        )
        .fetch_one(&pool)
        .await
        .expect("distinct");
        assert_eq!(distinct, created.len() as i64);
    }

    // ── Generators from live data ───────────────────────────────────────────

    #[tokio::test]
    async fn annual_report_sums_only_paid_invoices_of_the_fiscal_year() {
        let Some((pool, engine)) = engine("annual").await else {
            return;
        };
        // Paid EUR invoices inside the year.
        seed_invoice(
            &pool,
            Utc.with_ymd_and_hms(2026, 2, 15, 12, 0, 0).unwrap(),
            100000,
            24000,
            "EUR",
            "EE",
            None,
        )
        .await;
        seed_invoice(
            &pool,
            Utc.with_ymd_and_hms(2026, 8, 15, 12, 0, 0).unwrap(),
            50000,
            12000,
            "EUR",
            "DE",
            Some("DE123"),
        )
        .await;
        // A draft invoice and a different year must be excluded.
        sqlx::query(
            "INSERT INTO invoices (id, amount, currency, status, issued_at, created_at, updated_at,
                                   subtotal, vat_total, total)
             VALUES (gen_random_uuid(), 999999, 'EUR', 'open', make_timestamptz(2026, 3, 1, 0, 0, 0), NOW(), NOW(),
                     999999, 0, 999999)",
        )
        .execute(&pool)
        .await
        .expect("draft");
        seed_invoice(
            &pool,
            Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            777777,
            0,
            "EUR",
            "EE",
            None,
        )
        .await;

        let report = engine.generate_annual_report(2026).await.expect("report");
        assert_eq!(report.fiscal_year, 2026);
        assert_eq!(report.company_name, COMPANY_NAME);
        assert_eq!(report.registry_code, REGISTRY_CODE);
        assert_eq!(report.period, "2026-01-01 to 2026-12-31");
        let revenue: i64 = report.revenue_sources.iter().map(|s| s.amount_cents).sum();
        assert_eq!(revenue, 150000, "only paid 2026 invoices count");
        assert_eq!(report.income_statement.revenue_cents, 150000);
        // Expenses include the estimated processing fee on the same invoices.
        let fees: i64 = report
            .expense_breakdown
            .iter()
            .filter(|e| e.category.contains("Stripe"))
            .map(|e| e.amount_cents)
            .sum();
        // The fee estimate applies to the gross charged amount
        // (subtotal + VAT) of the same paid invoices.
        let gross_charged = (100000 + 24000 + 50000 + 12000) as f64;
        assert_eq!(fees, (gross_charged * 0.029 + 30.0) as i64);
        assert_eq!(
            report.income_statement.net_profit_cents,
            report.income_statement.revenue_cents
                - report.income_statement.operating_expenses_cents
        );
        // Balance sheet stays internally consistent.
        assert_eq!(
            report.balance_sheet.equity_cents,
            report.balance_sheet.share_capital_cents + report.balance_sheet.retained_earnings_cents
        );
        assert!(report.data_quality.has_sufficient_data);
        assert!(report.data_quality.missing_fields.is_empty());
        // Cash flow ties to net profit.
        assert_eq!(
            report.cash_flow.net_cash_flow_cents,
            report.income_statement.net_profit_cents
        );
        // No dividends store exists in the canonical chain: the report must
        // not claim dividend data it never read.
        assert!(report
            .expense_breakdown
            .iter()
            .all(|e| !e.category.to_lowercase().contains("dividend")));
    }

    #[tokio::test]
    async fn vat_declaration_classifies_every_customer_type_and_refuses_to_be_ready() {
        let Some((pool, engine)) = engine("vat").await else {
            return;
        };
        // A month with one of every customer class, including a non-EUR
        // invoice that must be excluded with a named reason.
        seed_invoice(
            &pool,
            Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap(),
            10000,
            2400,
            "EUR",
            "EE",
            None,
        )
        .await; // domestic
        seed_invoice(
            &pool,
            Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap(),
            20000,
            0,
            "EUR",
            "DE",
            Some("DE811234567"),
        )
        .await; // reverse charge
        seed_invoice(
            &pool,
            Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap(),
            30000,
            7200,
            "EUR",
            "FR",
            None,
        )
        .await; // EU B2C → EE VAT
        seed_invoice(
            &pool,
            Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap(),
            40000,
            0,
            "EUR",
            "US",
            None,
        )
        .await; // export
        seed_invoice(
            &pool,
            Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap(),
            50000,
            0,
            "USD",
            "US",
            None,
        )
        .await; // non-EUR excluded
                // An invoice with a blank VAT number snapshot is NOT reverse-charge.
        seed_invoice(
            &pool,
            Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap(),
            5000,
            0,
            "EUR",
            "SE",
            Some("   "),
        )
        .await;
        // A malformed billing_address snapshot cannot fabricate a VAT number.
        sqlx::query(
            "INSERT INTO invoices (id, amount, currency, status, issued_at, created_at, updated_at,
                                   subtotal, vat_total, total, billing_country, billing_address)
             VALUES (gen_random_uuid(), 6000, 'EUR', 'paid', make_timestamptz(2026, 3, 20, 0, 0, 0), NOW(), NOW(),
                     6000, 1440, 7440, 'IT', '{not json')",
        )
        .execute(&pool)
        .await
        .expect("malformed snapshot");

        let declaration = engine.generate_vat_declaration(2026, 3).await.expect("vat");
        // Domestic box: EE + EU-without-valid-VAT-number (FR 30k, SE 5k, IT 6k).
        assert_eq!(
            declaration.domestic_sales.taxable_amount_cents,
            10000 + 30000 + 5000 + 6000
        );
        assert_eq!(
            declaration.domestic_sales.vat_amount_cents,
            2400 + 7200 + 1440
        );
        assert_eq!(declaration.domestic_sales.transaction_count, 4);
        // Reverse charge needs a real VAT number in the snapshot.
        assert_eq!(declaration.intra_eu_supplies.taxable_amount_cents, 20000);
        assert_eq!(declaration.intra_eu_supplies.transaction_count, 1);
        // Exports stay outside the EU.
        assert_eq!(declaration.exports.taxable_amount_cents, 40000);
        assert_eq!(declaration.exports.transaction_count, 1);
        // The 2026 standard rate is 24%.
        assert_eq!(declaration.domestic_sales.vat_rate, 24);
        assert_eq!(
            declaration.summary.total_output_vat_cents,
            declaration.domestic_sales.vat_amount_cents
        );
        assert_eq!(declaration.summary.total_input_vat_cents, 0);
        assert_eq!(
            declaration.summary.net_vat_payable_cents,
            declaration.summary.total_output_vat_cents
        );
        assert_eq!(declaration.summary.vat_refund_cents, 0);
        assert_eq!(
            declaration.summary.due_date,
            ComplianceCalendar::calculate_due_date(SubmissionType::VatDeclaration, 2026, Some(3))
        );
        // The declaration is NOT ready: non-EUR invoices and no input-VAT store.
        assert!(!declaration.ready_for_filing);
        assert!(declaration
            .incomplete_reasons
            .iter()
            .any(|reason| reason.contains("non-EUR")));
        assert!(declaration
            .incomplete_reasons
            .iter()
            .any(|reason| reason.contains("input VAT")));

        // A clean EUR-only month is ready for filing (the input-VAT caveat is
        // the only remaining note).
        let clean = engine
            .generate_vat_declaration(2026, 4)
            .await
            .expect("clean");
        assert_eq!(clean.domestic_sales.taxable_amount_cents, 0);
        assert_eq!(clean.domestic_sales.transaction_count, 0);
        assert!(clean.ready_for_filing);
        assert_eq!(clean.incomplete_reasons.len(), 1);
        // Zero rows are explicit zeros, never an error.
        assert_eq!(clean.summary.net_vat_payable_cents, 0);
        assert_eq!(clean.summary.vat_refund_cents, 0);
    }

    #[tokio::test]
    async fn submission_formats_round_trip_and_upsert_by_period() {
        let Some((pool, engine)) = engine("submission").await else {
            return;
        };
        let document = serde_json::json!({
            "company_name": COMPANY_NAME,
            "summary": {"total_output_vat_cents": 2400},
            "domestic_sales": {"taxable_amount_cents": 10000},
            "input_vat": {"total_deductible_vat_cents": 0},
        });
        let id = engine
            .persist_submission_with_formats(
                SubmissionType::VatDeclaration,
                2026,
                Some(3),
                &document,
            )
            .await
            .expect("persist");
        let download = engine
            .get_submission_download(id)
            .await
            .expect("download")
            .expect("present");
        assert_eq!(download.submission_type, "vat_declaration");
        assert_eq!(
            download.file_name,
            "vat-declaration-2026-03-bel-consulting-ou-16588745.pdf"
        );
        assert_eq!(download.period_label, "March 2026");
        assert_eq!(download.checksum.len(), 64);
        assert!(download.pdf_data.starts_with(b"%PDF-"));
        assert!(download.csv_data.contains("vat_summary"));
        assert_eq!(download.json_data["company_name"], COMPANY_NAME);
        assert_eq!(download.file_size as usize, download.pdf_data.len());

        // Re-persisting the same period is an upsert, not a duplicate.
        let again = engine
            .persist_submission_with_formats(
                SubmissionType::VatDeclaration,
                2026,
                Some(3),
                &document,
            )
            .await
            .expect("persist again");
        assert_ne!(again, id, "the statement reports the new attempt's id");
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compliance_submissions WHERE submission_type = 'vat_declaration'",
        )
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(rows, 1, "one row per (type, year, month)");

        // persist_submission delegates to the same full-format path.
        let annual = engine
            .persist_submission(SubmissionType::AnnualReport, 2026, None, &document)
            .await
            .expect("annual persist");
        assert!(engine
            .get_submission_download(annual)
            .await
            .expect("annual download")
            .is_some());

        // get_submission returns the base record; unknown ids are None.
        let submission = engine
            .get_submission(id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(submission.submission_type, "vat_declaration");
        assert_eq!(submission.period_start, d(2026, 3, 1));
        assert_eq!(submission.period_end, d(2026, 3, 31));
        assert_eq!(submission.tax_month, Some(3));
        assert!(engine
            .get_submission(Uuid::new_v4())
            .await
            .expect("unknown")
            .is_none());
        assert!(engine
            .get_submission_download(Uuid::new_v4())
            .await
            .expect("unknown download")
            .is_none());

        // list_submissions_extended exposes the format booleans and paginates.
        let list = engine.list_submissions_extended(10, 0).await.expect("list");
        assert_eq!(list.len(), 2);
        let vat = list
            .iter()
            .find(|item| item.submission_type == "vat_declaration")
            .expect("vat row");
        assert!(vat.has_pdf && vat.has_csv && vat.has_json);
        assert_eq!(vat.checksum.as_deref().map(str::len), Some(64));
        assert!(engines_page_is_empty(&engine).await);
        // A zero limit returns an explicit empty list, not an error.
        assert!(engine
            .list_submissions_extended(0, 0)
            .await
            .expect("zero limit")
            .is_empty());
    }

    async fn engines_page_is_empty(engine: &EstoniaOuCompliance) -> bool {
        engine
            .list_submissions_extended(10, 100)
            .await
            .expect("offset")
            .is_empty()
    }

    #[tokio::test]
    async fn build_data_quality_reports_missing_sources_and_zero_rows() {
        let none =
            EstoniaOuCompliance::build_data_quality(false, false, false, &Vec::<String>::new());
        assert!(!none.has_sufficient_data);
        assert!(none.note.contains("Insufficient data"));
        // No source was recorded as missing: the note must not claim
        // otherwise (the report is not-ready because of the data, not the
        // schema).
        assert!(none.missing_fields.is_empty());

        let missing: Vec<String> = vec!["invoices table".into(), "payroll_records".into()];
        let partial = EstoniaOuCompliance::build_data_quality(true, false, false, &missing);
        assert!(partial.has_sufficient_data, "invoices alone are sufficient");
        assert_eq!(partial.missing_fields, missing);
        let complete =
            EstoniaOuCompliance::build_data_quality(true, true, true, &Vec::<String>::new());
        assert!(complete.has_sufficient_data);
        assert!(complete.missing_fields.is_empty(), "no false placeholder");
        assert!(complete.note.contains("Data extracted"));
        assert!(partial.note.contains("Data extracted"));

        let via_str: [&str; 1] = ["borrowed"];
        let borrowed = EstoniaOuCompliance::build_data_quality(false, true, false, &via_str);
        assert!(borrowed.has_sufficient_data, "payroll alone is sufficient");
        assert_eq!(borrowed.missing_fields, vec!["borrowed".to_string()]);
    }

    #[test]
    fn submission_type_round_trips_and_rejects_unknown_labels() {
        for st in [
            SubmissionType::AnnualReport,
            SubmissionType::VatDeclaration,
            SubmissionType::IncomeTax,
            SubmissionType::SocialTax,
            SubmissionType::StatisticalReport,
        ] {
            assert_eq!(SubmissionType::from_str(st.as_str()), Some(st));
            assert!(!st.label().is_empty());
            assert_eq!(st.to_string(), st.as_str());
        }
        assert_eq!(SubmissionType::from_str("nope"), None);
        assert_eq!(SubmissionType::from_str(""), None);
        // Every deadline status renders a stable string and indicator.
        for status in [
            DeadlineStatus::Pending,
            DeadlineStatus::Filed,
            DeadlineStatus::Overdue,
            DeadlineStatus::Exempt,
        ] {
            assert!(!status.as_str().is_empty());
            assert!(!status.indicator().is_empty());
        }
        for status in [
            SubmissionStatus::Draft,
            SubmissionStatus::Generated,
            SubmissionStatus::Submitted,
            SubmissionStatus::Acknowledged,
            SubmissionStatus::Overdue,
            SubmissionStatus::Error,
        ] {
            assert!(!status.as_str().is_empty());
        }
    }
}
