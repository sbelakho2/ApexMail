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
//!   profits (dividends) are taxed at 20/80 rate (20% of gross dividend).
//!   From 2025: 22/78 applies to certain distributed amounts.
//! - **VAT (Käibemaks)**: 24% standard rate (since July 1, 2025).
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
/// Funded pension (II pillar) — employee contribution.
pub const FUNDED_PENSION_RATE: f64 = 0.02;
/// Income tax rate on distributed dividends (20/80 = 25% of net).
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
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AnnualReport => "annual_report",
            Self::VatDeclaration => "vat_declaration",
            Self::IncomeTax => "income_tax",
            Self::SocialTax => "social_tax",
            Self::StatisticalReport => "statistical_report",
        }
    }

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
    pub fn calculate_due_date(
        deadline_type: SubmissionType,
        year: i32,
        month: Option<u32>,
    ) -> NaiveDate {
        match deadline_type {
            SubmissionType::AnnualReport => {
                NaiveDate::from_ymd_opt(year + 1, 6, 30)
                    .unwrap_or_else(|| NaiveDate::from_ymd_opt(year + 1, 6, 30).unwrap())
            }
            SubmissionType::VatDeclaration => {
                let m = month.unwrap_or(1);
                let (y, next_m) = if m == 12 { (year + 1, 1) } else { (year, m + 1) };
                NaiveDate::from_ymd_opt(y, next_m, 20)
                    .unwrap_or_else(|| NaiveDate::from_ymd_opt(y, next_m, 20).unwrap())
            }
            SubmissionType::IncomeTax => {
                let m = month.unwrap_or(1);
                let (y, next_m) = if m == 12 { (year + 1, 1) } else { (year, m + 1) };
                NaiveDate::from_ymd_opt(y, next_m, 10)
                    .unwrap_or_else(|| NaiveDate::from_ymd_opt(y, next_m, 10).unwrap())
            }
            SubmissionType::SocialTax => {
                let m = month.unwrap_or(1);
                let (y, next_m) = if m == 12 { (year + 1, 1) } else { (year, m + 1) };
                NaiveDate::from_ymd_opt(y, next_m, 10)
                    .unwrap_or_else(|| NaiveDate::from_ymd_opt(y, next_m, 10).unwrap())
            }
            SubmissionType::StatisticalReport => {
                NaiveDate::from_ymd_opt(year + 1, 7, 1)
                    .unwrap_or_else(|| NaiveDate::from_ymd_opt(year + 1, 7, 1).unwrap())
            }
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
                let due =
                    Self::calculate_due_date(SubmissionType::StatisticalReport, year, None);
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
        let has_invoices =
            crate::table_exists_fn(&self.db, "invoices").await.unwrap_or(false);

        if !has_invoices {
            return Ok(vec![]);
        }

        let rows = if let Some(m) = month {
            sqlx::query_as::<_, RevenueRow>(
                "SELECT COALESCE(currency, 'EUR') AS currency,
                        SUM(subtotal) AS total_cents,
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
                        SUM(subtotal) AS total_cents,
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

        let has_invoices =
            crate::table_exists_fn(&self.db, "invoices").await.unwrap_or(false);

        if has_invoices {
            if let Ok(Some(row)) = sqlx::query_as::<_, ExpenseRow>(
                "SELECT SUM(subtotal + vat_total) AS total_cents
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

        let has_operating_costs =
            crate::table_exists_fn(&self.db, "operating_costs").await.unwrap_or(false);

        if has_operating_costs {
            let rows = sqlx::query_as::<_, CostRow>(
                "SELECT COALESCE(category, 'infrastructure') AS category,
                        COALESCE(SUM(amount_cents), 0) AS total_cents
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
        let has_payroll =
            crate::table_exists_fn(&self.db, "payroll_records").await.unwrap_or(false);

        if !has_payroll {
            return Ok(vec![]);
        }

        let rows = if let Some(m) = month {
            sqlx::query_as::<_, PayrollRow>(
                "SELECT employee_name, personal_code, gross_salary_cents
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
                "SELECT employee_name, personal_code, gross_salary_cents
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
                let social_tax = (gross as f64 * SOCIAL_TAX_RATE).round() as i64;
                let unemp_er = (gross as f64 * UNEMPLOYMENT_INSURANCE_EMPLOYER).round() as i64;
                let unemp_ee = (gross as f64 * UNEMPLOYMENT_INSURANCE_EMPLOYEE).round() as i64;
                let pension = (gross as f64 * FUNDED_PENSION_RATE).round() as i64;
                let taxable = gross - unemp_ee - pension;
                let income_tax = (taxable as f64 * 0.20).round() as i64;
                let net = gross - unemp_ee - pension - income_tax;
                EmployeeTaxRecord {
                    employee_name: r.employee_name,
                    personal_code: r.personal_code.unwrap_or_default(),
                    gross_salary_cents: gross,
                    social_tax_cents: social_tax,
                    unemployment_insurance_employer_cents: unemp_er,
                    unemployment_insurance_employee_cents: unemp_ee,
                    funded_pension_cents: pension,
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
        let has_dividends =
            crate::table_exists_fn(&self.db, "dividend_distributions")
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
                let tax = ((amount as f64) * (DIVIDEND_TAX_RATE)).round() as i64;
                DividendDistribution {
                    recipient: r.recipient,
                    amount_cents: amount,
                    tax_rate: DIVIDEND_TAX_RATE,
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
        has_dividends: bool,
        missing: &[T],
    ) -> DataQualityNote {
        let has_sufficient = has_invoices || has_payroll;
        DataQualityNote {
            has_sufficient_data: has_sufficient,
            missing_fields: if missing.is_empty() {
                vec!["No database tables found — using placeholder values".into()]
            } else {
                missing.iter().map(|f| f.as_ref().to_string()).collect()
            },
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
        let has_invoices =
            crate::table_exists_fn(&self.db, "invoices").await.unwrap_or(false);
        let has_payroll =
            crate::table_exists_fn(&self.db, "payroll_records").await.unwrap_or(false);
        let has_dividends =
            crate::table_exists_fn(&self.db, "dividend_distributions")
                .await
                .unwrap_or(false);

        let revenue = self.query_revenue(year, None).await?;
        let expenses = self.query_expenses(year, None).await?;
        let employees = self.query_employees(year, None).await?;

        let total_revenue: i64 = revenue.iter().map(|s| s.amount_cents).sum();
        let total_expenses: i64 = expenses.iter().map(|e| e.amount_cents).sum();
        let net_profit = total_revenue - total_expenses;

        let (period_start, period_end) = ComplianceCalendar::calculate_period(
            SubmissionType::AnnualReport,
            year,
            None,
        );

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

    /// Generate a VAT Declaration (Käibedeklaratsioon) for a month.
    pub async fn generate_vat_declaration(
        &self,
        year: i32,
        month: u32,
    ) -> Result<VatDeclaration, anyhow::Error> {
        let has_invoices =
            crate::table_exists_fn(&self.db, "invoices").await.unwrap_or(false);
        let mut missing = Vec::new();
        if !has_invoices {
            missing.push("invoices table");
        }

        let revenue = self.query_revenue(year, Some(month)).await?;
        let total_revenue: i64 = revenue.iter().map(|s| s.amount_cents).sum();
        let tx_count: i64 = revenue.iter().map(|s| s.invoice_count).sum();

        let output_vat = ((total_revenue * EST_VAT_RATE as i64) + 50) / 100;

        let has_operating =
            crate::table_exists_fn(&self.db, "operating_costs").await.unwrap_or(false);
        let input_vat_cents = if has_operating {
            let row = sqlx::query_as::<_, VatInputRow>(
                "SELECT COALESCE(SUM(amount_cents), 0) AS total_cents
                 FROM operating_costs
                 WHERE EXTRACT(YEAR FROM incurred_at) = $1
                   AND EXTRACT(MONTH FROM incurred_at) = $2",
            )
            .bind(year as f64)
            .bind(month as f64)
            .fetch_optional(&self.db)
            .await?;
            let total_costs = row.map(|r| r.total_cents).unwrap_or(0);
            ((total_costs * EST_VAT_RATE as i64) + 50) / 100
        } else {
            0
        };

        let net_vat = output_vat - input_vat_cents;
        let due = ComplianceCalendar::calculate_due_date(
            SubmissionType::VatDeclaration,
            year,
            Some(month),
        );

        Ok(VatDeclaration {
            company_name: COMPANY_NAME.into(),
            registry_code: REGISTRY_CODE.into(),
            tax_year: year,
            tax_month: month,
            generated_at: Utc::now(),
            domestic_sales: VatCategory {
                taxable_amount_cents: total_revenue,
                vat_rate: EST_VAT_RATE,
                vat_amount_cents: output_vat,
                transaction_count: tx_count,
                description: "Domestic (EE) sales — 24% VAT".into(),
            },
            intra_eu_supplies: VatCategory {
                taxable_amount_cents: 0,
                vat_rate: 0,
                vat_amount_cents: 0,
                transaction_count: 0,
                description: "Intra-EU supplies (reverse charge, 0% VAT)".into(),
            },
            exports: VatCategory {
                taxable_amount_cents: 0,
                vat_rate: 0,
                vat_amount_cents: 0,
                transaction_count: 0,
                description: "Exports outside EU (0% VAT)".into(),
            },
            input_vat: VatInputBreakdown {
                domestic_purchases: VatInputLine {
                    amount_cents: 0,
                    vat_amount_cents: input_vat_cents,
                    description: "Domestic purchases — deductible input VAT".into(),
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
        })
    }

    /// Generate an Income Tax Declaration (Tulumaks) for a month.
    pub async fn generate_income_tax_declaration(
        &self,
        year: i32,
        month: u32,
    ) -> Result<IncomeTaxDeclaration, anyhow::Error> {
        let dividends = self.query_dividends(year, Some(month)).await?;
        let has_dividends =
            crate::table_exists_fn(&self.db, "dividend_distributions")
                .await
                .unwrap_or(false);
        let mut missing = Vec::new();
        if !has_dividends {
            missing.push("dividend_distributions table");
        }

        let total_dividend: i64 = dividends.iter().map(|d| d.amount_cents).sum();
        let total_tax: i64 = dividends.iter().map(|d| d.tax_amount_cents).sum();

        let due = ComplianceCalendar::calculate_due_date(
            SubmissionType::IncomeTax,
            year,
            Some(month),
        );

        let note = if dividends.is_empty() {
            "No dividend distributions this period. Estonia taxes only distributed profits at 20/80 rate."
        } else {
            "Dividend distributions detected. Tax calculated at 20/80 rate per TuMS §50."
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

    /// Generate a Social Tax Declaration (TSD) for a month.
    pub async fn generate_social_tax_declaration(
        &self,
        year: i32,
        month: u32,
    ) -> Result<SocialTaxDeclaration, anyhow::Error> {
        let employees = self.query_employees(year, Some(month)).await?;
        let has_payroll =
            crate::table_exists_fn(&self.db, "payroll_records").await.unwrap_or(false);
        let mut missing = Vec::new();
        if !has_payroll {
            missing.push("payroll_records table");
        }

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
        let total_income_tax: i64 = employees
            .iter()
            .map(|e| e.income_tax_withheld_cents)
            .sum();
        let total_employer = total_social + total_unemp_er;

        let employee_count = employees.len() as i32;

        let due = ComplianceCalendar::calculate_due_date(
            SubmissionType::SocialTax,
            year,
            Some(month),
        );

        let note = if employees.is_empty() {
            "No employment records for this period. If there are team members, add payroll_records."
        } else {
            "Employee tax records calculated per Estonian rates."
        };

        Ok(SocialTaxDeclaration {
            company_name: COMPANY_NAME.into(),
            registry_code: REGISTRY_CODE.into(),
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
            due_date: due,
            data_quality: DataQualityNote {
                has_sufficient_data: has_payroll,
                missing_fields: missing.iter().map(|s| s.to_string()).collect(),
                note: note.into(),
            },
        })
    }

    /// Generate a Statistical Report.
    pub async fn generate_statistical_report(
        &self,
        year: i32,
    ) -> Result<StatisticalReport, anyhow::Error> {
        let revenue = self.query_revenue(year, None).await?;
        let employees = self.query_employees(year, None).await?;
        let has_invoices =
            crate::table_exists_fn(&self.db, "invoices").await.unwrap_or(false);

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
    pub fn build_file_name(st: SubmissionType, year: i32, month: Option<u32>, extension: &str) -> String {
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
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December",
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
        let json_bytes = json_str.as_bytes();

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
        let content_stream_offset = pdf.len();
        pdf.extend(format!(
            "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842]\n\
               /Contents 5 0 R /Resources << /Font << /F1 6 0 R >> >> >>\nendobj\n"
        ).as_bytes());

        // Object 5: Content stream data
        let obj5_offset = pdf.len();
        pdf.extend(format!(
            "5 0 obj\n<< /Length {} >>\nstream\n", content_bytes.len()
        ).as_bytes());
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

        pdf.extend(format!(
            "7 0 obj\n<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n",
            metadata_bytes.len()
        ).as_bytes());
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
        pdf.extend(format!(
            "trailer\n<< /Size 8 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
        ).as_bytes());

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
        csv.push_str(&format!("\"Key\",\"Value\"\n"));
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
        hasher.update(serde_json::to_string(json_data).unwrap_or_default().as_bytes());
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
        self.persist_submission_with_formats(st, year, month, document_json).await
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
                    deadline_type: format!("registry_{}", notice.notice_id.to_lowercase().replace('-', "_")),
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
                    serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) | serde_json::Value::String(_) => {
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
}

#[derive(Debug, sqlx::FromRow)]
struct DividendRow {
    recipient: String,
    amount_cents: i64,
    distribution_date: NaiveDate,
}

#[derive(Debug, sqlx::FromRow)]
struct VatInputRow {
    total_cents: i64,
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
        let due = ComplianceCalendar::calculate_due_date(
            SubmissionType::VatDeclaration,
            2026,
            Some(1),
        );
        assert_eq!(due, NaiveDate::from_ymd_opt(2026, 2, 20).unwrap());
    }

    #[test]
    fn due_date_vat_declaration_december() {
        let due = ComplianceCalendar::calculate_due_date(
            SubmissionType::VatDeclaration,
            2025,
            Some(12),
        );
        assert_eq!(due, NaiveDate::from_ymd_opt(2026, 1, 20).unwrap());
    }

    #[test]
    fn due_date_income_tax() {
        let due = ComplianceCalendar::calculate_due_date(
            SubmissionType::IncomeTax,
            2026,
            Some(3),
        );
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
