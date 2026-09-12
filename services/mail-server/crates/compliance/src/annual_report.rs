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
//! # XBRL / structured output — an honest format decision
//!
//! The repository contains no Estonian e-aruande (Äriregister) taxonomy and
//! no tool contract pinning an XBRL schema, and XBRL is not used anywhere
//! else in this workspace. The official taxonomy is therefore **not
//! guessed**: the canonical machine output is the documented structured JSON
//! document ([`ANNUAL_REPORT_FORMAT`], persisted in
//! `annual_reports.structured_document` and `balance_sheet` /
//! `income_statement`), and [`build_xbrl_instance`] additionally emits a
//! **well-formed XBRL 2.1 instance container**: standard
//! `http://www.xbrl.org/2003/instance` contexts/units with facts in the
//! documented ApexMail extension namespace ([`XBRL_EXTENSION_NAMESPACE`]).
//! It is deliberately NOT claimed to be a submission-ready e-aruande file —
//! turning it into one requires the official taxonomy, which must be vendored
//! (and its version pinned) before any authority submission is attempted.

#![deny(unsafe_code)]

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

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
// XBRL instance
// ---------------------------------------------------------------------------

/// Build a well-formed XBRL 2.1 instance container.
///
/// Standard `xbrli` contexts/units carry facts in the documented ApexMail
/// extension namespace. See the module docs: this is NOT the official
/// Estonian e-aruande taksonoomia.
pub fn build_xbrl_instance(
    company: &CompanyIdentity,
    fiscal_year: i32,
    period_start: NaiveDate,
    period_end: NaiveDate,
    balance_sheet: &BalanceSheet,
    income_statement: &IncomeStatement,
    lines: &[LedgerBalanceLine],
) -> String {
    let duration_context = format!("duration-FY{fiscal_year}");
    let instant_context = format!("instant-{period_end}");
    let mut xml = String::with_capacity(4096);

    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(
        "<!-- Generated by ApexMail from posted journal lines of a CLOSED fiscal period. \
         This instance uses the documented ApexMail extension namespace \
         (https://apexmail.com/xbrl/ee-annual-report/1); the official Estonian e-aruande \
         taksonoomia is not bundled, so this file is a well-formed structured container, \
         not a submission-ready e-aruande document. -->\n",
    );
    xml.push_str(&format!(
        "<xbrli:xbrl xmlns:xbrli=\"{XBRL_INSTANCE_NAMESPACE}\" \
         xmlns:link=\"{XBRL_LINKBASE_NAMESPACE}\" \
         xmlns:xlink=\"http://www.w3.org/1999/xlink\" \
         xmlns:iso4217=\"{XBRL_ISO4217_NAMESPACE}\" \
         xmlns:apex=\"{XBRL_EXTENSION_NAMESPACE}\">\n"
    ));

    xml.push_str(
        "  <link:schemaRef xlink:type=\"simple\" \
         xlink:href=\"urn:apexmail:xbrl:ee-annual-report:1\"/>\n",
    );

    xml.push_str(&format!("  <xbrli:context id=\"{duration_context}\">\n"));
    xml.push_str(&format!(
        "    <xbrli:entity><xbrli:identifier scheme=\"https://ariregister.rik.ee\">{}</xbrli:identifier></xbrli:entity>\n",
        xml_escape(&company.registry_code)
    ));
    xml.push_str(&format!(
        "    <xbrli:period><xbrli:startDate>{period_start}</xbrli:startDate>\
         <xbrli:endDate>{period_end}</xbrli:endDate></xbrli:period>\n"
    ));
    xml.push_str("  </xbrli:context>\n");

    xml.push_str(&format!("  <xbrli:context id=\"{instant_context}\">\n"));
    xml.push_str(&format!(
        "    <xbrli:entity><xbrli:identifier scheme=\"https://ariregister.rik.ee\">{}</xbrli:identifier></xbrli:entity>\n",
        xml_escape(&company.registry_code)
    ));
    xml.push_str(&format!(
        "    <xbrli:period><xbrli:instant>{period_end}</xbrli:instant></xbrli:period>\n"
    ));
    xml.push_str("  </xbrli:context>\n");

    xml.push_str(&format!(
        "  <xbrli:unit id=\"EUR\"><xbrli:measure>iso4217:{}</xbrli:measure></xbrli:unit>\n",
        xml_escape(&company.currency)
    ));

    // Statement totals.
    {
        let mut fact = |name: &str, context: &str, cents: i64| {
            xml.push_str(&format!(
                "  <apex:{name} contextRef=\"{context}\" unitRef=\"EUR\" decimals=\"2\">{}</apex:{name}>\n",
                format_cents(cents)
            ));
        };
        fact("Assets", &instant_context, balance_sheet.assets_cents);
        fact(
            "Liabilities",
            &instant_context,
            balance_sheet.liabilities_cents,
        );
        fact("Equity", &instant_context, balance_sheet.equity_cents);
        fact(
            "ProfitLossForPeriod",
            &duration_context,
            balance_sheet.period_profit_cents,
        );
        fact("Revenue", &duration_context, income_statement.revenue_cents);
        fact(
            "Expenses",
            &duration_context,
            income_statement.expenses_cents,
        );
        fact(
            "NetProfit",
            &duration_context,
            income_statement.net_profit_cents,
        );
    }

    // Account-level facts (traceable to chart-of-accounts codes).
    for line in lines {
        let context = if line.account_type == "revenue" || line.account_type == "expense" {
            &duration_context
        } else {
            &instant_context
        };
        xml.push_str(&format!(
            "  <apex:Account_{} contextRef=\"{context}\" unitRef=\"EUR\" decimals=\"2\">{}</apex:Account_{}>\n",
            xml_fact_name(&line.account_code),
            format_cents(line.balance_debit_positive),
            xml_fact_name(&line.account_code)
        ));
    }

    xml.push_str("</xbrli:xbrl>\n");
    xml
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
pub async fn generate_annual_report(
    db: &PgPool,
    legal_entity_id: Uuid,
    fiscal_period_id: Uuid,
    actor: &str,
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
    let xbrl = build_xbrl_instance(
        &company,
        period.end_date.year(),
        period.start_date,
        period.end_date,
        &balance_sheet,
        &income_statement,
        &lines,
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
        .bind(&xbrl)
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
        .bind(&xbrl)
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
    xbrl: &str,
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
            "instance_embedded": true,
            "instance_sha256": hex::encode(Sha256::digest(xbrl.as_bytes())),
            "namespace": XBRL_EXTENSION_NAMESPACE,
            "official_estonian_taxonomy": false,
            "note": "Well-formed XBRL 2.1 container in the documented ApexMail extension \
                namespace. The official e-aruande taksonoomia is not bundled by this repository; \
                do not treat this as a submission-ready e-aruande file.",
        },
        "warnings": warnings,
    })
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
