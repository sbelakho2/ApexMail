//! TSD (payroll and social-tax return) derivation from the **posted ledger**.
//!
//! The monthly TSD is a statutory declaration of the amounts paid to natural
//! persons: gross payment, income tax withheld, social tax, employer and
//! employee unemployment insurance, and the funded-pension (II pillar)
//! contribution. Estonian law requires the declared figures to agree with the
//! entity's accounting — so the declaration must be derived from what was
//! actually BOOKED, not from the operational payroll input rows.
//!
//! # Derivation contract
//!
//! * **Amounts** come from migration 220's posted ledger only, through the
//!   documented read contract
//!   [`accounting_core::derive::payroll_taxes_for_period`] (view
//!   `v_accounting_payroll_taxes`), which returns a posting only when its
//!   journal entry is posted (`posted_at IS NOT NULL`). This module never
//!   re-computes a rate: a rate recomputation cannot disagree with the ledger,
//!   it can only hide a disagreement.
//! * **Person identity and the declaration's completeness inputs** (personal
//!   code, II-pillar rate, exemptions) come from the canonical payroll input
//!   (`payroll_records`, migration 199) the posting was created from — the
//!   ledger posting stores the amount, not the person. Identity is a *fact
//!   about the person*; the amount is a *fact about the books*.
//! * The fiscal period(s) read are the ones **contained in the calendar
//!   month** (`start_date >= month_start AND end_date <= month_end`). A year
//!   or quarter period that merely contains the month is NOT accepted: a
//!   monthly return cannot be derived from a period that spans other months,
//!   and silently prorating it would be an invention. The absence of a
//!   monthly period is reported as missing data, never worked around.
//!
//! # Incompleteness is reported, never guessed
//!
//! The source struct carries every reason the derived declaration might not
//! be filable, and [`TsdLedgerSource::missing_fields`] spells each one out:
//!
//! * no monthly fiscal period inside the month (nothing was booked);
//! * a monthly period exists but holds no posted payroll posting;
//! * `payroll_records` rows exist for the month that are NOT posted to the
//!   ledger (the payroll sweep has not run / the posting was reversed);
//! * a posting's employee is missing a personal code or an II-pillar rate
//!   (migration 199: NULL rate = participation unknown — never assumed);
//! * a posting's own arithmetic is inconsistent
//!   (`gross − unemployment(employee) − pension − income tax ≠ net`), which
//!   means the books disagree with themselves and no figure can be trusted;
//! * a posting is not in EUR, or the month mixes currencies (the return is
//!   filed in EUR).
//!
//! A caller that ignores these flags gets a declaration whose
//! `data_quality.has_sufficient_data` is `false` and whose `missing_fields`
//! names the reason — the failure mode is a visibly-not-ready filing, not a
//! plausible-but-wrong number.
//!
//! # Known limitation of the unposted count (fails safe)
//!
//! `payroll_records` (migration 199) carries no legal entity, so
//! `unposted_payroll_records` counts the whole database's unbooked payroll
//! inputs for the month, not one entity's. In a multi-entity deployment this
//! can only OVER-report, i.e. it can mark a declaration not-ready that is in
//! fact complete — the safe direction. It can never hide an unbooked row.

#![deny(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use accounting_core::derive::payroll_taxes_for_period;

/// Time zone the payroll input's payment period is interpreted in. Estonian
/// payroll periods are the entity's local calendar months; the session's
/// `TimeZone` must not change which month a payment belongs to.
pub const PAYROLL_PERIOD_ZONE: &str = "Europe/Tallinn";

/// Why a TSD could not be derived at all (as opposed to being derivable but
/// incomplete, which is reported through [`TsdLedgerSource::missing_fields`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsdSourceError {
    /// The calendar month is not a real date (e.g. month 13).
    InvalidPeriod { year: i32, month: u32 },
    /// No `legal_entities` row carries the registry code the declaration is
    /// for: the declaration's own identity has no books to read.
    EntityNotFound { registry_code: String },
    /// No `legal_entities` row with the requested id.
    EntityIdNotFound { legal_entity_id: Uuid },
    /// A ledger read failed.
    Lookup {
        what: &'static str,
        detail: String,
    },
}

impl fmt::Display for TsdSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPeriod { year, month } => {
                write!(f, "{year}-{month:02} is not a valid calendar month")
            }
            Self::EntityNotFound { registry_code } => write!(
                f,
                "no legal entity with registry code {registry_code} exists in the ledger; \
                 the TSD cannot be derived for an entity with no books"
            ),
            Self::EntityIdNotFound { legal_entity_id } => write!(
                f,
                "no legal entity with id {legal_entity_id} exists in the ledger"
            ),
            Self::Lookup { what, detail } => write!(f, "failed to read {what}: {detail}"),
        }
    }
}

impl std::error::Error for TsdSourceError {}

/// A fiscal period contained in the reported month.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsdPeriod {
    pub id: Uuid,
    pub period_type: String,
    pub label: String,
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    /// `open` | `closed` | `locked`. Postings are read from any of them; an
    /// `open` period means the figures can still change before close, which
    /// the declaration's note states.
    pub status: String,
}

/// One posted payroll posting, with the person facts resolved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TsdEmployee {
    pub posting_id: Uuid,
    pub payroll_record_id: Uuid,
    pub fiscal_period_id: Uuid,
    /// The posted journal entry the amount comes from (never NULL: the read
    /// contract requires a posted entry).
    pub journal_entry_id: Uuid,
    /// From the posting, falling back to the payroll record. `None` means
    /// neither carries a name.
    pub employee_name: Option<String>,
    pub personal_code: Option<String>,
    /// The rate to DECLARE: `Some(0.0)` for an exempt employee, the recorded
    /// employee-specific rate (2/4/6%), or `None` when participation is
    /// unknown — in which case the record is incomplete, not zero-rated.
    pub funded_pension_rate: Option<f64>,
    pub gross_salary_cents: i64,
    pub social_tax_cents: i64,
    pub unemployment_insurance_employer_cents: i64,
    pub unemployment_insurance_employee_cents: i64,
    pub funded_pension_cents: i64,
    pub income_tax_withheld_cents: i64,
    pub net_salary_cents: i64,
    pub currency: String,
}

/// A posting that cannot be declared as filed: the person facts the return
/// requires are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsdIncompleteEmployee {
    pub posting_id: Uuid,
    pub employee_name: Option<String>,
    /// Field names from [`TsdEmployee`], e.g. `personal_code`.
    pub missing: Vec<String>,
}

/// The ledger's answer for one calendar month. Every field is read or
/// counted; nothing is estimated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TsdLedgerSource {
    pub legal_entity_id: Uuid,
    pub legal_name: String,
    pub registry_code: String,
    pub vat_number: Option<String>,
    /// Default currency of the entity (the return's currency).
    pub currency: String,
    pub year: i32,
    pub month: u32,
    pub periods: Vec<TsdPeriod>,
    pub employees: Vec<TsdEmployee>,
    /// `payroll_records` rows whose payment period falls in this month but
    /// which have no POSTED journal entry. Non-zero means the derived
    /// declaration is short by those rows.
    pub unposted_payroll_records: i64,
    pub incomplete_employees: Vec<TsdIncompleteEmployee>,
    /// Postings whose own arithmetic is inconsistent; identifiers so the
    /// broken entries can be found.
    pub identity_violations: Vec<Uuid>,
    /// Distinct posting currencies found in the month, sorted.
    pub currencies: Vec<String>,
    pub read_at: DateTime<Utc>,
}

impl TsdLedgerSource {
    /// Distinct journal entries the declared amounts came from (audit trail).
    pub fn journal_entry_ids(&self) -> Vec<Uuid> {
        let mut ids: Vec<Uuid> = self.employees.iter().map(|e| e.journal_entry_id).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Periods that are still `open`, i.e. the figures are not frozen.
    pub fn open_periods(&self) -> Vec<&TsdPeriod> {
        self.periods
            .iter()
            .filter(|p| p.status == "open")
            .collect()
    }

    /// True when the derived declaration reproduces the books completely.
    pub fn has_sufficient_data(&self) -> bool {
        !self.employees.is_empty()
            && self.unposted_payroll_records == 0
            && self.incomplete_employees.is_empty()
            && self.identity_violations.is_empty()
            && self
                .currencies
                .iter()
                .all(|c| c == &self.currency.as_str())
    }

    /// The reporting period label (`YYYY-MM`).
    pub fn period_label(&self) -> String {
        month_label(self.year, self.month)
    }

    /// Every reason the declaration is not filable as derived, in the order
    /// the caller should fix them. Empty when [`Self::has_sufficient_data`].
    pub fn missing_fields(&self) -> Vec<String> {
        let mut missing = Vec::new();
        let month = self.period_label();
        if self.periods.is_empty() {
            missing.push(format!(
                "monthly fiscal period for {month} (no period contained in the month exists)"
            ));
        }
        if self.employees.is_empty() {
            missing.push(format!("posted payroll postings for {month}"));
        }
        if self.unposted_payroll_records > 0 {
            missing.push(format!(
                "{} payroll record(s) for {month} are not posted to the ledger \
                 (the payroll sweep has not run, or their entry was reversed)",
                self.unposted_payroll_records
            ));
        }
        for employee in &self.incomplete_employees {
            missing.push(format!(
                "posting {} ({}): {} not recorded",
                employee.posting_id,
                employee
                    .employee_name
                    .clone()
                    .unwrap_or_else(|| "unnamed".to_string()),
                employee.missing.join(", ")
            ));
        }
        for posting in &self.identity_violations {
            missing.push(format!(
                "posting {posting} is internally inconsistent: \
                 gross − unemployment(employee) − pension − income tax ≠ net"
            ));
        }
        let foreign: Vec<&String> = self
            .currencies
            .iter()
            .filter(|c| c.as_str() != self.currency.as_str())
            .collect();
        if !foreign.is_empty() {
            let listed: Vec<&str> = foreign.iter().map(|c| c.as_str()).collect();
            missing.push(format!(
                "postings in a currency other than {}: {}",
                self.currency,
                listed.join(", ")
            ));
        }
        missing
    }

    /// Human-readable provenance note for the declaration.
    pub fn note(&self) -> String {
        let ready = if self.has_sufficient_data() {
            String::new()
        } else {
            format!(
                " NOT READY TO FILE: {}.",
                self.missing_fields().join("; ")
            )
        };

        if self.employees.is_empty() {
            return format!(
                "No posted payroll postings for {}. The TSD is derived from the \
                 posted ledger ({}); nothing was booked for this month. \
                 If team members were paid, post the payroll records first \
                 (payroll_records → payroll_postings → journal entry).{}",
                self.period_label(),
                self.provenance(),
                ready
            );
        }
        let mut note = format!(
            "Derived from {} posted payroll posting(s) across {} fiscal period(s) \
             [{}] in the {} ledger, referencing {} journal entr{} ({}).",
            self.employees.len(),
            self.periods.len(),
            self.periods
                .iter()
                .map(|p| format!("{} ({})", p.label, p.status))
                .collect::<Vec<_>>()
                .join(", "),
            self.currency,
            self.journal_entry_ids().len(),
            if self.journal_entry_ids().len() == 1 {
                "y"
            } else {
                "ies"
            },
            self.provenance()
        );
        let open = self.open_periods();
        if !open.is_empty() {
            note.push_str(&format!(
                " WARNING: fiscal period(s) {} are still OPEN — corrections before close \
                 will change these figures.",
                open.iter()
                    .map(|p| p.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        note.push_str(&ready);
        note
    }

    /// Where the amounts came from (named so a reader can verify the claim).
    pub fn provenance(&self) -> String {
        "accounting 220: v_accounting_payroll_taxes (posted entries only)".to_string()
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct EntityRow {
    id: Uuid,
    legal_name: String,
    registry_code: String,
    vat_number: Option<String>,
    default_currency: String,
}

#[derive(Debug, sqlx::FromRow)]
struct PeriodRow {
    id: Uuid,
    period_type: String,
    label: String,
    start_date: NaiveDate,
    end_date: NaiveDate,
    status: String,
}

#[derive(Debug, sqlx::FromRow)]
struct PersonRow {
    payroll_record_id: Uuid,
    employee_name: String,
    personal_code: Option<String>,
    funded_pension_rate: Option<f64>,
    pension_exemption: bool,
}

/// First and last day of a calendar month.
pub fn month_bounds(year: i32, month: u32) -> Result<(NaiveDate, NaiveDate), TsdSourceError> {
    if !(1..=12).contains(&month) {
        return Err(TsdSourceError::InvalidPeriod { year, month });
    }
    let start = NaiveDate::from_ymd_opt(year, month, 1)
        .ok_or(TsdSourceError::InvalidPeriod { year, month })?;
    let (next_year, next_month) = if month == 12 {
        (year.checked_add(1), 1)
    } else {
        (Some(year), month + 1)
    };
    let next_year = next_year.ok_or(TsdSourceError::InvalidPeriod { year, month })?;
    let next_start = NaiveDate::from_ymd_opt(next_year, next_month, 1)
        .ok_or(TsdSourceError::InvalidPeriod { year, month })?;
    let end = next_start
        .pred_opt()
        .ok_or(TsdSourceError::InvalidPeriod { year, month })?;
    Ok((start, end))
}

/// Read the posted ledger for one calendar month of one legal entity.
///
/// Returns a source carrying whatever the ledger holds plus every gap; only a
/// missing entity or a failed read is an error (see [`TsdSourceError`]).
pub async fn read_month(
    db: &PgPool,
    legal_entity_id: Uuid,
    year: i32,
    month: u32,
) -> Result<TsdLedgerSource, TsdSourceError> {
    let (month_start, month_end) = month_bounds(year, month)?;

    let entity = sqlx::query_as::<_, EntityRow>(
        "SELECT id, legal_name, registry_code, vat_number, default_currency \
         FROM legal_entities WHERE id = $1",
    )
    .bind(legal_entity_id)
    .fetch_optional(db)
    .await
    .map_err(|error| TsdSourceError::Lookup {
        what: "legal_entities",
        detail: error.to_string(),
    })?
    .ok_or(TsdSourceError::EntityIdNotFound { legal_entity_id })?;

    read_month_for_entity(db, entity, year, month, month_start, month_end).await
}

/// Read the posted ledger for the month of the entity carrying
/// `registry_code`. Used by the document generator, whose printed identity
/// (company name + registry code) must be the identity the books belong to.
pub async fn read_month_by_registry_code(
    db: &PgPool,
    registry_code: &str,
    year: i32,
    month: u32,
) -> Result<TsdLedgerSource, TsdSourceError> {
    let (month_start, month_end) = month_bounds(year, month)?;

    let entity = sqlx::query_as::<_, EntityRow>(
        "SELECT id, legal_name, registry_code, vat_number, default_currency \
         FROM legal_entities WHERE registry_code = $1",
    )
    .bind(registry_code)
    .fetch_optional(db)
    .await
    .map_err(|error| TsdSourceError::Lookup {
        what: "legal_entities",
        detail: error.to_string(),
    })?
    .ok_or_else(|| TsdSourceError::EntityNotFound {
        registry_code: registry_code.to_string(),
    })?;

    read_month_for_entity(db, entity, year, month, month_start, month_end).await
}

async fn read_month_for_entity(
    db: &PgPool,
    entity: EntityRow,
    year: i32,
    month: u32,
    month_start: NaiveDate,
    month_end: NaiveDate,
) -> Result<TsdLedgerSource, TsdSourceError> {
    // Only periods CONTAINED in the month: a year period containing the month
    // cannot produce a monthly return (see the module docs).
    let periods = sqlx::query_as::<_, PeriodRow>(
        "SELECT id, period_type, label, start_date, end_date, status \
         FROM fiscal_periods \
         WHERE legal_entity_id = $1 AND start_date >= $2 AND end_date <= $3 \
         ORDER BY start_date, id",
    )
    .bind(entity.id)
    .bind(month_start)
    .bind(month_end)
    .fetch_all(db)
    .await
    .map_err(|error| TsdSourceError::Lookup {
        what: "fiscal_periods",
        detail: error.to_string(),
    })?;

    // Amounts: the documented ledger read contract, posted entries only.
    let mut postings: Vec<accounting_core::derive::PayrollTaxRow> = Vec::new();
    for period in &periods {
        let rows = payroll_taxes_for_period(db, entity.id, period.id)
            .await
            .map_err(|error| TsdSourceError::Lookup {
                what: "v_accounting_payroll_taxes",
                detail: error.to_string(),
            })?;
        postings.extend(rows);
    }
    postings.sort_by(|a, b| {
        a.employee_name
            .cmp(&b.employee_name)
            .then_with(|| a.id.cmp(&b.id))
    });

    // Person facts for exactly the payroll inputs the postings reference.
    let record_ids: Vec<Uuid> = postings.iter().map(|p| p.payroll_record_id).collect();
    let persons = if record_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, PersonRow>(
            "SELECT id AS payroll_record_id, employee_name, personal_code, \
                    funded_pension_rate, pension_exemption \
             FROM payroll_records WHERE id = ANY($1)",
        )
        .bind(&record_ids)
        .fetch_all(db)
        .await
        .map_err(|error| TsdSourceError::Lookup {
            what: "payroll_records",
            detail: error.to_string(),
        })?
    };
    let persons: std::collections::HashMap<Uuid, PersonRow> =
        persons.into_iter().map(|p| (p.payroll_record_id, p)).collect();

    let mut employees = Vec::with_capacity(postings.len());
    let mut incomplete = Vec::new();
    let mut violations = Vec::new();
    let mut currencies = BTreeSet::new();

    for posting in postings {
        let person = persons.get(&posting.payroll_record_id);
        let name = posting
            .employee_name
            .clone()
            .or_else(|| person.map(|p| p.employee_name.clone()));

        // The rate to declare: exemption means 0%, otherwise the recorded
        // employee-specific rate; None stays None (participation unknown).
        let funded_pension_rate = match person {
            Some(p) if p.pension_exemption => Some(0.0),
            Some(p) => p.funded_pension_rate,
            None => None,
        };

        let mut missing = Vec::new();
        if person.is_none() {
            missing.push("payroll_record (the canonical payroll input)".to_string());
        }
        if person
            .and_then(|p| p.personal_code.as_deref())
            .map(|code| code.trim().is_empty())
            .unwrap_or(true)
        {
            missing.push("personal_code".to_string());
        }
        if funded_pension_rate.is_none() {
            missing.push("funded_pension_rate".to_string());
        }
        if !missing.is_empty() {
            incomplete.push(TsdIncompleteEmployee {
                posting_id: posting.id,
                employee_name: name.clone(),
                missing,
            });
        }

        // The posting's own arithmetic must hold; otherwise the books
        // disagree with themselves and no derived figure is trustworthy.
        let expected_net = posting.gross_cents
            - posting.unemployment_employee_cents
            - posting.pension_cents
            - posting.income_tax_cents;
        if expected_net != posting.net_cents {
            violations.push(posting.id);
        }

        currencies.insert(posting.currency.trim().to_string());

        employees.push(TsdEmployee {
            posting_id: posting.id,
            payroll_record_id: posting.payroll_record_id,
            fiscal_period_id: posting.fiscal_period_id,
            journal_entry_id: posting.journal_entry_id.ok_or_else(|| {
                // Unreachable through the read contract's posted-only filter;
                // modelled as missing data rather than a panic.
                TsdSourceError::Lookup {
                    what: "v_accounting_payroll_taxes.journal_entry_id",
                    detail: format!(
                        "posting {} was returned without a journal entry",
                        posting.id
                    ),
                }
            })?,
            employee_name: name,
            personal_code: person.and_then(|p| p.personal_code.clone()),
            funded_pension_rate,
            gross_salary_cents: posting.gross_cents,
            social_tax_cents: posting.social_tax_cents,
            unemployment_insurance_employer_cents: posting.unemployment_employer_cents,
            unemployment_insurance_employee_cents: posting.unemployment_employee_cents,
            funded_pension_cents: posting.pension_cents,
            income_tax_withheld_cents: posting.income_tax_cents,
            net_salary_cents: posting.net_cents,
            currency: posting.currency.trim().to_string(),
        });
    }

    // Payroll inputs for the month that are NOT in the posted ledger. The
    // month is the entity's local calendar month, so the comparison is pinned
    // to Europe/Tallinn instead of the session TimeZone.
    let unposted_payroll_records: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM payroll_records pr \
         WHERE date_trunc('month', pr.pay_period AT TIME ZONE $2) = $1::date \
           AND NOT EXISTS ( \
                 SELECT 1 FROM payroll_postings pp \
                 JOIN journal_entries e ON e.id = pp.journal_entry_id \
                 WHERE pp.payroll_record_id = pr.id AND e.posted_at IS NOT NULL)",
    )
    .bind(month_start)
    .bind(PAYROLL_PERIOD_ZONE)
    .fetch_one(db)
    .await
    .map_err(|error| TsdSourceError::Lookup {
        what: "payroll_records (unposted count)",
        detail: error.to_string(),
    })?;

    Ok(TsdLedgerSource {
        legal_entity_id: entity.id,
        legal_name: entity.legal_name,
        registry_code: entity.registry_code,
        vat_number: entity.vat_number,
        currency: entity.default_currency.trim().to_string(),
        year,
        month,
        periods: periods
            .into_iter()
            .map(|p| TsdPeriod {
                id: p.id,
                period_type: p.period_type,
                label: p.label,
                start_date: p.start_date,
                end_date: p.end_date,
                status: p.status,
            })
            .collect(),
        employees,
        unposted_payroll_records,
        incomplete_employees: incomplete,
        identity_violations: violations,
        currencies: currencies.into_iter().collect(),
        read_at: Utc::now(),
    })
}

/// The reporting period label used by the declaration (`YYYY-MM`).
pub fn month_label(year: i32, month: u32) -> String {
    format!("{year:04}-{month:02}")
}
