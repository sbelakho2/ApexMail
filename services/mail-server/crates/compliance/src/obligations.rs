//! Statutory obligation scheduler.
//!
//! Obligations are **derived from the entity's facts** — VAT registration
//! date, VD reporting start, employer status, OSS registration and financial
//! year end — never from a hard-coded "annual report = June 30" table.
//!
//! Every legal due date is routed through
//! [`crate::statutory_calendar::statutory_due_date`], so KMD, TSD, VD, OSS
//! and annual-report deadlines share one Estonian working-day rule and one
//! versioned holiday calendar.
//!
//! # Deadlines modelled
//!
//! | Obligation | Period | Legal due date | Basis |
//! |---|---|---|---|
//! | `kmd` (VAT) | month | 20th of the following month | KMS §27 |
//! | `tsd` (payroll/social tax) | month | 10th of the following month | TuMS §54, SOS §9 |
//! | `vd` (intra-Community supplies) | month | 20th of the following month | filed with KMD |
//! | `oss_union` | quarter | last day of the month following the quarter | VAT Directive Art. 364 |
//! | `annual_report` | financial year | last day of the 6th month after the financial year end | ÄS §179 |
//!
//! Facts that are absent create no obligations: an entity with no VAT
//! registration has no KMD/VD rows, an entity that never employed anyone has
//! no TSD rows, and no OSS registration means no OSS rows.
//!
//! # Horizon
//!
//! [`ObligationHorizon`] is a rolling window over effective due dates.
//! [`ObligationHorizon::advance_month`] moves it one month forward — the
//! scheduler's monthly tick — and re-derivation is idempotent because rows
//! are keyed by `(legal_entity_id, obligation_type, period_start)`.

use chrono::{Datelike, Months, NaiveDate};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::statutory_calendar::{statutory_due_date, ESTONIA_CALENDAR_VERSION};

/// A statutory filing obligation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatutoryObligationType {
    /// VAT return (KMD), monthly.
    Kmd,
    /// Payroll / social tax return (TSD), monthly.
    Tsd,
    /// Intra-Community supply report (VD), monthly.
    Vd,
    /// OSS Union scheme return, quarterly.
    OssUnion,
    /// Annual report, per financial year.
    AnnualReport,
}

impl StatutoryObligationType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kmd => "kmd",
            Self::Tsd => "tsd",
            Self::Vd => "vd",
            Self::OssUnion => "oss_union",
            Self::AnnualReport => "annual_report",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "kmd" => Some(Self::Kmd),
            "tsd" => Some(Self::Tsd),
            "vd" => Some(Self::Vd),
            "oss_union" => Some(Self::OssUnion),
            "annual_report" => Some(Self::AnnualReport),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Kmd => "VAT return (KMD)",
            Self::Tsd => "Payroll and social tax return (TSD)",
            Self::Vd => "Intra-Community supply report (VD)",
            Self::OssUnion => "OSS Union scheme return",
            Self::AnnualReport => "Annual report",
        }
    }
}

impl std::fmt::Display for StatutoryObligationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The facts from which obligations are derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityFilingFacts {
    pub legal_entity_id: Uuid,
    /// Date the entity entered the Estonian VAT register (KMD + VD duty).
    pub vat_registered_from: Option<NaiveDate>,
    /// Optional later start for VD reporting (defaults to VAT registration).
    pub vd_reporting_from: Option<NaiveDate>,
    /// Date the entity first had employees (TSD duty).
    pub employer_since: Option<NaiveDate>,
    /// OSS Union scheme registration date (quarterly OSS duty).
    pub oss_registered_from: Option<NaiveDate>,
    /// Financial year end month (1..=12).
    pub fiscal_year_end_month: u32,
    /// When the entity started to exist (legal_entities.created_at); used to
    /// avoid scheduling annual reports for years before the entity existed.
    pub entity_active_from: Option<NaiveDate>,
}

impl EntityFilingFacts {
    /// Facts for an entity with only a calendar-year annual-report duty.
    pub fn annual_only(legal_entity_id: Uuid, fiscal_year_end_month: u32) -> Self {
        Self {
            legal_entity_id,
            vat_registered_from: None,
            vd_reporting_from: None,
            employer_since: None,
            oss_registered_from: None,
            fiscal_year_end_month,
            entity_active_from: None,
        }
    }
}

/// One derived obligation (not yet persisted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatutoryObligation {
    pub obligation_type: StatutoryObligationType,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub period_label: String,
    /// The date the law states, before the working-day adjustment.
    pub legal_due_date: NaiveDate,
    /// The effective due date (working-day adjusted).
    pub due_date: NaiveDate,
    pub calendar_version: String,
}

/// A rolling window of effective due dates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObligationHorizon {
    pub start: NaiveDate,
    pub end: NaiveDate,
}

impl ObligationHorizon {
    /// A horizon covering `days` days from `start` (inclusive).
    pub fn from_start(start: NaiveDate, days: i64) -> Self {
        let days = days.max(0);
        Self {
            start,
            end: start + chrono::Duration::days(days),
        }
    }

    /// The calendar month containing `start`, or the given month explicitly.
    pub fn month(year: i32, month: u32) -> Option<Self> {
        let start = NaiveDate::from_ymd_opt(year, month, 1)?;
        let end = last_day_of_month(year, month)?;
        Some(Self { start, end })
    }

    /// Advance the horizon by one calendar month — the scheduler's monthly
    /// tick. The window keeps its length in days when possible.
    pub fn advance_month(&self) -> Self {
        let length = (self.end - self.start).num_days();
        let start = self
            .start
            .checked_add_months(Months::new(1))
            .unwrap_or(self.start);
        Self {
            start,
            end: start + chrono::Duration::days(length),
        }
    }

    fn contains(&self, date: NaiveDate) -> bool {
        date >= self.start && date <= self.end
    }
}

// ---------------------------------------------------------------------------
// Date helpers
// ---------------------------------------------------------------------------

fn last_day_of_month(year: i32, month: u32) -> Option<NaiveDate> {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    NaiveDate::from_ymd_opt(next_year, next_month, 1)?.pred_opt()
}

fn first_of_next_month(year: i32, month: u32) -> Option<NaiveDate> {
    if month == 12 {
        NaiveDate::from_ymd_opt(year + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(year, month + 1, 1)
    }
}

fn add_months_clamped(date: NaiveDate, months: u32) -> Option<NaiveDate> {
    date.checked_add_months(Months::new(months))
}

/// Months from `from` (inclusive) through `to` (inclusive); empty if reversed.
fn month_range(from: (i32, u32), to: (i32, u32)) -> Vec<(i32, u32)> {
    let mut out = Vec::new();
    let (mut year, mut month) = from;
    // Guard against absurd ranges (hostile input) with a generous cap.
    for _ in 0..=1200 {
        if (year, month) > to {
            break;
        }
        out.push((year, month));
        if month == 12 {
            year += 1;
            month = 1;
        } else {
            month += 1;
        }
    }
    out
}

fn quarter_label(year: i32, quarter: u32) -> String {
    format!("{year}-Q{quarter}")
}

/// The legal due date for a monthly return (day of the following month).
fn monthly_legal_due_date(year: i32, month: u32, day: u32) -> Option<NaiveDate> {
    first_of_next_month(year, month)?.with_day(day)
}

/// The legal OSS Union due date for the quarter ending in `(year, month)`:
/// the last day of the month following the quarter.
fn oss_legal_due_date_for_quarter_end(year: i32, month: u32) -> Option<NaiveDate> {
    let due_month = first_of_next_month(year, month)?;
    last_day_of_month(due_month.year(), due_month.month())
}

/// The annual-report legal due date for a financial year ending on
/// `fiscal_year_end`: the last day of the sixth month after the year end
/// (ÄS §179).
pub fn annual_report_legal_due_date(fiscal_year_end: NaiveDate) -> Option<NaiveDate> {
    let sixth = add_months_clamped(fiscal_year_end, 6)?;
    last_day_of_month(sixth.year(), sixth.month())
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/// Derive the obligations whose **effective due date** falls inside `horizon`.
///
/// Pure and idempotent: the same facts and horizon always yield the same set,
/// ordered by due date then obligation type.
pub fn derive_obligations(
    facts: &EntityFilingFacts,
    horizon: ObligationHorizon,
) -> Vec<StatutoryObligation> {
    let mut obligations = Vec::new();
    if horizon.end < horizon.start {
        // Hostile horizon (reversed): nothing to schedule, never a panic.
        return obligations;
    }

    // Monthly obligations. Include the month before the horizon start (its
    // due date falls inside the horizon at the start of a month).
    let first_month = first_of_month_offset(horizon.start, -1);
    let last_month = (horizon.end.year(), horizon.end.month());
    let monthly_specs: &[(StatutoryObligationType, u32, Option<NaiveDate>)] = &[
        (StatutoryObligationType::Kmd, 20, facts.vat_registered_from),
        (
            StatutoryObligationType::Vd,
            20,
            facts.vd_reporting_from.or(facts.vat_registered_from),
        ),
        (StatutoryObligationType::Tsd, 10, facts.employer_since),
    ];

    for (obligation_type, due_day, active_from) in monthly_specs {
        let Some(active_from) = active_from else {
            continue;
        };
        for (year, month) in month_range(first_month, last_month) {
            let Some(period_end) = last_day_of_month(year, month) else {
                continue;
            };
            if period_end < *active_from {
                continue;
            }
            let Some(period_start) = NaiveDate::from_ymd_opt(year, month, 1) else {
                continue;
            };
            let Some(legal_due) = monthly_legal_due_date(year, month, *due_day) else {
                continue;
            };
            let due = statutory_due_date(legal_due);
            if horizon.contains(due) {
                obligations.push(StatutoryObligation {
                    obligation_type: *obligation_type,
                    period_start,
                    period_end,
                    period_label: format!("{year:04}-{month:02}"),
                    legal_due_date: legal_due,
                    due_date: due,
                    calendar_version: ESTONIA_CALENDAR_VERSION.to_string(),
                });
            }
        }
    }

    // OSS Union: quarterly. Start three months before the horizon start so a
    // Q4 return due 31 January is found when the horizon starts 1 January.
    if let Some(oss_from) = facts.oss_registered_from {
        let (quarter_start_year, quarter_start_month) = first_of_month_offset(horizon.start, -3);
        let mut quarter_year = quarter_start_year;
        let mut quarter_number = (quarter_start_month - 1) / 3 + 1; // 1..=4
        for _ in 0..=40 {
            let start_month = (quarter_number - 1) * 3 + 1;
            let Some(period_start) = NaiveDate::from_ymd_opt(quarter_year, start_month, 1) else {
                break;
            };
            if period_start > horizon.end {
                break;
            }
            let Some(period_end) = last_day_of_month(quarter_year, (start_month + 2).min(12))
            else {
                break;
            };
            if period_end >= oss_from {
                if let Some(legal_due) =
                    oss_legal_due_date_for_quarter_end(quarter_year, period_end.month())
                {
                    let due = statutory_due_date(legal_due);
                    if horizon.contains(due) {
                        obligations.push(StatutoryObligation {
                            obligation_type: StatutoryObligationType::OssUnion,
                            period_start,
                            period_end,
                            period_label: quarter_label(quarter_year, quarter_number),
                            legal_due_date: legal_due,
                            due_date: due,
                            calendar_version: ESTONIA_CALENDAR_VERSION.to_string(),
                        });
                    }
                }
            }
            quarter_number += 1;
            if quarter_number > 4 {
                quarter_number = 1;
                quarter_year += 1;
            }
        }
    }

    // Annual report: financial years whose six-month deadline falls in the
    // horizon. The FYE month comes from the entity's facts.
    if (1..=12).contains(&facts.fiscal_year_end_month) {
        for fye_year in (horizon.start.year() - 1)..=(horizon.end.year() + 1) {
            let Some(period_end) = last_day_of_month(fye_year, facts.fiscal_year_end_month) else {
                continue;
            };
            if let Some(active_from) = facts.entity_active_from {
                if period_end < active_from {
                    continue;
                }
            }
            let period_start = period_end
                .checked_sub_months(Months::new(11))
                .and_then(|first_of_end_month| first_of_end_month.with_day(1));
            let Some(period_start) = period_start else {
                continue;
            };
            let Some(legal_due) = annual_report_legal_due_date(period_end) else {
                continue;
            };
            let due = statutory_due_date(legal_due);
            if horizon.contains(due) {
                obligations.push(StatutoryObligation {
                    obligation_type: StatutoryObligationType::AnnualReport,
                    period_start,
                    period_end,
                    period_label: format!("FY {fye_year}"),
                    legal_due_date: legal_due,
                    due_date: due,
                    calendar_version: ESTONIA_CALENDAR_VERSION.to_string(),
                });
            }
        }
    }

    obligations.sort_by(|a, b| {
        a.due_date
            .cmp(&b.due_date)
            .then_with(|| a.obligation_type.as_str().cmp(b.obligation_type.as_str()))
            .then_with(|| a.period_start.cmp(&b.period_start))
    });
    obligations
}

/// First day of the month obtained by shifting `date`'s month by `offset`
/// (negative allowed).
fn first_of_month_offset(date: NaiveDate, offset: i32) -> (i32, u32) {
    let shifted = if offset >= 0 {
        date.checked_add_months(Months::new(offset as u32))
    } else {
        date.checked_sub_months(Months::new((-offset) as u32))
    }
    .unwrap_or(date);
    (shifted.year(), shifted.month())
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Load an entity's filing facts, falling back to `legal_entities` defaults
/// (fiscal-year start month, creation date) when the facts row is absent.
pub async fn load_filing_facts(
    db: &PgPool,
    legal_entity_id: Uuid,
) -> Result<EntityFilingFacts, String> {
    let row = sqlx::query_as::<_, FilingFactsRow>(
        r#"
        SELECT le.id AS legal_entity_id,
               f.vat_registered_from,
               f.vd_reporting_from,
               f.employer_since,
               f.oss_registered_from,
               COALESCE(f.fiscal_year_end_month,
                        (le.fiscal_year_start_month + 10) % 12 + 1) AS fiscal_year_end_month,
               le.created_at::date AS entity_active_from
        FROM legal_entities le
        LEFT JOIN legal_entity_filing_facts f ON f.legal_entity_id = le.id
        WHERE le.id = $1
        "#,
    )
    .bind(legal_entity_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load filing facts: {error}"))?
    .ok_or_else(|| format!("legal entity {legal_entity_id} not found"))?;

    Ok(EntityFilingFacts {
        legal_entity_id: row.legal_entity_id,
        vat_registered_from: row.vat_registered_from,
        vd_reporting_from: row.vd_reporting_from,
        employer_since: row.employer_since,
        oss_registered_from: row.oss_registered_from,
        fiscal_year_end_month: row.fiscal_year_end_month.clamp(1, 12) as u32,
        entity_active_from: Some(row.entity_active_from),
    })
}

#[derive(Debug, sqlx::FromRow)]
struct FilingFactsRow {
    legal_entity_id: Uuid,
    vat_registered_from: Option<NaiveDate>,
    vd_reporting_from: Option<NaiveDate>,
    employer_since: Option<NaiveDate>,
    oss_registered_from: Option<NaiveDate>,
    fiscal_year_end_month: i32,
    entity_active_from: NaiveDate,
}

/// Idempotently persist the derived obligations for `(facts, horizon)`.
///
/// Re-running the same horizon updates pending rows in place; rows already
/// marked filed/waived keep their status (a deadline correction never
/// re-opens a filed obligation). Returns the number of rows upserted.
pub async fn sync_obligations(
    db: &PgPool,
    facts: &EntityFilingFacts,
    horizon: ObligationHorizon,
) -> Result<u64, String> {
    let obligations = derive_obligations(facts, horizon);
    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("failed to begin obligation sync: {error}"))?;

    let mut upserted = 0u64;
    for obligation in &obligations {
        let result = sqlx::query(
            r#"
            INSERT INTO statutory_obligations
                (legal_entity_id, obligation_type, period_start, period_end,
                 period_label, legal_due_date, due_date, calendar_version)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (legal_entity_id, obligation_type, period_start) DO UPDATE SET
                period_end = EXCLUDED.period_end,
                period_label = EXCLUDED.period_label,
                legal_due_date = EXCLUDED.legal_due_date,
                due_date = EXCLUDED.due_date,
                calendar_version = EXCLUDED.calendar_version,
                updated_at = NOW()
            WHERE statutory_obligations.status = 'pending'
            "#,
        )
        .bind(facts.legal_entity_id)
        .bind(obligation.obligation_type.as_str())
        .bind(obligation.period_start)
        .bind(obligation.period_end)
        .bind(&obligation.period_label)
        .bind(obligation.legal_due_date)
        .bind(obligation.due_date)
        .bind(&obligation.calendar_version)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("failed to upsert statutory obligation: {error}"))?;
        upserted += result.rows_affected();
    }

    tx.commit()
        .await
        .map_err(|error| format!("failed to commit obligation sync: {error}"))?;
    Ok(upserted)
}

/// Mark pending obligations past their effective due date as overdue.
pub async fn mark_overdue(db: &PgPool, today: NaiveDate) -> Result<u64, String> {
    let result = sqlx::query(
        "UPDATE statutory_obligations SET status = 'overdue', updated_at = NOW() \
         WHERE due_date < $1 AND status = 'pending'",
    )
    .bind(today)
    .execute(db)
    .await
    .map_err(|error| format!("failed to mark obligations overdue: {error}"))?;
    Ok(result.rows_affected())
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

    fn full_facts() -> EntityFilingFacts {
        EntityFilingFacts {
            legal_entity_id: Uuid::nil(),
            vat_registered_from: Some(d(2020, 1, 1)),
            vd_reporting_from: None,
            employer_since: Some(d(2020, 1, 1)),
            oss_registered_from: Some(d(2025, 1, 1)),
            fiscal_year_end_month: 12,
            entity_active_from: Some(d(2020, 1, 1)),
        }
    }

    fn find<'a>(
        obligations: &'a [StatutoryObligation],
        obligation_type: StatutoryObligationType,
        period_label: &str,
    ) -> Option<&'a StatutoryObligation> {
        obligations
            .iter()
            .find(|o| o.obligation_type == obligation_type && o.period_label == period_label)
    }

    // ── Legal due dates per obligation type ────────────────────────────

    #[test]
    fn monthly_deadlines_follow_the_law_then_the_calendar() {
        let facts = full_facts();
        // February 2026 horizon: January KMD/VD due 20 Feb, TSD due 10 Feb.
        let horizon = ObligationHorizon::month(2026, 2).unwrap();
        let obligations = derive_obligations(&facts, horizon);

        let kmd = find(&obligations, StatutoryObligationType::Kmd, "2026-01")
            .expect("January KMD due in February");
        assert_eq!(kmd.legal_due_date, d(2026, 2, 20));
        assert_eq!(kmd.due_date, d(2026, 2, 20)); // Friday, no shift

        let tsd = find(&obligations, StatutoryObligationType::Tsd, "2026-01")
            .expect("January TSD due in February");
        assert_eq!(tsd.legal_due_date, d(2026, 2, 10));

        let vd = find(&obligations, StatutoryObligationType::Vd, "2026-01")
            .expect("January VD due in February");
        assert_eq!(vd.legal_due_date, d(2026, 2, 20));

        // The 20th of June 2026 is a Saturday: the effective KMD/VD deadline
        // moves to Monday 22 June (23 June is Victory Day).
        let june = ObligationHorizon::month(2026, 6).unwrap();
        let obligations = derive_obligations(&facts, june);
        let kmd = find(&obligations, StatutoryObligationType::Kmd, "2026-05")
            .expect("May KMD due in June");
        assert_eq!(kmd.legal_due_date, d(2026, 6, 20));
        assert_eq!(kmd.due_date, d(2026, 6, 22));
    }

    #[test]
    fn oss_is_quarterly_and_due_end_of_following_month() {
        let facts = full_facts();
        let horizon = ObligationHorizon::from_start(d(2026, 4, 1), 31);
        let obligations = derive_obligations(&facts, horizon);
        let q1 = find(&obligations, StatutoryObligationType::OssUnion, "2026-Q1")
            .expect("Q1 OSS due 30 April");
        assert_eq!(q1.period_start, d(2026, 1, 1));
        assert_eq!(q1.period_end, d(2026, 3, 31));
        assert_eq!(q1.legal_due_date, d(2026, 4, 30)); // Thursday

        // Q4 2025 is legally due 31 January 2026 (a Saturday), so the
        // effective deadline is Monday 2 February — the February horizon
        // contains it, the January one does not (the shift moved it out).
        let february = ObligationHorizon::month(2026, 2).unwrap();
        let obligations = derive_obligations(&facts, february);
        let q4 = find(&obligations, StatutoryObligationType::OssUnion, "2025-Q4")
            .expect("Q4 2025 OSS due in January");
        assert_eq!(q4.legal_due_date, d(2026, 1, 31));
        assert_eq!(q4.due_date, d(2026, 2, 2));
    }

    #[test]
    fn annual_report_due_date_comes_from_the_fiscal_year_end() {
        // Calendar-year entity: FY2025 ends 31 Dec 2025, due 30 Jun 2026.
        let facts = EntityFilingFacts::annual_only(Uuid::nil(), 12);
        let horizon = ObligationHorizon::from_start(d(2026, 6, 1), 30);
        let obligations = derive_obligations(&facts, horizon);
        let report = find(
            &obligations,
            StatutoryObligationType::AnnualReport,
            "FY 2025",
        )
        .expect("FY2025 annual report");
        assert_eq!(report.legal_due_date, d(2026, 6, 30));
        assert_eq!(report.due_date, d(2026, 6, 30));
        assert_eq!(report.period_start, d(2025, 1, 1));
        assert_eq!(report.period_end, d(2025, 12, 31));

        // Non-calendar financial year (June end): due 31 December.
        let facts = EntityFilingFacts::annual_only(Uuid::nil(), 6);
        let horizon = ObligationHorizon::from_start(d(2026, 12, 1), 31);
        let obligations = derive_obligations(&facts, horizon);
        let report = find(
            &obligations,
            StatutoryObligationType::AnnualReport,
            "FY 2026",
        )
        .expect("FY ending June 2026");
        assert_eq!(report.period_start, d(2025, 7, 1));
        assert_eq!(report.period_end, d(2026, 6, 30));
        assert_eq!(report.legal_due_date, d(2026, 12, 31));
    }

    // ── Facts drive the obligation set ─────────────────────────────────

    #[test]
    fn absent_facts_create_no_obligations() {
        let facts = EntityFilingFacts::annual_only(Uuid::nil(), 12);
        let horizon = ObligationHorizon::from_start(d(2026, 1, 1), 365);
        let obligations = derive_obligations(&facts, horizon);
        assert!(obligations
            .iter()
            .all(|o| o.obligation_type == StatutoryObligationType::AnnualReport));
        assert!(!obligations.is_empty());
    }

    #[test]
    fn obligations_start_at_the_registration_date() {
        let facts = EntityFilingFacts {
            legal_entity_id: Uuid::nil(),
            vat_registered_from: Some(d(2026, 3, 15)),
            vd_reporting_from: None,
            employer_since: Some(d(2026, 4, 1)),
            oss_registered_from: Some(d(2026, 5, 20)),
            fiscal_year_end_month: 12,
            entity_active_from: Some(d(2026, 3, 15)),
        };
        let horizon = ObligationHorizon::from_start(d(2026, 1, 1), 700);
        let obligations = derive_obligations(&facts, horizon);

        // March is the first KMD month (registered 15 March); February is not.
        assert!(find(&obligations, StatutoryObligationType::Kmd, "2026-03").is_some());
        assert!(find(&obligations, StatutoryObligationType::Kmd, "2026-02").is_none());
        // TSD starts with the first payroll month (April).
        assert!(find(&obligations, StatutoryObligationType::Tsd, "2026-04").is_some());
        assert!(find(&obligations, StatutoryObligationType::Tsd, "2026-03").is_none());
        // OSS starts with the quarter containing the registration (Q2 2026).
        assert!(find(&obligations, StatutoryObligationType::OssUnion, "2026-Q2").is_some());
        assert!(find(&obligations, StatutoryObligationType::OssUnion, "2026-Q1").is_none());
        // No annual report for a year that ended before the entity existed.
        assert!(find(
            &obligations,
            StatutoryObligationType::AnnualReport,
            "FY 2025"
        )
        .is_none());
        assert!(find(
            &obligations,
            StatutoryObligationType::AnnualReport,
            "FY 2026"
        )
        .is_some());
    }

    // ── The horizon advances month over month ──────────────────────────

    #[test]
    fn obligation_horizon_advances_month_over_month() {
        let facts = full_facts();
        // A 30-day horizon so month-over-month advancement keeps a stable
        // window length.
        let mut horizon = ObligationHorizon::from_start(d(2026, 2, 1), 30);

        let first = derive_obligations(&facts, horizon);
        let first_months: Vec<&str> = first
            .iter()
            .filter(|o| o.obligation_type == StatutoryObligationType::Kmd)
            .map(|o| o.period_label.as_str())
            .collect();
        assert_eq!(first_months, vec!["2026-01"]);

        horizon = horizon.advance_month();
        assert_eq!(horizon.start, d(2026, 3, 1));
        let second = derive_obligations(&facts, horizon);
        let second_months: Vec<&str> = second
            .iter()
            .filter(|o| o.obligation_type == StatutoryObligationType::Kmd)
            .map(|o| o.period_label.as_str())
            .collect();
        assert_eq!(second_months, vec!["2026-02"]);

        // One more month: the monthly deadline keeps advancing, and Q1 OSS
        // now appears (due 30 April is outside the March horizon; Q1 is due
        // 30 April, so it appears when the horizon reaches April).
        horizon = horizon.advance_month();
        assert_eq!(horizon.start, d(2026, 4, 1));
        let third = derive_obligations(&facts, horizon);
        assert!(find(&third, StatutoryObligationType::Kmd, "2026-03").is_some());
        assert!(find(&third, StatutoryObligationType::OssUnion, "2026-Q1").is_some());
    }

    // ── Hostile input ──────────────────────────────────────────────────

    #[test]
    fn reversed_or_zero_length_horizons_do_not_panic() {
        let facts = full_facts();
        let reversed = ObligationHorizon {
            start: d(2026, 5, 1),
            end: d(2026, 1, 1),
        };
        assert!(derive_obligations(&facts, reversed).is_empty());

        let zero = ObligationHorizon {
            start: d(2026, 5, 1),
            end: d(2026, 5, 1),
        };
        // Must not panic; a single-day horizon schedules only that day's due
        // dates (none for a working Friday 1 May? it is a holiday, so none).
        let _ = derive_obligations(&facts, zero);

        let empty_facts = EntityFilingFacts {
            legal_entity_id: Uuid::nil(),
            vat_registered_from: None,
            vd_reporting_from: None,
            employer_since: None,
            oss_registered_from: None,
            fiscal_year_end_month: 12,
            entity_active_from: None,
        };
        assert!(derive_obligations(
            &empty_facts,
            ObligationHorizon::from_start(d(2026, 1, 1), 30)
        )
        .is_empty());
    }

    #[test]
    fn obligation_type_round_trips() {
        for obligation_type in [
            StatutoryObligationType::Kmd,
            StatutoryObligationType::Tsd,
            StatutoryObligationType::Vd,
            StatutoryObligationType::OssUnion,
            StatutoryObligationType::AnnualReport,
        ] {
            assert_eq!(
                StatutoryObligationType::from_db(obligation_type.as_str()),
                Some(obligation_type)
            );
        }
        assert_eq!(StatutoryObligationType::from_db("nonsense"), None);
    }

    #[test]
    fn migration_declares_every_obligation_type() {
        let migration = include_str!("../../../migrations/221_statutory_filing_completion.sql");
        for obligation_type in [
            StatutoryObligationType::Kmd,
            StatutoryObligationType::Tsd,
            StatutoryObligationType::Vd,
            StatutoryObligationType::OssUnion,
            StatutoryObligationType::AnnualReport,
        ] {
            assert!(
                migration.contains(obligation_type.as_str()),
                "migration must declare obligation type {}",
                obligation_type.as_str()
            );
        }
    }
}
