//! Idempotent auto-provisioning of the statutory ledger (audit SM7 F1).
//!
//! Before this module, `default_legal_entity` was a bare `SELECT ... WHERE
//! is_default` (migration 220 seeds no entity) and
//! `find_open_period_for_date` failed with `NoOpenPeriod` unless an operator
//! had hand-provisioned an open period — so on every fresh deployment ALL
//! statutory postings (invoice revenue, AR settlement, credit-note reversal,
//! bank lines) were silently skipped forever with only an ERROR log.
//!
//! The posting path now ensures its own preconditions, inside the caller's
//! transaction (DML only — this crate's "no runtime DDL" guarantee stands:
//! the schema itself is deploy-time, migration 220):
//!
//! * **default legal entity + chart** — created on first use with a stable
//!   registry-code anchor ([`AUTO_PROVISIONED_REGISTRY_CODE`]), so concurrent
//!   provisioners collapse onto one row (`ON CONFLICT (registry_code)`), and
//!   the standard chart is seeded idempotently. The identity fields are
//!   deliberately minimal: an operator should correct the legal identity on a
//!   live deployment, but the books never again wait for a manual bootstrap.
//! * **an open fiscal period covering the document date** — the covering
//!   month is created when NOTHING covers the date. When a period covers the
//!   date but is closed/locked, provisioning FAILS CLOSED with
//!   `NoOpenPeriod`: backdating into closed books is a human decision, never
//!   something the posting path does silently (creating a second, overlapping
//!   open period would corrupt the close invariants).

use chrono::{Datelike, Months, NaiveDate};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::chart::{self, LegalEntityInput};
use crate::error::{AccountingError, Result};

/// The stable registry-code anchor for the auto-provisioned default legal
/// entity. `create_legal_entity` is idempotent by registry code, so this is
/// what makes concurrent first postings collapse onto ONE entity row.
pub const AUTO_PROVISIONED_REGISTRY_CODE: &str = "APEXMAIL-DEFAULT";

/// Ensure a default legal entity (with its standard chart) exists, creating
/// the platform default when none is configured. Returns its id.
///
/// Idempotent and safe to call on every posting: an existing default entity
/// short-circuits to the same `SELECT` the adapters always ran.
pub async fn ensure_default_entity_in(conn: &mut PgConnection) -> Result<Uuid> {
    match chart::default_legal_entity(conn).await {
        Ok(id) => Ok(id),
        Err(AccountingError::NoDefaultLegalEntity) => {
            let input = LegalEntityInput {
                legal_name: "ApexMail platform entity (auto-provisioned)".to_string(),
                trading_name: Some("ApexMail".to_string()),
                registry_code: AUTO_PROVISIONED_REGISTRY_CODE.to_string(),
                vat_number: None,
                address_line1: None,
                city: None,
                postal_code: None,
                country_code: "EE".to_string(),
                default_currency: "EUR".to_string(),
                fiscal_year_start_month: 1,
                is_default: true,
            };
            let id = chart::create_legal_entity(conn, &input).await?;
            chart::ensure_standard_chart(conn, id).await?;
            tracing::info!(
                legal_entity_id = %id,
                "accounting: auto-provisioned the default legal entity and standard chart"
            );
            Ok(id)
        }
        Err(other) => Err(other),
    }
}

/// Ensure an open fiscal period covers `date`, creating the covering calendar
/// month when nothing does. A closed/locked period covering the date fails
/// closed (`NoOpenPeriod`) — see the module docs.
pub async fn ensure_open_period_in(
    conn: &mut PgConnection,
    legal_entity_id: Uuid,
    date: NaiveDate,
) -> Result<Uuid> {
    if let Ok(open) = crate::periods::find_open_period_for_date(conn, legal_entity_id, date).await {
        return Ok(open);
    }

    // A period of ANY status covering the date means provisioning already
    // happened for this month and the books were deliberately closed over it.
    let covering: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM fiscal_periods \
         WHERE legal_entity_id = $1 AND start_date <= $2 AND end_date >= $2 \
         ORDER BY start_date DESC LIMIT 1",
    )
    .bind(legal_entity_id)
    .bind(date)
    .fetch_optional(&mut *conn)
    .await?;
    if covering.is_some() {
        return Err(AccountingError::NoOpenPeriod {
            legal_entity_id,
            date,
        });
    }

    let (start, end) = month_bounds(date)?;
    crate::periods::ensure_period(
        conn,
        legal_entity_id,
        "month",
        &month_label(start),
        start,
        end,
    )
    .await?;
    tracing::info!(
        legal_entity_id = %legal_entity_id,
        period_start = %start,
        period_end = %end,
        "accounting: auto-provisioned the open fiscal period covering a posting date"
    );
    crate::periods::find_open_period_for_date(conn, legal_entity_id, date).await
}

/// Ensure both preconditions the posting adapters need: the default legal
/// entity (+ chart) and an open fiscal period covering `document_date`.
/// Returns `(legal_entity_id, fiscal_period_id)`.
pub async fn ensure_ledger_ready_in(
    conn: &mut PgConnection,
    document_date: NaiveDate,
) -> Result<(Uuid, Uuid)> {
    let legal_entity_id = ensure_default_entity_in(conn).await?;
    let fiscal_period_id = ensure_open_period_in(conn, legal_entity_id, document_date).await?;
    Ok((legal_entity_id, fiscal_period_id))
}

/// Calendar-month bounds containing `date` (pure — the provisioning date math
/// is pinned by unit tests, incl. year boundaries and leap years).
pub fn month_bounds(date: NaiveDate) -> Result<(NaiveDate, NaiveDate)> {
    let start = NaiveDate::from_ymd_opt(date.year(), date.month(), 1).ok_or_else(|| {
        AccountingError::Invalid(format!("date {date} has no representable month start"))
    })?;
    let end = start
        .checked_add_months(Months::new(1))
        .and_then(|next_month| next_month.pred_opt())
        .ok_or_else(|| {
            AccountingError::Invalid(format!("date {date} has no representable month end"))
        })?;
    Ok((start, end))
}

/// The fiscal-period label for a month start: `2026-09` (pure).
pub fn month_label(month_start: NaiveDate) -> String {
    format!("{:04}-{:02}", month_start.year(), month_start.month())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_bounds_cover_the_whole_calendar_month() {
        let (start, end) =
            month_bounds(NaiveDate::from_ymd_opt(2026, 9, 30).expect("date")).expect("bounds");
        assert_eq!(
            (start, end),
            (
                NaiveDate::from_ymd_opt(2026, 9, 1).expect("date"),
                NaiveDate::from_ymd_opt(2026, 9, 30).expect("date")
            )
        );

        // Year boundary: December wraps into January of the next year.
        let (start, end) =
            month_bounds(NaiveDate::from_ymd_opt(2026, 12, 15).expect("date")).expect("bounds");
        assert_eq!(
            (start, end),
            (
                NaiveDate::from_ymd_opt(2026, 12, 1).expect("date"),
                NaiveDate::from_ymd_opt(2026, 12, 31).expect("date")
            )
        );

        // Leap year: February has 29 days.
        let (_, end) =
            month_bounds(NaiveDate::from_ymd_opt(2028, 2, 3).expect("date")).expect("bounds");
        assert_eq!(end, NaiveDate::from_ymd_opt(2028, 2, 29).expect("date"));
        // Non-leap year: February has 28 days.
        let (_, end) =
            month_bounds(NaiveDate::from_ymd_opt(2026, 2, 3).expect("date")).expect("bounds");
        assert_eq!(end, NaiveDate::from_ymd_opt(2026, 2, 28).expect("date"));
    }

    #[test]
    fn month_labels_are_zero_padded_and_sorted() {
        assert_eq!(
            month_label(NaiveDate::from_ymd_opt(2026, 9, 1).expect("date")),
            "2026-09"
        );
        assert_eq!(
            month_label(NaiveDate::from_ymd_opt(2026, 12, 1).expect("date")),
            "2026-12"
        );
        assert!(
            month_label(NaiveDate::from_ymd_opt(2026, 9, 1).expect("date"))
                < month_label(NaiveDate::from_ymd_opt(2026, 10, 1).expect("date")),
            "labels sort lexicographically like the months they name"
        );
    }

    /// The auto-provisioned entity input is anchored on the stable registry
    /// code — that anchor is what makes concurrent first postings idempotent.
    #[test]
    fn auto_provisioning_is_anchored_on_a_stable_registry_code() {
        assert_eq!(AUTO_PROVISIONED_REGISTRY_CODE, "APEXMAIL-DEFAULT");
        // The seeded standard chart defines every role the adapters resolve;
        // a fresh entity must therefore never fail with MissingAccountRole.
        for role in crate::types::ACCOUNT_ROLES {
            assert!(
                crate::chart::STANDARD_CHART
                    .iter()
                    .any(|spec| spec.role == Some(*role)),
                "role {role} has no standard-chart account; a fresh auto-provisioned entity could not post"
            );
        }
    }
}
