//! Fiscal periods: creation, open-period resolution, close and lock.
//!
//! The state machine is open → closed → locked. The database trigger
//! `trg_fiscal_periods_guard` forbids going back, and the journal-entry
//! guard refuses to post into a non-open period; `close_period` /
//! `lock_period` record a `period_close_runs` audit row in the same
//! transaction as the status change.

use chrono::NaiveDate;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::error::{AccountingError, Result};

/// Result of a close/lock run (also persisted in `period_close_runs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodCloseReport {
    pub period_id: Uuid,
    pub status: String,
    pub run_id: Uuid,
    pub posted_entries: i64,
    pub debit_cents: i64,
    pub credit_cents: i64,
}

/// Create a fiscal period if it does not exist; returns its id. Existing
/// periods (including closed/locked) are returned unchanged.
pub async fn ensure_period(
    conn: &mut PgConnection,
    legal_entity_id: Uuid,
    period_type: &str,
    label: &str,
    start_date: NaiveDate,
    end_date: NaiveDate,
) -> Result<Uuid> {
    if !matches!(period_type, "month" | "quarter" | "year" | "custom") {
        return Err(AccountingError::Invalid(format!(
            "unknown period type '{period_type}'"
        )));
    }
    if end_date < start_date {
        return Err(AccountingError::Invalid(
            "fiscal period end_date is before start_date".to_string(),
        ));
    }

    let inserted: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO fiscal_periods (legal_entity_id, period_type, label, start_date, end_date)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (legal_entity_id, start_date, end_date) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(legal_entity_id)
    .bind(period_type)
    .bind(label)
    .bind(start_date)
    .bind(end_date)
    .fetch_optional(&mut *conn)
    .await?;

    if let Some(id) = inserted {
        return Ok(id);
    }

    sqlx::query_scalar(
        "SELECT id FROM fiscal_periods \
         WHERE legal_entity_id = $1 AND start_date = $2 AND end_date = $3",
    )
    .bind(legal_entity_id)
    .bind(start_date)
    .bind(end_date)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| {
        AccountingError::Invalid(
            "fiscal period not found after insert conflict — concurrent delete?".to_string(),
        )
    })
}

/// The open period covering `date`, or a typed error.
pub async fn find_open_period_for_date(
    conn: &mut PgConnection,
    legal_entity_id: Uuid,
    date: NaiveDate,
) -> Result<Uuid> {
    sqlx::query_scalar(
        r#"
        SELECT id FROM fiscal_periods
        WHERE legal_entity_id = $1
          AND status = 'open'
          AND start_date <= $2
          AND end_date >= $2
        ORDER BY start_date DESC
        LIMIT 1
        "#,
    )
    .bind(legal_entity_id)
    .bind(date)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(AccountingError::NoOpenPeriod {
        legal_entity_id,
        date,
    })
}

/// Current status of a period.
pub async fn period_status(conn: &mut PgConnection, period_id: Uuid) -> Result<String> {
    sqlx::query_scalar("SELECT status FROM fiscal_periods WHERE id = $1")
        .bind(period_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| AccountingError::Invalid(format!("fiscal period {period_id} not found")))
}

/// Close an open period: refuses if any draft entry exists, records the
/// `period_close_runs` row and flips the period to `closed` atomically.
pub async fn close_period(
    pool: &PgPool,
    period_id: Uuid,
    actor: &str,
) -> Result<PeriodCloseReport> {
    let mut tx = pool.begin().await?;

    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM fiscal_periods WHERE id = $1 FOR UPDATE")
            .bind(period_id)
            .fetch_optional(&mut *tx)
            .await?;

    match status.as_deref() {
        None => {
            return Err(AccountingError::Invalid(format!(
                "fiscal period {period_id} not found"
            )))
        }
        Some("open") => {}
        Some(other) => {
            return Err(AccountingError::PeriodNotOpen {
                period_id,
                status: other.to_string(),
            })
        }
    }

    let draft_entries: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM journal_entries \
         WHERE fiscal_period_id = $1 AND posted_at IS NULL",
    )
    .bind(period_id)
    .fetch_one(&mut *tx)
    .await?;

    if draft_entries > 0 {
        return Err(AccountingError::Invalid(format!(
            "fiscal period {period_id} has {draft_entries} draft journal entries; \
             post or delete them before closing"
        )));
    }

    let (posted_entries, debit_cents, credit_cents): (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT e.id)::bigint,
               COALESCE(SUM(l.debit_cents), 0)::bigint,
               COALESCE(SUM(l.credit_cents), 0)::bigint
        FROM journal_entries e
        JOIN journal_lines l ON l.entry_id = e.id
        WHERE e.fiscal_period_id = $1
          AND e.posted_at IS NOT NULL
        "#,
    )
    .bind(period_id)
    .fetch_one(&mut *tx)
    .await?;

    if debit_cents != credit_cents {
        // Structurally impossible for posted entries (the deferred balance
        // trigger committed them balanced); fail closed if it is ever seen.
        return Err(AccountingError::Unbalanced {
            debit_cents,
            credit_cents,
        });
    }

    let checks = serde_json::json!({
        "posted_entries": posted_entries,
        "sum_debit_cents": debit_cents,
        "sum_credit_cents": credit_cents,
        "balanced": true,
    });

    let run_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO period_close_runs
            (fiscal_period_id, run_type, status, checks, completed_at, performed_by)
        VALUES ($1, 'close', 'completed', $2, NOW(), $3)
        RETURNING id
        "#,
    )
    .bind(period_id)
    .bind(&checks)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await?;

    let updated = sqlx::query(
        "UPDATE fiscal_periods \
         SET status = 'closed', closed_at = NOW(), closed_by = $2 \
         WHERE id = $1 AND status = 'open'",
    )
    .bind(period_id)
    .bind(actor)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() != 1 {
        return Err(AccountingError::Invalid(format!(
            "fiscal period {period_id} changed state during close — aborted"
        )));
    }

    tx.commit().await?;

    Ok(PeriodCloseReport {
        period_id,
        status: "closed".to_string(),
        run_id,
        posted_entries,
        debit_cents,
        credit_cents,
    })
}

/// Lock a closed period (final state; no posting, no reopening).
pub async fn lock_period(pool: &PgPool, period_id: Uuid, actor: &str) -> Result<PeriodCloseReport> {
    let mut tx = pool.begin().await?;

    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM fiscal_periods WHERE id = $1 FOR UPDATE")
            .bind(period_id)
            .fetch_optional(&mut *tx)
            .await?;

    match status.as_deref() {
        None => {
            return Err(AccountingError::Invalid(format!(
                "fiscal period {period_id} not found"
            )))
        }
        Some("closed") => {}
        Some(other) => {
            return Err(AccountingError::PeriodNotOpen {
                period_id,
                status: other.to_string(),
            })
        }
    }

    let (posted_entries, debit_cents, credit_cents): (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT e.id)::bigint,
               COALESCE(SUM(l.debit_cents), 0)::bigint,
               COALESCE(SUM(l.credit_cents), 0)::bigint
        FROM journal_entries e
        JOIN journal_lines l ON l.entry_id = e.id
        WHERE e.fiscal_period_id = $1
          AND e.posted_at IS NOT NULL
        "#,
    )
    .bind(period_id)
    .fetch_one(&mut *tx)
    .await?;

    let checks = serde_json::json!({
        "posted_entries": posted_entries,
        "sum_debit_cents": debit_cents,
        "sum_credit_cents": credit_cents,
        "balanced": debit_cents == credit_cents,
    });

    let run_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO period_close_runs
            (fiscal_period_id, run_type, status, checks, completed_at, performed_by)
        VALUES ($1, 'lock', 'completed', $2, NOW(), $3)
        RETURNING id
        "#,
    )
    .bind(period_id)
    .bind(&checks)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await?;

    let updated = sqlx::query(
        "UPDATE fiscal_periods \
         SET status = 'locked', locked_at = NOW(), closed_at = COALESCE(closed_at, NOW()), \
             locked_by = $2 \
         WHERE id = $1 AND status = 'closed'",
    )
    .bind(period_id)
    .bind(actor)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() != 1 {
        return Err(AccountingError::Invalid(format!(
            "fiscal period {period_id} changed state during lock — aborted"
        )));
    }

    tx.commit().await?;

    Ok(PeriodCloseReport {
        period_id,
        status: "locked".to_string(),
        run_id,
        posted_entries,
        debit_cents,
        credit_cents,
    })
}
