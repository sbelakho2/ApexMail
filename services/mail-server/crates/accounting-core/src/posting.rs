//! Journal posting, idempotency, reversal.
//!
//! * [`post_journal_entry`] validates the balance before writing (typed
//!   error), inserts the source document (idempotency anchor), inserts the
//!   entry as a draft, inserts the lines and only then stamps `posted_at` —
//!   so the deferred constraint trigger sees complete lines at commit.
//! * Replaying the same idempotency key / source document returns
//!   [`PostStatus::AlreadyPosted`] with the original entry id; a divergent
//!   payload is refused.
//! * [`reverse_entry`] creates a mirror entry (debit/credit swapped) that
//!   references the original. Posted entries are never updated or deleted —
//!   the database refuses it (`trg_journal_entries_guard` /
//!   `trg_journal_lines_guard`), and this module never issues such a
//!   statement.

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::error::{AccountingError, Result};
use crate::hash::entry_content_hash;
use crate::types::*;

/// Result of the pure balance check: `(sum(debit), sum(credit))`.
pub fn validate_lines(lines: &[JournalLine]) -> Result<(i64, i64)> {
    if lines.is_empty() {
        return Err(AccountingError::NoLines);
    }

    let mut debit: i128 = 0;
    let mut credit: i128 = 0;

    for line in lines {
        if line.debit_cents < 0
            || line.credit_cents < 0
            || (line.debit_cents > 0) == (line.credit_cents > 0)
        {
            return Err(AccountingError::InvalidLine {
                debit_cents: line.debit_cents,
                credit_cents: line.credit_cents,
            });
        }
        debit += i128::from(line.debit_cents);
        credit += i128::from(line.credit_cents);
    }

    if debit != credit {
        let clamp = |value: i128| -> i64 {
            i64::try_from(value).unwrap_or(if value.is_negative() {
                i64::MIN
            } else {
                i64::MAX
            })
        };
        return Err(AccountingError::Unbalanced {
            debit_cents: clamp(debit),
            credit_cents: clamp(credit),
        });
    }

    // Balance equal ⇒ both sums fit i64 whenever the inputs were i64 sums of
    // non-negative values; still convert without unwrap.
    let debit_i64 = i64::try_from(debit).unwrap_or(i64::MAX);
    Ok((debit_i64, debit_i64))
}

/// Compute the evidence hash of an entry with no external source document.
pub fn manual_entry_hash(req: &PostJournalRequest) -> String {
    let lines: Vec<(String, i64, i64)> = req
        .lines
        .iter()
        .map(|line| {
            (
                line.account_id.to_string(),
                line.debit_cents,
                line.credit_cents,
            )
        })
        .collect();
    entry_content_hash(
        &req.legal_entity_id.to_string(),
        &req.entry_date.to_string(),
        req.entry_type.as_str(),
        &req.memo,
        &lines,
    )
}

/// Post a journal entry in its own transaction.
pub async fn post_journal_entry(pool: &PgPool, req: &PostJournalRequest) -> Result<PostOutcome> {
    let mut tx = pool.begin().await?;
    let outcome = post_journal_entry_in(&mut tx, req).await?;
    tx.commit().await?;
    Ok(outcome)
}

/// Post a journal entry on a caller-owned connection/transaction.
///
/// The deferred balance trigger is evaluated at the CALLER's commit when a
/// transaction is used, so an unbalanced entry inserted here aborts the
/// whole caller transaction.
pub async fn post_journal_entry_in(
    conn: &mut PgConnection,
    req: &PostJournalRequest,
) -> Result<PostOutcome> {
    validate_lines(&req.lines)?;

    if req.entry_type == EntryType::Reversal && req.reversal_of_entry_id.is_none() {
        return Err(AccountingError::Invalid(
            "a reversal entry must reference the entry it reverses".to_string(),
        ));
    }

    let evidence_hash = match &req.source {
        Some(source) => source.source_hash.clone(),
        None => manual_entry_hash(req),
    };

    let source_document_id = match &req.source {
        Some(source) => Some(register_source_document(conn, req.legal_entity_id, source).await?),
        None => None,
    };

    let inserted: Option<(Uuid, String)> = sqlx::query_as(
        r#"
        INSERT INTO journal_entries (
            legal_entity_id, fiscal_period_id, entry_date, entry_type, memo,
            source_document_id, source_hash, idempotency_key, reversal_of_entry_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (idempotency_key) DO NOTHING
        RETURNING id, source_hash
        "#,
    )
    .bind(req.legal_entity_id)
    .bind(req.fiscal_period_id)
    .bind(req.entry_date)
    .bind(req.entry_type.as_str())
    .bind(&req.memo)
    .bind(source_document_id)
    .bind(&evidence_hash)
    .bind(&req.idempotency_key)
    .bind(req.reversal_of_entry_id)
    .fetch_optional(&mut *conn)
    .await?;

    let entry_id = match inserted {
        Some((id, _)) => id,
        None => {
            // Replay: resolve the existing entry and verify the evidence.
            let existing: Option<(Uuid, String, Option<DateTime<Utc>>)> = sqlx::query_as(
                "SELECT id, source_hash, posted_at FROM journal_entries \
                 WHERE idempotency_key = $1",
            )
            .bind(&req.idempotency_key)
            .fetch_optional(&mut *conn)
            .await?;

            let Some((id, stored_hash, posted_at)) = existing else {
                return Err(AccountingError::Invalid(
                    "journal entry disappeared after insert conflict".to_string(),
                ));
            };

            if stored_hash != evidence_hash {
                return Err(AccountingError::IdempotencyKeyConflict(
                    req.idempotency_key.clone(),
                ));
            }

            if posted_at.is_some() {
                return Ok(PostOutcome::already_posted(id));
            }
            // A draft with this key exists (e.g. a manual draft); posting it
            // again through the adapter would silently attach new lines.
            return Err(AccountingError::IdempotencyKeyConflict(
                req.idempotency_key.clone(),
            ));
        }
    };

    for (index, line) in req.lines.iter().enumerate() {
        sqlx::query(
            r#"
            INSERT INTO journal_lines (
                entry_id, line_no, account_id, debit_cents, credit_cents,
                currency, net_cents, vat_cents, vat_rate_bp, vat_code, description
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(entry_id)
        .bind(index as i32 + 1)
        .bind(line.account_id)
        .bind(line.debit_cents)
        .bind(line.credit_cents)
        .bind(&line.currency)
        .bind(line.net_cents)
        .bind(line.vat_cents)
        .bind(line.vat_rate_bp)
        .bind(line.vat_code.as_deref())
        .bind(&line.description)
        .execute(&mut *conn)
        .await?;
    }

    let posted = sqlx::query(
        "UPDATE journal_entries SET posted_at = NOW(), posted_by = $2 \
         WHERE id = $1 AND posted_at IS NULL",
    )
    .bind(entry_id)
    .bind(&req.posted_by)
    .execute(&mut *conn)
    .await?;

    if posted.rows_affected() != 1 {
        return Err(AccountingError::Invalid(format!(
            "journal entry {entry_id} could not be transitioned to posted"
        )));
    }

    Ok(PostOutcome::posted(entry_id))
}

/// Register (or resolve) the source document for a posting. Replays with
/// the same identity and hash resolve to the existing row; a divergent hash
/// is refused.
pub async fn register_source_document(
    conn: &mut PgConnection,
    legal_entity_id: Uuid,
    source: &SourceIdentity,
) -> Result<Uuid> {
    let inserted: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO accounting_source_documents (
            legal_entity_id, source_type, source_table, source_id,
            source_hash, document_date, currency, total_cents, payload,
            retention_class
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (source_type, source_table, source_id) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(legal_entity_id)
    .bind(&source.source_type)
    .bind(&source.source_table)
    .bind(&source.source_id)
    .bind(&source.source_hash)
    .bind(source.document_date)
    .bind(&source.currency)
    .bind(source.total_cents)
    .bind(&source.payload)
    .bind(&source.retention_class)
    .fetch_optional(&mut *conn)
    .await?;

    if let Some(id) = inserted {
        return Ok(id);
    }

    let existing: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, source_hash FROM accounting_source_documents \
         WHERE source_type = $1 AND source_table = $2 AND source_id = $3",
    )
    .bind(&source.source_type)
    .bind(&source.source_table)
    .bind(&source.source_id)
    .fetch_optional(&mut *conn)
    .await?;

    match existing {
        Some((id, hash)) if hash == source.source_hash => Ok(id),
        Some(_) => Err(AccountingError::SourceHashMismatch {
            source_type: source.source_type.clone(),
            source_table: source.source_table.clone(),
            source_id: source.source_id.clone(),
        }),
        None => Err(AccountingError::Invalid(
            "source document disappeared after insert conflict".to_string(),
        )),
    }
}

/// Parameters for [`reverse_entry`].
#[derive(Debug, Clone)]
pub struct ReversalRequest {
    /// The posted entry to reverse.
    pub entry_id: Uuid,
    /// Date for the reversal entry; must lie in an OPEN period (reversing a
    /// closed-period entry posts the correction in the current period, which
    /// is the legally correct treatment).
    pub entry_date: NaiveDate,
    pub memo: String,
    pub posted_by: String,
}

/// Reverse a posted entry with a mirror entry. Idempotent: the reversal
/// source document is unique on `(reversal, journal_entries, entry_id)`, so
/// a second call returns `AlreadyPosted`.
pub async fn reverse_entry(pool: &PgPool, req: &ReversalRequest) -> Result<PostOutcome> {
    let mut tx = pool.begin().await?;
    let outcome = reverse_entry_in(&mut tx, req).await?;
    tx.commit().await?;
    Ok(outcome)
}

/// Reversal on a caller-owned connection/transaction.
pub async fn reverse_entry_in(
    conn: &mut PgConnection,
    req: &ReversalRequest,
) -> Result<PostOutcome> {
    let original: Option<(Uuid, String, String, Option<DateTime<Utc>>, i64)> = sqlx::query_as(
        "SELECT legal_entity_id, entry_type::text, source_hash, posted_at, entry_no \
         FROM journal_entries WHERE id = $1",
    )
    .bind(req.entry_id)
    .fetch_optional(&mut *conn)
    .await?;

    let Some((legal_entity_id, _original_type, original_hash, posted_at, entry_no)) = original
    else {
        return Err(AccountingError::Invalid(format!(
            "journal entry {} not found",
            req.entry_id
        )));
    };

    if posted_at.is_none() {
        return Err(AccountingError::Invalid(format!(
            "journal entry {} is not posted; delete the draft instead of reversing it",
            req.entry_id
        )));
    }

    let original_lines: Vec<(
        Uuid,
        i64,
        i64,
        String,
        Option<i64>,
        Option<i64>,
        Option<i32>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT account_id, debit_cents, credit_cents, currency, net_cents, \
                    vat_cents, vat_rate_bp, vat_code, description \
             FROM journal_lines WHERE entry_id = $1 ORDER BY line_no",
    )
    .bind(req.entry_id)
    .fetch_all(&mut *conn)
    .await?;

    if original_lines.is_empty() {
        return Err(AccountingError::NoLines);
    }

    let currency = original_lines
        .first()
        .map(|line| line.3.clone())
        .unwrap_or_else(|| "EUR".to_string());

    let fiscal_period_id =
        crate::periods::find_open_period_for_date(conn, legal_entity_id, req.entry_date).await?;

    // The evidence identity of a reversal is the ENTRY it reverses, not the
    // operator-supplied memo: a retry with a different note must still be
    // the same idempotent reversal, not a second pair.
    let payload = serde_json::json!({
        "reverses_entry_id": req.entry_id,
        "reverses_entry_no": entry_no,
        "reverses_source_hash": original_hash,
    });

    let source = SourceIdentity::new(
        "reversal",
        "journal_entries",
        &req.entry_id.to_string(),
        req.entry_date,
        &currency,
        0,
        payload,
    );

    let lines: Vec<JournalLine> = original_lines
        .into_iter()
        .map(
            |(account_id, debit, credit, currency, net, vat, rate, code, description)| {
                let mut line = if credit > 0 {
                    JournalLine::debit(account_id, credit, &currency)
                } else {
                    JournalLine::credit(account_id, debit, &currency)
                };
                line.net_cents = net;
                line.vat_cents = vat;
                line.vat_rate_bp = rate;
                line.vat_code = code;
                line.description = description;
                line
            },
        )
        .collect();

    let memo = if req.memo.trim().is_empty() {
        format!("Reversal of journal entry #{entry_no}")
    } else {
        req.memo.clone()
    };

    let request = PostJournalRequest {
        legal_entity_id,
        fiscal_period_id,
        entry_date: req.entry_date,
        entry_type: EntryType::Reversal,
        memo,
        posted_by: req.posted_by.clone(),
        idempotency_key: format!("reversal:{}", req.entry_id),
        source: Some(source),
        reversal_of_entry_id: Some(req.entry_id),
        lines,
    };

    post_journal_entry_in(conn, &request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Uuid {
        Uuid::from_u128(1)
    }

    #[test]
    fn balanced_lines_pass() {
        let lines = vec![
            JournalLine::debit(account(), 100, "EUR"),
            JournalLine::credit(account(), 100, "EUR"),
        ];
        let (debit, credit) = validate_lines(&lines).expect("balanced");
        assert_eq!((debit, credit), (100, 100));
    }

    #[test]
    fn unbalanced_lines_are_refused_before_any_write() {
        let lines = vec![
            JournalLine::debit(account(), 100, "EUR"),
            JournalLine::credit(account(), 99, "EUR"),
        ];
        match validate_lines(&lines) {
            Err(AccountingError::Unbalanced {
                debit_cents,
                credit_cents,
            }) => {
                assert_eq!((debit_cents, credit_cents), (100, 99));
            }
            other => panic!("expected Unbalanced, got {other:?}"),
        }
    }

    #[test]
    fn zero_and_two_sided_lines_are_refused() {
        let zero = vec![JournalLine::debit(account(), 0, "EUR")];
        assert!(matches!(
            validate_lines(&zero),
            Err(AccountingError::InvalidLine { .. })
        ));

        let mut both = JournalLine::debit(account(), 5, "EUR");
        both.credit_cents = 5;
        assert!(matches!(
            validate_lines(&[both]),
            Err(AccountingError::InvalidLine { .. })
        ));
    }

    #[test]
    fn empty_lines_are_refused() {
        assert!(matches!(validate_lines(&[]), Err(AccountingError::NoLines)));
    }

    #[test]
    fn integration_sql_never_updates_a_posted_entry() {
        // Guard against future edits: this module must not contain an
        // UPDATE/DELETE of posted entries outside the posting transition.
        let source = include_str!("posting.rs");
        // Scan only production code (this test module itself contains the
        // query snippets it searches for).
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let needle = format!("UPDATE {} SET", "journal_entries");
        let mutations = production.matches(&needle).collect::<Vec<_>>();
        assert_eq!(
            mutations.len(),
            1,
            "posting.rs must contain exactly one journal_entries UPDATE (the posting transition)"
        );
        assert!(production.contains("SET posted_at = NOW(), posted_by = $2"));
        assert!(!production.contains(&format!("UPDATE {}", "journal_lines")));
        assert!(!production.contains(&format!("DELETE FROM {}", "journal_entries")));
    }
}
