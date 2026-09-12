//! Legally-restricted retention archive — the holding state between an
//! erasure and a statutory expiry.
//!
//! A customer may exercise GDPR rights while invoices / accounting / tax
//! evidence has an independent legal-retention obligation (Estonia: seven
//! years, [`crate::retention_classes::STATUTORY_ACCOUNTING_CLASS_ID`]).
//! Deleting those records to satisfy an ordinary account erasure would
//! destroy evidence the controller is legally required to keep; keeping them
//! in the product-active store without a recorded reason would violate
//! storage limitation. The archive is the explicit middle state:
//!
//! ```text
//! product-active → legally-restricted archive → statutory expiry → deletion
//! ```
//!
//! Properties:
//!
//! * **Explicit** — every retained record is a row naming the source table,
//!   the record, the retention class, the reason and the exact expiry date.
//! * **Disclosed** — [`disclosure_for_subject`] returns the what/why/until
//!   when that the DSAR result must carry.
//! * **Monotonic** — [`transition_allowed`] is the pure rule; the database
//!   trigger `trg_legal_retention_archive_guard` (migration 213) enforces the
//!   same rule for direct SQL, so no path can move a record backwards or out
//!   of `deleted`.
//! * **Expiring** — [`advance_due_archives`] performs
//!   `statutory_expired → deleted` and removes the source record only for
//!   tables the platform owns and only after the statutory expiry has passed.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

/// Source tables the archive is allowed to purge after statutory expiry.
///
/// The archive never deletes from a table that merely appears in its rows:
/// only known, owned records can reach deletion. Anything else stays in
/// `statutory_expired` and is reported (an honest stuck state beats a wrong
/// delete).
pub const PURGEABLE_SOURCE_TABLES: &[&str] = &["invoices"];

/// The three archive states, in order.
pub const STATE_LEGALLY_RESTRICTED: &str = "legally_restricted";
pub const STATE_STATUTORY_EXPIRED: &str = "statutory_expired";
pub const STATE_DELETED: &str = "deleted";

/// Monotonic rank of an archive state; `None` for an unknown value.
pub fn state_rank(state: &str) -> Option<u8> {
    match state {
        STATE_LEGALLY_RESTRICTED => Some(0),
        STATE_STATUTORY_EXPIRED => Some(1),
        STATE_DELETED => Some(2),
        _ => None,
    }
}

/// The pure transition rule: exactly one step forward, never backwards.
pub fn transition_allowed(from: &str, to: &str) -> bool {
    match (state_rank(from), state_rank(to)) {
        (Some(f), Some(t)) => t == f + 1,
        _ => false,
    }
}

/// One archived record.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ArchivedRecord {
    pub id: String,
    pub tenant_id: String,
    pub subject_email_hash: String,
    pub source_table: String,
    pub source_record_id: String,
    pub retention_class_id: String,
    pub reason: String,
    pub state: String,
    pub archived_at: DateTime<Utc>,
    pub statutory_expiry_at: DateTime<Utc>,
    pub statutory_expired_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub disclosure: serde_json::Value,
}

/// Input for archiving one retained record.
#[derive(Debug, Clone)]
pub struct ArchiveRecordInput {
    pub tenant_id: String,
    pub subject_email_hash: String,
    pub source_table: String,
    pub source_record_id: String,
    pub retention_class_id: String,
    pub reason: String,
    pub statutory_expiry_at: DateTime<Utc>,
    pub disclosure: serde_json::Value,
}

/// sha256 of a subject email — the archive never stores a second plaintext
/// copy of the erased address.
pub fn subject_email_hash(email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.as_bytes());
    hex::encode(hasher.finalize())
}

const ARCHIVE_COLUMNS: &str = "id, tenant_id, subject_email_hash, source_table, source_record_id, \
     retention_class_id, reason, state, archived_at, statutory_expiry_at, \
     statutory_expired_at, deleted_at, disclosure";

/// Archive one record in the `legally_restricted` state. Idempotent per
/// (source_table, source_record_id): a second erasure of the same record does
/// not reset its clock or move it backwards.
pub async fn archive_record(
    db: &PgPool,
    input: &ArchiveRecordInput,
) -> Result<ArchivedRecord, String> {
    if input.reason.trim().is_empty() {
        return Err("archive reason must not be empty".into());
    }
    if !PURGEABLE_SOURCE_TABLES.contains(&input.source_table.as_str()) {
        return Err(format!(
            "source table {} is not an owned archive source",
            input.source_table
        ));
    }
    sqlx::query(
        "INSERT INTO legal_retention_archive
           (id, tenant_id, subject_email_hash, source_table, source_record_id,
            retention_class_id, reason, state, archived_at, statutory_expiry_at,
            disclosure, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'legally_restricted',NOW(),$8,$9,NOW(),NOW())
         ON CONFLICT (source_table, source_record_id) DO NOTHING",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&input.tenant_id)
    .bind(&input.subject_email_hash)
    .bind(&input.source_table)
    .bind(&input.source_record_id)
    .bind(&input.retention_class_id)
    .bind(&input.reason)
    .bind(input.statutory_expiry_at)
    .bind(&input.disclosure)
    .execute(db)
    .await
    .map_err(|e| {
        format!(
            "DB error archiving {}/{}: {e}",
            input.source_table, input.source_record_id
        )
    })?;

    record_for(db, &input.source_table, &input.source_record_id)
        .await?
        .ok_or_else(|| "archive row missing after insert".to_string())
}

/// Fetch the archive row for a source record.
pub async fn record_for(
    db: &PgPool,
    source_table: &str,
    source_record_id: &str,
) -> Result<Option<ArchivedRecord>, String> {
    sqlx::query_as(&format!(
        "SELECT {ARCHIVE_COLUMNS} FROM legal_retention_archive
         WHERE source_table = $1 AND source_record_id = $2"
    ))
    .bind(source_table)
    .bind(source_record_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("DB error reading archive row: {e}"))
}

/// Fetch one archive row by id.
pub async fn get(db: &PgPool, id: &str) -> Result<Option<ArchivedRecord>, String> {
    sqlx::query_as(&format!(
        "SELECT {ARCHIVE_COLUMNS} FROM legal_retention_archive WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("DB error reading archive row {id}: {e}"))
}

/// Advance one archive row by exactly one monotonic step. The database
/// trigger rejects illegal transitions even if this guard were bypassed.
pub async fn advance_state(db: &PgPool, id: &str, to: &str) -> Result<ArchivedRecord, String> {
    let current = get(db, id)
        .await?
        .ok_or_else(|| format!("archive row {id} not found"))?;
    if !transition_allowed(&current.state, to) {
        return Err(format!(
            "illegal archive transition {} -> {to} (order is \
             legally_restricted -> statutory_expired -> deleted)",
            current.state
        ));
    }

    let now = Utc::now();
    sqlx::query(
        "UPDATE legal_retention_archive
            SET state = $2,
                statutory_expired_at = CASE WHEN $2 = 'statutory_expired'
                                            THEN COALESCE(statutory_expired_at, $3)
                                            ELSE statutory_expired_at END,
                deleted_at = CASE WHEN $2 = 'deleted' THEN COALESCE(deleted_at, $3)
                                  ELSE deleted_at END,
                updated_at = $3
          WHERE id = $1",
    )
    .bind(id)
    .bind(to)
    .bind(now)
    .execute(db)
    .await
    .map_err(|e| format!("DB error advancing archive row {id}: {e}"))?;

    get(db, id)
        .await?
        .ok_or_else(|| format!("archive row {id} missing after update"))
}

/// Outcome of one archive sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ArchiveSweepOutcome {
    /// Rows moved `legally_restricted → statutory_expired`.
    pub expired: u64,
    /// Rows moved `statutory_expired → deleted`.
    pub deleted: u64,
    /// Source records actually removed (invoices past their statutory expiry).
    pub source_records_deleted: u64,
    /// Rows past expiry whose source table is not owned/purgeable — left in
    /// `statutory_expired` and reported.
    pub stuck_unpurgeable: u64,
}

/// Advance every due archive row one step, deleting source records only after
/// statutory expiry and only for [`PURGEABLE_SOURCE_TABLES`].
pub async fn advance_due_archives(
    db: &PgPool,
    now: DateTime<Utc>,
) -> Result<ArchiveSweepOutcome, String> {
    let mut outcome = ArchiveSweepOutcome::default();

    let due: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM legal_retention_archive
          WHERE state = 'legally_restricted' AND statutory_expiry_at <= $1
          ORDER BY statutory_expiry_at
          LIMIT 5000",
    )
    .bind(now)
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error listing due archive rows: {e}"))?;

    for id in &due {
        match advance_state(db, id, STATE_STATUTORY_EXPIRED).await {
            Ok(_) => outcome.expired += 1,
            Err(e) => warn!(archive_id = %id, error = %e, "archive expiry transition failed"),
        }
    }

    let expired: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, source_table, source_record_id
           FROM legal_retention_archive
          WHERE state = 'statutory_expired'
          ORDER BY statutory_expiry_at
          LIMIT 5000",
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error listing expired archive rows: {e}"))?;

    for (id, source_table, source_record_id) in &expired {
        if !PURGEABLE_SOURCE_TABLES.contains(&source_table.as_str()) {
            outcome.stuck_unpurgeable += 1;
            continue;
        }
        // Remove the source record first; only then certify deletion.
        let table = source_table.as_str();
        let deleted = sqlx::query(&format!("DELETE FROM {table} WHERE id::text = $1"))
            .bind(source_record_id)
            .execute(db)
            .await
            .map_err(|e| format!("DB error purging {table}/{source_record_id}: {e}"))?
            .rows_affected();
        match advance_state(db, id, STATE_DELETED).await {
            Ok(_) => {
                outcome.deleted += 1;
                outcome.source_records_deleted += deleted;
            }
            Err(e) => warn!(archive_id = %id, error = %e, "archive deletion transition failed"),
        }
    }

    Ok(outcome)
}

/// The exact disclosure the DSAR result must carry for a subject: what was
/// retained, why, and until when.
pub async fn disclosure_for_subject(
    db: &PgPool,
    tenant_id: &str,
    email: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let hash = subject_email_hash(email);
    let rows: Vec<ArchivedRecord> = sqlx::query_as(&format!(
        "SELECT {ARCHIVE_COLUMNS} FROM legal_retention_archive
          WHERE tenant_id = $1 AND subject_email_hash = $2
            AND state <> 'deleted'
          ORDER BY statutory_expiry_at"
    ))
    .bind(tenant_id)
    .bind(&hash)
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error reading retention disclosure: {e}"))?;

    Ok(rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "source_table": row.source_table,
                "record_id": row.source_record_id,
                "retention_class_id": row.retention_class_id,
                "reason": row.reason,
                "state": row.state,
                "retained_since": row.archived_at.to_rfc3339(),
                "retain_until": row.statutory_expiry_at.to_rfc3339(),
                "detail": row.disclosure,
            })
        })
        .collect())
}

/// Count of rows still in the archive for a subject (not yet deleted).
pub async fn retained_for_subject(
    db: &PgPool,
    tenant_id: &str,
    email: &str,
) -> Result<i64, String> {
    let hash = subject_email_hash(email);
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM legal_retention_archive
          WHERE tenant_id = $1 AND subject_email_hash = $2 AND state <> 'deleted'",
    )
    .bind(tenant_id)
    .bind(&hash)
    .fetch_one(db)
    .await
    .map_err(|e| format!("DB error counting archived records: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_are_one_step_forward_only() {
        assert!(transition_allowed(
            STATE_LEGALLY_RESTRICTED,
            STATE_STATUTORY_EXPIRED
        ));
        assert!(transition_allowed(STATE_STATUTORY_EXPIRED, STATE_DELETED));
        // Never backwards.
        assert!(!transition_allowed(
            STATE_STATUTORY_EXPIRED,
            STATE_LEGALLY_RESTRICTED
        ));
        assert!(!transition_allowed(STATE_DELETED, STATE_STATUTORY_EXPIRED));
        assert!(!transition_allowed(STATE_DELETED, STATE_LEGALLY_RESTRICTED));
        // Never skipping.
        assert!(!transition_allowed(STATE_LEGALLY_RESTRICTED, STATE_DELETED));
        // Unknown states are rejected, not ranked.
        assert!(!transition_allowed("product-active", STATE_DELETED));
        assert!(!transition_allowed(STATE_LEGALLY_RESTRICTED, "nonsense"));
    }

    #[test]
    fn only_owned_source_tables_are_purgeable() {
        assert!(PURGEABLE_SOURCE_TABLES.contains(&"invoices"));
        assert!(
            !PURGEABLE_SOURCE_TABLES.contains(&"users"),
            "the archive must not be able to purge arbitrary tables"
        );
    }

    #[test]
    fn subject_hash_is_stable_and_one_way() {
        let hash = subject_email_hash("subject@example.com");
        assert_eq!(hash, subject_email_hash("subject@example.com"));
        assert_ne!(hash, subject_email_hash("other@example.com"));
        assert_eq!(hash.len(), 64);
        assert!(!hash.contains("subject"));
    }
}
