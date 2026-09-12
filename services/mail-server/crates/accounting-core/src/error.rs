//! Typed errors. The posting API validates before writing so callers get a
//! typed error instead of a raw SQLSTATE; the database triggers remain the
//! structural backstop (a direct-SQL writer sees the SQLSTATE/exception).

use chrono::NaiveDate;
use uuid::Uuid;

/// Accounting-domain error.
#[derive(Debug, thiserror::Error)]
pub enum AccountingError {
    #[error("journal entry is unbalanced: SUM(debit)={debit_cents} <> SUM(credit)={credit_cents}")]
    Unbalanced { debit_cents: i64, credit_cents: i64 },

    #[error("journal entry has no lines")]
    NoLines,

    #[error(
        "journal line must have a positive amount on exactly one side \
         (debit={debit_cents}, credit={credit_cents})"
    )]
    InvalidLine { debit_cents: i64, credit_cents: i64 },

    #[error("posted journal entry {0} is immutable; post a reversal or adjusting entry instead")]
    PostedEntryImmutable(Uuid),

    #[error("fiscal period {period_id} is not open (status: {status})")]
    PeriodNotOpen { period_id: Uuid, status: String },

    #[error("no open fiscal period for legal entity {legal_entity_id} covering {date}")]
    NoOpenPeriod {
        legal_entity_id: Uuid,
        date: NaiveDate,
    },

    #[error(
        "source document {source_type}/{source_table}/{source_id} already exists with a \
         different evidence hash — divergent replay refused"
    )]
    SourceHashMismatch {
        source_type: String,
        source_table: String,
        source_id: String,
    },

    #[error("idempotency key '{0}' was already used by a posting with different evidence")]
    IdempotencyKeyConflict(String),

    #[error("missing chart-of-accounts role '{role}' for legal entity {legal_entity_id}")]
    MissingAccountRole {
        legal_entity_id: Uuid,
        role: &'static str,
    },

    #[error("no default legal entity configured — run the accounting bootstrap first")]
    NoDefaultLegalEntity,

    #[error("source table '{0}' is absent in this deployment")]
    SourceTableMissing(String),

    #[error("source row {table}:{id} not found")]
    SourceRowMissing { table: &'static str, id: String },

    #[error("record {record} is in a statutory retention class and cannot be deleted")]
    RetentionProtected { record: String },

    #[error("invalid accounting input: {0}")]
    Invalid(String),

    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, AccountingError>;

/// True when the error is a database-enforced refusal (trigger), as opposed
/// to an application-level validation. Useful in tests and for callers that
/// want to distinguish "the DB refused" from "the request was invalid".
pub fn is_trigger_refusal(error: &AccountingError) -> bool {
    match error {
        AccountingError::Db(sqlx::Error::Database(db)) => matches!(
            db.code().as_deref(),
            // check_violation, object_not_in_prerequisite_state,
            // restrict_violation, foreign_key_violation
            Some("23514") | Some("55000") | Some("23001") | Some("23503")
        ),
        _ => false,
    }
}
