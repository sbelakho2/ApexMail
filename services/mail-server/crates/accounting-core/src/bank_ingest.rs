//! Bank statement ingestion — the canonical writer `bank_statement_lines`
//! never had.
//!
//! Migration 220 created [`crate::sweeps::sweep_unposted_bank_statement_lines`]'s
//! source table with no feed and no importer anywhere in the repository. This
//! module is the missing writer: it validates a statement and stores it as a
//! `bank_statement_imports` record plus its `bank_statement_lines`, in one
//! transaction, all-or-nothing.
//!
//! # Accepted format — CSV
//!
//! The product receives statements as CSV text (bank portals export CSV; a
//! future API feed can call the same function with the same format). The
//! header is matched case-insensitively after trimming; column order is free;
//! unknown columns are ignored.
//!
//! | column | required | meaning |
//! |---|---|---|
//! | `external_id` | yes | the bank's own unique id for the line (line identity, `UNIQUE (bank_account_id, external_id)`, migration 220) |
//! | `statement_date` | yes | booking date, ISO 8601 `YYYY-MM-DD`; must fall inside the declared statement period |
//! | `amount` | yes | **signed** decimal, `.` or `,` as decimal separator, at most two fraction digits (e.g. `-12.34`); positive = money in, negative = money out |
//! | `value_date` | no | ISO 8601 `YYYY-MM-DD` |
//! | `currency` | no | ISO code; when present it must equal the bank account's currency, otherwise the row is rejected; defaults to the account currency |
//! | `reference` | no | free text |
//! | `counterparty_name` | no | free text |
//! | `counterparty_account` | no | free text |
//! | `bank_account` | no | IBAN or UUID of the row's account; when present it must resolve to the same account the statement is for — an unknown or different account rejects the row |
//!
//! # Identity and idempotency (database-enforced, see migration 225)
//!
//! * Statement identity: `UNIQUE (bank_account_id, file_digest)` on
//!   `bank_statement_imports`, where `file_digest` is the sha256 hex of the
//!   exact bytes received, computed here and never supplied by the caller.
//!   Re-importing the same statement is an idempotent no-op: nothing is
//!   written and the existing import is returned with
//!   `already_imported = true`.
//! * Line identity: `UNIQUE (bank_account_id, external_id)` on
//!   `bank_statement_lines` (migration 220). A different file that repeats an
//!   `external_id` already stored for the account is rejected per row
//!   (nothing partially imported); the constraint remains the backstop.
//!
//! # Per-row errors, never a silent partial import
//!
//! Every validation failure is collected with its 1-based CSV line number
//! (the header is line 1) and returned as [`IngestError::Rejected`] (or
//! [`IngestError::Conflict`] for lines that already exist). If any row fails,
//! no import record and no line is written. Request-level problems (unknown
//! statement account, `period_start > period_end`, missing required header,
//! too many lines) are [`IngestError::Invalid`] /
//! [`IngestError::UnknownAccount`].

use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// Hard cap on lines per statement; the compliance HTTP route additionally
/// enforces its 1 MB body limit.
pub const MAX_IMPORT_LINES: usize = 10_000;

/// One statement to ingest. Borrowed so the HTTP handler can pass request
/// fields without cloning.
#[derive(Debug, Clone)]
pub struct BankStatementImport<'a> {
    /// The account the statement is for: a `bank_accounts.id` UUID or an IBAN.
    pub bank_account: &'a str,
    /// First day of the statement period (inclusive).
    pub period_start: NaiveDate,
    /// Last day of the statement period (inclusive).
    pub period_end: NaiveDate,
    /// Original file name, stored for the audit trail.
    pub filename: Option<&'a str>,
    /// The full CSV text (including its header row).
    pub csv: &'a str,
    /// Operator identity for the audit trail (the route uses the claimed
    /// `X-User-Id`, prefixed, or `compliance-api`).
    pub imported_by: &'a str,
}

/// What an ingest did. `already_imported` means this exact statement (same
/// bytes, same account) was stored before and nothing was written now.
#[derive(Debug, Clone, Serialize)]
pub struct ImportOutcome {
    pub import_id: Uuid,
    pub bank_account_id: Uuid,
    pub file_digest: String,
    pub line_count: i64,
    pub credit_total_cents: i64,
    pub debit_total_cents: i64,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub filename: Option<String>,
    pub already_imported: bool,
}

/// One rejected CSV row. `row` is the 1-based line number in the submitted
/// file (header = line 1); for a malformed quoted record it is the line where
/// the record starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RowError {
    pub row: u32,
    pub column: String,
    pub message: String,
}

/// Ingest failure. `Rejected` and `Conflict` carry per-row detail; nothing is
/// written for either.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("bank account {0:?} is not registered in bank_accounts")]
    UnknownAccount(String),

    #[error("invalid bank statement import: {0}")]
    Invalid(String),

    #[error("bank statement rejected: {} row error(s)", .errors.len())]
    Rejected { errors: Vec<RowError> },

    #[error("bank statement line(s) already exist for this account: {} conflict(s)", .errors.len())]
    Conflict { errors: Vec<RowError> },

    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(Debug, sqlx::FromRow)]
struct AccountRow {
    id: Uuid,
    currency: String,
}

#[derive(Debug, sqlx::FromRow)]
struct ImportRow {
    id: Uuid,
    period_start: NaiveDate,
    period_end: NaiveDate,
    line_count: i32,
    credit_total_cents: i64,
    debit_total_cents: i64,
    filename: Option<String>,
}

#[derive(Debug, Clone)]
struct ParsedLine {
    row: u32,
    external_id: String,
    statement_date: NaiveDate,
    value_date: Option<NaiveDate>,
    amount_cents: i64,
    currency: String,
    reference: Option<String>,
    counterparty_name: Option<String>,
    counterparty_account: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct HeaderIndex {
    external_id: usize,
    statement_date: usize,
    amount: usize,
    value_date: Option<usize>,
    currency: Option<usize>,
    reference: Option<usize>,
    counterparty_name: Option<usize>,
    counterparty_account: Option<usize>,
    bank_account: Option<usize>,
}

/// Known `bank_accounts` rows, preloaded once per ingest so the optional
/// per-row `bank_account` column resolves without a query per row.
#[derive(Debug, Default)]
struct KnownAccounts {
    ids: HashSet<Uuid>,
    /// Upper-cased IBAN → matching account ids. More than one id means the
    /// IBAN is ambiguous across legal entities (`UNIQUE (legal_entity_id,
    /// iban)` allows it) and rows naming it are rejected as ambiguous.
    ibans: HashMap<String, Vec<Uuid>>,
}

/// Parse a signed decimal amount into cents. Accepts `.` or `,` as the
/// decimal separator, an optional leading sign, and at most two fraction
/// digits. Thousands separators and currency symbols are rejected (a bank
/// CSV using them must be normalised first — guessing would silently
/// misinterpret amounts).
pub fn parse_amount_cents(raw: &str) -> Result<i64, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("amount is empty".to_string());
    }
    let (negative, rest) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(format!("amount {trimmed:?} has no digits"));
    }

    let mut parts = rest.split(['.', ',']);
    let whole = parts.next().unwrap_or("");
    let fraction = parts.next();
    if parts.next().is_some() {
        return Err(format!(
            "amount {trimmed:?} has more than one decimal separator"
        ));
    }
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("amount {trimmed:?} has a non-digit integer part"));
    }
    let fraction = fraction.unwrap_or("");
    if fraction.len() > 2 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "amount {trimmed:?} must have at most two decimal digits"
        ));
    }

    let whole: i128 = whole
        .parse()
        .map_err(|_| format!("amount {trimmed:?} is out of range"))?;
    let fraction_cents: i128 = match fraction.as_bytes() {
        [] => 0,
        [only] => i128::from(only - b'0') * 10,
        [tens, ones, ..] => i128::from(tens - b'0') * 10 + i128::from(ones - b'0'),
    };
    let magnitude = whole
        .checked_mul(100)
        .and_then(|value| value.checked_add(fraction_cents))
        .ok_or_else(|| format!("amount {trimmed:?} is out of range"))?;
    let signed = if negative { -magnitude } else { magnitude };
    i64::try_from(signed).map_err(|_| format!("amount {trimmed:?} is out of range"))
}

/// Parse the bank's `YYYY-MM-DD` date (ISO 8601). Anything else is a row
/// error — the importer never guesses a date format.
pub fn parse_iso_date(raw: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d")
        .map_err(|_| format!("date {raw:?} is not ISO 8601 YYYY-MM-DD"))
}

fn parse_reference(record: &csv::StringRecord, index: Option<usize>) -> Option<String> {
    index
        .and_then(|index| record.get(index))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Ingest one CSV bank statement for one account, all-or-nothing.
///
/// See the module docs for the format and the identity rules. On success the
/// import record and every line are committed together; on
/// [`IngestError::Rejected`] / [`IngestError::Conflict`] nothing is written.
pub async fn ingest_bank_statement(
    pool: &PgPool,
    input: &BankStatementImport<'_>,
) -> Result<ImportOutcome, IngestError> {
    let account_ref = input.bank_account.trim();
    if account_ref.is_empty() {
        return Err(IngestError::Invalid(
            "bank_account (IBAN or UUID) is required".to_string(),
        ));
    }
    if input.period_end < input.period_start {
        return Err(IngestError::Invalid(format!(
            "period_end {} is before period_start {}",
            input.period_end, input.period_start
        )));
    }
    if input.csv.trim().is_empty() {
        return Err(IngestError::Invalid("csv body is empty".to_string()));
    }
    if input.imported_by.trim().is_empty() {
        return Err(IngestError::Invalid("imported_by is required".to_string()));
    }

    // Statement identity: sha256 of the exact bytes received.
    let digest = hex::encode(Sha256::digest(input.csv.as_bytes()));

    let account = resolve_account(pool, account_ref).await?;
    let account_currency = account.currency.trim().to_ascii_uppercase();

    // Already imported: idempotent no-op, reported with the stored record.
    if let Some(existing) = find_import(pool, account.id, &digest).await? {
        return Ok(outcome_from_import(account.id, &digest, existing, true));
    }

    let known = load_known_accounts(pool).await?;
    let (lines, row_errors) = parse_rows(input, &account, &account_currency, &known)?;
    if !row_errors.is_empty() {
        return Err(IngestError::Rejected { errors: row_errors });
    }
    if lines.len() > MAX_IMPORT_LINES {
        return Err(IngestError::Invalid(format!(
            "statement has {} lines; the maximum is {MAX_IMPORT_LINES}",
            lines.len()
        )));
    }

    // Line identity: a line the bank already reported for this account must
    // not be stored twice, even when a re-issued file has different bytes.
    let conflicts = existing_line_conflicts(pool, account.id, &lines).await?;
    if !conflicts.is_empty() {
        return Err(IngestError::Conflict { errors: conflicts });
    }

    let credit_total_cents: i64 = lines
        .iter()
        .filter(|line| line.amount_cents > 0)
        .map(|line| line.amount_cents)
        .sum();
    let debit_total_cents: i64 = lines
        .iter()
        .filter(|line| line.amount_cents < 0)
        .map(|line| -line.amount_cents)
        .sum();
    let line_count = lines.len() as i64;

    let mut tx = pool.begin().await?;
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO bank_statement_imports \
             (bank_account_id, period_start, period_end, file_digest, filename, \
              source_kind, line_count, credit_total_cents, debit_total_cents, imported_by) \
         VALUES ($1, $2, $3, $4, $5, 'csv_upload', $6, $7, $8, $9) \
         ON CONFLICT (bank_account_id, file_digest) DO NOTHING \
         RETURNING id",
    )
    .bind(account.id)
    .bind(input.period_start)
    .bind(input.period_end)
    .bind(&digest)
    .bind(input.filename)
    .bind(line_count as i32)
    .bind(credit_total_cents)
    .bind(debit_total_cents)
    .bind(input.imported_by.trim())
    .fetch_optional(&mut *tx)
    .await?;

    let Some(import_id) = inserted else {
        // Lost the race with a concurrent import of the same statement.
        tx.rollback().await?;
        let existing = find_import(pool, account.id, &digest)
            .await?
            .ok_or_else(|| {
                IngestError::Invalid(
                    "import identity conflicted but the existing import could not be read"
                        .to_string(),
                )
            })?;
        return Ok(outcome_from_import(account.id, &digest, existing, true));
    };

    for line in &lines {
        sqlx::query(
            "INSERT INTO bank_statement_lines \
                 (bank_account_id, import_id, external_id, statement_date, value_date, \
                  amount_cents, currency, reference, counterparty_name, counterparty_account) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(account.id)
        .bind(import_id)
        .bind(&line.external_id)
        .bind(line.statement_date)
        .bind(line.value_date)
        .bind(line.amount_cents)
        .bind(&line.currency)
        .bind(&line.reference)
        .bind(&line.counterparty_name)
        .bind(&line.counterparty_account)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(ImportOutcome {
        import_id,
        bank_account_id: account.id,
        file_digest: digest,
        line_count,
        credit_total_cents,
        debit_total_cents,
        period_start: input.period_start,
        period_end: input.period_end,
        filename: input.filename.map(str::to_string),
        already_imported: false,
    })
}

fn outcome_from_import(
    bank_account_id: Uuid,
    digest: &str,
    existing: ImportRow,
    already_imported: bool,
) -> ImportOutcome {
    ImportOutcome {
        import_id: existing.id,
        bank_account_id,
        file_digest: digest.to_string(),
        line_count: i64::from(existing.line_count),
        credit_total_cents: existing.credit_total_cents,
        debit_total_cents: existing.debit_total_cents,
        period_start: existing.period_start,
        period_end: existing.period_end,
        filename: existing.filename,
        already_imported,
    }
}

async fn resolve_account(pool: &PgPool, account_ref: &str) -> Result<AccountRow, IngestError> {
    if let Ok(id) = Uuid::parse_str(account_ref) {
        let row: Option<AccountRow> =
            sqlx::query_as("SELECT id, btrim(currency) AS currency FROM bank_accounts WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?;
        return row.ok_or_else(|| IngestError::UnknownAccount(account_ref.to_string()));
    }

    let rows: Vec<AccountRow> = sqlx::query_as(
        "SELECT id, btrim(currency) AS currency FROM bank_accounts \
         WHERE upper(btrim(iban)) = upper(btrim($1))",
    )
    .bind(account_ref)
    .fetch_all(pool)
    .await?;
    match rows.len() {
        0 => Err(IngestError::UnknownAccount(account_ref.to_string())),
        1 => rows
            .into_iter()
            .next()
            .ok_or_else(|| IngestError::UnknownAccount(account_ref.to_string())),
        _ => Err(IngestError::Invalid(format!(
            "IBAN {account_ref:?} matches more than one bank account; import by account UUID"
        ))),
    }
}

async fn find_import(
    pool: &PgPool,
    bank_account_id: Uuid,
    digest: &str,
) -> Result<Option<ImportRow>, IngestError> {
    let row: Option<ImportRow> = sqlx::query_as(
        "SELECT id, period_start, period_end, line_count, credit_total_cents, \
                debit_total_cents, filename \
         FROM bank_statement_imports \
         WHERE bank_account_id = $1 AND file_digest = $2",
    )
    .bind(bank_account_id)
    .bind(digest)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

async fn load_known_accounts(pool: &PgPool) -> Result<KnownAccounts, IngestError> {
    let rows: Vec<(Uuid, Option<String>)> =
        sqlx::query_as("SELECT id, iban FROM bank_accounts")
            .fetch_all(pool)
            .await?;
    let mut known = KnownAccounts::default();
    for (id, iban) in rows {
        known.ids.insert(id);
        if let Some(iban) = iban.map(|value| value.trim().to_ascii_uppercase()) {
            if !iban.is_empty() {
                known.ibans.entry(iban).or_default().push(id);
            }
        }
    }
    Ok(known)
}

/// Resolve the optional per-row `bank_account` cell to the statement's
/// account. Returns `Err(message)` for an unknown, ambiguous, or different
/// account.
fn check_row_account(value: &str, account: &AccountRow, known: &KnownAccounts) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    if let Ok(id) = Uuid::parse_str(value) {
        if !known.ids.contains(&id) {
            return Err(format!("bank account {value:?} is not registered"));
        }
        if id != account.id {
            return Err(format!(
                "bank account {value:?} is not the statement's account ({})",
                account.id
            ));
        }
        return Ok(());
    }
    match known.ibans.get(&value.to_ascii_uppercase()) {
        None => Err(format!("bank account {value:?} is not registered")),
        Some(ids) if ids.len() > 1 => Err(format!(
            "bank account {value:?} is ambiguous across legal entities"
        )),
        Some(ids) if ids[0] != account.id => Err(format!(
            "bank account {value:?} is not the statement's account ({})",
            account.id
        )),
        Some(_) => Ok(()),
    }
}

fn row_error(row: u32, column: &str, message: String) -> RowError {
    RowError {
        row,
        column: column.to_string(),
        message,
    }
}

fn parse_rows(
    input: &BankStatementImport<'_>,
    account: &AccountRow,
    account_currency: &str,
    known: &KnownAccounts,
) -> Result<(Vec<ParsedLine>, Vec<RowError>), IngestError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .trim(csv::Trim::All)
        .flexible(true)
        .from_reader(input.csv.as_bytes());

    let headers = reader
        .headers()
        .map_err(|error| IngestError::Invalid(format!("CSV header could not be read: {error}")))?
        .clone();
    let header = |name: &str| {
        headers
            .iter()
            .position(|value| value.trim().eq_ignore_ascii_case(name))
    };

    let index = HeaderIndex {
        external_id: header("external_id").unwrap_or(0),
        statement_date: header("statement_date").unwrap_or(0),
        amount: header("amount").unwrap_or(0),
        value_date: header("value_date"),
        currency: header("currency"),
        reference: header("reference"),
        counterparty_name: header("counterparty_name"),
        counterparty_account: header("counterparty_account"),
        bank_account: header("bank_account"),
    };
    let mut missing: Vec<&str> = Vec::new();
    if header("external_id").is_none() {
        missing.push("external_id");
    }
    if header("statement_date").is_none() {
        missing.push("statement_date");
    }
    if header("amount").is_none() {
        missing.push("amount");
    }
    if !missing.is_empty() {
        return Err(IngestError::Invalid(format!(
            "CSV is missing required column(s): {}",
            missing.join(", ")
        )));
    }

    let mut lines: Vec<ParsedLine> = Vec::new();
    let mut errors: Vec<RowError> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for (offset, record) in reader.records().enumerate() {
        let literal_row = (offset + 2) as u32;
        let record = match record {
            Ok(record) => record,
            Err(error) => {
                let row = error
                    .position()
                    .map(|position| position.line() as u32)
                    .unwrap_or(literal_row);
                errors.push(RowError {
                    row,
                    column: "csv".to_string(),
                    message: format!("malformed CSV record: {error}"),
                });
                continue;
            }
        };
        let row = record
            .position()
            .map(|position| position.line() as u32)
            .unwrap_or(literal_row);

        let mut row_errors: Vec<RowError> = Vec::new();

        let external_id = record
            .get(index.external_id)
            .unwrap_or("")
            .trim()
            .to_string();
        if external_id.is_empty() {
            row_errors.push(row_error(row, "external_id", "external_id is required".into()));
        } else if !seen.insert(external_id.clone()) {
            row_errors.push(row_error(
                row,
                "external_id",
                format!("external_id {external_id:?} is repeated in this statement"),
            ));
        }

        let statement_date = match parse_iso_date(record.get(index.statement_date).unwrap_or("")) {
            Ok(date) => {
                if date < input.period_start || date > input.period_end {
                    row_errors.push(row_error(
                        row,
                        "statement_date",
                        format!(
                            "statement_date {date} is outside the declared period {}..{}",
                            input.period_start, input.period_end
                        ),
                    ));
                }
                Some(date)
            }
            Err(message) => {
                row_errors.push(row_error(row, "statement_date", message));
                None
            }
        };

        let amount_cents = match parse_amount_cents(record.get(index.amount).unwrap_or("")) {
            Ok(cents) => Some(cents),
            Err(message) => {
                row_errors.push(row_error(row, "amount", message));
                None
            }
        };

        let value_date = match index.value_date {
            Some(value_date_index) => {
                let raw = record.get(value_date_index).unwrap_or("");
                if raw.trim().is_empty() {
                    None
                } else {
                    match parse_iso_date(raw) {
                        Ok(date) => Some(date),
                        Err(message) => {
                            row_errors.push(row_error(row, "value_date", message));
                            None
                        }
                    }
                }
            }
            None => None,
        };

        let currency = match index.currency {
            Some(currency_index) => {
                let raw = record.get(currency_index).unwrap_or("");
                if raw.trim().is_empty() {
                    account_currency.to_string()
                } else {
                    let currency = raw.trim().to_ascii_uppercase();
                    if currency != account_currency {
                        row_errors.push(row_error(
                            row,
                            "currency",
                            format!(
                                "currency {currency} disagrees with the account currency {account_currency}"
                            ),
                        ));
                    }
                    currency
                }
            }
            None => account_currency.to_string(),
        };

        if let Some(bank_account_index) = index.bank_account {
            let raw = record.get(bank_account_index).unwrap_or("");
            if let Err(message) = check_row_account(raw, account, known) {
                row_errors.push(row_error(row, "bank_account", message));
            }
        }

        if row_errors.is_empty() {
            if let (Some(statement_date), Some(amount_cents)) = (statement_date, amount_cents) {
                lines.push(ParsedLine {
                    row,
                    external_id,
                    statement_date,
                    value_date,
                    amount_cents,
                    currency,
                    reference: parse_reference(&record, index.reference),
                    counterparty_name: parse_reference(&record, index.counterparty_name),
                    counterparty_account: parse_reference(&record, index.counterparty_account),
                });
            } else {
                // Unreachable by construction: a missing date/amount always
                // pushes an error. Kept as a defensive error, not a panic.
                errors.push(RowError {
                    row,
                    column: "row".to_string(),
                    message: "row could not be parsed".to_string(),
                });
            }
        } else {
            errors.append(&mut row_errors);
        }
    }

    Ok((lines, errors))
}

async fn existing_line_conflicts(
    pool: &PgPool,
    bank_account_id: Uuid,
    lines: &[ParsedLine],
) -> Result<Vec<RowError>, IngestError> {
    if lines.is_empty() {
        return Ok(Vec::new());
    }
    let external_ids: Vec<String> = lines
        .iter()
        .map(|line| line.external_id.clone())
        .collect();
    let existing: Vec<String> = sqlx::query_scalar(
        "SELECT external_id FROM bank_statement_lines \
         WHERE bank_account_id = $1 AND external_id = ANY($2)",
    )
    .bind(bank_account_id)
    .bind(&external_ids)
    .fetch_all(pool)
    .await?;
    let existing: HashSet<String> = existing.into_iter().collect();
    Ok(lines
        .iter()
        .filter(|line| existing.contains(&line.external_id))
        .map(|line| RowError {
            row: line.row,
            column: "external_id".to_string(),
            message: format!(
                "line {:?} already exists for this account; the statement was imported before \
                 (possibly as a re-issued file with different bytes)",
                line.external_id
            ),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_parsing_is_exact_and_rejects_ambiguity() {
        assert_eq!(parse_amount_cents("0"), Ok(0));
        assert_eq!(parse_amount_cents("1"), Ok(100));
        assert_eq!(parse_amount_cents("1.2"), Ok(120));
        assert_eq!(parse_amount_cents("1,23"), Ok(123));
        assert_eq!(parse_amount_cents("-12.34"), Ok(-1234));
        assert_eq!(parse_amount_cents(" +5.00 "), Ok(500));
        assert_eq!(parse_amount_cents("-0.00"), Ok(0));
        assert_eq!(parse_amount_cents("92233720368547758.07"), Ok(i64::MAX));
        assert!(parse_amount_cents("").is_err());
        assert!(parse_amount_cents("-").is_err());
        assert!(parse_amount_cents("1.234").is_err());
        assert!(parse_amount_cents("1,2,3").is_err());
        assert!(parse_amount_cents("1 000").is_err());
        assert!(parse_amount_cents("12 EUR").is_err());
        assert!(parse_amount_cents("92233720368547758.08").is_err());
    }

    #[test]
    fn dates_are_iso_only() {
        assert_eq!(
            parse_iso_date("2026-06-30"),
            Ok(NaiveDate::from_ymd_opt(2026, 6, 30).expect("date"))
        );
        assert!(parse_iso_date("30.06.2026").is_err());
        assert!(parse_iso_date("2026-13-01").is_err());
    }
}
