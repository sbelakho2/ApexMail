//! DB-backed tests for the bank statement ingest → sweep → posted-ledger loop.
//!
//! Every test provisions its OWN canonical database through
//! `migrator::test_support::fresh_canonical_pool` (the workspace convention):
//! the sweep is a global operation, so counters are only unambiguous against a
//! pristine database. `TEST_DATABASE_URL` unset means soft-skip; a CONFIGURED
//! provisioning failure panics.
//!
//! Covered:
//!  1. ingest stores the statement (account, amounts, dates, digest, import
//!     link) and re-ingesting the same statement is a no-op (line count
//!     unchanged);
//!  2. malformed rows are refused with per-row errors and NOTHING is written
//!     — unparseable dates/amounts, currency disagreeing with the account,
//!     unknown accounts, duplicates in the file, dates outside the declared
//!     period, and lines already stored (re-issued file → conflict);
//!  3. the sweep posts the ingested non-zero lines exactly once (journal
//!     entry, idempotency key, source document), a replay posts nothing,
//!     zero-amount lines are reported unpostable and retained, and the posted
//!     entry appears in `v_accounting_period_movement`.

use accounting_core::bank_ingest::{ingest_bank_statement, BankStatementImport, IngestError};
use accounting_core::chart::{self, LegalEntityInput};
use accounting_core::periods;
use accounting_core::sweeps::{self, SweepConfig};
use accounting_core::ROLE_BANK;
use chrono::NaiveDate;
use sha2::Digest;
use sqlx::PgPool;
use uuid::Uuid;

async fn provision(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(
        test_name,
        &format!("bank_ingest_{test_name}"),
    )
    .await
    {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn date(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("valid date")
}

async fn seed_entity(pool: &PgPool, tag: &str) -> Uuid {
    let mut conn = pool.acquire().await.expect("pool acquire");
    let entity = chart::create_legal_entity(
        &mut conn,
        &LegalEntityInput {
            legal_name: format!("Bank Ingest {tag} OÜ"),
            trading_name: None,
            registry_code: format!("BANK-{tag}"),
            vat_number: None,
            address_line1: None,
            city: None,
            postal_code: None,
            country_code: "EE".to_string(),
            default_currency: "EUR".to_string(),
            fiscal_year_start_month: 1,
            is_default: false,
        },
    )
    .await
    .expect("create legal entity");
    chart::ensure_standard_chart(&mut conn, entity)
        .await
        .expect("chart");
    periods::ensure_period(
        &mut conn,
        entity,
        "year",
        tag,
        date(2026, 1, 1),
        date(2026, 12, 31),
    )
    .await
    .expect("period");
    entity
}

async fn seed_bank_account(pool: &PgPool, entity: Uuid, iban: &str, currency: &str) -> Uuid {
    let mut conn = pool.acquire().await.expect("pool acquire");
    let bank_ledger = chart::resolve_account_role(&mut conn, entity, ROLE_BANK)
        .await
        .expect("bank ledger role");
    drop(conn);
    sqlx::query_scalar(
        "INSERT INTO bank_accounts (legal_entity_id, name, iban, currency, account_id) \
         VALUES ($1, 'Statement Account', $2, $3, $4) RETURNING id",
    )
    .bind(entity)
    .bind(iban)
    .bind(currency)
    .bind(bank_ledger)
    .fetch_one(pool)
    .await
    .expect("bank account")
}

fn statement_csv() -> String {
    [
        "external_id,statement_date,value_date,amount,currency,reference,counterparty_name,counterparty_account,bank_account",
        "ING-1,2026-06-05,2026-06-05,1250.00,EUR,INV-1,Acme OÜ,EE111,EE00BANK0000000001",
        "ING-2,2026-06-07,,-99.50,EUR,RENT,Landlord OÜ,EE222,EE00BANK0000000001",
        "ING-3,2026-06-09,2026-06-10,0,EUR,ZERO LINE,,,",
        "ING-4,2026-06-11,,1000,EUR,Second receipt,,,",
    ]
    .join("\n")
        + "\n"
}

// ---------------------------------------------------------------------------
// 1. Ingest + idempotent re-ingest
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ingest_stores_statement_and_reingest_is_a_noop() {
    let Some(pool) = provision("idempotent").await else {
        return;
    };
    let entity = seed_entity(&pool, "idempotent").await;
    let account = seed_bank_account(&pool, entity, "EE00BANK0000000001", "EUR").await;

    let csv = statement_csv();
    let input = BankStatementImport {
        bank_account: "EE00BANK0000000001",
        period_start: date(2026, 6, 1),
        period_end: date(2026, 6, 30),
        filename: Some("june-2026.csv"),
        csv: &csv,
        imported_by: "test-operator",
    };
    let outcome = ingest_bank_statement(&pool, &input)
        .await
        .expect("ingest");
    assert!(!outcome.already_imported, "{outcome:?}");
    assert_eq!(outcome.bank_account_id, account);
    assert_eq!(outcome.line_count, 4, "{outcome:?}");
    assert_eq!(outcome.credit_total_cents, 125_000 + 100_000, "{outcome:?}");
    assert_eq!(outcome.debit_total_cents, 9_950, "{outcome:?}");
    assert_eq!(outcome.file_digest.len(), 64, "{outcome:?}");
    assert_eq!(
        outcome.file_digest,
        hex::encode(sha2::Sha256::digest(csv.as_bytes())),
        "the stored digest must be the sha256 of the exact bytes received"
    );

    // The import record is the statement identity.
    let import: (Uuid, i32, Option<String>) = sqlx::query_as(
        "SELECT bank_account_id, line_count, filename \
         FROM bank_statement_imports WHERE id = $1",
    )
    .bind(outcome.import_id)
    .fetch_one(&pool)
    .await
    .expect("import row");
    assert_eq!(import.0, account);
    assert_eq!(import.1, 4);
    assert_eq!(import.2.as_deref(), Some("june-2026.csv"));

    // Lines carry the account, the import link, the amounts and the dates.
    let lines: Vec<(String, NaiveDate, Option<NaiveDate>, i64, String, Uuid, Option<Uuid>)> =
        sqlx::query_as(
            "SELECT external_id, statement_date, value_date, amount_cents, btrim(currency), \
                    bank_account_id, import_id \
             FROM bank_statement_lines WHERE bank_account_id = $1 ORDER BY external_id",
        )
        .bind(account)
        .fetch_all(&pool)
        .await
        .expect("lines");
    assert_eq!(lines.len(), 4);
    assert_eq!(
        lines[0],
        (
            "ING-1".to_string(),
            date(2026, 6, 5),
            Some(date(2026, 6, 5)),
            125_000,
            "EUR".to_string(),
            account,
            Some(outcome.import_id)
        )
    );
    assert_eq!(lines[1].0, "ING-2");
    assert_eq!(lines[1].2, None);
    assert_eq!(lines[1].3, -9_950);
    assert_eq!(lines[2].0, "ING-3");
    assert_eq!(lines[2].3, 0);
    assert_eq!(lines[3].0, "ING-4");
    assert_eq!(lines[3].1, date(2026, 6, 11));

    // Re-ingest the very same statement, now addressed by account UUID: a
    // no-op that reports the stored import. Line and import counts unchanged.
    let by_uuid = account.to_string();
    let replay_input = BankStatementImport {
        bank_account: &by_uuid,
        period_start: date(2026, 6, 1),
        period_end: date(2026, 6, 30),
        filename: Some("june-2026-copy.csv"),
        csv: &csv,
        imported_by: "test-operator",
    };
    let replay = ingest_bank_statement(&pool, &replay_input)
        .await
        .expect("replay");
    assert!(replay.already_imported, "{replay:?}");
    assert_eq!(replay.import_id, outcome.import_id, "{replay:?}");
    assert_eq!(replay.line_count, 4);

    let line_count: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM bank_statement_lines")
        .fetch_one(&pool)
        .await
        .expect("line count");
    assert_eq!(line_count, 4, "re-ingest must not duplicate lines");
    let import_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM bank_statement_imports")
            .fetch_one(&pool)
            .await
            .expect("import count");
    assert_eq!(import_count, 1, "re-ingest must not create a second import");

    // Unknown request-level account is refused before any write.
    let unknown = BankStatementImport {
        bank_account: "EE99UNKNOWN0000000000",
        period_start: date(2026, 6, 1),
        period_end: date(2026, 6, 30),
        filename: None,
        csv: &csv,
        imported_by: "test-operator",
    };
    assert!(matches!(
        ingest_bank_statement(&pool, &unknown).await,
        Err(IngestError::UnknownAccount(account)) if account == "EE99UNKNOWN0000000000"
    ));

    // A period in the wrong order is a request-level refusal, not a row error.
    let bad_period = BankStatementImport {
        bank_account: "EE00BANK0000000001",
        period_start: date(2026, 7, 1),
        period_end: date(2026, 6, 1),
        filename: None,
        csv: &csv,
        imported_by: "test-operator",
    };
    assert!(matches!(
        ingest_bank_statement(&pool, &bad_period).await,
        Err(IngestError::Invalid(_))
    ));
}

// ---------------------------------------------------------------------------
// 2. Malformed input: per-row errors, nothing written
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ingest_rejects_malformed_rows_and_writes_nothing() {
    let Some(pool) = provision("malformed").await else {
        return;
    };
    let entity = seed_entity(&pool, "malformed").await;
    let account = seed_bank_account(&pool, entity, "EE00BANK0000000002", "EUR").await;

    let csv = [
        "external_id,statement_date,amount,currency,bank_account",
        "OK-ROW,2026-06-05,10.00,EUR,",
        "BAD-DATE,2026-13-40,10.00,EUR,",
        "BAD-AMOUNT,2026-06-06,12x.00,EUR,",
        "BAD-CURRENCY,2026-06-07,10.00,USD,",
        "UNKNOWN-ACCT,2026-06-08,10.00,EUR,EE99UNKNOWN0000000000",
        "OUT-OF-PERIOD,2026-07-01,10.00,EUR,",
        "DUP,2026-06-09,10.00,EUR,",
        "DUP,2026-06-10,11.00,EUR,",
    ]
    .join("\n")
        + "\n";
    let input = BankStatementImport {
        bank_account: "EE00BANK0000000002",
        period_start: date(2026, 6, 1),
        period_end: date(2026, 6, 30),
        filename: Some("bad.csv"),
        csv: &csv,
        imported_by: "test-operator",
    };

    let error = ingest_bank_statement(&pool, &input)
        .await
        .expect_err("must reject");
    let IngestError::Rejected { errors } = error else {
        panic!("expected per-row rejection, got {error:?}");
    };
    let pairs: Vec<(u32, &str)> = errors
        .iter()
        .map(|error| (error.row, error.column.as_str()))
        .collect();
    assert_eq!(
        pairs,
        vec![
            (3, "statement_date"),
            (4, "amount"),
            (5, "currency"),
            (6, "bank_account"),
            (7, "statement_date"),
            (9, "external_id"),
        ],
        "each bad row must be named: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("outside the declared period")),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("repeated in this statement")),
        "{errors:?}"
    );

    // All-or-nothing: the valid rows of a rejected file are NOT imported.
    let import_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM bank_statement_imports")
            .fetch_one(&pool)
            .await
            .expect("import count");
    let line_count: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM bank_statement_lines")
        .fetch_one(&pool)
        .await
        .expect("line count");
    assert_eq!(import_count, 0);
    assert_eq!(line_count, 0);

    // A missing required column is a request-level refusal.
    let missing_header = BankStatementImport {
        bank_account: "EE00BANK0000000002",
        period_start: date(2026, 6, 1),
        period_end: date(2026, 6, 30),
        filename: None,
        csv: "external_id,statement_date\nX,2026-06-05\n",
        imported_by: "test-operator",
    };
    match ingest_bank_statement(&pool, &missing_header).await {
        Err(IngestError::Invalid(message)) => {
            assert!(message.contains("amount"), "{message}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }

    // A re-issued file (different bytes) repeating an external_id already
    // stored for this account is a per-row conflict and writes nothing.
    let good = [
        "external_id,statement_date,amount",
        "REISSUE-1,2026-06-15,42.00",
    ]
    .join("\n")
        + "\n";
    let first = BankStatementImport {
        bank_account: "EE00BANK0000000002",
        period_start: date(2026, 6, 1),
        period_end: date(2026, 6, 30),
        filename: None,
        csv: &good,
        imported_by: "test-operator",
    };
    let first_outcome = ingest_bank_statement(&pool, &first)
        .await
        .expect("first import");
    assert_eq!(first_outcome.line_count, 1);

    let reissued = [
        "external_id,statement_date,amount",
        "REISSUE-1,2026-06-15,42.00",
        "REISSUE-2,2026-06-16,7.00",
    ]
    .join("\n")
        + "\n";
    let account_ref = account.to_string();
    let reissued_input = BankStatementImport {
        bank_account: &account_ref,
        period_start: date(2026, 6, 1),
        period_end: date(2026, 6, 30),
        filename: None,
        csv: &reissued,
        imported_by: "test-operator",
    };
    match ingest_bank_statement(&pool, &reissued_input).await {
        Err(IngestError::Conflict { errors }) => {
            assert_eq!(errors.len(), 1, "{errors:?}");
            assert_eq!(errors[0].row, 2, "{errors:?}");
            assert_eq!(errors[0].column, "external_id");
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
    let line_count: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM bank_statement_lines")
        .fetch_one(&pool)
        .await
        .expect("line count after conflict");
    assert_eq!(line_count, 1, "the conflicting file must not be partially imported");
}

// ---------------------------------------------------------------------------
// 3. Ingest → sweep → posted ledger → view
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ingested_lines_sweep_into_the_posted_ledger_once() {
    let Some(pool) = provision("sweep_loop").await else {
        return;
    };
    let entity = seed_entity(&pool, "sweep_loop").await;
    // Same IBAN the shared statement CSV rows carry in their bank_account
    // column, so the row-level account check proves the row agrees with the
    // statement's account.
    let account = seed_bank_account(&pool, entity, "EE00BANK0000000001", "EUR").await;

    let csv = statement_csv();
    let input = BankStatementImport {
        bank_account: "EE00BANK0000000001",
        period_start: date(2026, 6, 1),
        period_end: date(2026, 6, 30),
        filename: Some("loop.csv"),
        csv: &csv,
        imported_by: "test-operator",
    };
    let outcome = ingest_bank_statement(&pool, &input)
        .await
        .expect("ingest");

    let line_ids: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT id, external_id, amount_cents FROM bank_statement_lines \
         WHERE bank_account_id = $1 ORDER BY external_id",
    )
    .bind(account)
    .fetch_all(&pool)
    .await
    .expect("line ids");
    let receipt = line_ids[0].0;
    let payment = line_ids[1].0;
    let zero = line_ids[2].0;
    let second_receipt = line_ids[3].0;

    // The sweep the compliance cron hosts posts every non-zero line once
    // (ING-1, ING-2, ING-4); the zero-amount ING-3 is unpostable.
    let config = SweepConfig::default();
    let report = sweeps::sweep_unposted_bank_statement_lines(&pool, &config)
        .await
        .expect("sweep");
    assert_eq!(report.posted, 3, "{report:?}");
    assert_eq!(report.unpostable, 1, "{report:?}");

    for (line_id, key) in [
        (receipt, format!("bank_statement_line:{receipt}")),
        (payment, format!("bank_statement_line:{payment}")),
        (
            second_receipt,
            format!("bank_statement_line:{second_receipt}"),
        ),
    ] {
        let entries: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM journal_entries WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("entry count");
        assert_eq!(entries, 1, "line {line_id} must post exactly once");
        let stamp: Option<Uuid> =
            sqlx::query_scalar("SELECT journal_entry_id FROM bank_statement_lines WHERE id = $1")
                .bind(line_id)
                .fetch_one(&pool)
                .await
                .expect("stamp");
        assert!(stamp.is_some(), "the line must carry its journal entry id");
        let sources: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM accounting_source_documents \
             WHERE source_type = 'bank_statement_line' AND source_table = 'bank_statement_lines' \
               AND source_id = $1",
        )
        .bind(line_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("source document");
        assert_eq!(sources, 1, "the posting must be registered as a source document");
    }

    // The zero-amount line is unpostable: retained, unstamped, reported.
    let zero_stamp: Option<Uuid> =
        sqlx::query_scalar("SELECT journal_entry_id FROM bank_statement_lines WHERE id = $1")
            .bind(zero)
            .fetch_one(&pool)
            .await
            .expect("zero line");
    assert!(zero_stamp.is_none());
    let zero_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM bank_statement_lines WHERE id = $1",
    )
    .bind(zero)
    .fetch_one(&pool)
    .await
    .expect("zero retained");
    assert_eq!(zero_rows, 1, "an unpostable line is never deleted");

    // Replay: nothing to claim; the idempotency keys still hold one entry.
    let replay = sweeps::sweep_unposted_bank_statement_lines(&pool, &config)
        .await
        .expect("replay");
    assert_eq!(replay.claimed, 0, "{replay:?}");
    assert_eq!(replay.posted, 0, "{replay:?}");

    // The loop is provably closed: the posted entry is in the accounting
    // view (period movement), balanced.
    let period_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM fiscal_periods WHERE legal_entity_id = $1 AND start_date = DATE '2026-01-01'",
    )
    .bind(entity)
    .fetch_one(&pool)
    .await
    .expect("period");
    let movement: (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(debit_cents),0)::bigint, COALESCE(SUM(credit_cents),0)::bigint \
         FROM v_accounting_period_movement \
         WHERE legal_entity_id = $1 AND fiscal_period_id = $2",
    )
    .bind(entity)
    .bind(period_id)
    .fetch_one(&pool)
    .await
    .expect("movement");
    // receipts 125000 + 100000 Dr bank / Cr AR; payment 9950 Dr expense /
    // Cr bank.
    assert_eq!(movement, (234_950, 234_950), "view must show the posted entries balanced");
    let bank_movement: (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(debit_cents),0)::bigint, COALESCE(SUM(credit_cents),0)::bigint \
         FROM v_accounting_period_movement \
         WHERE legal_entity_id = $1 AND fiscal_period_id = $2 AND account_type = 'asset'",
    )
    .bind(entity)
    .bind(period_id)
    .fetch_one(&pool)
    .await
    .expect("asset movement");
    assert_eq!(
        bank_movement,
        (225_000, 234_950),
        "asset side: bank debited 225000; bank credited 9950 and AR credited 225000"
    );
    assert_eq!(outcome.line_count, 4);
}
