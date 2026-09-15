//! DB-backed invariants for the statutory accounting core (migration 220).
//!
//! Every test provisions the REAL production migration chain through
//! `migrator::test_support` (the workspace convention). Tests in this binary
//! share ONE canonical database (`shared_canonical_db`) and isolate
//! themselves by working on their own legal entity with a per-run unique
//! registry code — the full migration chain is ~5 GB per clone, so
//! per-test clones would exhaust the disk. Set `TEST_DATABASE_URL` to run
//! them; without it each test skips, and a configured-but-broken
//! provisioning is a hard failure — never a silent skip.
//!
//! Covered invariants (the finding's mandatory list):
//!  1. unbalanced journal cannot be posted (API check + deferred trigger),
//!  2. posted entries cannot be mutated (update/delete/line changes refused),
//!  3. a correction is a reversal pair,
//!  4. replaying the same source document posts once,
//!  5. a closed period refuses a new posting,
//!  6. the two structural invariants hold over 100 randomized postings,
//!  7. retention-class records are excluded from an ordinary customer
//!     deletion path,
//!  8. source adapters (invoice, settlement, credit note/refund, payroll,
//!     bank, expense) post idempotently and the derivation read contract
//!     reflects them.

use accounting_core::adapters;
use accounting_core::chart::{self, LegalEntityInput};
use accounting_core::derive;
use accounting_core::hash::evidence_hash;
use accounting_core::periods;
use accounting_core::posting::{self, ReversalRequest};
use accounting_core::retention;
use accounting_core::types::*;
use accounting_core::AccountingError;
use chrono::NaiveDate;
use sqlx::PgPool;
use std::sync::OnceLock;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/// One shared database for the whole test binary.
const SHARED_DB: &str = "apexmail_accounting_test";

/// Per-run uniquifier: lets the suite re-run against the persistent shared
/// database without colliding with rows created by a previous run.
fn run_tag() -> &'static str {
    static TAG: OnceLock<String> = OnceLock::new();
    TAG.get_or_init(|| Uuid::new_v4().simple().to_string()[..8].to_string())
}

async fn provision(test_name: &str) -> Option<PgPool> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("skipping {test_name}: TEST_DATABASE_URL is not configured");
        return None;
    };
    if url.trim().is_empty() {
        eprintln!("skipping {test_name}: TEST_DATABASE_URL is not configured");
        return None;
    }
    let (server, db_part) = url
        .rsplit_once('/')
        .expect("TEST_DATABASE_URL has a db segment");
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    let base_url = format!("{server}/{db_only}");
    match migrator::test_support::shared_canonical_db(&base_url, SHARED_DB).await {
        Ok(Some(pool)) => Some(pool),
        Ok(None) => None,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

struct Seed {
    entity: Uuid,
    period: Uuid,
}

/// Seed a legal entity + standard chart + a fiscal period.
///
/// `tag` must be unique per test AND per run: it keys the registry code and
/// the period label. `make_default` is used by the adapter suite only,
/// because the production adapters resolve the default entity.
async fn seed(pool: &PgPool, tag: &str, make_default: bool) -> Seed {
    let mut conn = pool.acquire().await.expect("pool acquire");

    let entity = if make_default {
        let existing: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM legal_entities WHERE is_default LIMIT 1")
                .fetch_optional(&mut *conn)
                .await
                .expect("default entity probe");
        match existing {
            Some(entity) => entity,
            None => chart::create_legal_entity(
                &mut conn,
                &LegalEntityInput {
                    legal_name: "Test OÜ".to_string(),
                    trading_name: Some("ApexMail Test".to_string()),
                    registry_code: "DEFAULT-ENTITY".to_string(),
                    vat_number: Some("EE123456789".to_string()),
                    address_line1: Some("Test 1".to_string()),
                    city: Some("Tallinn".to_string()),
                    postal_code: Some("10111".to_string()),
                    country_code: "EE".to_string(),
                    default_currency: "EUR".to_string(),
                    fiscal_year_start_month: 1,
                    is_default: true,
                },
            )
            .await
            .expect("create default legal entity"),
        }
    } else {
        chart::create_legal_entity(
            &mut conn,
            &LegalEntityInput {
                legal_name: format!("Test {tag} OÜ"),
                trading_name: None,
                registry_code: format!("REG-{tag}"),
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
        .expect("create legal entity")
    };

    chart::ensure_standard_chart(&mut conn, entity)
        .await
        .expect("chart");

    let period = periods::ensure_period(
        &mut conn,
        entity,
        "year",
        tag,
        date(2026, 1, 1),
        date(2026, 12, 31),
    )
    .await
    .expect("period");
    Seed { entity, period }
}

fn date(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("valid date")
}

async fn account(pool: &PgPool, entity: Uuid, role: &'static str) -> Uuid {
    let mut conn = pool.acquire().await.expect("pool acquire");
    chart::resolve_account_role(&mut conn, entity, role)
        .await
        .expect("account role")
}

fn request(
    seed: &Seed,
    key: &str,
    entry_type: EntryType,
    lines: Vec<JournalLine>,
    source: Option<SourceIdentity>,
) -> PostJournalRequest {
    PostJournalRequest {
        legal_entity_id: seed.entity,
        fiscal_period_id: seed.period,
        entry_date: date(2026, 6, 15),
        entry_type,
        memo: format!("test {key}"),
        posted_by: "test".to_string(),
        idempotency_key: key.to_string(),
        source,
        reversal_of_entry_id: None,
        lines,
    }
}

fn simple_lines(debit_account: Uuid, credit_account: Uuid, cents: i64) -> Vec<JournalLine> {
    vec![
        JournalLine::debit(debit_account, cents, "EUR"),
        JournalLine::credit(credit_account, cents, "EUR"),
    ]
}

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .expect("count")
}

// ---------------------------------------------------------------------------
// 1. Unbalanced journal cannot be posted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unbalanced_journal_cannot_be_posted() {
    let Some(pool) = provision("acct_unbalanced").await else {
        return;
    };
    let tag = format!("unbalanced-{}", run_tag());
    let seed = seed(&pool, &tag, false).await;
    let ar = account(&pool, seed.entity, ROLE_AR).await;
    let revenue = account(&pool, seed.entity, ROLE_REVENUE).await;

    // (a) The posting API refuses before writing anything.
    let lines = vec![
        JournalLine::debit(ar, 100, "EUR"),
        JournalLine::credit(revenue, 99, "EUR"),
    ];
    let error = posting::post_journal_entry(
        &pool,
        &request(
            &seed,
            &format!("{tag}-api"),
            EntryType::Standard,
            lines,
            None,
        ),
    )
    .await
    .expect_err("unbalanced must be refused");
    assert!(
        matches!(
            error,
            AccountingError::Unbalanced {
                debit_cents: 100,
                credit_cents: 99
            }
        ),
        "expected Unbalanced, got {error:?}"
    );
    assert_eq!(
        count(
            &pool,
            &format!(
                "SELECT COUNT(*) FROM journal_entries WHERE legal_entity_id = '{}'",
                seed.entity
            )
        )
        .await,
        0
    );

    // (b) The DEFERRED CONSTRAINT TRIGGER refuses even a raw-SQL writer at
    // commit time — the structural backstop. A raw writer must post via the
    // draft → lines → posted sequence (lines cannot be added to a posted
    // entry), exactly like the API.
    let mut tx = pool.begin().await.expect("tx");
    let hash = evidence_hash(&["raw-unbalanced"]);
    let entry_id: Uuid = sqlx::query_scalar(
        "INSERT INTO journal_entries (legal_entity_id, fiscal_period_id, entry_date, entry_type, \
            memo, source_hash, idempotency_key) \
         VALUES ($1, $2, $3, 'standard', 'raw', $4, $5) RETURNING id",
    )
    .bind(seed.entity)
    .bind(seed.period)
    .bind(date(2026, 6, 15))
    .bind(&hash)
    .bind(format!("{tag}-raw"))
    .fetch_one(&mut *tx)
    .await
    .expect("entry insert");
    sqlx::query(
        "INSERT INTO journal_lines (entry_id, line_no, account_id, debit_cents, credit_cents, currency) \
         VALUES ($1, 1, $2, 100, 0, 'EUR'), ($1, 2, $3, 0, 50, 'EUR')",
    )
    .bind(entry_id)
    .bind(ar)
    .bind(revenue)
    .execute(&mut *tx)
    .await
    .expect("line insert");
    sqlx::query("UPDATE journal_entries SET posted_at = NOW(), posted_by = 'raw' WHERE id = $1")
        .bind(entry_id)
        .execute(&mut *tx)
        .await
        .expect("post transition");
    let commit = tx.commit().await;
    assert!(commit.is_err(), "unbalanced commit must be refused");
    assert_eq!(
        count(
            &pool,
            &format!(
                "SELECT COUNT(*) FROM journal_entries WHERE legal_entity_id = '{}'",
                seed.entity
            )
        )
        .await,
        0,
        "the refused transaction must have rolled back"
    );
}

// ---------------------------------------------------------------------------
// 2. Posted entries are immutable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn posted_entry_cannot_be_mutated() {
    let Some(pool) = provision("acct_immutable").await else {
        return;
    };
    let tag = format!("immutable-{}", run_tag());
    let seed = seed(&pool, &tag, false).await;
    let ar = account(&pool, seed.entity, ROLE_AR).await;
    let revenue = account(&pool, seed.entity, ROLE_REVENUE).await;

    let key = format!("{tag}-1");
    let outcome = posting::post_journal_entry(
        &pool,
        &request(
            &seed,
            &key,
            EntryType::Standard,
            simple_lines(ar, revenue, 500),
            None,
        ),
    )
    .await
    .expect("post");
    assert_eq!(outcome.status, PostStatus::Posted);
    let entry_id = outcome.entry_id.expect("entry id");

    // UPDATE of the posted header is refused.
    let update = sqlx::query("UPDATE journal_entries SET memo = 'tampered' WHERE id = $1")
        .bind(entry_id)
        .execute(&pool)
        .await;
    assert!(update.is_err(), "posted entry UPDATE must be refused");
    assert!(AccountingError::Db(update.unwrap_err())
        .to_string()
        .contains("immutable"));

    // DELETE of the posted header is refused.
    let delete = sqlx::query("DELETE FROM journal_entries WHERE id = $1")
        .bind(entry_id)
        .execute(&pool)
        .await;
    assert!(delete.is_err(), "posted entry DELETE must be refused");

    // Changing a posted line is refused.
    let line_update =
        sqlx::query("UPDATE journal_lines SET debit_cents = debit_cents + 1 WHERE entry_id = $1")
            .bind(entry_id)
            .execute(&pool)
            .await;
    assert!(line_update.is_err(), "posted line UPDATE must be refused");

    let line_delete = sqlx::query("DELETE FROM journal_lines WHERE entry_id = $1")
        .bind(entry_id)
        .execute(&pool)
        .await;
    assert!(line_delete.is_err(), "posted line DELETE must be refused");

    let line_insert = sqlx::query(
        "INSERT INTO journal_lines (entry_id, line_no, account_id, debit_cents, credit_cents, currency) \
         VALUES ($1, 99, $2, 1, 0, 'EUR')",
    )
    .bind(entry_id)
    .bind(ar)
    .execute(&pool)
    .await;
    assert!(
        line_insert.is_err(),
        "line INSERT into a posted entry must be refused"
    );

    // The entry survived untouched.
    let (memo, line_count): (String, i64) = sqlx::query_as(
        "SELECT e.memo, (SELECT COUNT(*) FROM journal_lines l WHERE l.entry_id = e.id)::bigint \
         FROM journal_entries e WHERE e.id = $1",
    )
    .bind(entry_id)
    .fetch_one(&pool)
    .await
    .expect("read back");
    assert_eq!(memo, format!("test {key}"));
    assert_eq!(line_count, 2);
}

// ---------------------------------------------------------------------------
// 3. A correction is a reversal pair
// ---------------------------------------------------------------------------

#[tokio::test]
async fn correction_is_a_reversal_pair() {
    let Some(pool) = provision("acct_reversal").await else {
        return;
    };
    let tag = format!("reversal-{}", run_tag());
    let seed = seed(&pool, &tag, false).await;
    let ar = account(&pool, seed.entity, ROLE_AR).await;
    let revenue = account(&pool, seed.entity, ROLE_REVENUE).await;

    let original = posting::post_journal_entry(
        &pool,
        &request(
            &seed,
            &format!("{tag}-original"),
            EntryType::Standard,
            simple_lines(ar, revenue, 1000),
            None,
        ),
    )
    .await
    .expect("post original")
    .entry_id
    .expect("entry");

    let reversal = posting::reverse_entry(
        &pool,
        &ReversalRequest {
            entry_id: original,
            entry_date: date(2026, 6, 16),
            memo: "wrong account".to_string(),
            posted_by: "test".to_string(),
        },
    )
    .await
    .expect("reverse");
    let reversal_id = reversal.entry_id.expect("reversal entry");

    let (entry_type, reversal_of): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT entry_type::text, reversal_of_entry_id FROM journal_entries WHERE id = $1",
    )
    .bind(reversal_id)
    .fetch_one(&pool)
    .await
    .expect("read reversal");
    assert_eq!(entry_type, "reversal");
    assert_eq!(reversal_of, Some(original));

    // The pair nets to zero: the reversal mirrors the original's lines.
    let original_lines: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT debit_cents, credit_cents FROM journal_lines WHERE entry_id = $1 ORDER BY line_no",
    )
    .bind(original)
    .fetch_all(&pool)
    .await
    .expect("original lines");
    let reversal_lines: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT debit_cents, credit_cents FROM journal_lines WHERE entry_id = $1 ORDER BY line_no",
    )
    .bind(reversal_id)
    .fetch_all(&pool)
    .await
    .expect("reversal lines");
    assert_eq!(original_lines.len(), reversal_lines.len());
    for (original_line, reversal_line) in original_lines.iter().zip(reversal_lines.iter()) {
        assert_eq!(
            (original_line.0, original_line.1),
            (reversal_line.1, reversal_line.0)
        );
    }

    // Net movement over the pair is zero.
    let net: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(debit_cents - credit_cents),0)::bigint FROM journal_lines \
         WHERE entry_id IN ($1, $2)",
    )
    .bind(original)
    .bind(reversal_id)
    .fetch_one(&pool)
    .await
    .expect("net");
    assert_eq!(net, 0);

    // Reversing again is an idempotent replay, not a second pair.
    let again = posting::reverse_entry(
        &pool,
        &ReversalRequest {
            entry_id: original,
            entry_date: date(2026, 6, 17),
            memo: "retry".to_string(),
            posted_by: "test".to_string(),
        },
    )
    .await
    .expect("replay reversal");
    assert_eq!(again.status, PostStatus::AlreadyPosted);
    assert_eq!(again.entry_id, Some(reversal_id));
    assert_eq!(
        count(
            &pool,
            &format!(
                "SELECT COUNT(*) FROM journal_entries \
                 WHERE reversal_of_entry_id IS NOT NULL AND legal_entity_id = '{}'",
                seed.entity
            )
        )
        .await,
        1
    );

    // The original remains immutable after reversal.
    let tamper = sqlx::query("UPDATE journal_entries SET memo = 'x' WHERE id = $1")
        .bind(original)
        .execute(&pool)
        .await;
    assert!(tamper.is_err());
}

// ---------------------------------------------------------------------------
// 4. Replaying a source document posts once
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replaying_source_document_posts_once() {
    let Some(pool) = provision("acct_replay").await else {
        return;
    };
    let tag = format!("replay-{}", run_tag());
    let seed = seed(&pool, &tag, false).await;
    let ar = account(&pool, seed.entity, ROLE_AR).await;
    let revenue = account(&pool, seed.entity, ROLE_REVENUE).await;

    let source = SourceIdentity::new(
        "invoice",
        "invoices",
        &format!("replay-doc-{tag}"),
        date(2026, 6, 15),
        "EUR",
        1200,
        serde_json::json!({"total_cents": 1200}),
    );

    let first = posting::post_journal_entry(
        &pool,
        &request(
            &seed,
            &format!("{tag}-key"),
            EntryType::Standard,
            simple_lines(ar, revenue, 1200),
            Some(source.clone()),
        ),
    )
    .await
    .expect("first post");
    assert_eq!(first.status, PostStatus::Posted);

    // Exact replay (Stripe webhook redelivery / invoice retry): no new entry.
    let second = posting::post_journal_entry(
        &pool,
        &request(
            &seed,
            &format!("{tag}-key"),
            EntryType::Standard,
            simple_lines(ar, revenue, 1200),
            Some(source.clone()),
        ),
    )
    .await
    .expect("replay");
    assert_eq!(second.status, PostStatus::AlreadyPosted);
    assert_eq!(second.entry_id, first.entry_id);

    assert_eq!(
        count(
            &pool,
            &format!(
                "SELECT COUNT(*) FROM journal_entries WHERE legal_entity_id = '{}'",
                seed.entity
            )
        )
        .await,
        1,
        "replay must not create a second entry"
    );
    assert_eq!(
        count(
            &pool,
            &format!(
                "SELECT COUNT(*) FROM accounting_source_documents WHERE legal_entity_id = '{}'",
                seed.entity
            )
        )
        .await,
        1,
        "replay must not create a second source document"
    );

    // Same source identity with different evidence is a divergent replay.
    let divergent = SourceIdentity::new(
        "invoice",
        "invoices",
        &format!("replay-doc-{tag}"),
        date(2026, 6, 15),
        "EUR",
        9999,
        serde_json::json!({"total_cents": 9999}),
    );
    let error = posting::post_journal_entry(
        &pool,
        &request(
            &seed,
            &format!("{tag}-key-2"),
            EntryType::Standard,
            simple_lines(ar, revenue, 9999),
            Some(divergent),
        ),
    )
    .await
    .expect_err("divergent hash must be refused");
    assert!(
        matches!(error, AccountingError::SourceHashMismatch { .. }),
        "expected SourceHashMismatch, got {error:?}"
    );
    assert_eq!(
        count(
            &pool,
            &format!(
                "SELECT COUNT(*) FROM journal_entries WHERE legal_entity_id = '{}'",
                seed.entity
            )
        )
        .await,
        1
    );
}

// ---------------------------------------------------------------------------
// 5. A closed period refuses a new posting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn closed_period_refuses_new_posting() {
    let Some(pool) = provision("acct_closed").await else {
        return;
    };
    let tag = format!("closed-{}", run_tag());
    let seed = seed(&pool, &tag, false).await;
    let ar = account(&pool, seed.entity, ROLE_AR).await;
    let revenue = account(&pool, seed.entity, ROLE_REVENUE).await;

    posting::post_journal_entry(
        &pool,
        &request(
            &seed,
            &format!("{tag}-before"),
            EntryType::Standard,
            simple_lines(ar, revenue, 700),
            None,
        ),
    )
    .await
    .expect("post before close");

    let report = periods::close_period(&pool, seed.period, "test")
        .await
        .expect("close");
    assert_eq!(report.status, "closed");
    assert_eq!(report.debit_cents, report.credit_cents);

    let refused = posting::post_journal_entry(
        &pool,
        &request(
            &seed,
            &format!("{tag}-after"),
            EntryType::Standard,
            simple_lines(ar, revenue, 10),
            None,
        ),
    )
    .await;
    assert!(refused.is_err(), "posting into a closed period must fail");

    // Close again is refused; reopening is impossible.
    assert!(periods::close_period(&pool, seed.period, "test")
        .await
        .is_err());
    let reopen = sqlx::query("UPDATE fiscal_periods SET status = 'open' WHERE id = $1")
        .bind(seed.period)
        .execute(&pool)
        .await;
    assert!(reopen.is_err(), "closed period must not reopen");

    // Lock is the terminal state.
    let locked = periods::lock_period(&pool, seed.period, "test")
        .await
        .expect("lock");
    assert_eq!(locked.status, "locked");
    let (status, locked_flag): (String, bool) =
        sqlx::query_as("SELECT status, locked FROM fiscal_periods WHERE id = $1")
            .bind(seed.period)
            .fetch_one(&pool)
            .await
            .expect("period read back");
    assert_eq!(status, "locked");
    assert!(locked_flag);

    // Every close/lock run is audited.
    let runs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM period_close_runs WHERE fiscal_period_id = $1",
    )
    .bind(seed.period)
    .fetch_one(&pool)
    .await
    .expect("runs");
    assert_eq!(runs, 2);
}

// ---------------------------------------------------------------------------
// 6. The invariants hold over 100 randomized postings
// ---------------------------------------------------------------------------

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

#[tokio::test]
async fn randomized_100_postings_hold_invariants() {
    let Some(pool) = provision("acct_random100").await else {
        return;
    };
    let tag = format!("random100-{}", run_tag());
    let seed = seed(&pool, &tag, false).await;

    let mut conn = pool.acquire().await.expect("conn");
    let accounts: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM chart_of_accounts WHERE legal_entity_id = $1 ORDER BY code",
    )
    .bind(seed.entity)
    .fetch_all(&mut *conn)
    .await
    .expect("accounts");
    drop(conn);

    let mut rng = Lcg(0x5EED_1234);
    for index in 0..100u32 {
        let debit = accounts[(rng.next() as usize) % accounts.len()];
        let credit = accounts[(rng.next() as usize) % accounts.len()];
        let cents = (rng.next() % 100_000) as i64 + 1;
        let outcome = posting::post_journal_entry(
            &pool,
            &request(
                &seed,
                &format!("{tag}-random-{index}"),
                EntryType::Standard,
                simple_lines(debit, credit, cents),
                None,
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("random posting {index} failed: {error}"));
        assert_eq!(outcome.status, PostStatus::Posted);
    }

    assert_eq!(
        count(
            &pool,
            &format!(
                "SELECT COUNT(*) FROM journal_entries \
                 WHERE posted_at IS NOT NULL AND legal_entity_id = '{}'",
                seed.entity
            )
        )
        .await,
        100
    );

    // Invariant 1: every posted entry balances.
    let unbalanced: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM ( \
                 SELECT l.entry_id FROM journal_lines l \
                 JOIN journal_entries e ON e.id = l.entry_id \
                 WHERE e.posted_at IS NOT NULL AND e.legal_entity_id = $1 \
                 GROUP BY l.entry_id \
                 HAVING SUM(l.debit_cents) <> SUM(l.credit_cents) \
             ) broken",
    )
    .bind(seed.entity)
    .fetch_one(&pool)
    .await
    .expect("broken count");
    assert_eq!(unbalanced, 0, "no posted entry may be unbalanced");

    // Global debit == credit, and the trial balance closes to zero.
    let (debit, credit): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(l.debit_cents),0)::bigint, COALESCE(SUM(l.credit_cents),0)::bigint \
         FROM journal_lines l JOIN journal_entries e ON e.id = l.entry_id \
         WHERE e.posted_at IS NOT NULL AND e.legal_entity_id = $1",
    )
    .bind(seed.entity)
    .fetch_one(&pool)
    .await
    .expect("globals");
    assert_eq!(debit, credit);

    let mut conn = pool.acquire().await.expect("conn");
    let trial = derive::trial_balance(&mut *conn, seed.entity, seed.period)
        .await
        .expect("trial balance");
    let net: i64 = trial.iter().map(|row| row.balance_debit_positive).sum();
    assert_eq!(net, 0, "trial balance must close to zero");

    // Invariant 2: a random posted entry is immutable.
    let victim: Uuid = sqlx::query_scalar(
        "SELECT id FROM journal_entries \
         WHERE posted_at IS NOT NULL AND legal_entity_id = $1 \
         ORDER BY entry_no LIMIT 1 OFFSET $2",
    )
    .bind(seed.entity)
    .bind((rng.next() % 100) as i64)
    .fetch_one(&pool)
    .await
    .expect("victim");
    let tamper = sqlx::query("UPDATE journal_entries SET memo = 'tampered' WHERE id = $1")
        .bind(victim)
        .execute(&pool)
        .await;
    assert!(tamper.is_err(), "posted entries stay immutable");
}

// ---------------------------------------------------------------------------
// 7. Retention-class records are excluded from ordinary customer deletion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retention_class_excludes_ordinary_customer_deletion() {
    let Some(pool) = provision("acct_retention").await else {
        return;
    };
    let tag = format!("retention-{}", run_tag());
    let seed = seed(&pool, &tag, false).await;
    let ar = account(&pool, seed.entity, ROLE_AR).await;
    let revenue = account(&pool, seed.entity, ROLE_REVENUE).await;

    // A posted entry is a legal_7y record.
    let posted = posting::post_journal_entry(
        &pool,
        &request(
            &seed,
            &format!("{tag}-1"),
            EntryType::Standard,
            simple_lines(ar, revenue, 300),
            None,
        ),
    )
    .await
    .expect("post");
    let entry_id = posted.entry_id.expect("entry");

    let class: String =
        sqlx::query_scalar("SELECT retention_class FROM journal_entries WHERE id = $1")
            .bind(entry_id)
            .fetch_one(&pool)
            .await
            .expect("class");
    assert_eq!(class, RETENTION_LEGAL_7Y);
    assert!(retention::is_statutory(&class));

    // The catalogue records the seven-year floor.
    let mut conn = pool.acquire().await.expect("conn");
    let classes = retention::retention_classes(&mut conn)
        .await
        .expect("classes");
    let legal_7y = classes
        .iter()
        .find(|(code, _)| code == RETENTION_LEGAL_7Y)
        .expect("legal_7y class");
    assert!(legal_7y.1 >= 7, "statutory class must be >= 7 years");

    // Ordinary deletion of a retention-protected record is refused.
    let customer: Uuid = sqlx::query_scalar(
        "INSERT INTO customers (legal_entity_id, tenant_id, name) VALUES ($1, $2, 'Acme') RETURNING id",
    )
    .bind(seed.entity)
    .bind(format!("tenant-{tag}"))
    .fetch_one(&pool)
    .await
    .expect("customer");

    let delete = sqlx::query("DELETE FROM customers WHERE id = $1")
        .bind(customer)
        .execute(&pool)
        .await;
    let error = delete.expect_err("retention-protected customer DELETE must be refused");
    let code = error
        .as_database_error()
        .and_then(|db| db.code().map(|c| c.to_string()))
        .unwrap_or_default();
    assert_eq!(code, "23001", "expected restrict_violation, got {code}");
    let still_there: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM customers WHERE id = $1")
            .bind(customer)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(still_there, 1, "the row must survive the refused deletion");

    // The guard is bypassable only through the explicit audited override.
    let mut tx = pool.begin().await.expect("tx");
    retention::set_retention_override(&mut tx)
        .await
        .expect("override");
    sqlx::query("DELETE FROM customers WHERE id = $1")
        .bind(customer)
        .execute(&mut *tx)
        .await
        .expect("override delete");
    tx.rollback().await.expect("rollback");
}

// ---------------------------------------------------------------------------
// 8. Adapters: invoice, settlement, credit note/refund, payroll, bank, expense
//
// All adapters resolve the DEFAULT legal entity, so this suite shares one
// (persistent) default entity and makes every assertion relative to a
// baseline / scoped to this run's source ids.
// ---------------------------------------------------------------------------

const TENANT: &str = "01TESTTENANT0000000000001";

async fn ensure_tenant(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO tenants (id, name, settings) \
         VALUES ($1, 'Acme OÜ', '{\"registryCode\":\"87654321\"}') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(TENANT)
    .execute(pool)
    .await
    .expect("tenant");
    sqlx::query(
        "INSERT INTO billing_addresses (tenant_id, company_name, vat_number, country) \
         SELECT $1, 'Acme OÜ', 'EE999999999', 'EE' \
         WHERE NOT EXISTS (SELECT 1 FROM billing_addresses WHERE tenant_id = $1)",
    )
    .bind(TENANT)
    .execute(pool)
    .await
    .expect("billing address");
}

async fn insert_invoice(pool: &PgPool, invoice_id: Uuid, paid: bool, number: &str) {
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, status, currency, amount, subtotal, vat_total, total, \
            vat_rate, issued_at, due_at, invoice_number, line_items) \
         VALUES ($1, $2, $3, 'EUR', 12400, 10000, 2400, 12400, 24.0, NOW(), NOW() + INTERVAL '30 days', \
                 $4, $5)",
    )
    .bind(invoice_id)
    .bind(TENANT)
    .bind(if paid { "paid" } else { "pending" })
    .bind(number)
    .bind(serde_json::json!([]))
    .execute(pool)
    .await
    .expect("invoice");
}

#[tokio::test]
async fn adapters_post_idempotently_and_feed_derivation() {
    let Some(pool) = provision("acct_adapters").await else {
        return;
    };
    let tag = run_tag().to_string();
    let seed = seed(&pool, "adapters", true).await;
    ensure_tenant(&pool).await;

    let baseline = {
        let mut conn = pool.acquire().await.expect("conn");
        derive::vat_totals_for_period(&mut *conn, seed.entity, seed.period)
            .await
            .expect("baseline vat")
    };

    // ── Invoice finalization + Stripe settlement ────────────────────────
    let invoice_id = Uuid::new_v4();
    insert_invoice(&pool, invoice_id, false, &format!("INV-{tag}-1")).await;

    let first = adapters::post_invoice_issued(&pool, invoice_id)
        .await
        .expect("invoice posting");
    assert_eq!(first.status, PostStatus::Posted);
    let invoice_entry = first.entry_id.expect("entry");

    // Revenue/AR/VAT lines.
    let balances: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT a.account_role, COALESCE(SUM(l.debit_cents),0)::bigint, COALESCE(SUM(l.credit_cents),0)::bigint \
         FROM journal_lines l JOIN chart_of_accounts a ON a.id = l.account_id \
         WHERE l.entry_id = $1 GROUP BY a.account_role ORDER BY a.account_role",
    )
    .bind(invoice_entry)
    .fetch_all(&pool)
    .await
    .expect("balances");
    assert!(balances.contains(&(ROLE_AR.to_string(), 12400, 0)));
    assert!(balances.contains(&(ROLE_REVENUE.to_string(), 0, 10000)));
    assert!(balances.contains(&(ROLE_VAT_OUTPUT.to_string(), 0, 2400)));

    // Derivation read contract: the KMD total moved by exactly this invoice.
    let totals = {
        let mut conn = pool.acquire().await.expect("conn");
        derive::vat_totals_for_period(&mut *conn, seed.entity, seed.period)
            .await
            .expect("vat totals")
    };
    assert_eq!(totals.output_base_cents, baseline.output_base_cents + 10000);
    assert_eq!(totals.output_vat_cents, baseline.output_vat_cents + 2400);
    let vat_rows = {
        let mut conn = pool.acquire().await.expect("conn");
        derive::vat_entries_for_period(&mut *conn, seed.entity, seed.period)
            .await
            .expect("vat rows")
    };
    let invoice_vat = vat_rows
        .iter()
        .find(|row| row.journal_entry_id == invoice_entry)
        .expect("invoice VAT row");
    assert_eq!(invoice_vat.source_type.as_deref(), Some("invoice"));
    assert_eq!(invoice_vat.net_cents, Some(10000));
    assert_eq!(invoice_vat.vat_cents, Some(2400));

    // Replaying the finalization posts once.
    let replay = adapters::post_invoice_issued(&pool, invoice_id)
        .await
        .expect("replay");
    assert_eq!(replay.status, PostStatus::AlreadyPosted);
    assert_eq!(replay.entry_id, first.entry_id);

    let operation_id = format!("stripe:{tag}");
    sqlx::query(
        "INSERT INTO invoice_payment_allocations (tenant_id, invoice_id, operation_id, source, amount_cents, currency) \
         VALUES ($1, $2, $3, 'stripe', 12400, 'EUR')",
    )
    .bind(TENANT)
    .bind(invoice_id)
    .bind(&operation_id)
    .execute(&pool)
    .await
    .expect("allocation");

    let settlement = adapters::post_payment_allocation(&pool, &operation_id)
        .await
        .expect("settlement posting");
    assert_eq!(settlement.status, PostStatus::Posted);
    let settlement_replay = adapters::post_payment_allocation(&pool, &operation_id)
        .await
        .expect("settlement replay");
    assert_eq!(settlement_replay.status, PostStatus::AlreadyPosted);

    // AR is fully settled in the subledger; the ledger AR nets to zero for
    // THIS invoice (the settlement credits exactly what finalization
    // debited). Scoped to the two entries so the (persistent) shared
    // database cannot add unrelated bank receipts.
    let (settled, status): (i64, String) = sqlx::query_as(
        "SELECT settled_cents, status FROM accounts_receivable WHERE invoice_id = $1",
    )
    .bind(invoice_id)
    .fetch_one(&pool)
    .await
    .expect("AR");
    assert_eq!(settled, 12400);
    assert_eq!(status, "settled");
    let settlement_entry = settlement.entry_id.expect("settlement entry");
    let ar_net: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(l.debit_cents - l.credit_cents),0)::bigint \
         FROM journal_lines l JOIN chart_of_accounts a ON a.id = l.account_id \
         WHERE a.account_role = 'ar' AND l.entry_id IN ($1, $2)",
    )
    .bind(invoice_entry)
    .bind(settlement_entry)
    .fetch_one(&pool)
    .await
    .expect("AR net");
    assert_eq!(ar_net, 0, "settlement must clear the receivable");

    // ── Credit note / refund ────────────────────────────────────────────
    let credit_invoice = Uuid::new_v4();
    insert_invoice(&pool, credit_invoice, true, &format!("INV-{tag}-2")).await;
    let note_id: Uuid = sqlx::query_scalar(
        "INSERT INTO credit_notes (invoice_id, tenant_id, amount, currency, reason, idempotency_key, \
            operation_id, debt_reduction_cents, refunded_cents) \
         VALUES ($1, $2, 2400, 'EUR', 'goodwill', $3, $4, 0, 2400) RETURNING id",
    )
    .bind(credit_invoice)
    .bind(TENANT)
    .bind(format!("idem-cn-{tag}"))
    .bind(format!("credit_note:{tag}:1"))
    .fetch_one(&pool)
    .await
    .expect("credit note");

    let outcomes = adapters::post_credit_note(&pool, note_id)
        .await
        .expect("credit note posting");
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[1].status, PostStatus::Posted, "refund part posts");
    let refund_entry = outcomes[1].entry_id.expect("refund entry");

    // Refund: Dr refunds (net) + Dr VAT (proportional), Cr wallet liability.
    let wallet_credit: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(l.credit_cents),0)::bigint FROM journal_lines l \
         JOIN chart_of_accounts a ON a.id = l.account_id \
         WHERE l.entry_id = $1 AND a.account_role = 'wallet_liability'",
    )
    .bind(refund_entry)
    .fetch_one(&pool)
    .await
    .expect("wallet");
    assert_eq!(wallet_credit, 2400);
    let debit_sum: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(debit_cents),0)::bigint FROM journal_lines WHERE entry_id = $1",
    )
    .bind(refund_entry)
    .fetch_one(&pool)
    .await
    .expect("debits");
    assert_eq!(debit_sum, 2400);

    let replay = adapters::post_credit_note(&pool, note_id)
        .await
        .expect("replay");
    assert!(replay
        .iter()
        .all(|outcome| outcome.status != PostStatus::Posted));

    // The refund reduced the VAT base by exactly its proportional share.
    let refunded_vat = {
        let mut conn = pool.acquire().await.expect("conn");
        derive::vat_totals_for_period(&mut *conn, seed.entity, seed.period)
            .await
            .expect("vat")
    };
    assert_eq!(
        refunded_vat.output_base_cents,
        totals.output_base_cents - 1935
    );
    assert_eq!(refunded_vat.output_vat_cents, totals.output_vat_cents - 465);

    // ── Payroll ─────────────────────────────────────────────────────────
    let record_id: Uuid = sqlx::query_scalar(
        "INSERT INTO payroll_records (employee_name, personal_code, gross_salary_cents, \
            funded_pension_rate, pay_period) \
         VALUES ('Mari Maasikas', 'EST-1', 200000, 0.02, TIMESTAMPTZ '2026-06-30 12:00:00+00') \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("payroll record");

    let amounts = PayrollAmounts {
        income_tax_cents: 52_000,
        social_tax_cents: 66_000,
        unemployment_employee_cents: 3_200,
        unemployment_employer_cents: 1_600,
        pension_cents: 4_000,
        net_cents: 140_800,
    };
    let payroll = adapters::post_payroll_record(&pool, seed.entity, record_id, amounts)
        .await
        .expect("payroll posting");
    assert_eq!(payroll.status, PostStatus::Posted);
    let payroll_entry = payroll.entry_id.expect("entry");
    let replay = adapters::post_payroll_record(&pool, seed.entity, record_id, amounts)
        .await
        .expect("payroll replay");
    assert_eq!(replay.status, PostStatus::AlreadyPosted);
    let posting_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM payroll_postings WHERE payroll_record_id = $1",
    )
    .bind(record_id)
    .fetch_one(&pool)
    .await
    .expect("payroll postings");
    assert_eq!(posting_rows, 1);

    let (debit, credit): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(debit_cents),0)::bigint, COALESCE(SUM(credit_cents),0)::bigint \
         FROM journal_lines WHERE entry_id = $1",
    )
    .bind(payroll_entry)
    .fetch_one(&pool)
    .await
    .expect("payroll lines");
    assert_eq!((debit, credit), (267_600, 267_600));

    let tsd = {
        let mut conn = pool.acquire().await.expect("conn");
        derive::payroll_taxes_for_period(&mut *conn, seed.entity, seed.period)
            .await
            .expect("tsd")
    };
    let row = tsd
        .iter()
        .find(|row| row.payroll_record_id == record_id)
        .expect("TSD row for this payroll record");
    assert_eq!(row.gross_cents, 200_000);
    assert_eq!(row.income_tax_cents, 52_000);
    assert_eq!(row.journal_entry_id, Some(payroll_entry));

    // ── Bank statement lines ────────────────────────────────────────────
    let bank_account = account(&pool, seed.entity, ROLE_BANK).await;
    let bank_account_id: Uuid = sqlx::query_scalar(
        "INSERT INTO bank_accounts (legal_entity_id, name, iban, currency, account_id) \
         VALUES ($1, 'Main', $2, 'EUR', $3) RETURNING id",
    )
    .bind(seed.entity)
    .bind(format!("EE00{tag}0000000000"))
    .bind(bank_account)
    .fetch_one(&pool)
    .await
    .expect("bank account");

    let receipt: Uuid = sqlx::query_scalar(
        "INSERT INTO bank_statement_lines (bank_account_id, external_id, statement_date, amount_cents, currency, reference) \
         VALUES ($1, $2, DATE '2026-06-20', 5000, 'EUR', 'INV') RETURNING id",
    )
    .bind(bank_account_id)
    .bind(format!("stmt-{tag}-1"))
    .fetch_one(&pool)
    .await
    .expect("receipt line");
    let payment: Uuid = sqlx::query_scalar(
        "INSERT INTO bank_statement_lines (bank_account_id, external_id, statement_date, amount_cents, currency, reference) \
         VALUES ($1, $2, DATE '2026-06-21', -2000, 'EUR', 'Hetzner') RETURNING id",
    )
    .bind(bank_account_id)
    .bind(format!("stmt-{tag}-2"))
    .fetch_one(&pool)
    .await
    .expect("payment line");

    let receipt_outcome = adapters::post_bank_statement_line(&pool, receipt)
        .await
        .expect("receipt posting");
    assert_eq!(receipt_outcome.status, PostStatus::Posted);
    let receipt_replay = adapters::post_bank_statement_line(&pool, receipt)
        .await
        .expect("receipt replay");
    assert_eq!(receipt_replay.status, PostStatus::AlreadyPosted);

    let payment_outcome = adapters::post_bank_statement_line(&pool, payment)
        .await
        .expect("payment posting");
    assert_eq!(payment_outcome.status, PostStatus::Posted);

    let stamped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM bank_statement_lines \
         WHERE journal_entry_id IS NOT NULL AND id IN ($1, $2)",
    )
    .bind(receipt)
    .bind(payment)
    .fetch_one(&pool)
    .await
    .expect("stamped");
    assert_eq!(stamped, 2);

    // ── Expenses ────────────────────────────────────────────────────────
    // No canonical `operating_costs` table exists in the migration chain —
    // the adapter must report the gap, not silently drop the expense. (The
    // check is conditional because the shared test database may already
    // carry the table from a previous run of this suite.)
    let table_exists: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.operating_costs')::text")
            .fetch_one(&pool)
            .await
            .expect("regclass");
    if table_exists.is_none() {
        let missing = adapters::post_operating_cost(&pool, seed.entity, Uuid::new_v4()).await;
        assert!(
            matches!(missing, Err(AccountingError::SourceTableMissing(ref table)) if table == "operating_costs"),
            "expected SourceTableMissing, got {missing:?}"
        );
    }

    // When a deployment provisions the optional expense store, posting works.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS operating_costs ( \
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(), \
            category TEXT, \
            amount_cents BIGINT NOT NULL, \
            incurred_at TIMESTAMPTZ NOT NULL)",
    )
    .execute(&pool)
    .await
    .expect("optional expense table");
    let cost_id: Uuid = sqlx::query_scalar(
        "INSERT INTO operating_costs (category, amount_cents, incurred_at) \
         VALUES ('infrastructure', 4500, TIMESTAMPTZ '2026-06-10 00:00:00+00') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("cost");

    let outcome = adapters::post_operating_cost(&pool, seed.entity, cost_id)
        .await
        .expect("expense posting");
    assert_eq!(outcome.status, PostStatus::Posted);
    let balances: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT a.account_role, COALESCE(SUM(l.debit_cents),0)::bigint, COALESCE(SUM(l.credit_cents),0)::bigint \
         FROM journal_lines l JOIN chart_of_accounts a ON a.id = l.account_id \
         WHERE l.entry_id = $1 GROUP BY a.account_role",
    )
    .bind(outcome.entry_id.expect("entry"))
    .fetch_all(&pool)
    .await
    .expect("expense lines");
    assert!(balances.contains(&(ROLE_EXPENSE_DEFAULT.to_string(), 4500, 0)));
    assert!(balances.contains(&(ROLE_AP.to_string(), 0, 4500)));
}

// ---------------------------------------------------------------------------
// 9. Adversarial: refusal paths write nothing, replay divergence refused,
//    period boundaries are exact, derivation arithmetic is integer-exact.
// ---------------------------------------------------------------------------

/// A rejected posting must leave the ledger byte-identical: no entry, no
/// line, no draft — and a divergent replay of an accepted key must be
/// refused rather than silently attach different lines.
#[tokio::test]
async fn rejected_and_divergent_postings_change_nothing() {
    let Some(pool) = provision("acct_refusals").await else {
        return;
    };
    let tag = run_tag().to_string();
    let seed = seed(&pool, &format!("refusals-{tag}"), false).await;
    let debit = account(&pool, seed.entity, ROLE_AR).await;
    let credit = account(&pool, seed.entity, ROLE_REVENUE).await;

    let entries_before = count(
        &pool,
        &format!(
            "SELECT COUNT(*)::bigint FROM journal_entries WHERE legal_entity_id = '{}'",
            seed.entity
        ),
    )
    .await;
    let lines_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM journal_lines l JOIN journal_entries e ON e.id = l.entry_id \
         WHERE e.legal_entity_id = $1",
    )
    .bind(seed.entity)
    .fetch_one(&pool)
    .await
    .expect("scoped line count");

    // Unbalanced: refused before any write.
    let unbalanced = request(
        &seed,
        &format!("adv-unbalanced-{tag}"),
        EntryType::Standard,
        vec![
            JournalLine::debit(debit, 100, "EUR"),
            JournalLine::credit(credit, 99, "EUR"),
        ],
        None,
    );
    assert!(matches!(
        posting::post_journal_entry(&pool, &unbalanced).await,
        Err(AccountingError::Unbalanced { .. })
    ));

    // Zero lines: refused.
    let empty = request(
        &seed,
        &format!("adv-empty-{tag}"),
        EntryType::Standard,
        vec![],
        None,
    );
    assert!(matches!(
        posting::post_journal_entry(&pool, &empty).await,
        Err(AccountingError::NoLines)
    ));

    // A reversal that does not name the entry it reverses: refused.
    let dangling = request(
        &seed,
        &format!("adv-dangling-reversal-{tag}"),
        EntryType::Reversal,
        simple_lines(debit, credit, 500),
        None,
    );
    assert!(matches!(
        posting::post_journal_entry(&pool, &dangling).await,
        Err(AccountingError::Invalid(message)) if message.contains("must reference")
    ));

    let entries_after = count(
        &pool,
        &format!(
            "SELECT COUNT(*)::bigint FROM journal_entries WHERE legal_entity_id = '{}'",
            seed.entity
        ),
    )
    .await;
    assert_eq!(
        entries_after, entries_before,
        "refused postings must not insert entries"
    );
    let lines_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM journal_lines l JOIN journal_entries e ON e.id = l.entry_id \
         WHERE e.legal_entity_id = $1",
    )
    .bind(seed.entity)
    .fetch_one(&pool)
    .await
    .expect("scoped line count");
    assert_eq!(
        lines_after, lines_before,
        "refused postings must not insert lines"
    );

    // Accepted manual entry: replay is idempotent…
    let accepted = request(
        &seed,
        &format!("adv-accepted-{tag}"),
        EntryType::Standard,
        simple_lines(debit, credit, 1000),
        None,
    );
    let first = posting::post_journal_entry(&pool, &accepted)
        .await
        .expect("accepted posting");
    assert_eq!(first.status, PostStatus::Posted);
    let replay = posting::post_journal_entry(&pool, &accepted)
        .await
        .expect("replay");
    assert_eq!(replay.status, PostStatus::AlreadyPosted);
    assert_eq!(replay.entry_id, first.entry_id);

    // …but a divergent payload under the same key is a conflict, not a
    // second posting of different lines.
    let mut divergent = accepted.clone();
    divergent.lines = simple_lines(debit, credit, 9999);
    assert!(matches!(
        posting::post_journal_entry(&pool, &divergent).await,
        Err(AccountingError::IdempotencyKeyConflict(key)) if key == format!("adv-accepted-{tag}")
    ));

    // A pre-existing DRAFT with the same key must not be silently posted
    // through the adapter path (that would attach the adapter's lines to a
    // hand-written draft).
    let draft_key = format!("adv-draft-{}", run_tag());
    let (draft_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO journal_entries (legal_entity_id, fiscal_period_id, entry_date, entry_type, \
            memo, source_hash, idempotency_key) \
         VALUES ($1, $2, DATE '2026-06-15', 'standard', 'manual draft', $3, $4) RETURNING id",
    )
    .bind(seed.entity)
    .bind(seed.period)
    .bind("0".repeat(64))
    .bind(&draft_key)
    .fetch_one(&pool)
    .await
    .expect("draft insert");
    let mut draft_replay = request(
        &seed,
        &draft_key,
        EntryType::Standard,
        simple_lines(debit, credit, 700),
        None,
    );
    draft_replay.entry_date = date(2026, 6, 15);
    assert!(matches!(
        posting::post_journal_entry(&pool, &draft_replay).await,
        Err(AccountingError::IdempotencyKeyConflict(key)) if key == draft_key
    ));
    let still_draft: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT posted_at FROM journal_entries WHERE id = $1")
            .bind(draft_id)
            .fetch_one(&pool)
            .await
            .expect("draft row");
    assert!(still_draft.is_none(), "the draft must stay a draft");

    // Reversing a draft is refused (delete it instead), reversing a missing
    // entry is a typed error.
    let reverse_draft = posting::reverse_entry(
        &pool,
        &ReversalRequest {
            entry_id: draft_id,
            entry_date: date(2026, 6, 16),
            memo: String::new(),
            posted_by: "test".to_string(),
        },
    )
    .await;
    assert!(matches!(reverse_draft, Err(AccountingError::Invalid(_))));
    let reverse_missing = posting::reverse_entry(
        &pool,
        &ReversalRequest {
            entry_id: Uuid::new_v4(),
            entry_date: date(2026, 6, 16),
            memo: String::new(),
            posted_by: "test".to_string(),
        },
    )
    .await;
    assert!(matches!(
        reverse_missing,
        Err(AccountingError::Invalid(message)) if message.contains("not found")
    ));
    sqlx::query("DELETE FROM journal_entries WHERE id = $1")
        .bind(draft_id)
        .execute(&pool)
        .await
        .expect("draft delete is allowed");

    // Reversal with an empty memo gets the canonical "Reversal of …" memo
    // and is itself replay-safe even when the caller changes the note.
    let posted = posting::post_journal_entry(
        &pool,
        &request(
            &seed,
            &format!("adv-reversal-target-{tag}"),
            EntryType::Standard,
            simple_lines(debit, credit, 4321),
            None,
        ),
    )
    .await
    .expect("target posting");
    let target = posted.entry_id.expect("entry id");
    let reversal = posting::reverse_entry(
        &pool,
        &ReversalRequest {
            entry_id: target,
            entry_date: date(2026, 6, 20),
            memo: "   ".to_string(),
            posted_by: "test".to_string(),
        },
    )
    .await
    .expect("reversal");
    assert_eq!(reversal.status, PostStatus::Posted);
    let (target_no,): (i64,) = sqlx::query_as("SELECT entry_no FROM journal_entries WHERE id = $1")
        .bind(target)
        .fetch_one(&pool)
        .await
        .expect("target row");
    let (memo,): (String,) = sqlx::query_as("SELECT memo FROM journal_entries WHERE id = $1")
        .bind(reversal.entry_id.expect("reversal id"))
        .fetch_one(&pool)
        .await
        .expect("reversal row");
    assert_eq!(memo, format!("Reversal of journal entry #{target_no}"));
    let mut retry = ReversalRequest {
        entry_id: target,
        entry_date: date(2026, 6, 21),
        memo: "a different note".to_string(),
        posted_by: "test".to_string(),
    };
    retry.memo = "a different note".to_string();
    let replay = posting::reverse_entry(&pool, &retry)
        .await
        .expect("reversal replay");
    assert_eq!(replay.status, PostStatus::AlreadyPosted);
    assert_eq!(replay.entry_id, reversal.entry_id);
}

/// Period boundaries: a posting lands in the period covering its date and
/// nowhere else; a leap day is covered exactly once; a closed period refuses
/// new postings; the close/lock state machine runs exactly once.
#[tokio::test]
async fn period_boundaries_are_exact_and_close_lock_transitions_once() {
    let Some(pool) = provision("acct_periods").await else {
        return;
    };
    let seed = seed(&pool, &format!("periods-{}", run_tag()), false).await;
    let debit = account(&pool, seed.entity, ROLE_AR).await;
    let credit = account(&pool, seed.entity, ROLE_REVENUE).await;

    // Adjacent, NON-overlapping periods in years the seed year-period does
    // not cover: January 2027 and leap February 2028 (29 days exactly once).
    let mut conn = pool.acquire().await.expect("conn");
    let jan = periods::ensure_period(
        &mut conn,
        seed.entity,
        "month",
        "2027-01",
        date(2027, 1, 1),
        date(2027, 1, 31),
    )
    .await
    .expect("january");
    let leap_feb = periods::ensure_period(
        &mut conn,
        seed.entity,
        "month",
        "2028-02",
        date(2028, 2, 1),
        date(2028, 2, 29),
    )
    .await
    .expect("leap february");

    // ensure_period is exactly-once: a duplicate returns the same id.
    let jan_again = periods::ensure_period(
        &mut conn,
        seed.entity,
        "month",
        "2027-01-retry",
        date(2027, 1, 1),
        date(2027, 1, 31),
    )
    .await
    .expect("duplicate");
    assert_eq!(jan, jan_again, "duplicate ranges resolve to one period");

    assert!(matches!(
        periods::ensure_period(
            &mut conn,
            seed.entity,
            "fortnight",
            "bogus",
            date(2027, 1, 1),
            date(2027, 1, 14)
        )
        .await,
        Err(AccountingError::Invalid(_))
    ));
    assert!(matches!(
        periods::ensure_period(
            &mut conn,
            seed.entity,
            "month",
            "reversed",
            date(2027, 3, 1),
            date(2027, 2, 1)
        )
        .await,
        Err(AccountingError::Invalid(_))
    ));

    // Exact boundaries: first and last day resolve to their own period; a
    // date outside every period is a typed NoOpenPeriod.
    assert_eq!(
        periods::find_open_period_for_date(&mut conn, seed.entity, date(2027, 1, 1))
            .await
            .expect("jan first day"),
        jan
    );
    assert_eq!(
        periods::find_open_period_for_date(&mut conn, seed.entity, date(2027, 1, 31))
            .await
            .expect("jan last day"),
        jan
    );
    assert_eq!(
        periods::find_open_period_for_date(&mut conn, seed.entity, date(2028, 2, 29))
            .await
            .expect("leap day"),
        leap_feb
    );
    assert!(matches!(
        periods::find_open_period_for_date(&mut conn, seed.entity, date(2028, 3, 1)).await,
        Err(AccountingError::NoOpenPeriod { .. })
    ));

    // Post exactly on both January edges and on the leap day; each lands in
    // its own period exactly once.
    for (period, day, amount) in [
        (jan, date(2027, 1, 1), 101i64),
        (jan, date(2027, 1, 31), 131),
        (leap_feb, date(2028, 2, 29), 229),
    ] {
        let mut req = request(
            &seed,
            &format!("boundary-{day}-{}", run_tag()),
            EntryType::Standard,
            simple_lines(debit, credit, amount),
            None,
        );
        req.fiscal_period_id = period;
        req.entry_date = day;
        let outcome = posting::post_journal_entry(&pool, &req)
            .await
            .unwrap_or_else(|error| panic!("boundary posting {day}: {error}"));
        assert_eq!(outcome.status, PostStatus::Posted);
    }
    let jan_entries: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM journal_entries WHERE fiscal_period_id = $1 AND posted_at IS NOT NULL",
    )
    .bind(jan)
    .fetch_one(&pool)
    .await
    .expect("jan count");
    assert_eq!(jan_entries, 2, "each January posting lands once");
    let leap_entries: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM journal_entries WHERE fiscal_period_id = $1 AND posted_at IS NOT NULL",
    )
    .bind(leap_feb)
    .fetch_one(&pool)
    .await
    .expect("leap count");
    assert_eq!(leap_entries, 1, "the leap day is covered exactly once");

    // A draft in a period blocks its close until it is resolved.
    let (draft_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO journal_entries (legal_entity_id, fiscal_period_id, entry_date, entry_type, \
            memo, source_hash, idempotency_key) \
         VALUES ($1, $2, DATE '2028-02-10', 'standard', 'draft', $3, $4) RETURNING id",
    )
    .bind(seed.entity)
    .bind(leap_feb)
    .bind("0".repeat(64))
    .bind(format!("period-draft-{}", run_tag()))
    .fetch_one(&pool)
    .await
    .expect("draft");
    let blocked = periods::close_period(&pool, leap_feb, "tester").await;
    assert!(
        matches!(blocked, Err(AccountingError::Invalid(ref message)) if message.contains("draft")),
        "a period with a draft cannot close: {blocked:?}"
    );
    sqlx::query("DELETE FROM journal_entries WHERE id = $1")
        .bind(draft_id)
        .execute(&pool)
        .await
        .expect("draft delete");

    // Closing February is refused while it still holds posted entries? No:
    // posted entries are exactly what a close is FOR — it must succeed and
    // report the balanced totals.
    let closed = periods::close_period(&pool, leap_feb, "tester")
        .await
        .expect("close");
    assert_eq!(closed.status, "closed");
    assert_eq!(closed.posted_entries, 1);
    assert_eq!(closed.debit_cents, 229);
    assert_eq!(closed.credit_cents, 229);
    assert_eq!(
        periods::period_status(&mut conn, leap_feb)
            .await
            .expect("status"),
        "closed"
    );
    let close_again = periods::close_period(&pool, leap_feb, "tester").await;
    assert!(matches!(
        close_again,
        Err(AccountingError::PeriodNotOpen { .. })
    ));

    // Posting into a closed period is refused by the period guard and the
    // ledger does not move: re-opening is impossible.
    let closed_entries_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM journal_entries WHERE fiscal_period_id = $1",
    )
    .bind(leap_feb)
    .fetch_one(&pool)
    .await
    .expect("count");
    let mut into_closed = request(
        &seed,
        &format!("closed-period-{}", run_tag()),
        EntryType::Standard,
        simple_lines(debit, credit, 50),
        None,
    );
    into_closed.fiscal_period_id = leap_feb;
    into_closed.entry_date = date(2028, 2, 10);
    let refused = posting::post_journal_entry(&pool, &into_closed).await;
    match &refused {
        Err(error) => assert!(
            error.to_string().contains("not open")
                || accounting_core::error::is_trigger_refusal(error),
            "closed-period posting must be refused by the period guard: {error}"
        ),
        Ok(outcome) => panic!("posting into a closed period succeeded: {outcome:?}"),
    }
    let closed_entries_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM journal_entries WHERE fiscal_period_id = $1",
    )
    .bind(leap_feb)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(closed_entries_before, closed_entries_after);

    // Locking an OPEN period is refused; locking the closed one succeeds and
    // is terminal.
    let lock_open = periods::lock_period(&pool, jan, "tester").await;
    assert!(matches!(
        lock_open,
        Err(AccountingError::PeriodNotOpen { .. })
    ));
    let locked = periods::lock_period(&pool, leap_feb, "tester")
        .await
        .expect("lock");
    assert_eq!(locked.status, "locked");
    let lock_again = periods::lock_period(&pool, leap_feb, "tester").await;
    assert!(matches!(
        lock_again,
        Err(AccountingError::PeriodNotOpen { .. })
    ));
    // A locked period also refuses new postings.
    assert!(posting::post_journal_entry(&pool, &into_closed)
        .await
        .is_err());

    // Close/lock on a missing period: typed error, never a panic.
    assert!(matches!(
        periods::close_period(&pool, Uuid::new_v4(), "tester").await,
        Err(AccountingError::Invalid(_))
    ));
    assert!(matches!(
        periods::lock_period(&pool, Uuid::new_v4(), "tester").await,
        Err(AccountingError::Invalid(_))
    ));
    assert!(matches!(
        periods::period_status(&mut conn, Uuid::new_v4()).await,
        Err(AccountingError::Invalid(_))
    ));
}

/// Derivation arithmetic is integer-exact: VAT totals in cents with no
/// float rounding, period result = revenue − expenses.
#[tokio::test]
async fn derivation_is_integer_exact_with_no_rounding_drift() {
    let Some(pool) = provision("acct_derive").await else {
        return;
    };
    let seed = seed(&pool, &format!("derive-{}", run_tag()), false).await;
    let ar = account(&pool, seed.entity, ROLE_AR).await;
    let revenue = account(&pool, seed.entity, ROLE_REVENUE).await;
    let vat_out = account(&pool, seed.entity, ROLE_VAT_OUTPUT).await;
    let vat_in = account(&pool, seed.entity, ROLE_VAT_INPUT).await;
    let expense = account(&pool, seed.entity, ROLE_EXPENSE_DEFAULT).await;
    let ap = account(&pool, seed.entity, ROLE_AP).await;

    let mut conn = pool.acquire().await.expect("conn");
    let before = derive::vat_totals_for_period(&mut *conn, seed.entity, seed.period)
        .await
        .expect("baseline vat");

    // A sale with odd cents (100 007 = 1000.07 EUR) to catch float rounding:
    // vat = net * rate / 10 000 in integer cents, no drift.
    let net: i64 = 100_007;
    let vat: i64 = (net as i128 * 2400 / 10_000) as i64;
    let total = net + vat;
    let sale = PostJournalRequest {
        legal_entity_id: seed.entity,
        fiscal_period_id: seed.period,
        entry_date: date(2026, 6, 15),
        entry_type: EntryType::Standard,
        memo: "integer-exact sale".to_string(),
        posted_by: "test".to_string(),
        idempotency_key: format!("derive-sale-{}", run_tag()),
        source: None,
        reversal_of_entry_id: None,
        lines: vec![
            JournalLine::debit(ar, total, "EUR"),
            JournalLine::credit(revenue, net, "EUR"),
            JournalLine::credit(vat_out, vat, "EUR").with_vat(
                net,
                vat,
                Some(2400),
                Some("OUTPUT".to_string()),
            ),
        ],
    };
    posting::post_journal_entry(&pool, &sale)
        .await
        .expect("sale posting");

    // A reverse-charged purchase: input VAT on an expense.
    let purchase = PostJournalRequest {
        legal_entity_id: seed.entity,
        fiscal_period_id: seed.period,
        entry_date: date(2026, 6, 16),
        entry_type: EntryType::Standard,
        memo: "integer-exact purchase".to_string(),
        posted_by: "test".to_string(),
        idempotency_key: format!("derive-purchase-{}", run_tag()),
        source: None,
        reversal_of_entry_id: None,
        lines: vec![
            JournalLine::debit(expense, 50_00, "EUR"),
            JournalLine::debit(vat_in, 12_00, "EUR").with_vat(
                50_00,
                12_00,
                Some(2400),
                Some("INPUT".to_string()),
            ),
            JournalLine::credit(ap, 62_00, "EUR"),
        ],
    };
    posting::post_journal_entry(&pool, &purchase)
        .await
        .expect("purchase posting");

    let rows = derive::vat_entries_for_period(&mut *conn, seed.entity, seed.period)
        .await
        .expect("vat entries");
    let output_rows: Vec<_> = rows
        .iter()
        .filter(|row| row.vat_role.as_deref() == Some(ROLE_VAT_OUTPUT))
        .collect();
    assert!(!output_rows.is_empty());
    assert_eq!(output_rows[0].net_cents, Some(net));
    assert_eq!(output_rows[0].vat_cents, Some(vat));
    assert_eq!(output_rows[0].vat_rate_bp, Some(2400));
    assert_eq!(output_rows[0].vat_code.as_deref(), Some("OUTPUT"));

    let totals = derive::vat_totals_for_period(&mut *conn, seed.entity, seed.period)
        .await
        .expect("vat totals");
    assert_eq!(totals.output_base_cents, before.output_base_cents + net);
    assert_eq!(totals.output_vat_cents, before.output_vat_cents + vat);
    assert_eq!(totals.input_base_cents, before.input_base_cents + 50_00);
    assert_eq!(totals.input_vat_cents, before.input_vat_cents + 12_00);
    assert_eq!(
        totals.payable_cents(),
        (before.output_vat_cents + vat) - (before.input_vat_cents + 12_00),
        "payable is output − input in integer cents"
    );

    // Period movement + result: revenue and expense movement in cents.
    let movement = derive::period_movement(&mut *conn, seed.entity, seed.period)
        .await
        .expect("movement");
    assert!(movement
        .iter()
        .any(|row| row.account_type == "revenue" && row.credit_cents >= net));
    let (revenue_cents, expenses_cents, result) =
        derive::period_result(&mut *conn, seed.entity, seed.period)
            .await
            .expect("result");
    assert!(revenue_cents >= net);
    assert!(expenses_cents >= 50_00);
    assert_eq!(result, revenue_cents.saturating_sub(expenses_cents));

    // Posted-entry read contract reflects the entries.
    let posted = derive::posted_entries(&mut *conn, seed.entity, seed.period)
        .await
        .expect("posted entries");
    assert!(posted.iter().any(|row| row.memo == "integer-exact sale"));
    let by_source = derive::entries_for_source(&mut *conn, "does-not-exist", "nowhere", "none")
        .await
        .expect("entries for unknown source");
    assert!(by_source.is_empty());

    // Trial balance: balanced totals per account-role pair.
    let trial = derive::trial_balance(&mut *conn, seed.entity, seed.period)
        .await
        .expect("trial balance");
    let sum_debit: i128 = trial.iter().map(|row| row.debit_cents as i128).sum();
    let sum_credit: i128 = trial.iter().map(|row| row.credit_cents as i128).sum();
    assert_eq!(sum_debit, sum_credit, "trial balance must balance");
}

/// Adapter refusals: missing/draft/zero sources and the wallet/manual
/// settlement branches. Every refusal is a typed error or an explicit skip,
/// never a fabricated entry.
#[tokio::test]
async fn adapter_refusals_are_typed_and_settlement_sources_are_honest() {
    let Some(pool) = provision("acct_adapter_refusals").await else {
        return;
    };
    let seed = seed(&pool, &format!("adapter-refusals-{}", run_tag()), true).await;
    ensure_tenant(&pool).await;

    // Missing source rows.
    assert!(matches!(
        adapters::post_invoice_issued(&pool, Uuid::new_v4()).await,
        Err(AccountingError::SourceRowMissing {
            table: "invoices",
            ..
        })
    ));
    assert!(matches!(
        adapters::post_payment_allocation(&pool, "no-such-operation").await,
        Err(AccountingError::SourceRowMissing {
            table: "invoice_payment_allocations",
            ..
        })
    ));
    assert!(matches!(
        adapters::post_credit_note(&pool, Uuid::new_v4()).await,
        Err(AccountingError::SourceRowMissing {
            table: "credit_notes",
            ..
        })
    ));
    assert!(matches!(
        adapters::post_payroll_record(
            &pool,
            seed.entity,
            Uuid::new_v4(),
            PayrollAmounts {
                income_tax_cents: 0,
                social_tax_cents: 0,
                unemployment_employee_cents: 0,
                unemployment_employer_cents: 0,
                pension_cents: 0,
                net_cents: 0,
            },
        )
        .await,
        Err(AccountingError::SourceRowMissing {
            table: "payroll_records",
            ..
        })
    ));
    assert!(matches!(
        adapters::post_bank_statement_line(&pool, Uuid::new_v4()).await,
        Err(AccountingError::SourceRowMissing {
            table: "bank_statement_lines",
            ..
        })
    ));

    // Draft invoices are refused (finalization is the trigger); a zero-total
    // invoice is an explicit skip.
    let tag = run_tag().to_string();
    let draft_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, status, currency, amount, subtotal, vat_total, total, \
            vat_rate, issued_at, due_at, invoice_number, line_items) \
         VALUES ($1, $2, 'draft', 'EUR', 100, 100, 0, 100, 0, NOW(), NOW(), $3, '[]')",
    )
    .bind(draft_id)
    .bind(TENANT)
    .bind(format!("INV-{tag}-draft"))
    .execute(&pool)
    .await
    .expect("draft invoice");
    assert!(matches!(
        adapters::post_invoice_issued(&pool, draft_id).await,
        Err(AccountingError::Invalid(message)) if message.contains("draft")
    ));

    let zero_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, status, currency, amount, subtotal, vat_total, total, \
            vat_rate, issued_at, due_at, invoice_number, line_items) \
         VALUES ($1, $2, 'pending', 'EUR', 0, 0, 0, 0, 0, NOW(), NOW(), $3, '[]')",
    )
    .bind(zero_id)
    .bind(TENANT)
    .bind(format!("INV-{tag}-zero"))
    .execute(&pool)
    .await
    .expect("zero invoice");
    let skipped = adapters::post_invoice_issued(&pool, zero_id)
        .await
        .expect("zero invoice skip");
    assert_eq!(skipped.status, PostStatus::Skipped);

    // Wallet settlement: the clearing account is the wallet liability, and
    // the source document type is `wallet_settlement`.
    // A DRAFT invoice row is enough: the settlement adapter does not require
    // a posted receivable, and leaving it unposted keeps this test from
    // shifting the shared adapters suite's VAT deltas.
    let wallet_invoice = Uuid::new_v4();
    insert_invoice(&pool, wallet_invoice, false, &format!("INV-{tag}-wallet")).await;
    let wallet_op = format!("wallet:{tag}");
    sqlx::query(
        "INSERT INTO invoice_payment_allocations (tenant_id, invoice_id, operation_id, source, amount_cents, currency) \
         VALUES ($1, $2, $3, 'wallet', 12400, 'EUR')",
    )
    .bind(TENANT)
    .bind(wallet_invoice)
    .bind(&wallet_op)
    .execute(&pool)
    .await
    .expect("wallet allocation");
    let wallet_outcome = adapters::post_payment_allocation(&pool, &wallet_op)
        .await
        .expect("wallet settlement");
    assert_eq!(wallet_outcome.status, PostStatus::Posted);
    let wallet_entry = wallet_outcome.entry_id.expect("entry");
    let wallet_debit_role: String = sqlx::query_scalar(
        "SELECT a.account_role FROM journal_lines l JOIN chart_of_accounts a ON a.id = l.account_id \
         WHERE l.entry_id = $1 AND l.debit_cents > 0 LIMIT 1",
    )
    .bind(wallet_entry)
    .fetch_one(&pool)
    .await
    .expect("wallet debit role");
    assert_eq!(wallet_debit_role, ROLE_WALLET_LIABILITY);
    let wallet_source_type: String = sqlx::query_scalar(
        "SELECT source_type FROM accounting_source_documents \
         WHERE source_table = 'invoice_payment_allocations' AND source_id = $1",
    )
    .bind(&wallet_op)
    .fetch_one(&pool)
    .await
    .expect("source type");
    assert_eq!(wallet_source_type, "wallet_settlement");

    // Manual settlement: falls back to the bank account role.
    let manual_invoice = Uuid::new_v4();
    insert_invoice(&pool, manual_invoice, false, &format!("INV-{tag}-manual")).await;
    let manual_op = format!("manual:{tag}");
    sqlx::query(
        "INSERT INTO invoice_payment_allocations (tenant_id, invoice_id, operation_id, source, amount_cents, currency) \
         VALUES ($1, $2, $3, 'manual', 12400, 'EUR')",
    )
    .bind(TENANT)
    .bind(manual_invoice)
    .bind(&manual_op)
    .execute(&pool)
    .await
    .expect("manual allocation");
    let manual_outcome = adapters::post_payment_allocation(&pool, &manual_op)
        .await
        .expect("manual settlement");
    assert_eq!(manual_outcome.status, PostStatus::Posted);
    let manual_role: String = sqlx::query_scalar(
        "SELECT a.account_role FROM journal_lines l JOIN chart_of_accounts a ON a.id = l.account_id \
         WHERE l.entry_id = $1 AND l.debit_cents > 0 LIMIT 1",
    )
    .bind(manual_outcome.entry_id.expect("entry"))
    .fetch_one(&pool)
    .await
    .expect("manual debit role");
    assert_eq!(manual_role, ROLE_BANK);

    // A credit-note-sourced allocation is skipped here (the credit-note
    // adapter owns it) rather than double counted.
    let cn_op = format!("cn-sourced:{tag}");
    sqlx::query(
        "INSERT INTO invoice_payment_allocations (tenant_id, invoice_id, operation_id, source, amount_cents, currency) \
         VALUES ($1, $2, $3, 'credit_note', 100, 'EUR')",
    )
    .bind(TENANT)
    .bind(manual_invoice)
    .bind(&cn_op)
    .execute(&pool)
    .await
    .expect("credit-note allocation");
    let cn_skipped = adapters::post_payment_allocation(&pool, &cn_op)
        .await
        .expect("credit-note sourced allocation");
    assert_eq!(cn_skipped.status, PostStatus::Skipped);

    // Payroll guard: a record whose gross is not net + withheld taxes is
    // refused (the amounts must be computed first), and the ledger does not
    // move.
    let record_id: Uuid = sqlx::query_scalar(
        "INSERT INTO payroll_records (employee_name, personal_code, gross_salary_cents, \
            funded_pension_rate, pay_period) \
         VALUES ('Guard Test', $1, 100000, 0.02, TIMESTAMPTZ '2026-06-30 12:00:00+00') \
         RETURNING id",
    )
    .bind(format!("GUARD-{tag}"))
    .fetch_one(&pool)
    .await
    .expect("payroll record");
    let payroll_key = format!("payroll:{record_id}");
    let entries_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM journal_entries WHERE idempotency_key = $1",
    )
    .bind(&payroll_key)
    .fetch_one(&pool)
    .await
    .expect("payroll entry count");
    let mismatch = adapters::post_payroll_record(
        &pool,
        seed.entity,
        record_id,
        PayrollAmounts {
            income_tax_cents: 1,
            social_tax_cents: 1,
            unemployment_employee_cents: 1,
            unemployment_employer_cents: 1,
            pension_cents: 1,
            net_cents: 1,
        },
    )
    .await;
    assert!(
        matches!(mismatch, Err(AccountingError::Invalid(ref message)) if message.contains("gross")),
        "miscomputed payroll must be refused: {mismatch:?}"
    );
    let entries_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM journal_entries WHERE idempotency_key = $1",
    )
    .bind(&payroll_key)
    .fetch_one(&pool)
    .await
    .expect("payroll entry count");
    assert_eq!(
        entries_after, entries_before,
        "a refused payroll record must not post"
    );

    // Zero-amount bank line: refused.
    let bank_ledger = account(&pool, seed.entity, ROLE_BANK).await;
    let bank_account_id: Uuid = sqlx::query_scalar(
        "INSERT INTO bank_accounts (legal_entity_id, name, iban, currency, account_id) \
         VALUES ($1, 'Zero', $2, 'EUR', $3) RETURNING id",
    )
    .bind(seed.entity)
    .bind(format!("EE00ZERO{tag}000000"))
    .bind(bank_ledger)
    .fetch_one(&pool)
    .await
    .expect("bank account");
    let zero_line: Uuid = sqlx::query_scalar(
        "INSERT INTO bank_statement_lines (bank_account_id, external_id, statement_date, amount_cents, currency, reference) \
         VALUES ($1, $2, DATE '2026-06-21', 0, 'EUR', 'ZERO') RETURNING id",
    )
    .bind(bank_account_id)
    .bind(format!("zero-{tag}"))
    .fetch_one(&pool)
    .await
    .expect("zero line");
    assert!(matches!(
        adapters::post_bank_statement_line(&pool, zero_line).await,
        Err(AccountingError::Invalid(message)) if message.contains("zero")
    ));
}
