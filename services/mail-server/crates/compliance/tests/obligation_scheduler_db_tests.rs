//! Dogfood 2026-10-06 wave B: the statutory-obligation scheduler pass.
//!
//! `sync_all_obligations` is the production caller the engine lacked — before
//! it, `statutory_obligations` was written only by tests and the live table
//! stayed EMPTY (verified 2026-10-07) while the module documented a
//! "scheduler's monthly tick". These tests exercise the pass against the
//! canonical schema.
//!
//! Gated on `TEST_DATABASE_URL` (workspace convention).

use chrono::{Datelike, NaiveDate, Utc};
use compliance::obligations::sync_all_obligations;
use sqlx::PgPool;
use uuid::Uuid;

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    let suffix = format!("obl_{}", test_name);
    match migrator::test_support::fresh_canonical_pool(test_name, &suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// Seed a legal entity (and, when requested, explicit filing facts).
async fn seed_entity(
    pool: &PgPool,
    registry_code: &str,
    vat_registered_from: Option<NaiveDate>,
    employer_since: Option<NaiveDate>,
) -> Uuid {
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO legal_entities (legal_name, registry_code, country_code)
         VALUES ($1, $2, 'EE') RETURNING id",
    )
    .bind(format!("Obligation Test OÜ {registry_code}"))
    .bind(registry_code)
    .fetch_one(pool)
    .await
    .expect("seed legal entity");

    if vat_registered_from.is_some() || employer_since.is_some() {
        sqlx::query(
            "INSERT INTO legal_entity_filing_facts
                (legal_entity_id, vat_registered_from, employer_since, fiscal_year_end_month)
             VALUES ($1, $2, $3, 12)",
        )
        .bind(id)
        .bind(vat_registered_from)
        .bind(employer_since)
        .execute(pool)
        .await
        .expect("seed filing facts");
    }
    id
}

/// The scheduler pass populates the statutory calendar for every entity: a
/// VAT-registered employer gets monthly KMD + TSD rows over the forward
/// horizon, and an entity without facts gets none (absent facts create no
/// obligations).
#[tokio::test]
async fn scheduler_pass_populates_the_calendar_idempotently() {
    let Some(pool) = canonical_pool("scheduler_pass").await else {
        return;
    };
    let today = Utc::now().date_naive();

    let with_facts = seed_entity(
        &pool,
        "reg-obl-1",
        Some(NaiveDate::from_ymd_opt(2020, 1, 1).unwrap()),
        Some(NaiveDate::from_ymd_opt(2020, 1, 1).unwrap()),
    )
    .await;
    let without_facts = seed_entity(&pool, "reg-obl-2", None, None).await;

    let run = sync_all_obligations(&pool, today)
        .await
        .expect("scheduler pass");
    assert_eq!(run.entities, 2, "both entities are visited");
    assert!(
        run.upserted >= 2,
        "a VAT-registered employer owes at least KMD + TSD, got {}",
        run.upserted
    );

    let kmd_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM statutory_obligations
          WHERE legal_entity_id = $1 AND obligation_type = 'kmd'",
    )
    .bind(with_facts)
    .fetch_one(&pool)
    .await
    .expect("count KMD");
    assert!(kmd_rows >= 12, "monthly KMD over the forward year");

    let tsd_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM statutory_obligations
          WHERE legal_entity_id = $1 AND obligation_type = 'tsd'",
    )
    .bind(with_facts)
    .fetch_one(&pool)
    .await
    .expect("count TSD");
    assert!(tsd_rows >= 12, "monthly TSD for an employer");

    let bare_types: Vec<String> = sqlx::query_scalar(
        "SELECT obligation_type FROM statutory_obligations WHERE legal_entity_id = $1",
    )
    .bind(without_facts)
    .fetch_all(&pool)
    .await
    .expect("bare entity rows");
    assert_eq!(
        bare_types,
        vec!["annual_report".to_string()],
        "no VAT/employer/OSS registration means NO KMD/TSD/VD/OSS rows — only the \
         annual report derived from the entity's creation date"
    );

    // Every row (of whatever type) carries the shared calendar version, so
    // the working-day rule is always traceable (no unversioned deadlines).
    let (total_rows, unversioned): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE calendar_version IS NULL)
           FROM statutory_obligations WHERE legal_entity_id = $1",
    )
    .bind(with_facts)
    .fetch_one(&pool)
    .await
    .expect("count versioned");
    assert!(total_rows > 0);
    assert_eq!(unversioned, 0, "every deadline names its calendar version");

    // Idempotent: a second pass inserts nothing new.
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM statutory_obligations")
        .fetch_one(&pool)
        .await
        .expect("count before");
    let second = sync_all_obligations(&pool, today)
        .await
        .expect("second pass");
    assert_eq!(second.entities, 2);
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM statutory_obligations")
        .fetch_one(&pool)
        .await
        .expect("count after");
    assert_eq!(before, after, "re-derivation must upsert, never duplicate");

    // Every obligation's due date falls inside the forward horizon.
    let horizon_end = today + chrono::Duration::days(366);
    let outside: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM statutory_obligations WHERE due_date > $1 OR due_date < $2",
    )
    .bind(horizon_end)
    .bind(today)
    .fetch_one(&pool)
    .await
    .expect("count outside horizon");
    assert_eq!(outside, 0, "the pass must not invent far-past/far-future rows");

    pool.close().await;
}

/// A pending obligation whose due date is in the past is moved to `overdue` by
/// the same pass — the state machine advances instead of leaving stale
/// `pending` rows forever.
#[tokio::test]
async fn scheduler_pass_marks_past_due_obligations_overdue() {
    let Some(pool) = canonical_pool("marks_overdue").await else {
        return;
    };
    let today = Utc::now().date_naive();
    let entity = seed_entity(&pool, "reg-obl-3", None, None).await;

    let stale_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO statutory_obligations
            (id, legal_entity_id, obligation_type, period_start, period_end,
             period_label, legal_due_date, due_date, calendar_version, status)
         VALUES ($1, $2, 'kmd', $3, $3, 'stale', $3, $3, $4, 'pending')",
    )
    .bind(stale_id)
    .bind(entity)
    .bind(today - chrono::Duration::days(30))
    .bind(compliance::statutory_calendar::ESTONIA_CALENDAR_VERSION)
    .execute(&pool)
    .await
    .expect("seed stale obligation");

    let run = sync_all_obligations(&pool, today)
        .await
        .expect("scheduler pass");
    assert!(
        run.marked_overdue >= 1,
        "the stale pending row must be marked overdue"
    );

    let (status,): (String,) =
        sqlx::query_as("SELECT status FROM statutory_obligations WHERE id = $1")
            .bind(stale_id)
            .fetch_one(&pool)
            .await
            .expect("read stale row");
    assert_eq!(status, "overdue");

    pool.close().await;
}

/// The pass derives the ANNUAL REPORT deadline from the entity's fiscal-year
/// configuration, so an entity without VAT/employer registrations still gets
/// its ÄS §179 deadline — and the fiscal year end month moves the date.
#[tokio::test]
async fn scheduler_pass_derives_annual_report_from_the_fiscal_year() {
    let Some(pool) = canonical_pool("annual_report").await else {
        return;
    };
    let today = Utc::now().date_naive();
    let entity = seed_entity(&pool, "reg-obl-4", None, None).await;
    // December fiscal-year end (the legal_entities default is January start →
    // December end; make it explicit for the assertion).
    sqlx::query(
        "INSERT INTO legal_entity_filing_facts (legal_entity_id, fiscal_year_end_month)
         VALUES ($1, 12)",
    )
    .bind(entity)
    .execute(&pool)
    .await
    .expect("facts");

    sync_all_obligations(&pool, today)
        .await
        .expect("scheduler pass");

    let (period_label, due_date, legal_due_date): (String, NaiveDate, NaiveDate) = sqlx::query_as(
        "SELECT period_label, due_date, legal_due_date FROM statutory_obligations
          WHERE legal_entity_id = $1 AND obligation_type = 'annual_report'
          ORDER BY period_start DESC LIMIT 1",
    )
    .bind(entity)
    .fetch_one(&pool)
    .await
    .expect("annual report obligation");

    // ÄS §179: the last day of the sixth month after the financial year end.
    // For a December year end that is June 30 of the following year, wherever
    // the working-day shift puts the effective date (in the same month).
    assert_eq!(legal_due_date.month(), 6, "label {period_label}");
    assert_eq!(legal_due_date.day(), 30, "label {period_label}");
    assert_eq!(due_date.month(), 6, "effective date stays in June");

    pool.close().await;
}
