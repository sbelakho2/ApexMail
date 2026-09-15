//! Canonical-schema DB tests for the placement engine's tenant-scoped SQL.
//!
//! The engine's queries bind the VARCHAR(26) canonical tenant key (migration
//! 064) on every read and write; these tests drive them against a freshly
//! provisioned canonical database so a wrong bind/decode type fails HERE
//! instead of in production. Postgres soft-skips only when
//! `TEST_DATABASE_URL` is unset; a configured provisioning failure panics.

use chrono::Utc;
use inbox_placement::config::PlacementConfig;
use inbox_placement::engine::PlacementEngine;
use inbox_placement::types::CreateTestRequest;
use sqlx::PgPool;
use uuid::Uuid;

async fn canonical_pool(test_name: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// A VARCHAR(26)-conforming tenant key unique to this run.
fn tenant_key(label: &str) -> String {
    let hex = Uuid::new_v4().simple().to_string();
    format!("{label}{}", &hex[..26 - label.len()])
}

async fn seed_tenant(db: &PgPool, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, $1, $1, 'free', 'active')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .execute(db)
    .await
    .expect("seed tenant");
}

async fn seed_verified_domain(db: &PgPool, tenant_id: &str, domain: &str, verified: bool) {
    sqlx::query("INSERT INTO domains (tenant_id, name, verified) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(domain)
        .bind(verified)
        .execute(db)
        .await
        .expect("seed domain");
}

/// One active gmail seed account (the provider row is seeded by migration
/// 033). Returns the account id.
async fn seed_gmail_account(db: &PgPool, email: &str) -> Uuid {
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO seed_accounts (provider_id, email, imap_password_encrypted, is_active) \
         SELECT p.id, $1, 'plaintext-test-password', true \
         FROM seed_providers p WHERE p.name = 'gmail' \
         RETURNING id",
    )
    .bind(email)
    .fetch_one(db)
    .await
    .expect("seed account");
    id
}

async fn insert_result(
    db: &PgPool,
    test_id: Uuid,
    account: Uuid,
    inbox_type: Option<&str>,
    delivery_ms: Option<i32>,
    spf: Option<bool>,
    dkim: Option<bool>,
) {
    sqlx::query(
        "INSERT INTO placement_results \
         (test_id, seed_account_id, inbox_type, delivery_time_ms, spf_pass, dkim_pass, dmarc_pass) \
         VALUES ($1, $2, $3, $4, $5, $6, NULL)",
    )
    .bind(test_id)
    .bind(account)
    .bind(inbox_type)
    .bind(delivery_ms)
    .bind(spf)
    .bind(dkim)
    .execute(db)
    .await
    .expect("insert placement result");
}

#[tokio::test]
async fn create_test_persists_the_canonical_tenant_key_and_resolves_seeds() {
    let Some(db) = canonical_pool("ip_engine_create").await else {
        return;
    };
    let tenant = tenant_key("t");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    let account = seed_gmail_account(&db, &format!("{tenant}@seed.example")).await;

    let engine = PlacementEngine::new(PlacementConfig::default(), db.clone());
    let test = engine
        .create_test(
            CreateTestRequest {
                name: Some("canonical key test".into()),
                from_email: "sender@send.example".into(),
                subject: "ApexMail Inbox Placement Test probe".into(),
                body_text: None,
                body_html: None,
                target_providers: Some(vec!["gmail".into()]),
                schedule_at: None,
            },
            &tenant,
        )
        .await
        .expect("create_test must succeed against the canonical schema");

    assert_eq!(test.tenant_id, tenant);
    assert_eq!(test.status, "pending");
    assert_eq!(test.seed_accounts_used, vec![account]);

    // The row round-trips with the SAME tenant key under the VARCHAR(26)
    // column (no uuid coercion, no truncation).
    let stored: (String, String, Vec<Uuid>) = sqlx::query_as(
        "SELECT tenant_id, status, seed_accounts_used FROM placement_tests WHERE id = $1",
    )
    .bind(test.id)
    .fetch_one(&db)
    .await
    .expect("stored row");
    assert_eq!(stored, (tenant.clone(), "pending".into(), vec![account]));

    // A From domain that exists but is NOT verified is refused with
    // operator guidance (Protocol), never silently accepted.
    seed_verified_domain(&db, &tenant, "unverified.example", false).await;
    let err = engine
        .create_test(
            CreateTestRequest {
                name: None,
                from_email: "sender@unverified.example".into(),
                subject: "s".into(),
                body_text: None,
                body_html: None,
                target_providers: Some(vec!["gmail".into()]),
                schedule_at: None,
            },
            &tenant,
        )
        .await
        .expect_err("unverified From domain must be refused");
    assert!(
        err.to_string().contains("not a verified sending domain"),
        "{err}"
    );
}

#[tokio::test]
async fn results_and_trends_are_tenant_scoped_with_exact_aggregates() {
    let Some(db) = canonical_pool("ip_engine_read").await else {
        return;
    };
    let tenant = tenant_key("r");
    let outsider = tenant_key("o");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    let account = seed_gmail_account(&db, &format!("{tenant}@seed.example")).await;

    let engine = PlacementEngine::new(PlacementConfig::default(), db.clone());
    let test = engine
        .create_test(
            CreateTestRequest {
                name: None,
                from_email: "sender@send.example".into(),
                subject: "s".into(),
                body_text: None,
                body_html: None,
                target_providers: Some(vec!["gmail".into()]),
                schedule_at: None,
            },
            &tenant,
        )
        .await
        .expect("create");

    // Two measured placements: one inbox (fast, spf pass), one spam (slow,
    // dkim fail). Delivery latency averages ONLY over measured rows.
    insert_result(
        &db,
        test.id,
        account,
        Some("inbox"),
        Some(1_000),
        Some(true),
        None,
    )
    .await;
    insert_result(
        &db,
        test.id,
        account,
        Some("spam"),
        Some(3_000),
        None,
        Some(false),
    )
    .await;
    // An absent row has NO delivery time and must not dilute the average.
    insert_result(&db, test.id, account, None, None, None, None).await;

    let results = engine
        .get_test_results(test.id, &tenant)
        .await
        .expect("results");
    assert_eq!(results.len(), 1, "one provider group: {results:?}");
    let gmail = &results[0];
    assert_eq!(gmail.provider, "gmail");
    assert_eq!(gmail.accounts_tested, 3);
    assert_eq!(gmail.inbox, 1);
    assert_eq!(gmail.spam, 1);
    assert_eq!(gmail.absent, 1);
    assert_eq!(gmail.avg_delivery_time_ms, 2_000.0);
    // auth rows = 2 (spf row + dkim row); spf 1/2, dkim 0/2.
    assert_eq!(gmail.spf_pass_rate, 0.5);
    assert_eq!(gmail.dkim_pass_rate, 0.0);

    // A different tenant's key sees NOTHING (join scoping, not a leak).
    assert!(engine
        .get_test_results(test.id, &outsider)
        .await
        .expect("outsider results")
        .is_empty());

    // Trends aggregate the same rows per day.
    let trends = engine.get_trends(&tenant, 1, None).await.expect("trends");
    assert_eq!(trends.len(), 1, "{trends:?}");
    // Same operation order as the engine ((count / total) * 100) so the
    // assertion is exact, not tolerance-based.
    let expected_third = (1.0f64 / 3.0) * 100.0;
    assert_eq!(trends[0].inbox_pct, expected_third);
    assert_eq!(trends[0].spam_pct, expected_third);
    assert!(
        engine
            .get_trends(&outsider, 1, None)
            .await
            .unwrap()
            .is_empty(),
        "trends must be tenant scoped"
    );

    // The score reads through the same scoped query.
    let score = engine
        .get_placement_score(test.id, &tenant)
        .await
        .expect("score");
    assert!(score.overall <= 100, "{score:?}");
}

#[tokio::test]
async fn reaped_tests_are_not_resurrected_by_finalize() {
    let Some(db) = canonical_pool("ip_engine_finalize").await else {
        return;
    };
    // Drive the check-and-set SQL the engine uses: a terminal status must
    // survive both the claim and the finalize statements.
    let tenant = tenant_key("f");
    seed_tenant(&db, &tenant).await;
    seed_verified_domain(&db, &tenant, "send.example", true).await;
    seed_gmail_account(&db, &format!("{tenant}@seed.example")).await;

    let engine = PlacementEngine::new(PlacementConfig::default(), db.clone());
    let test = engine
        .create_test(
            CreateTestRequest {
                name: None,
                from_email: "sender@send.example".into(),
                subject: "s".into(),
                body_text: None,
                body_html: None,
                target_providers: Some(vec!["gmail".into()]),
                schedule_at: None,
            },
            &tenant,
        )
        .await
        .expect("create");

    // The reaper marks the test failed while the run is queued.
    sqlx::query("UPDATE placement_tests SET status = 'failed' WHERE id = $1")
        .bind(test.id)
        .execute(&db)
        .await
        .expect("reap");

    let claimed = sqlx::query(inbox_placement::engine::CLAIM_RUNNING_SQL)
        .bind(test.id)
        .execute(&db)
        .await
        .expect("claim");
    assert_eq!(
        claimed.rows_affected(),
        0,
        "a terminal test must not be claimed"
    );

    sqlx::query(inbox_placement::engine::FINALIZE_STATUS_SQL)
        .bind("completed")
        .bind(1i32)
        .bind(Utc::now())
        .bind(test.id)
        .execute(&db)
        .await
        .expect("finalize");
    let status: (String,) = sqlx::query_as("SELECT status FROM placement_tests WHERE id = $1")
        .bind(test.id)
        .fetch_one(&db)
        .await
        .expect("status");
    assert_eq!(status.0, "failed", "finalize must not flip a reaped test");
}
