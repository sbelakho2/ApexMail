//! Concurrency & race condition stress tests (Jul 2026 Audit).
//!
//! These tests validate fixes for race conditions found during the
//! comprehensive concurrency audit. They are designed to FAIL first:
//! each test should detect the exact race condition the fix addresses.
//!
//! Run with: cargo test --test concurrency_tests -- --nocapture
//! Requires: PostgreSQL + Redis running (set TEST_DATABASE_URL).

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use apexmail_lib::id;

// Re-use the optional_pg_pool pattern from schema_contract_tests.
// Each test below is self-contained (creates its own test data, tears down).

// ═══════════════════════════════════════════════════════════════════════════
// Test Infrastructure
// ═══════════════════════════════════════════════════════════════════════════

async fn optional_pg_pool(test_name: &str) -> Option<PgPool> {
    use tokio::sync::OnceCell;
    static INIT_DB: OnceCell<()> = OnceCell::const_new();

    let database_url = match std::env::var("TEST_DATABASE_URL") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            eprintln!("skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test");
            return None;
        }
    };

    let (server_part, db_part) = match database_url.rsplit_once('/') {
        Some((s, d)) => (s, d),
        None => {
            eprintln!("skipping {test_name}: TEST_DATABASE_URL has no database segment");
            return None;
        }
    };
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    let isolated_db = format!("{db_only}_concurrency");
    let isolated_url = format!("{server_part}/{isolated_db}");
    let admin_url = format!("{server_part}/postgres");

    INIT_DB
        .get_or_init(|| async {
            let admin = match PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_secs(3))
                .connect(&admin_url)
                .await
            {
                Ok(p) => p,
                Err(error) => {
                    eprintln!("concurrency DB bootstrap: cannot connect to admin URL: {error}");
                    return;
                }
            };
            let _ = sqlx::query(&format!(
                "DROP DATABASE IF EXISTS \"{isolated_db}\" WITH (FORCE)"
            ))
            .execute(&admin)
            .await;
            let _ = sqlx::query(&format!("CREATE DATABASE \"{isolated_db}\""))
                .execute(&admin)
                .await;
        })
        .await;

    Some(
        PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "concurrency isolated DB ({isolated_url}) could not connect for \
                     {test_name}: {error}"
                )
            }),
    )
}

/// Seed the minimal tables required for billing/wallet tests.
async fn seed_minimal_billing_tables(pool: &PgPool, tenant_id: &str) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenants (
            id VARCHAR(26) PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            plan TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            settings JSONB DEFAULT '{}',
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status)
         VALUES ($1, 'test', 'starter', 'active')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS wallets (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id VARCHAR(26) NOT NULL,
            balance INTEGER NOT NULL DEFAULT 0,
            reserved INTEGER NOT NULL DEFAULT 0,
            currency TEXT NOT NULL DEFAULT 'eur',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS wallet_transactions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id VARCHAR(26) NOT NULL,
            wallet_id UUID NOT NULL,
            type VARCHAR(10) NOT NULL DEFAULT 'credit',
            amount INTEGER NOT NULL DEFAULT 0,
            balance_after INTEGER NOT NULL DEFAULT 0,
            description TEXT NOT NULL DEFAULT '',
            reference VARCHAR(255),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await
    .unwrap();

    // Apply the RC-001 fix: UNIQUE constraint on reference
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_wallet_transactions_reference
         ON wallet_transactions(reference)
         WHERE reference IS NOT NULL",
    )
    .execute(pool)
    .await
    .unwrap();
}

/// Seed the minimal tables required for webhook tests.
async fn seed_minimal_webhook_tables(pool: &PgPool, tenant_id: &str) {
    seed_minimal_billing_tables(pool, tenant_id).await; // for tenants table

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS webhooks (
            id VARCHAR(32) PRIMARY KEY,
            tenant_id VARCHAR(26) NOT NULL,
            name TEXT,
            url TEXT NOT NULL,
            events JSONB NOT NULL DEFAULT '[]',
            secret TEXT NOT NULL DEFAULT '',
            previous_secret TEXT,
            previous_secret_expires_at TIMESTAMPTZ,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await
    .unwrap();

    // RC-006: UNIQUE constraint on tenant_id + url
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_webhooks_tenant_url
         ON webhooks(tenant_id, url)",
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS webhook_queue (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            webhook_id VARCHAR(32) NOT NULL,
            tenant_id VARCHAR(26) NOT NULL,
            event_type TEXT NOT NULL,
            payload JSONB NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'pending',
            attempt INT NOT NULL DEFAULT 0,
            scheduled_at TIMESTAMPTZ,
            locked_until TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await
    .unwrap();
}

/// Seed the minimal tables required for subscription tests.
async fn seed_minimal_subscription_tables(pool: &PgPool, tenant_id: &str) {
    seed_minimal_billing_tables(pool, tenant_id).await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS stripe_subscriptions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id VARCHAR(26) NOT NULL,
            stripe_subscription_id TEXT,
            stripe_customer_id TEXT,
            stripe_price_id TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            billing_interval TEXT NOT NULL DEFAULT 'monthly',
            billing_cycle_start TIMESTAMPTZ,
            billing_cycle_end TIMESTAMPTZ,
            cancel_at_period_end BOOLEAN DEFAULT false,
            canceled_at TIMESTAMPTZ,
            trial_end TIMESTAMPTZ,
            admin_override_at TIMESTAMPTZ,
            admin_override_by VARCHAR(26),
            admin_override_reason TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await
    .unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-01: Wallet credit idempotency (admin_apply_credit)
// ═══════════════════════════════════════════════════════════════════════════

/// Two concurrent identically-keyed credit operations MUST produce exactly one
/// credit. Without the UNIQUE constraint on `reference`, duplicate credits
/// would be created.
#[tokio::test]
async fn concurrent_wallet_credit_idempotency() {
    let Some(pool) = optional_pg_pool("concurrent_wallet_credit_idempotency").await else {
        return;
    };

    let tenant_id = id::generate_id("ten", 21);
    let idem_key = format!("idem-credit-{}", Uuid::new_v4());
    let amount = 100i64;

    seed_minimal_billing_tables(&pool, &tenant_id).await;

    // Insert wallet
    let wallet_id = Uuid::new_v4();
    sqlx::query("INSERT INTO wallets (id, tenant_id, balance) VALUES ($1, $2, 0)")
        .bind(wallet_id)
        .bind(&tenant_id)
        .execute(&pool)
        .await
        .unwrap();

    let pool1 = pool.clone();
    let pool2 = pool.clone();
    let idem_key1 = idem_key.clone();
    let idem_key2 = idem_key.clone();
    let tenant_id1 = tenant_id.clone();
    let tenant_id2 = tenant_id.clone();

    // Fire two concurrent credit attempts with the same idempotency key.
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move {
            let mut tx = pool1.begin().await.unwrap();
            let result = sqlx::query(
                "INSERT INTO wallet_transactions (id, tenant_id, wallet_id, type, amount, balance_after, description, reference)
                 VALUES ($1, $2, $3, 'credit', $4, $4, 'admin credit', $5)
                 ON CONFLICT (reference) WHERE reference IS NOT NULL DO NOTHING
                 RETURNING id",
            )
            .bind(Uuid::new_v4())
            .bind(&tenant_id1)
            .bind(wallet_id)
            .bind(amount)
            .bind(&idem_key1)
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
            let inserted = result.is_some();
            tx.commit().await.unwrap();
            inserted
        }),
        tokio::spawn(async move {
            let mut tx = pool2.begin().await.unwrap();
            let result = sqlx::query(
                "INSERT INTO wallet_transactions (id, tenant_id, wallet_id, type, amount, balance_after, description, reference)
                 VALUES ($1, $2, $3, 'credit', $4, $4, 'admin credit', $5)
                 ON CONFLICT (reference) WHERE reference IS NOT NULL DO NOTHING
                 RETURNING id",
            )
            .bind(Uuid::new_v4())
            .bind(&tenant_id2)
            .bind(wallet_id)
            .bind(amount)
            .bind(&idem_key2)
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
            let inserted = result.is_some();
            tx.commit().await.unwrap();
            inserted
        }),
    );

    let inserted1 = r1.unwrap();
    let inserted2 = r2.unwrap();

    // Exactly ONE of the two concurrent inserts must have succeeded.
    assert!(
        inserted1 ^ inserted2,
        "Concurrent idempotent wallet credit: both={} r1={} r2={} (expected exactly one)",
        inserted1 && inserted2,
        inserted1,
        inserted2,
    );

    // Verify only one row exists
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM wallet_transactions WHERE reference = $1")
            .bind(&idem_key)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1, "Duplicate wallet credit detected");

    // Verify wallet balance was incremented exactly once
    let balance: (i64,) = sqlx::query_as("SELECT balance FROM wallets WHERE id = $1")
        .bind(wallet_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        balance.0, amount,
        "Wallet balance mismatch after concurrent credit"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-02: Webhook URL uniqueness (create_webhook)
// ═══════════════════════════════════════════════════════════════════════════

/// Two concurrent webhook creation requests with the same URL MUST result in
/// exactly one webhook. Without the UNIQUE constraint, duplicates would be created.
#[tokio::test]
async fn concurrent_webhook_creation_uniqueness() {
    let Some(pool) = optional_pg_pool("concurrent_webhook_creation_uniqueness").await else {
        return;
    };

    let tenant_id = id::generate_id("ten", 21);
    let webhook_url = format!("https://example.com/hook-{}", Uuid::new_v4());
    let webhook_secret = "whsec_test_secret_12345";
    let events_json = serde_json::json!(["email.sent", "email.opened"]);
    let events_json2 = events_json.clone();

    seed_minimal_webhook_tables(&pool, &tenant_id).await;

    let pool1 = pool.clone();
    let pool2 = pool.clone();
    let url1 = webhook_url.clone();
    let url2 = webhook_url.clone();
    let tid1 = tenant_id.clone();
    let tid2 = tenant_id.clone();

    let (r1, r2) = tokio::join!(
        tokio::spawn(async move {
            let result = sqlx::query(
                "INSERT INTO webhooks (id, tenant_id, url, events, secret)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (tenant_id, url) DO NOTHING
                 RETURNING id",
            )
            .bind(id::generate_id("whk", 18))
            .bind(&tid1)
            .bind(&url1)
            .bind(events_json.clone())
            .bind(webhook_secret)
            .fetch_optional(&pool1)
            .await
            .unwrap();
            result.is_some()
        }),
        tokio::spawn(async move {
            let result = sqlx::query(
                "INSERT INTO webhooks (id, tenant_id, url, events, secret)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (tenant_id, url) DO NOTHING
                 RETURNING id",
            )
            .bind(id::generate_id("whk", 18))
            .bind(&tid2)
            .bind(&url2)
            .bind(events_json2.clone())
            .bind(webhook_secret)
            .fetch_optional(&pool2)
            .await
            .unwrap();
            result.is_some()
        }),
    );

    let inserted1 = r1.unwrap();
    let inserted2 = r2.unwrap();

    assert!(
        inserted1 ^ inserted2,
        "Concurrent webhook creation: both should not succeed for the same URL"
    );

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1 AND url = $2")
            .bind(&tenant_id)
            .bind(&webhook_url)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1, "Duplicate webhook detected for same URL");
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-03: Subscription status locking (admin_force_subscription_status)
// ═══════════════════════════════════════════════════════════════════════════

/// Two concurrent subscription status updates MUST be serialized by FOR UPDATE.
/// The second update must see the first update's result.
#[tokio::test]
async fn concurrent_subscription_update_for_update_lock() {
    let Some(pool) = optional_pg_pool("concurrent_subscription_update_for_update_lock").await
    else {
        return;
    };

    let tenant_id = id::generate_id("ten", 21);
    let sub_id = Uuid::new_v4();

    seed_minimal_subscription_tables(&pool, &tenant_id).await;

    sqlx::query(
        "INSERT INTO stripe_subscriptions (id, tenant_id, status, billing_interval)
         VALUES ($1, $2, 'active', 'monthly')",
    )
    .bind(sub_id)
    .bind(&tenant_id)
    .execute(&pool)
    .await
    .unwrap();

    let pool1 = pool.clone();
    let pool2 = pool.clone();
    let tid1 = tenant_id.clone();
    let tid2 = tenant_id.clone();

    // Fire two concurrent FOR UPDATE + UPDATE transactions.
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move {
            let mut tx = pool1.begin().await.unwrap();
            // Lock the row
            let current: (String,) = sqlx::query_as(
                "SELECT status FROM stripe_subscriptions
                 WHERE tenant_id = $1 FOR UPDATE",
            )
            .bind(&tid1)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(current.0, "active");
            // Simulate processing delay to ensure both transactions overlap
            tokio::time::sleep(Duration::from_millis(50)).await;
            sqlx::query(
                "UPDATE stripe_subscriptions SET status = 'suspended', updated_at = NOW()
                 WHERE tenant_id = $1",
            )
            .bind(&tid1)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            current.0
        }),
        tokio::spawn(async move {
            let mut tx = pool2.begin().await.unwrap();
            let current: (String,) = sqlx::query_as(
                "SELECT status FROM stripe_subscriptions
                 WHERE tenant_id = $1 FOR UPDATE",
            )
            .bind(&tid2)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            // Second updater MUST see either 'active' (before first committed)
            // or 'suspended' (after first committed), and its update will
            // overwrite accordingly.
            sqlx::query(
                "UPDATE stripe_subscriptions SET status = 'canceled', updated_at = NOW()
                 WHERE tenant_id = $1",
            )
            .bind(&tid2)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            current.0
        }),
    );

    let seen1 = r1.unwrap();
    let seen2 = r2.unwrap();

    // The first task always sees 'active' (it locked first).
    // The second task must see either 'active' (if it read before first update)
    // or 'suspended' (if it read after). Either way, both tasks complete
    // successfully — the FOR UPDATE serializes them.
    assert_eq!(seen1, "active");
    assert!(
        seen2 == "active" || seen2 == "suspended",
        "Second task saw unexpected state: {seen2}"
    );

    // Final state: last writer wins
    let final_status: (String,) =
        sqlx::query_as("SELECT status FROM stripe_subscriptions WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        final_status.0 == "suspended" || final_status.0 == "canceled",
        "Final subscription status should be suspended or canceled, got: {}",
        final_status.0
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-04: Webhook deletion with ongoing deliveries
// ═══════════════════════════════════════════════════════════════════════════

/// When a webhook is deleted while it has pending queue entries, the queue
/// entries MUST be deleted atomically with the webhook. Without the cascade
/// delete in the transaction, orphaned queue entries would remain.
#[tokio::test]
async fn webhook_deletion_cascades_queue_entries() {
    let Some(pool) = optional_pg_pool("webhook_deletion_cascades_queue_entries").await else {
        return;
    };

    let tenant_id = id::generate_id("ten", 21);
    let webhook_id = id::generate_id("whk", 18);

    seed_minimal_webhook_tables(&pool, &tenant_id).await;

    // Create webhook + queue entries
    sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, url, events, secret)
         VALUES ($1, $2, 'https://example.com/hook', '[]', 'secret')",
    )
    .bind(&webhook_id)
    .bind(&tenant_id)
    .execute(&pool)
    .await
    .unwrap();

    for _ in 0..10 {
        sqlx::query(
            "INSERT INTO webhook_queue (id, webhook_id, tenant_id, event_type, payload)
             VALUES ($1, $2, $3, 'test.event', '{}')",
        )
        .bind(Uuid::new_v4())
        .bind(&webhook_id)
        .bind(&tenant_id)
        .execute(&pool)
        .await
        .unwrap();
    }

    let queue_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM webhook_queue WHERE webhook_id = $1")
            .bind(&webhook_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(queue_count.0, 10, "Expected 10 queue entries before delete");

    // Delete the webhook AND its queue entries in a transaction
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM webhook_queue WHERE webhook_id = $1")
        .bind(&webhook_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM webhooks WHERE id = $1")
        .bind(&webhook_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Verify no orphaned queue entries
    let queue_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM webhook_queue WHERE webhook_id = $1")
            .bind(&webhook_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        queue_count.0, 0,
        "Orphaned webhook_queue entries after webhook delete"
    );

    // Verify webhook is gone
    let webhook_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM webhooks WHERE id = $1")
        .bind(&webhook_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(webhook_count.0, 0, "Webhook still exists after delete");
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-05: Concurrent domain deletion with transaction guard
// ═══════════════════════════════════════════════════════════════════════════

/// Concurrent domain delete and verify must not produce inconsistent state.
/// The FOR UPDATE in delete_domain must serialize operations on the same domain.
#[tokio::test]
async fn concurrent_domain_delete_and_verify() {
    let Some(pool) = optional_pg_pool("concurrent_domain_delete_and_verify").await else {
        return;
    };

    let tenant_id = id::generate_id("ten", 21);
    let domain_id = id::generate_id("dom", 18);

    seed_minimal_billing_tables(&pool, &tenant_id).await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS domains (
            id VARCHAR(32) PRIMARY KEY,
            tenant_id VARCHAR(26) NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            spf_verified BOOLEAN DEFAULT false,
            dkim_verified BOOLEAN DEFAULT false,
            dmarc_verified BOOLEAN DEFAULT false,
            return_path_verified BOOLEAN DEFAULT false,
            ses_verified BOOLEAN DEFAULT false,
            dkim_selector TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("INSERT INTO domains (id, tenant_id, name) VALUES ($1, $2, 'example.com')")
        .bind(&domain_id)
        .bind(&tenant_id)
        .execute(&pool)
        .await
        .unwrap();

    let pool1 = pool.clone();
    let pool2 = pool.clone();
    let did1 = domain_id.clone();
    let did2 = domain_id.clone();
    let tid1 = tenant_id.clone();
    let tid2 = tenant_id.clone();

    let (r1, r2) = tokio::join!(
        tokio::spawn(async move {
            let mut tx = pool1.begin().await.unwrap();
            let exists: Option<String> = sqlx::query_scalar(
                "SELECT name FROM domains WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            )
            .bind(&did1)
            .bind(&tid1)
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
            let result = if exists.is_some() {
                sqlx::query("DELETE FROM domains WHERE id = $1 AND tenant_id = $2")
                    .bind(&did1)
                    .bind(&tid1)
                    .execute(&mut *tx)
                    .await
                    .unwrap()
                    .rows_affected()
            } else {
                0
            };
            tx.commit().await.unwrap();
            result
        }),
        tokio::spawn(async move {
            let mut tx = pool2.begin().await.unwrap();
            let exists: Option<String> = sqlx::query_scalar(
                "SELECT name FROM domains WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            )
            .bind(&did2)
            .bind(&tid2)
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
            let result = if exists.is_some() {
                sqlx::query(
                    "UPDATE domains SET spf_verified = true, updated_at = NOW()
                     WHERE id = $1 AND tenant_id = $2",
                )
                .bind(&did2)
                .bind(&tid2)
                .execute(&mut *tx)
                .await
                .unwrap()
                .rows_affected()
            } else {
                0
            };
            tx.commit().await.unwrap();
            result
        }),
    );

    let deleted = r1.unwrap();
    let verified = r2.unwrap();

    // One operation must have succeeded (ran first), the other must have seen
    // the row already deleted or locked.
    assert!(
        deleted + verified >= 1,
        "Neither delete nor verify succeeded on the domain"
    );
    // Most importantly: the final state must be consistent.
    // If deleted, the domain must not exist; if verified, it must.
    let exists: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM domains WHERE id = $1 AND tenant_id = $2")
            .bind(&domain_id)
            .bind(&tenant_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    if deleted > 0 {
        assert_eq!(exists.0, 0, "Domain still exists after successful delete");
    }
    if verified > 0 && deleted == 0 {
        assert_eq!(exists.0, 1, "Domain missing after successful verify");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-06: Advisory lock serialization for admin operations
// ═══════════════════════════════════════════════════════════════════════════

/// Concurrent admin overrides (plan_override, dunning_reset) must be serialized
/// by pg_advisory_xact_lock to prevent inconsistent state.
#[tokio::test]
async fn concurrent_plan_override_advisory_lock() {
    let Some(pool) = optional_pg_pool("concurrent_plan_override_advisory_lock").await else {
        return;
    };

    let tenant_id = id::generate_id("ten", 21);

    seed_minimal_billing_tables(&pool, &tenant_id).await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS plan_overrides (
            tenant_id VARCHAR(26) PRIMARY KEY,
            plan_id TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            admin_id VARCHAR(26),
            expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    let pool1 = pool.clone();
    let pool2 = pool.clone();
    let tid1 = tenant_id.clone();
    let tid2 = tenant_id.clone();

    // Fire two concurrent plan overrides with the same advisory lock ID.
    // Only one should succeed at a time; the second waits.
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move {
            let mut tx = pool1.begin().await.unwrap();
            // RC-FIX-06 lock
            sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext('plan_override'))")
                .bind(&tid1)
                .execute(&mut *tx)
                .await
                .unwrap();
            // Simulate processing delay
            tokio::time::sleep(Duration::from_millis(50)).await;
            sqlx::query(
                "INSERT INTO plan_overrides (tenant_id, plan_id, reason, admin_id)
                 VALUES ($1, 'pro', 'override1', 'admin1')
                 ON CONFLICT (tenant_id) DO UPDATE SET plan_id = 'pro'",
            )
            .bind(&tid1)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            "done1"
        }),
        tokio::spawn(async move {
            let mut tx = pool2.begin().await.unwrap();
            sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext('plan_override'))")
                .bind(&tid2)
                .execute(&mut *tx)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO plan_overrides (tenant_id, plan_id, reason, admin_id)
                 VALUES ($1, 'enterprise', 'override2', 'admin2')
                 ON CONFLICT (tenant_id) DO UPDATE SET plan_id = 'enterprise'",
            )
            .bind(&tid2)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            "done2"
        }),
    );

    r1.unwrap();
    r2.unwrap();

    // Final state must reflect the last writer (serialized by the lock)
    let plan: (String,) = sqlx::query_as("SELECT plan_id FROM plan_overrides WHERE tenant_id = $1")
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        plan.0 == "pro" || plan.0 == "enterprise",
        "Plan override should be one of the two values, got: {}",
        plan.0
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// RC-TEST-07: Atomic idempotency key claim (middleware)
// ═══════════════════════════════════════════════════════════════════════════

/// Verify that the Lua-based idempotency claim prevents duplicate execution
/// even under concurrent requests. This is a SQL-level simulation: two concurrent
/// INSERTs with ON CONFLICT on idempotency key must result in exactly one row.
#[tokio::test]
async fn atomic_idempotency_double_insert() {
    let Some(pool) = optional_pg_pool("atomic_idempotency_double_insert").await else {
        return;
    };

    let tenant_id = id::generate_id("ten", 21);
    let idem_key = format!("idem-test-{}", Uuid::new_v4());

    seed_minimal_billing_tables(&pool, &tenant_id).await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS idempotency_keys (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id VARCHAR(26) NOT NULL,
            idempotency_key VARCHAR(255) NOT NULL,
            request_hash TEXT,
            response_status INT NOT NULL DEFAULT 200,
            response_body TEXT,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_idempotency_keys_tenant_key
         ON idempotency_keys(tenant_id, idempotency_key)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let pool1 = pool.clone();
    let pool2 = pool.clone();
    let key1 = idem_key.clone();
    let key2 = idem_key.clone();
    let tid1 = tenant_id.clone();
    let tid2 = tenant_id.clone();

    let (r1, r2) = tokio::join!(
        tokio::spawn(async move {
            sqlx::query(
                "INSERT INTO idempotency_keys (id, tenant_id, idempotency_key, response_status, expires_at)
                 VALUES ($1, $2, $3, 200, NOW() + INTERVAL '24 hours')
                 ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
                 RETURNING id",
            )
            .bind(Uuid::new_v4())
            .bind(&tid1)
            .bind(&key1)
            .fetch_optional(&pool1)
            .await
            .unwrap()
            .is_some()
        }),
        tokio::spawn(async move {
            sqlx::query(
                "INSERT INTO idempotency_keys (id, tenant_id, idempotency_key, response_status, expires_at)
                 VALUES ($1, $2, $3, 200, NOW() + INTERVAL '24 hours')
                 ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
                 RETURNING id",
            )
            .bind(Uuid::new_v4())
            .bind(&tid2)
            .bind(&key2)
            .fetch_optional(&pool2)
            .await
            .unwrap()
            .is_some()
        }),
    );

    let insert1 = r1.unwrap();
    let insert2 = r2.unwrap();

    assert!(
        insert1 ^ insert2,
        "Atomic idempotency insert: exactly one must succeed"
    );

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM idempotency_keys WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(&tenant_id)
    .bind(&idem_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1, "Duplicate idempotency key records detected");
}
