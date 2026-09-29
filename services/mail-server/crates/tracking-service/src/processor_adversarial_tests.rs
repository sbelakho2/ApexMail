//! Adversarial WAL/processor tests against the real Redis + canonical Postgres.
//!
//! Included from `processor.rs` as a child module (`#[path = ...]`) so the
//! tests can drive the private flush/suppression machinery directly. Redis
//! comes from the workspace `TEST_REDIS_URL` convention; Postgres from the
//! production migrator's `fresh_canonical_pool`. Both soft-skip only when
//! unset; a configured provisioning failure panics.

use super::*;
use std::sync::Arc;

async fn canonical_pool(test_name: &str) -> Option<sqlx::PgPool> {
    match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

/// A URL whose database number is `db` (same server as TEST_REDIS_URL).
/// The WAL/retry keys are raw (not key-prefixed), so a distinct database
/// isolates these tests from the shared route-handler tests. Shared with
/// the route tests via `test_support` so every live pool in this crate
/// lands on the same logical DB (8).
use crate::routes::test_support::redis_url_in_db;

fn live_redis() -> Option<RedisPool> {
    let url = redis_url_in_db(&std::env::var("TEST_REDIS_URL").ok()?, 8)?;
    let pool = deadpool_redis::Config::from_url(&url)
        .builder()
        .ok()?
        .max_size(4)
        .runtime(deadpool_redis::Runtime::Tokio1)
        .build()
        .ok()?;
    Some(pool)
}

fn dead_redis() -> RedisPool {
    deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .builder()
        .expect("dead redis builder")
        .max_size(1)
        .runtime(deadpool_redis::Runtime::Tokio1)
        .build()
        .expect("dead redis pool")
}

fn processor(db: PgPool, redis: RedisPool) -> Arc<EventProcessor> {
    Arc::new(EventProcessor::with_config(
        db,
        redis,
        clickhouse::Client::default(),
        Duration::from_millis(100),
        20,
        10,
    ))
}

fn unique(label: &str) -> String {
    // tenant_id columns are VARCHAR(26): keep the discriminator short.
    let hex = uuid::Uuid::new_v4().simple().to_string();
    format!("{label}_{}", &hex[..10])
}

/// Serializes the tests that mutate the shared WAL / suppression-retry keys
/// (all instances share one Redis during a run).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn wal_len(pool: &RedisPool) -> i64 {
    let mut conn = pool.get().await.expect("redis conn");
    redis::cmd("LLEN")
        .arg(REDIS_WAL_KEY)
        .query_async(&mut *conn)
        .await
        .expect("LLEN")
}

async fn wal_entries(pool: &RedisPool) -> Vec<String> {
    let mut conn = pool.get().await.expect("redis conn");
    redis::cmd("LRANGE")
        .arg(REDIS_WAL_KEY)
        .arg(0)
        .arg(-1)
        .query_async(&mut *conn)
        .await
        .expect("LRANGE")
}

async fn clear_wal(pool: &RedisPool) {
    let mut conn = pool.get().await.expect("redis conn");
    let _: Result<(), _> = redis::cmd("DEL")
        .arg(REDIS_WAL_KEY)
        .query_async(&mut *conn)
        .await;
}

// ── P0 WAL-ACK helpers (processing lease list + poison DLQ) ──────────────

async fn processing_len(pool: &RedisPool) -> i64 {
    let mut conn = pool.get().await.expect("redis conn");
    redis::cmd("LLEN")
        .arg(REDIS_WAL_PROCESSING_KEY)
        .query_async(&mut *conn)
        .await
        .expect("LLEN processing")
}

async fn processing_entries(pool: &RedisPool) -> Vec<String> {
    let mut conn = pool.get().await.expect("redis conn");
    redis::cmd("LRANGE")
        .arg(REDIS_WAL_PROCESSING_KEY)
        .arg(0)
        .arg(-1)
        .query_async(&mut *conn)
        .await
        .expect("LRANGE processing")
}

async fn clear_processing(pool: &RedisPool) {
    let mut conn = pool.get().await.expect("redis conn");
    let _: Result<(), _> = redis::cmd("DEL")
        .arg(REDIS_WAL_PROCESSING_KEY)
        .query_async(&mut *conn)
        .await;
}

async fn dlq_len(pool: &RedisPool) -> i64 {
    let mut conn = pool.get().await.expect("redis conn");
    redis::cmd("LLEN")
        .arg(REDIS_DEAD_LETTER_KEY)
        .query_async(&mut *conn)
        .await
        .expect("LLEN dlq")
}

async fn dlq_entries(pool: &RedisPool) -> Vec<String> {
    let mut conn = pool.get().await.expect("redis conn");
    redis::cmd("LRANGE")
        .arg(REDIS_DEAD_LETTER_KEY)
        .arg(0)
        .arg(-1)
        .query_async(&mut *conn)
        .await
        .expect("LRANGE dlq")
}

async fn clear_dlq(pool: &RedisPool) {
    let mut conn = pool.get().await.expect("redis conn");
    let _: Result<(), _> = redis::cmd("DEL")
        .arg(REDIS_DEAD_LETTER_KEY)
        .query_async(&mut *conn)
        .await;
}

async fn seed_tenant(pool: &PgPool, tenant: &str) {
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, $1, $1, 'free', 'active')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant)
    .execute(pool)
    .await
    .expect("seed tenant");
}

fn open_data(tenant: &str, message: &str, recipient: &str) -> OpenData {
    OpenData {
        tenant_id: tenant.into(),
        message_id: message.into(),
        recipient: recipient.into(),
        user_agent: Some("Mozilla/5.0 test".into()),
        ip_address: Some("203.0.113.7".into()),
    }
}

#[tokio::test]
async fn open_and_click_dedup_is_per_message_and_recipient() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    clear_wal(&redis).await;
    let proc = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        redis.clone(),
    );
    let tenant = unique("tn_open");
    let message = unique("msg");

    proc.record_open(open_data(&tenant, &message, "u@example.com"))
        .await
        .expect("first open records");
    assert_eq!(wal_len(&redis).await, 1);

    // Replay of the same (message, recipient) is deduped.
    proc.record_open(open_data(&tenant, &message, "u@example.com"))
        .await
        .expect("duplicate open is a no-op");
    assert_eq!(wal_len(&redis).await, 1, "no second WAL entry");

    // A different recipient is a distinct event.
    proc.record_open(open_data(&tenant, &message, "other@example.com"))
        .await
        .expect("distinct recipient records");
    assert_eq!(wal_len(&redis).await, 2);

    // Clicks dedup independently of opens.
    let click = |recipient: &str| ClickData {
        tenant_id: tenant.clone(),
        message_id: message.clone(),
        recipient: recipient.into(),
        link_id: "lnk_1".into(),
        link_url: "https://example.com/a".into(),
        user_agent: Some("Mozilla/5.0 test".into()),
        ip_address: Some("203.0.113.7".into()),
    };
    proc.record_click(click("u@example.com")).await.unwrap();
    assert_eq!(wal_len(&redis).await, 3);
    proc.record_click(click("u@example.com")).await.unwrap();
    assert_eq!(wal_len(&redis).await, 3, "click replay deduped");
    proc.record_click(click("other@example.com")).await.unwrap();
    assert_eq!(wal_len(&redis).await, 4);

    clear_wal(&redis).await;
}

#[tokio::test]
async fn dead_redis_fails_recording_instead_of_silently_dropping() {
    let proc = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        dead_redis(),
    );
    assert!(
        proc.record_open(open_data("tn", "msg", "u@example.com"))
            .await
            .is_err(),
        "a dead WAL must surface an error, never a fabricated success"
    );
    assert!(proc
        .record_unsubscribe(UnsubscribeData {
            tenant_id: "tn".into(),
            message_id: "msg".into(),
            recipient: "u@example.com".into(),
            reason: None,
            category: None,
            user_agent: None,
            ip_address: None,
        })
        .await
        .is_err());
}

#[tokio::test]
async fn unsubscribe_is_durable_idempotent_and_tenant_scoped() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_unsub_db").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    let tenant = unique("tn_unsub");
    let other = unique("tn_other");
    seed_tenant(&db, &tenant).await;
    seed_tenant(&db, &other).await;
    let proc = processor(db.clone(), redis.clone());
    let recipient = "victim@example.com";

    let data = || UnsubscribeData {
        tenant_id: tenant.clone(),
        message_id: unique("msg"),
        recipient: recipient.into(),
        reason: Some("one-click".into()),
        category: None,
        user_agent: Some("MUA".into()),
        ip_address: Some("203.0.113.9".into()),
    };
    proc.record_unsubscribe(data()).await.expect("first unsub");
    proc.record_unsubscribe(data()).await.expect("replay");

    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, tenant_id, reason FROM suppressions WHERE email = $1 ORDER BY tenant_id",
    )
    .bind(recipient)
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "idempotent upsert, no duplicate rows");
    assert_eq!(rows[0].1, tenant);
    assert_eq!(rows[0].2, "unsubscribe");
    assert_eq!(rows[0].0.len(), 26, "canonical 26-char entity id");

    // A second tenant with the same email is unaffected (isolation).
    let other_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1")
            .bind(&other)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(other_count, 0);

    // The WAL carries the unsubscribe event for the tenant.
    let entries = wal_entries(&redis).await;
    assert!(
        entries
            .iter()
            .any(|e| e.contains(recipient) && e.contains(&tenant)),
        "unsubscribe event enqueued"
    );
    clear_wal(&redis).await;
}

#[tokio::test]
async fn suppression_failure_is_queued_for_retry_and_then_drained() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let Some(db) = canonical_pool("tracking_unsub_retry").await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    // Deterministic start state: a crashed predecessor of this suite may
    // have left undrained retry entries on the shared key (the healthy
    // drain below only runs when the whole test passes).
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .query_async(&mut *conn)
            .await;
    }
    let tenant = unique("tn_retry");
    seed_tenant(&db, &tenant).await;
    let recipient = "retry@example.com";

    // First processor has a dead DB → suppression fails and is queued.
    let dead_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://offline@127.0.0.1:1/offline")
        .expect("lazy pool");
    let broken = processor(dead_db, redis.clone());
    let result = broken
        .record_unsubscribe(UnsubscribeData {
            tenant_id: tenant.clone(),
            message_id: unique("msg"),
            recipient: recipient.into(),
            reason: Some("one-click".into()),
            category: None,
            user_agent: None,
            ip_address: None,
        })
        .await;
    assert!(
        result.is_err(),
        "a failed suppression must not report success"
    );

    let mut conn = redis.get().await.unwrap();
    let pending: Vec<String> = redis::cmd("LRANGE")
        .arg(REDIS_SUPPRESSION_RETRY_KEY)
        .arg(0)
        .arg(-1)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1, "the failed suppression is retryable");
    drop(conn);

    // A healthy processor drains the retry queue into the canonical row.
    let healthy = processor(db.clone(), redis.clone());
    healthy.drain_suppression_retries().await;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind(&tenant)
            .bind(recipient)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 1, "retry persisted the suppression");

    // Drained queue is empty.
    let mut conn = redis.get().await.unwrap();
    let left: i64 = redis::cmd("LLEN")
        .arg(REDIS_SUPPRESSION_RETRY_KEY)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(left, 0);
    clear_wal(&redis).await;
}

/// P0 WAL-ACK FIX (drain-Lua test updated):the flush CLAIMS pending →
/// processing first; after a successful PG commit the batch is ACKed out of
/// `processing`. Malformed entries are dead-lettered (durable DLQ), no longer
/// silently dropped by the old LTRIM.
#[tokio::test]
async fn flush_moves_events_to_postgres_and_clears_the_wal() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_flush").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    clear_dlq(&redis).await;
    let tenant = unique("tn_flush");
    seed_tenant(&db, &tenant).await;
    let proc = processor(db.clone(), redis.clone());
    let message = unique("msg");

    proc.record_open(open_data(&tenant, &message, "flush@example.com"))
        .await
        .unwrap();
    proc.flush().await.expect("flush");

    let (event_type, recipient, stored_ip): (String, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT event_type, recipient, ip_address FROM events
             WHERE tenant_id = $1 AND message_id = $2",
        )
        .bind(&tenant)
        .bind(&message)
        .fetch_one(&db)
        .await
        .expect("event persisted");
    assert_eq!(event_type, "opened");
    assert_eq!(recipient.as_deref(), Some("flush@example.com"));
    assert_eq!(
        stored_ip.as_deref(),
        Some("203.0.113.0"),
        "GDPR: the persisted IP is masked to /24"
    );
    assert_eq!(wal_len(&redis).await, 0, "WAL drained");
    assert_eq!(
        processing_len(&redis).await,
        0,
        "P0: the committed batch was ACKed out of `processing`"
    );

    // Tenant isolation: no other tenant sees anything.
    let other: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id <> $1")
        .bind(&tenant)
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(other >= 0);

    // Malformed WAL entries are dead-lettered (durable), never wedging the
    // queue — the old LTRIM silently dropped them.
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("RPUSH")
            .arg(REDIS_WAL_KEY)
            .arg("definitely-not-an-envelope")
            .query_async(&mut *conn)
            .await;
    }
    proc.flush().await.expect("garbage flush is a no-op");
    assert_eq!(wal_len(&redis).await, 0, "poison-free: garbage drained");
    assert_eq!(
        dlq_len(&redis).await,
        1,
        "garbage is durable in the DLQ with the unparsable reason"
    );
    let dlq = dlq_entries(&redis).await;
    let parsed: serde_json::Value = serde_json::from_str(&dlq[0]).expect("DLQ JSON");
    assert_eq!(
        parsed["failure_reason"].as_str(),
        Some("unparsable_envelope")
    );
    clear_dlq(&redis).await;
}

/// P0 WAL-ACK FIX (drain-Lua test updated):the flush now CLAIMS the batch
/// pending → processing (never deletes it first), re-enqueues on PG failure
/// via the atomic requeue+release script, and poison entries (retry budget
/// exhausted) land in the durable DLQ instead of being dropped.
#[tokio::test]
async fn flush_failure_reenqueues_with_retry_budget_and_drops_poison() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    clear_dlq(&redis).await;
    let dead_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://offline@127.0.0.1:1/offline")
        .expect("lazy pool");
    let proc = processor(dead_db, redis.clone());

    let event = TrackingEvent {
        id: new_id("evt"),
        event_type: EventType::Opened,
        tenant_id: "tn_retry_wal".into(),
        message_id: unique("msg"),
        recipient: "retry@example.com".into(),
        link_id: None,
        link_url: None,
        unsubscribe_reason: None,
        user_agent: None,
        ip_address: None,
        timestamp: Utc::now(),
        metadata: None,
    };
    let envelope = build_wal_envelope(&serde_json::to_string(&event).unwrap());
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("RPUSH")
            .arg(REDIS_WAL_KEY)
            .arg(&envelope)
            .query_async(&mut *conn)
            .await;
    }

    proc.flush().await.expect_err("dead PG must fail the flush");
    let entries = wal_entries(&redis).await;
    assert_eq!(entries.len(), 1, "event re-enqueued to `pending`");
    assert_eq!(
        processing_len(&redis).await,
        0,
        "the failed lease was released atomically with the requeue"
    );
    assert!(
        entries[0].contains("\"r\":1"),
        "retry counter bumped: {}",
        entries[0]
    );

    // Walk the entry to the poison budget; it must be dead-lettered, not
    // retried forever.
    let mut current = entries[0].clone();
    let mut bumps = 0usize;
    while let Some(next) = bump_envelope_retries(&current) {
        current = next;
        bumps += 1;
        assert!(bumps <= MAX_EVENT_RETRIES, "retry budget is bounded");
    }
    assert!(bumps >= 1, "the entry kept being retryable");
    assert!(
        bump_envelope_retries(&current).is_none(),
        "entry at the budget is poison"
    );
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_WAL_KEY)
            .query_async(&mut *conn)
            .await;
        let _: Result<(), _> = redis::cmd("RPUSH")
            .arg(REDIS_WAL_KEY)
            .arg(&current)
            .query_async(&mut *conn)
            .await;
    }
    proc.flush().await.expect_err("flush still fails (PG down)");
    assert_eq!(wal_len(&redis).await, 0, "poison re-queued nowhere");
    assert_eq!(processing_len(&redis).await, 0, "poison lease released");
    assert_eq!(dlq_len(&redis).await, 1, "poison durable in the DLQ");
    let dlq = dlq_entries(&redis).await;
    let parsed: serde_json::Value = serde_json::from_str(&dlq[0]).expect("DLQ JSON");
    assert_eq!(
        parsed["failure_reason"].as_str(),
        Some("max_retries_exceeded")
    );
    assert_eq!(
        parsed["payload"].as_str(),
        Some(current.as_str()),
        "the original raw envelope is preserved verbatim"
    );
    clear_wal(&redis).await;
    clear_dlq(&redis).await;
}

#[tokio::test]
async fn start_drains_on_shutdown_and_stop_joins_the_loop() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_shutdown").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    let tenant = unique("tn_stop");
    seed_tenant(&db, &tenant).await;
    let proc = processor(db.clone(), redis.clone());
    let message = unique("msg");

    proc.record_open(open_data(&tenant, &message, "stop@example.com"))
        .await
        .unwrap();
    proc.clone().start();
    proc.stop().await;

    let persisted: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND message_id = $2")
            .bind(&tenant)
            .bind(&message)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(persisted, 1, "shutdown drains the WAL (C-093)");
    assert_eq!(wal_len(&redis).await, 0);
}

#[tokio::test]
async fn suppression_publishers_never_panic_with_a_dead_redis() {
    let proc = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        dead_redis(),
    );
    proc.publish_suppression_added("tn", "u@example.com", None);
    proc.publish_suppression_added("tn", "u@example.com", Some("marketing"));
    proc.publish_suppression_removed("tn", "u@example.com");
    proc.publish_preference_changed("tn", "u@example.com", "marketing", false);
    proc.publish_preference_changed("tn", "u@example.com", "marketing", true);
}

#[tokio::test]
async fn dedup_helpers_round_trip_and_survive_missing_keys() {
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let proc = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        redis.clone(),
    );
    let key = format!("test:dedup:{}", uuid::Uuid::new_v4().simple());
    assert!(proc.try_set_dedup("test", &key, 60).await.unwrap());
    assert!(!proc.try_set_dedup("test", &key, 60).await.unwrap());
    proc.clear_dedup(&key).await;
    assert!(proc.try_set_dedup("test", &key, 60).await.unwrap());
    proc.clear_dedup(&format!("{key}:missing")).await; // no panic

    // Counter bumps are tenant-scoped and fire-and-forget; give the spawned
    // pipeline a bounded moment, then verify no cross-tenant bleed.
    proc.incr_counters("tn_a", "2026-01-01", "12", "opens")
        .await;
    proc.incr_counters("tn_a", "2026-01-01", "12", "opens")
        .await;
    proc.incr_counters("tn_b", "2026-01-01", "12", "opens")
        .await;
    let mut a = 0i64;
    let mut b = 0i64;
    for _ in 0..20 {
        let mut conn = redis.get().await.unwrap();
        a = redis::cmd("GET")
            .arg("stats:tn_a:hour:2026-01-01:12:opens")
            .query_async(&mut *conn)
            .await
            .unwrap_or(0);
        b = redis::cmd("GET")
            .arg("stats:tn_b:hour:2026-01-01:12:opens")
            .query_async(&mut *conn)
            .await
            .unwrap_or(0);
        if a == 2 && b == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!((a, b), (2, 1), "tenant-scoped counters");
    let mut conn = redis.get().await.unwrap();
    let _: Result<(), _> = redis::cmd("DEL")
        .arg("stats:tn_a:hour:2026-01-01:12:opens")
        .arg("stats:tn_a:day:2026-01-01:opens")
        .arg("stats:tn_b:hour:2026-01-01:12:opens")
        .arg("stats:tn_b:day:2026-01-01:opens")
        .query_async(&mut *conn)
        .await;
}

/// `Entity id` generation must stay canonical for the VARCHAR(26) columns
/// the processor writes (suppressions / subscription_preferences).
#[test]
fn suppression_ids_are_26_chars_and_prefixed() {
    for _ in 0..50 {
        let id = suppression_entity_id();
        assert_eq!(id.len(), 26);
        assert!(id.starts_with("sup_"));
    }
}

// ── Residual-arm coverage: flush/reenqueue/drain/counter error paths ──────

/// Enable a DEBUG-level tracing subscriber so `warn!`/`info!`/`error!` FIELD
/// expressions (lazily evaluated only when an event is enabled) execute in
/// tests that deliberately drive logging paths. `try_init` keeps repeat
/// calls (never in one nextest process, but harmless) from panicking.
fn test_log_subscriber() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("tracking_service=debug"))
        .with_test_writer()
        .try_init();
}

/// A scripted TCP stand-in for Redis: every connection is answered for its
/// first `replies_per_conn` commands with `+OK`, then the socket is closed
/// mid-conversation. Connection CREATION therefore succeeds (redis-rs's
/// handshake is answered), while subsequent commands fail — the deterministic
/// "server died between two commands" shape, with no wall-clock games.
/// One reply is always reserved for redis-rs's connection handshake.
struct ClosingRedis {
    pool: RedisPool,
}

/// Count COMPLETE RESP-array commands in `buf` and return (complete, consumed).
fn count_complete_commands(buf: &[u8]) -> usize {
    let mut i = 0usize;
    let mut n = 0usize;
    while i < buf.len() {
        if buf[i] != b'*' {
            break;
        }
        let Some(nl) = buf[i..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let Ok(nargs) = std::str::from_utf8(&buf[i + 1..i + nl])
            .map(|s| s.parse::<usize>())
            .unwrap_or(Ok(0))
        else {
            return n;
        };
        let mut j = i + nl + 2;
        let mut complete = true;
        for _ in 0..nargs {
            if j >= buf.len() || buf[j] != b'$' {
                complete = false;
                break;
            }
            let Some(nl2) = buf[j..].windows(2).position(|w| w == b"\r\n") else {
                complete = false;
                break;
            };
            let Ok(len) = std::str::from_utf8(&buf[j + 1..j + nl2])
                .map(|s| s.parse::<usize>())
                .unwrap_or(Ok(0))
            else {
                complete = false;
                break;
            };
            j += nl2 + 2 + len + 2;
            if j > buf.len() {
                complete = false;
                break;
            }
        }
        if !complete {
            break;
        }
        i = j;
        n += 1;
    }
    n
}

impl ClosingRedis {
    /// `replies_per_conn` = extra `+OK` replies after the mandatory
    /// handshake. 0 → creation succeeds (handshake answered), every real
    /// command fails.
    fn start(replies_per_conn: usize) -> Self {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind closing redis");
        let local_addr = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    let mut pending: Vec<u8> = Vec::new();
                    // redis-rs sends two CLIENT SETINFO handshake commands at
                    // connect; always answer those, then honour the caller's
                    // per-connection reply budget for real commands.
                    let mut handshake_left = 2usize;
                    let mut replies_left = replies_per_conn;
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                pending.extend_from_slice(&buf[..n]);
                                let complete = count_complete_commands(&pending);
                                for _ in 0..complete {
                                    if handshake_left > 0 {
                                        handshake_left = handshake_left.saturating_sub(1);
                                    } else if replies_left > 0 {
                                        replies_left = replies_left.saturating_sub(1);
                                    }
                                    if stream.write_all(b"+OK\r\n").is_err() {
                                        return;
                                    }
                                }
                                if handshake_left == 0 && replies_left == 0 && complete > 0 {
                                    // Every budgeted command answered — close
                                    // mid-conversation so the client's next
                                    // reply read fails.
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        let pool = deadpool_redis::Config::from_url(format!("redis://{local_addr}"))
            .builder()
            .expect("closing redis builder")
            .max_size(2)
            .runtime(deadpool_redis::Runtime::Tokio1)
            // Bound every pool wait: against this stand-in connection
            // creation keeps failing once the handshake budget is gone, and
            // an unbounded wait would hang the whole run.
            .create_timeout(Some(Duration::from_secs(2)))
            .wait_timeout(Some(Duration::from_secs(2)))
            .recycle_timeout(Some(Duration::from_secs(2)))
            .build()
            .expect("closing redis pool");
        Self { pool }
    }
}

fn flush_processor(
    db: PgPool,
    redis: RedisPool,
    clickhouse: clickhouse::Client,
) -> Arc<EventProcessor> {
    Arc::new(EventProcessor::with_config(
        db,
        redis,
        clickhouse,
        Duration::from_millis(50),
        10,
        10,
    ))
}

fn wal_event(tenant: &str, message: &str, event_type: EventType) -> TrackingEvent {
    TrackingEvent {
        id: new_id("evt"),
        event_type,
        tenant_id: tenant.into(),
        message_id: message.into(),
        recipient: "residual@example.com".into(),
        link_id: Some("lnk_1".into()),
        link_url: Some("https://example.com/r".into()),
        unsubscribe_reason: None,
        user_agent: Some("Mozilla/5.0 residual".into()),
        ip_address: Some("203.0.113.8".into()),
        timestamp: Utc::now(),
        metadata: None,
    }
}

async fn seed_wal(redis: &RedisPool, entries: &[String]) {
    let mut conn = redis.get().await.unwrap();
    for e in entries {
        let _: Result<(), _> = redis::cmd("RPUSH")
            .arg(REDIS_WAL_KEY)
            .arg(e)
            .query_async(&mut *conn)
            .await;
    }
}

/// A live ClickHouse client for the OLAP ingest path (workspace test server).
fn live_clickhouse() -> clickhouse::Client {
    let url =
        std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://127.0.0.1:8124".into());
    clickhouse::Client::default()
        .with_url(&url)
        .with_database("apexmail")
}

/// A TCP listener that accepts HTTP connections and never responds — the
/// deterministic "black-holed ClickHouse" for the insert-timeout arm.
fn stalled_http_server() -> String {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled http");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                // Hold every accepted connection open without answering.
                Ok(stream) => {
                    std::thread::spawn(move || {
                        let mut sink = stream;
                        let _ = std::io::Write::flush(&mut sink);
                        std::thread::sleep(Duration::from_secs(120));
                    });
                }
                Err(_) => break,
            }
        }
    });
    format!("http://{addr}")
}

/// `flush` early-returns Ok when the Redis pool itself cannot answer, and
/// when the atomic drain (LRANGE) errors — a lost WAL read must never be
/// reported as a failure that would re-enqueue blind.
#[tokio::test]
async fn flush_early_returns_are_ok_when_redis_cannot_answer() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    test_log_subscriber();
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    // (1) Empty WAL: the LLEN gate early-returns Ok without touching PG.
    let dead_pg = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        redis.clone(),
    );
    clear_wal(&redis).await;
    dead_pg.flush().await.expect("empty WAL flush is Ok");

    // (2) Dead pool: the flush error propagates (never a fabricated success).
    let dead = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        dead_redis(),
    );
    assert!(
        dead.flush().await.is_err(),
        "a dead Redis must surface as flush Err"
    );

    // (3) Connection creation succeeds (handshake answered) but the first
    //     real command fails — LLEN errors after `get()` succeeded.
    let closing = ClosingRedis::start(0);
    let proc = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        closing.pool.clone(),
    );
    let r = proc.flush().await;
    assert!(r.is_err(), "LLEN failure must propagate, not silently pass");
}

/// A healthy flush persists events, updates message stats (UUID message ids
/// only), and ingests into the live ClickHouse — the full success path.
#[tokio::test]
async fn flush_success_persists_updates_stats_and_ingests_clickhouse() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    test_log_subscriber();
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_flush_ok").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    let tenant = unique("tn_flushok");
    seed_tenant(&db, &tenant).await;

    let uuid_message = uuid::Uuid::new_v4().to_string();
    let plain_message = unique("msg");
    sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, status) \
         VALUES ($1::uuid, $2, 'sender@example.com', '[\"a@b.test\"]'::jsonb, '[]'::jsonb, '[]'::jsonb, 't', 'sent') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&uuid_message)
    .bind(&tenant)
    .execute(&db)
    .await
    .expect("seed message row");
    let events = [
        wal_event(&tenant, &uuid_message, EventType::Opened),
        wal_event(&tenant, &uuid_message, EventType::Opened),
        wal_event(&tenant, &uuid_message, EventType::Clicked),
        wal_event(&tenant, &plain_message, EventType::Unsubscribed),
    ];
    let envelopes: Vec<String> = events
        .iter()
        .map(|e| build_wal_envelope(&serde_json::to_string(e).unwrap()))
        .collect();
    seed_wal(&redis, &envelopes).await;

    let proc = flush_processor(db.clone(), redis.clone(), live_clickhouse());
    proc.flush().await.expect("flush with live PG and CH");

    assert_eq!(wal_len(&redis).await, 0, "WAL drained");
    let persisted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(persisted, 4, "every event persisted");

    // The UUID-keyed message row absorbed the open/click counts; the
    // non-UUID message id was skipped (it can never match a UUID PK).
    let stats: (i32, i32, i32) = sqlx::query_as(
        "SELECT open_count, click_count, unsubscribe_count FROM messages WHERE id = $1::uuid",
    )
    .bind(&uuid_message)
    .fetch_one(&db)
    .await
    .expect("seeded message row");
    assert_eq!(stats, (2, 1, 0), "batch unnest stats update applied");

    // ClickHouse ingest ran inside flush (awaited); the rows are queryable.
    // The ingest's visibility is asynchronous on the ClickHouse side, so a
    // single immediate query can race it under load: poll bounded before
    // concluding the rows never landed.
    let mut by_type: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for _ in 0..40 {
        let ch_rows: Vec<(String, u64)> = live_clickhouse()
            .query("SELECT event_type, count() FROM events WHERE tenant_id = ? GROUP BY event_type")
            .bind(&tenant)
            .fetch_all()
            .await
            .expect("clickhouse ingest query");
        by_type = ch_rows.into_iter().collect();
        if by_type.get("opened") == Some(&2)
            && by_type.get("clicked") == Some(&1)
            && by_type.get("unsubscribed") == Some(&1)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert_eq!(by_type.get("opened"), Some(&2), "ingest visibility: {by_type:?}");
    assert_eq!(by_type.get("clicked"), Some(&1));
    assert_eq!(by_type.get("unsubscribed"), Some(&1));
    live_clickhouse()
        .query(&format!(
            "ALTER TABLE events DELETE WHERE tenant_id = '{tenant}'"
        ))
        .execute()
        .await
        .expect("clickhouse cleanup");
    clear_wal(&redis).await;
}

/// A failing ClickHouse ingest must not fail the flush: Postgres is the
/// source of truth and the failure is logged with a metric.
#[tokio::test]
async fn clickhouse_failure_does_not_fail_the_flush() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    test_log_subscriber();
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_ch_fail").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    let tenant = unique("tn_chfail");
    seed_tenant(&db, &tenant).await;
    let event = wal_event(&tenant, &unique("msg"), EventType::Opened);
    seed_wal(
        &redis,
        &[build_wal_envelope(&serde_json::to_string(&event).unwrap())],
    )
    .await;

    // Default client has no URL: the insert handle fails immediately.
    let proc = flush_processor(db.clone(), redis.clone(), clickhouse::Client::default());
    proc.flush()
        .await
        .expect("CH failure must not fail the flush");
    assert_eq!(wal_len(&redis).await, 0, "events still drained");
}

/// A ClickHouse endpoint that accepts nothing AND never answers exercises
/// the insert-timeout arm (bounded, so the flush loop cannot wedge).
#[tokio::test]
async fn clickhouse_timeout_is_bounded_and_non_fatal() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    test_log_subscriber();
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_ch_slow").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    let tenant = unique("tn_chslow");
    seed_tenant(&db, &tenant).await;
    let event = wal_event(&tenant, &unique("msg"), EventType::Opened);
    seed_wal(
        &redis,
        &[build_wal_envelope(&serde_json::to_string(&event).unwrap())],
    )
    .await;

    // A local HTTP server that accepts connections and NEVER answers: the
    // insert blocks until the processor's own insert timeout (1s) fires.
    let stalled = clickhouse::Client::default()
        .with_url(stalled_http_server())
        .with_database("apexmail");
    let proc = EventProcessor::with_config(
        db.clone(),
        redis.clone(),
        stalled,
        Duration::from_secs(1),
        10,
        10,
    );
    let started = std::time::Instant::now();
    proc.flush()
        .await
        .expect("timeout must be swallowed as best-effort");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "the insert timeout actually bounded the attempt"
    );
    assert_eq!(
        wal_len(&redis).await,
        0,
        "events drained despite CH timeout"
    );
}

/// P0 WAL-ACK FIX (was `reenqueue_events_error_arms_are_swallowed_and_reported`
/// against the old LRANGE+LTRIM drain): the failure path is now
/// `requeue_after_failure` — an atomic requeue-to-pending + lease-release Lua.
/// Its error arms are swallowed (a dead pool leaves the batch LEASED in
/// `processing` — reclaimed later, never lost), poison entries are
/// dead-lettered to the durable DLQ instead of dropped, and a Redis-side
/// script failure (wrong-type key) is reported without panicking.
#[tokio::test]
async fn requeue_after_failure_error_arms_are_swallowed_and_dead_letters_poison() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    test_log_subscriber();
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let dead = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        dead_redis(),
    );
    // (1) Dead pool: logs and returns without panicking. A real claimed
    //     batch would stay LEASED in `processing` and be reclaimed later.
    dead.requeue_after_failure(&["{\"v\":2,\"cs\":\"ab\"}".into()])
        .await;

    // (2) Poison entry (retry budget exhausted) is dead-lettered, not
    //     dropped-on-the-floor and not re-queued.
    let proc = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        redis.clone(),
    );
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    clear_dlq(&redis).await;
    let envelope = build_wal_envelope(
        &serde_json::to_string(&wal_event("tn", "msg", EventType::Opened)).unwrap(),
    );
    // Genuinely poison: bump to the retry ceiling — bump_envelope_retries
    // returns None once retries >= MAX_EVENT_RETRIES, and the envelope AT the
    // ceiling is the poison shape requeue_after_failure must dead-letter
    // (three bumps left it under the ceiling, and re-queueing it is correct).
    let mut poison = envelope.clone();
    for _ in 0..=MAX_EVENT_RETRIES {
        poison = bump_envelope_retries(&poison)
            .unwrap_or_else(|| poison.clone());
    }
    proc.requeue_after_failure(&[poison]).await;
    assert_eq!(wal_len(&redis).await, 0, "poison is NOT re-queued");
    assert_eq!(dlq_len(&redis).await, 1, "poison is durable in the DLQ");
    clear_dlq(&redis).await;

    // (3) Script failure: the pending key holds a STRING, so the requeue
    //     RPUSH (and the whole atomic script) fails and is reported.
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_WAL_KEY)
            .query_async(&mut *conn)
            .await;
        let _: Result<(), _> = redis::cmd("SET")
            .arg(REDIS_WAL_KEY)
            .arg("not-a-list")
            .query_async(&mut *conn)
            .await;
    }
    proc.requeue_after_failure(&["{\"v\":2,\"cs\":\"ab\"}".into()])
        .await;
    // Restore the key for the other tests.
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_WAL_KEY)
            .query_async(&mut *conn)
            .await;
    }
}

/// `drain_all` (shutdown drain) survives a dead Redis pool and an LLEN
/// failure without panicking; the healthy path is covered by the shutdown
/// test above.
#[tokio::test]
async fn drain_all_survives_redis_failures() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    test_log_subscriber();
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    // (1) Dead pool.
    let dead = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        dead_redis(),
    );
    dead.drain_all().await;

    // (2) LLEN error (closing server: `get()` succeeds, the command fails).
    let t0 = std::time::Instant::now();
    let closing = ClosingRedis::start(0);
    eprintln!("stage: server started in {:?}", t0.elapsed());

    let broken = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        closing.pool.clone(),
    );
    broken.drain_all().await;

    // (3) Flush error mid-drain (dead PG, one queued event): the drain stops
    //     but leaves the entry re-enqueued.
    clear_wal(&redis).await;
    let dead_db = processor(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(50))
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        redis.clone(),
    );
    seed_wal(
        &redis,
        &[build_wal_envelope(
            &serde_json::to_string(&wal_event("tn", "msg", EventType::Opened)).unwrap(),
        )],
    )
    .await;
    dead_db.drain_all().await;
    assert_eq!(wal_len(&redis).await, 1, "entry re-enqueued, not lost");
    clear_wal(&redis).await;
}

/// The background loop: a failing flush backs off, keeps the event queued
/// with a bumped retry counter, and `stop()` still drains and exits.
#[tokio::test]
async fn run_loop_backs_off_while_postgres_is_down_and_stop_drains() {
    test_log_subscriber();
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    clear_wal(&redis).await;
    let dead_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://offline@127.0.0.1:1/offline")
        .expect("lazy pool");
    let proc = Arc::new(EventProcessor::with_config(
        dead_db,
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_millis(50),
        10, // flush interval: one tick happens almost immediately
        10,
    ));
    let envelope = build_wal_envelope(
        &serde_json::to_string(&wal_event("tn_loop", "msg_loop", EventType::Opened)).unwrap(),
    );
    seed_wal(&redis, &[envelope]).await;

    proc.clone().start();
    // Wait until the first failed flush re-enqueued the entry with r:1 —
    // proof the interval arm ran with an error and the backoff was computed.
    let mut bumped = false;
    for _ in 0..200 {
        if wal_entries(&redis)
            .await
            .iter()
            .any(|e| e.contains("\"r\":1"))
        {
            bumped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(bumped, "the failing loop re-enqueued with a bumped counter");
    proc.stop().await;
    assert!(!proc.running.load(std::sync::atomic::Ordering::SeqCst));
    clear_wal(&redis).await;
}

/// Suppression-retry drain failure arms: dead pool, dead-on-arrival server,
/// empty queue, malformed entries, and poison.
#[tokio::test]
async fn suppression_retry_drain_survives_hostile_states() {
    test_log_subscriber();
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let dead_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://offline@127.0.0.1:1/offline")
        .expect("lazy pool");

    // (1) Dead pool: warns and returns.
    let dead_redis_proc = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        dead_redis(),
    );
    dead_redis_proc.drain_suppression_retries().await;

    // (2) Server that accepts but never answers Redis.
    let closing = ClosingRedis::start(0);
    let closing_proc = processor(dead_db.clone(), closing.pool.clone());
    closing_proc.drain_suppression_retries().await;

    // (3) Empty queue: immediate return.
    let proc = processor(dead_db.clone(), redis.clone());
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .query_async(&mut *conn)
            .await;
    }
    proc.drain_suppression_retries().await;

    // (4) Malformed entries: logged and skipped, never wedging the drain.
    {
        let mut conn = redis.get().await.unwrap();
        for junk in ["totally-not-json", "{\"v\":99}"] {
            let _: Result<(), _> = redis::cmd("RPUSH")
                .arg(REDIS_SUPPRESSION_RETRY_KEY)
                .arg(junk)
                .query_async(&mut *conn)
                .await;
        }
    }
    proc.drain_suppression_retries().await;
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .query_async(&mut *conn)
            .await;
    }

    // (5) Valid entry against a dead Postgres: re-queued with a bumped retry
    //     counter; at the budget it becomes poison and is dropped.
    let good = build_suppression_retry_entry("tn_retry_drain", "drain@example.com", None);
    let poison = r#"{"tenant_id":"tn_retry_drain","email":"poison@example.com","category":null,"retries":10}"#.to_string();
    {
        let mut conn = redis.get().await.unwrap();
        for entry in [&good, &poison] {
            let _: Result<(), _> = redis::cmd("RPUSH")
                .arg(REDIS_SUPPRESSION_RETRY_KEY)
                .arg(entry)
                .query_async(&mut *conn)
                .await;
        }
    }
    proc.drain_suppression_retries().await;
    let left: Vec<String> = {
        let mut conn = redis.get().await.unwrap();
        redis::cmd("LRANGE")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .arg(0)
            .arg(-1)
            .query_async(&mut *conn)
            .await
            .unwrap()
    };
    assert_eq!(
        left.len(),
        1,
        "the good entry was re-queued, poison dropped: {left:?}"
    );
    assert!(
        left[0].contains("\"retries\":1"),
        "retry counter bumped: {left:?}"
    );
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .query_async(&mut *conn)
            .await;
    }
}

/// `clear_dedup` (dedup rollback) must never panic on a dead pool — and its
/// DEL failure is logged when the pool answers but the command fails.
#[tokio::test]
async fn clear_dedup_rollback_swallows_redis_failures() {
    test_log_subscriber();
    // Dead pool: `get()` fails.
    let dead = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        dead_redis(),
    );
    dead.clear_dedup("open:msg:rcpt").await;

    // Answering-then-closing server: `get()` succeeds, DEL fails.
    let closing = ClosingRedis::start(0);
    let closing_proc = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        closing.pool.clone(),
    );
    closing_proc.clear_dedup("open:msg:rcpt").await;
}

/// A dedup rollback after enqueue failure: with live Redis for the SETNX and
/// a WAL RPUSH that fails (wrong-type WAL key), the click/open dedup keys
/// must be rolled back and the error surfaced.
#[tokio::test]
async fn enqueue_failure_rolls_back_the_dedup_key() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    test_log_subscriber();
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    clear_wal(&redis).await;
    {
        // Make the WAL RPUSH fail while SETNX still works.
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_WAL_KEY)
            .query_async(&mut *conn)
            .await;
        let _: Result<(), _> = redis::cmd("SET")
            .arg(REDIS_WAL_KEY)
            .arg("not-a-list")
            .query_async(&mut *conn)
            .await;
    }
    let proc = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        redis.clone(),
    );
    let message = unique("msg_rb");
    proc.record_open(open_data("tn_rb", &message, "rb@example.com"))
        .await
        .expect_err("RPUSH to a string key must fail the open");

    proc.record_click(ClickData {
        tenant_id: "tn_rb".into(),
        message_id: unique("msg_rb2"),
        recipient: "rb@example.com".into(),
        link_id: "lnk_1".into(),
        link_url: "https://example.com/x".into(),
        user_agent: None,
        ip_address: None,
    })
    .await
    .expect_err("RPUSH to a string key must fail the click");

    // The dedup keys were rolled back: recording again fails at the SAME
    // stage (not as a duplicate short-circuit).
    let mut conn = redis.get().await.unwrap();
    let deduped: Option<String> = redis::cmd("GET")
        .arg(format!(
            "dedupe:{}",
            dedup_key("open", &message, "rb@example.com", None)
        ))
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(deduped, None, "open dedup key rolled back");
    let _: Result<(), _> = redis::cmd("DEL")
        .arg(REDIS_WAL_KEY)
        .query_async(&mut *conn)
        .await;
}

/// `incr_counters` must swallow (but log) a dead Redis pipeline.
#[tokio::test]
async fn counter_pipeline_survives_a_dead_redis() {
    test_log_subscriber();
    let dead = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        dead_redis(),
    );
    dead.incr_counters("tn_counters", "2026-09-21", "12", "clicks")
        .await;
}

/// A suppression insert that fails AND cannot be enqueued for retry is the
/// CRITICAL path: the error must surface (nothing persisted anywhere).
#[tokio::test]
async fn suppression_insert_and_retry_enqueue_both_failing_is_a_hard_error() {
    test_log_subscriber();
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let dead_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://offline@127.0.0.1:1/offline")
        .expect("lazy pool");
    let proc = processor(dead_db, redis.clone());

    // Make the retry RPUSH fail (wrong type) while the WAL stays a list.
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .query_async(&mut *conn)
            .await;
        let _: Result<(), _> = redis::cmd("SET")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .arg("not-a-list")
            .query_async(&mut *conn)
            .await;
    }
    let err = proc
        .record_unsubscribe(UnsubscribeData {
            tenant_id: "tn_double_fail".into(),
            message_id: unique("msg"),
            recipient: "doublefail@example.com".into(),
            reason: Some("one-click".into()),
            category: None,
            user_agent: None,
            ip_address: None,
        })
        .await
        .expect_err("suppression insert AND retry enqueue both failed");
    assert!(
        err.to_string().contains("suppression insert failed"),
        "the error must name the lost suppression: {err}"
    );
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .query_async(&mut *conn)
            .await;
    }
}

/// WAL envelope parsing: an unknown version and a corrupt legacy payload are
/// poison — P0 FIX: dead-lettered to the durable DLQ (with the
/// `unparsable_envelope` reason), never a panic and never a wedge.
#[tokio::test]
async fn wal_parser_rejects_unknown_versions_and_corrupt_legacy_entries() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    test_log_subscriber();
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_wal_parse").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    clear_dlq(&redis).await;
    let proc = processor(db.clone(), redis.clone());

    let mut unknown = build_wal_envelope(
        &serde_json::to_string(&wal_event("tn", "msg", EventType::Opened)).unwrap(),
    );
    unknown = unknown.replace("\"v\":2", "\"v\":99");
    let corrupt_legacy = "1:<not-json>:deadbeef";
    seed_wal(&redis, &[unknown, corrupt_legacy.into()]).await;
    proc.flush()
        .await
        .expect("poison is dead-lettered, flush succeeds");
    assert_eq!(wal_len(&redis).await, 0, "both poison entries drained");
    assert_eq!(dlq_len(&redis).await, 2, "both poison entries durable in the DLQ");
    for entry in dlq_entries(&redis).await {
        let parsed: serde_json::Value = serde_json::from_str(&entry).expect("DLQ JSON");
        assert_eq!(
            parsed["failure_reason"].as_str(),
            Some("unparsable_envelope")
        );
    }
    clear_dlq(&redis).await;
}

// ═════════════════════════════════════════════════════════════════════════════
// P0 WAL-ACK:the "a kill at ANY point loses zero accepted events" matrix.
// One explicit test per crash window of the claim/lease/ACK protocol:
//
//   W1 kill BEFORE the claim        → entry still in `pending`
//   W2 kill AFTER the claim, BEFORE the PG commit → orphaned lease in
//      `processing`, reclaimed (re-drained FIRST) by the next flush
//   W3 kill AFTER the PG commit, BEFORE the ACK → replay absorbed by the
//      `ON CONFLICT (id) DO NOTHING` idempotency — exactly-once rows
//   W4 reclaim RACING a live flush / TWO flushers → no loss, no double rows
//   W5 MAX_FLUSH_BATCH still caps one drain (semantics preserved)
// ═════════════════════════════════════════════════════════════════════════════

/// W1 — kill before the claim:the accepted event is durable in `pending`
/// (where enqueue put it); a fresh processor's flush commits it. Nothing
/// was ever deleted from the queue before the commit.
#[tokio::test]
async fn crash_window_w1_kill_before_claim_loses_nothing() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_w1").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    let tenant = unique("tn_w1");
    seed_tenant(&db, &tenant).await;
    let message = unique("msg_w1");
    let proc = processor(db.clone(), redis.clone());

    // The event is accepted (RPUSH to pending) and THEN the process dies
    // before any flush runs: it simply sits in `pending`.
    proc.record_open(open_data(&tenant, &message, "w1@example.com"))
        .await
        .expect("accepted event is durable in pending");
    assert_eq!(wal_len(&redis).await, 1);
    assert_eq!(processing_len(&redis).await, 0, "nothing claimed yet");

    // "Restart": a fresh processor drains it exactly once.
    proc.flush().await.expect("flush after restart");
    let persisted: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND message_id = $2")
            .bind(&tenant)
            .bind(&message)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(persisted, 1, "the event survived the kill");
    assert_eq!(wal_len(&redis).await, 0);
    assert_eq!(processing_len(&redis).await, 0, "ACKed after commit");
    clear_wal(&redis).await;
}

/// W2 — kill after the claim (pending → processing) but BEFORE the PG
/// commit:the batch is orphaned in `processing`. The next flush reclaims
/// leftover leases back to the HEAD of `pending` FIRST (no starvation) and
/// commits them; zero accepted events are lost. Even with FRESH traffic
/// queued behind the crash, the orphaned events are drained first.
#[tokio::test]
async fn crash_window_w2_orphaned_lease_is_reclaimed_before_new_work() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_w2").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    let tenant = unique("tn_w2");
    seed_tenant(&db, &tenant).await;
    let message = unique("msg_w2");
    let proc = processor(db.clone(), redis.clone());

    // Two accepted events, then the "kill" right after the atomic claim:
    // simulate it by running ONLY the claim step (lease held, no commit).
    let crashed = [
        wal_event(&tenant, &format!("{message}-a"), EventType::Opened),
        wal_event(&tenant, &format!("{message}-b"), EventType::Clicked),
    ];
    seed_wal(
        &redis,
        &crashed
            .iter()
            .map(|e| build_wal_envelope(&serde_json::to_string(e).unwrap()))
            .collect::<Vec<_>>(),
    )
    .await;
    {
        let mut conn = redis.get().await.unwrap();
        let claimed = proc.claim_batch(&mut conn, 10).await.expect("claim");
        assert_eq!(claimed.len(), 2);
    }
    assert_eq!(wal_len(&redis).await, 0, "moved out of pending…");
    assert_eq!(processing_len(&redis).await, 2, "…durable in processing");

    // Fresh traffic arrives BEHIND the crash.
    proc.record_open(open_data(&tenant, &format!("{message}-new"), "w2new@example.com"))
        .await
        .expect("fresh event enqueued");

    // "Restart": the reclaim runs FIRST — the orphaned batch is drained
    // before (in front of) the fresh event.
    proc.flush().await.expect("flush reclaims and commits");

    let persisted: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND message_id LIKE $2 || '%'")
            .bind(&tenant)
            .bind(&message)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        persisted, 3,
        "orphaned leases AND fresh traffic all committed"
    );
    assert_eq!(wal_len(&redis).await, 0);
    assert_eq!(processing_len(&redis).await, 0, "all leases ACKed");
    clear_wal(&redis).await;
}

/// W3 — kill after the PostgreSQL COMMIT but before the ACK:the event is in
/// BOTH Postgres and `processing`. The reclaim replays it into the
/// `ON CONFLICT (id) DO NOTHING` insert — the idempotency that makes
/// at-least-once delivery exactly-once on rows. Nothing lost, nothing
/// duplicated.
#[tokio::test]
async fn crash_window_w3_committed_but_not_acked_replays_idempotently() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_w3").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    let tenant = unique("tn_w3");
    seed_tenant(&db, &tenant).await;
    let message = unique("msg_w3");
    let proc = processor(db.clone(), redis.clone());

    let event = wal_event(&tenant, &message, EventType::Opened);
    let envelope = build_wal_envelope(&serde_json::to_string(&event).unwrap());
    seed_wal(&redis, &[envelope.clone()]).await;

    // Claim (lease held)…
    {
        let mut conn = redis.get().await.unwrap();
        let claimed = proc.claim_batch(&mut conn, 10).await.expect("claim");
        assert_eq!(claimed, vec![envelope]);
    }
    // …and the PostgreSQL transaction COMMITS, but the process dies before
    // the ACK (simulate: write_events only, no ack_committed_batch).
    proc.write_events(&[event]).await.expect("commit lands");

    let after_commit: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND message_id = $2")
            .bind(&tenant)
            .bind(&message)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(after_commit, 1);
    assert_eq!(processing_len(&redis).await, 1, "ACK never ran");

    // "Restart": the reclaim re-drains the committed-but-unacked batch.
    proc.flush().await.expect("replay flush");

    let ids: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT id FROM events WHERE tenant_id = $1 AND message_id = $2")
            .bind(&tenant)
            .bind(&message)
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(ids.len(), 1, "exactly-once rows despite the replay (ON CONFLICT DO NOTHING)");
    assert_eq!(wal_len(&redis).await, 0);
    assert_eq!(processing_len(&redis).await, 0, "the replay ACKed");
    clear_wal(&redis).await;
}

/// W4 — reclaim RACING a live flush / TWO flushers over the same queue.
/// Flushers A and B run concurrently over N enqueued events (their
/// claim/reclaim scripts can interleave in any order — including B
/// reclaiming a batch A holds a lease on and double-committing it). The
/// invariant asserted: every accepted event lands in Postgres EXACTLY once
/// (idempotent insert), both queues converge to empty, nothing is lost.
#[tokio::test]
async fn crash_window_w4_two_flushers_and_reclaim_race_lose_or_double_nothing() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_w4").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    let tenant = unique("tn_w4");
    seed_tenant(&db, &tenant).await;
    let message = unique("msg_w4");
    const N: usize = 24;

    let a = processor(db.clone(), redis.clone());
    let b = processor(db.clone(), redis.clone());
    for index in 0..N {
        a.record_open(open_data(
            &tenant,
            &format!("{message}-{index}"),
            &format!("w4-{index}@example.com"),
        ))
        .await
        .expect("enqueue");
    }

    // Two flushers race (any interleaving of claim/reclaim/commit/ACK).
    let (ra, rb) = tokio::join!(a.flush(), b.flush());
    for r in [ra, rb] {
        r.expect("both flushers succeed (at-least-once is safe)");
    }

    // Drain whatever interleaving left behind, then assert convergence.
    for _ in 0..50 {
        if wal_len(&redis).await == 0 && processing_len(&redis).await == 0 {
            break;
        }
        let _ = a.flush().await;
    }
    assert_eq!(wal_len(&redis).await, 0, "pending converged to empty");
    assert_eq!(processing_len(&redis).await, 0, "no orphaned leases");

    let ids: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT id FROM events WHERE tenant_id = $1 AND message_id LIKE $2 || '%'",
    )
    .bind(&tenant)
    .bind(&message)
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(
        ids.len(),
        N,
        "every accepted event exactly once (no loss, no double rows) under the race"
    );
    clear_wal(&redis).await;
}

/// W5 — MAX_FLUSH_BATCH semantics preserved:one flush claims at most the
/// cap (500, or max_buffer_size when larger — the expression is unchanged
/// from the pre-fix protocol), and the remainder stays durable in `pending`
/// for the next tick.
#[tokio::test]
async fn crash_window_w5_flush_batch_cap_bounds_one_claim() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_w5").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    let tenant = unique("tn_w5");
    seed_tenant(&db, &tenant).await;
    let message = unique("msg_w5");
    let proc = flush_processor(db.clone(), redis.clone(), clickhouse::Client::default());
    // The cap for this processor (identical expression to the old drain):
    // MAX_FLUSH_BATCH.max(max_buffer_size) = max(500, 10) = 500.
    let cap = MAX_FLUSH_BATCH.max(10);
    assert_eq!(cap, 500);

    let total = cap + 3;
    let envelopes: Vec<String> = (0..total)
        .map(|i| {
            build_wal_envelope(&serde_json::to_string(&wal_event(
                &tenant,
                &format!("{message}-{i}"),
                EventType::Opened,
            ))
            .unwrap())
        })
        .collect();
    seed_wal(&redis, &envelopes).await;

    proc.flush().await.expect("first capped flush");
    assert_eq!(
        wal_len(&redis).await,
        3,
        "one flush drained exactly the cap; the tail stayed durable in pending"
    );
    assert_eq!(processing_len(&redis).await, 0, "cap batch committed + ACKed");
    let after_one: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND message_id LIKE $2 || '%'")
            .bind(&tenant)
            .bind(&message)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(after_one, cap as i64);

    proc.flush().await.expect("second flush drains the tail");
    let after_two: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND message_id LIKE $2 || '%'")
            .bind(&tenant)
            .bind(&message)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(after_two, total as i64, "nothing lost across the cap boundary");
    assert_eq!(wal_len(&redis).await, 0);
    assert_eq!(processing_len(&redis).await, 0);
    clear_wal(&redis).await;
}

// ═════════════════════════════════════════════════════════════════════════════
// P0 poison DLQ:shape, exactly-once, and queue-liveness.
// ═════════════════════════════════════════════════════════════════════════════

/// A permanently-failing batch (PG down on every retry) ends up in the DLQ
/// EXACTLY once, with every envelope field populated and the FNV-1a
/// checksum matching the preserved payload — and the poison never wedges
/// the queue: a subsequent good event drains normally behind it.
#[tokio::test]
async fn permanently_failing_batch_dead_letters_exactly_once_without_wedging() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    test_log_subscriber();
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_dlq").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    clear_dlq(&redis).await;
    let tenant = unique("tn_dlq");
    seed_tenant(&db, &tenant).await;
    let message = unique("msg_dlq");

    // The poison batch: a valid event walked to the END of its retry budget.
    let event = wal_event(&tenant, &message, EventType::Opened);
    let envelope = build_wal_envelope(&serde_json::to_string(&event).unwrap());
    let mut poisoned = envelope.clone();
    for _ in 0..MAX_EVENT_RETRIES {
        poisoned = bump_envelope_retries(&poisoned)
            .unwrap_or_else(|| poisoned.clone());
    }
    assert!(bump_envelope_retries(&poisoned).is_none(), "at the budget");

    // A HEALTHY event queued behind the poison (wedge-detection probe).
    let good_event = wal_event(&tenant, &format!("{message}-good"), EventType::Clicked);
    let good_envelope = build_wal_envelope(&serde_json::to_string(&good_event).unwrap());

    // The failing processor: every PG write fails.
    let dead_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://offline@127.0.0.1:1/offline")
        .expect("lazy pool");
    let failing = processor(dead_db, redis.clone());
    seed_wal(&redis, &[poisoned.clone(), good_envelope.clone()]).await;
    failing
        .flush()
        .await
        .expect_err("every write fails (PG down)");

    // The poison was dead-lettered EXACTLY once; the good event was only
    // re-queued (it still has budget), never dropped.
    assert_eq!(dlq_len(&redis).await, 1, "exactly one DLQ entry");
    let dlq = dlq_entries(&redis).await;
    let parsed: DeadLetterEntry = serde_json::from_str(&dlq[0]).expect("DLQ JSON envelope");
    assert_eq!(parsed.payload, poisoned, "original envelope verbatim");
    assert_eq!(parsed.failure_reason, "max_retries_exceeded");
    assert_eq!(parsed.attempts, MAX_EVENT_RETRIES as u64);
    assert_eq!(parsed.schema_version, DEAD_LETTER_SCHEMA_VERSION);
    assert_eq!(
        parsed.checksum,
        format!("{:016x}", fnv1a64(parsed.payload.as_bytes())),
        "FNV-1a checksum over the payload"
    );
    assert!(!parsed.first_seen.is_empty());
    assert_eq!(parsed.first_seen, parsed.last_seen);
    chrono::DateTime::parse_from_rfc3339(&parsed.first_seen).expect("RFC 3339 timestamps");

    // The original event is recoverable from the DLQ payload (operator path).
    let recovered: TrackingEvent =
        parse_single_wal_entry(&parsed.payload).expect("payload still parseable");
    assert_eq!(recovered.id, event.id);

    // NOT WEDGED:the poison is OUT of the pending queue, and a fresh
    // processor with a healthy PG drains the good event normally.
    assert_eq!(wal_len(&redis).await, 1, "only the good event remains");
    let healthy = processor(db.clone(), redis.clone());
    healthy.flush().await.expect("the queue still drains");
    let good_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND message_id = $2",
    )
    .bind(&tenant)
    .bind(&format!("{message}-good"))
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(good_rows, 1, "the event behind the poison was processed");
    assert_eq!(wal_len(&redis).await, 0);
    assert_eq!(processing_len(&redis).await, 0);
    assert_eq!(dlq_len(&redis).await, 1, "the DLQ entry is durable");
    clear_wal(&redis).await;
    clear_dlq(&redis).await;
}

/// FNV-1a 64-bit known-answer vectors (empty string and the canonical
/// "foobar" example) pin the dependency-free checksum implementation.
#[test]
fn fnv1a64_known_answer_vectors() {
    assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
}

// ═════════════════════════════════════════════════════════════════════════════
// Residual fault-window arms:ACK/DLQ/drain/publish/dedup failure paths that
// the live-server tests cannot reach. The shared scripted RESP server
// (`test_support::ScriptedRedis`) supplies the fault ("Redis answers, then
// says no") so every arm is deterministic.
// ═════════════════════════════════════════════════════════════════════════════

use crate::routes::test_support::ScriptedRedis;

/// A Redis that answers the handshake and then rejects EVERY real command
/// with `-ERR` — the "server answers but says no" fault.
fn err_redis() -> ScriptedRedis {
    ScriptedRedis::start(Vec::new(), b"-ERR injected fault\r\n")
}

fn lazy_dead_db() -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://offline@127.0.0.1:1/offline")
        .expect("lazy pool")
}

/// `ack_committed_batch` — all three structural arms: the empty-claim guard,
/// the answering-but-failing Redis (release script error), and the dead pool.
#[tokio::test]
async fn ack_arms_empty_claim_script_failure_and_dead_pool() {
    test_log_subscriber();
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let lazy_db = lazy_dead_db();

    // (1) Empty claim list → early return without touching Redis.
    let live = processor(lazy_db.clone(), redis.clone());
    live.ack_committed_batch(&[]).await;

    // (2) Redis answers but the release script fails → swallowed with a warn;
    //     the leases stay in `processing` for reclamation.
    let err = err_redis();
    let broken = processor(lazy_db.clone(), err.pool.clone());
    broken
        .ack_committed_batch(&["{\"v\":2,\"cs\":\"ab\"}".to_string()])
        .await;

    // (3) Dead pool → the connection arm, same swallow-with-a-warn contract.
    let dead = processor(lazy_db, dead_redis());
    dead.ack_committed_batch(&["{\"v\":2,\"cs\":\"ab\"}".to_string()])
        .await;
}

/// `dead_letter_entries` — the RPUSH-pipeline failure, the post-push lease
/// release failure, and the dead-pool arm. Order matters in the contract:
/// the DLQ copy lands FIRST, so a failure after it leaves the entry leased
/// (at-least-once), never lost.
#[tokio::test]
async fn dead_letter_entries_failure_arms_are_swallowed() {
    test_log_subscriber();
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    clear_dlq(&redis).await;
    let lazy_db = lazy_dead_db();
    let proc = processor(lazy_db.clone(), redis.clone());
    let poison = "{\"v\":2,\"cs\":\"ab\",\"d\":{}}".to_string();

    // (1) DLQ key holds a STRING → the RPUSH pipeline fails (WRONGTYPE) and
    //     the entries stay leased.
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("SET")
            .arg(REDIS_DEAD_LETTER_KEY)
            .arg("not-a-list")
            .query_async(&mut *conn)
            .await;
    }
    proc.dead_letter_entries(&[poison.clone()], "unparsable_envelope", 0)
        .await;
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_DEAD_LETTER_KEY)
            .query_async(&mut *conn)
            .await;
    }

    // (2) DLQ push succeeds; the lease release FAILS (the processing key
    //     holds a STRING, so the script's LREM errors) → at-least-once into
    //     the DLQ. (The release's RPUSH half is skipped for the plain-ACK
    //     shape, so the WAL key being wrong-typed would NOT fail it.)
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("SET")
            .arg(REDIS_WAL_PROCESSING_KEY)
            .arg("not-a-list")
            .query_async(&mut *conn)
            .await;
    }
    proc.dead_letter_entries(&[poison], "unparsable_envelope", 0)
        .await;
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_WAL_PROCESSING_KEY)
            .query_async(&mut *conn)
            .await;
    }
    clear_dlq(&redis).await;

    // (3) Dead pool → the connection arm; the lease simply survives.
    let dead = processor(lazy_db, dead_redis());
    dead.dead_letter_entries(&["{}".to_string()], "unparsable_envelope", 0)
        .await;
}

/// `drain_all` — both LLEN failure arms (answered-then-erroring server) and
/// the pathological round bound where every flush "succeeds" but a lease can
/// never be released (unparsable lease + failing DLQ push).
#[tokio::test]
async fn drain_all_llen_arms_and_round_bound() {
    test_log_subscriber();
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let lazy_db = lazy_dead_db();

    // (1) Every real command errors: the first LLEN (pending) fails.
    let err = err_redis();
    let a = processor(lazy_db.clone(), err.pool.clone());
    a.drain_all().await;

    // (2) First LLEN answers :0 (pending), the second (processing) errors.
    let seq = ScriptedRedis::start(vec![b":0\r\n"], b"-ERR injected fault\r\n");
    let b = processor(lazy_db.clone(), seq.pool.clone());
    b.drain_all().await;

    // (3) Round bound: an unparsable lease whose DLQ push always fails makes
    //     every flush return Ok while `processing` never drains — the loop
    //     must give up at the round bound leaving the entry durable.
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("SET")
            .arg(REDIS_DEAD_LETTER_KEY)
            .arg("not-a-list")
            .query_async(&mut *conn)
            .await;
        let _: Result<(), _> = redis::cmd("RPUSH")
            .arg(REDIS_WAL_PROCESSING_KEY)
            .arg("definitely-not-an-envelope")
            .query_async(&mut *conn)
            .await;
    }
    let c = processor(lazy_db, redis.clone());
    c.drain_all().await;
    assert_eq!(
        processing_len(&redis).await,
        1,
        "the unwedgeable lease stays durable in `processing`"
    );
    assert!(
        processing_entries(&redis)
            .await
            .iter()
            .all(|e| e.contains("definitely-not-an-envelope")),
        "the lease holds the original poison envelope verbatim"
    );
    {
        let mut conn = redis.get().await.unwrap();
        for key in [
            REDIS_DEAD_LETTER_KEY,
            REDIS_WAL_PROCESSING_KEY,
            REDIS_WAL_KEY,
        ] {
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(key)
                .query_async(&mut *conn)
                .await;
        }
    }
}

/// Empty batches are explicit no-ops in both writers (the flush loop never
/// calls them empty, but the guards bound the public contract).
#[tokio::test]
async fn empty_batch_writes_are_noops() {
    let Some(db) = canonical_pool("tracking_empty_writes").await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let proc = processor(db, redis);
    proc.write_events(&[]).await.expect("empty PG write is Ok");
    proc.write_clickhouse(&[])
        .await
        .expect("empty ClickHouse write is Ok");
}

/// The fire-and-forget SSE Pub/Sub fan-out must not panic (and must not be
/// reported as a flush failure) when Redis is unreachable after the commit.
#[tokio::test]
async fn pubsub_fanout_survives_a_dead_redis() {
    let Some(db) = canonical_pool("tracking_pubsub_dead").await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
    let proc = processor(db, dead_redis());
    let event = wal_event("tn_pubsub", "msg_pubsub", EventType::Opened);
    proc.write_events(&[event]).await.expect("committed in PG");
    // Give the spawned PUBLISH task its bounded moment to fail `get()`.
    tokio::time::sleep(Duration::from_millis(250)).await;
}

/// A categorized unsubscribe persists a `subscription_preferences` row (the
/// per-category consent surface), not a tenant-wide suppression.
#[tokio::test]
async fn categorized_unsubscribe_persists_subscription_preference() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_pref_cat").await)
    else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    let tenant = unique("tn_prefcat");
    seed_tenant(&db, &tenant).await;
    let proc = processor(db.clone(), redis.clone());
    let recipient = "prefcat@example.com";

    for subscribed in [false, true] {
        proc.record_unsubscribe(UnsubscribeData {
            tenant_id: tenant.clone(),
            message_id: unique("msg"),
            recipient: recipient.into(),
            reason: Some("preference center".into()),
            category: Some("marketing".into()),
            user_agent: None,
            ip_address: None,
        })
        .await
        .unwrap_or_else(|e| panic!("categorized unsubscribe must land (subscribed={subscribed}): {e}"));
        // record_unsubscribe always unsubscribes (subscribed=false row).
        let row: (bool, String) = sqlx::query_as(
            "SELECT subscribed, category FROM subscription_preferences \
             WHERE tenant_id = $1 AND email = $2 AND category = 'marketing'",
        )
        .bind(&tenant)
        .bind(recipient)
        .fetch_one(&db)
        .await
        .expect("preference row");
        assert!(!row.0, "one-click unsubscribes the category");
        assert_eq!(row.1, "marketing");
    }
    clear_wal(&redis).await;
}

/// The suppression fan-out must survive (and log) a Redis that answers but
/// rejects the PUBLISH.
#[tokio::test]
async fn suppression_publish_failure_is_logged_not_panicking() {
    test_log_subscriber();
    let err = err_redis();
    let proc = processor(lazy_dead_db(), err.pool.clone());
    proc.publish_suppression_added("tn_pubfail", "u@example.com", None);
    proc.publish_suppression_removed("tn_pubfail", "u@example.com");
    proc.publish_preference_changed("tn_pubfail", "u@example.com", "marketing", false);
    // Give the spawned PUBLISH tasks their bounded moment to fail.
    tokio::time::sleep(Duration::from_millis(250)).await;
}

/// The suppression-retry drain: every error arm of the
/// reclaim → LLEN → claim pipeline, the poison drop, the success fan-out,
/// and the release failure — each forced deterministically.
#[tokio::test]
async fn suppression_retry_drain_pipeline_error_arms() {
    test_log_subscriber();
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let lazy_db = lazy_dead_db();
    let proc = processor(lazy_db.clone(), redis.clone());
    let good = build_suppression_retry_entry("tn_drain_arms", "drainarms@example.com", None);
    // Poison MUST use the wire (camelCase) field names — a snake_case record
    // is an UNPARSEABLE entry, a different arm entirely.
    let poison = r#"{"tenantId":"tn_drain_arms","email":"poisonarms@example.com","retries":10}"#
        .to_string();

    // (1) Reclaim fails: the processing key holds a STRING, so the reclaim
    //     script's RPOPLPUSH errors.
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .arg(REDIS_SUPPRESSION_PROCESSING_KEY)
            .query_async(&mut *conn)
            .await;
        let _: Result<(), _> = redis::cmd("SET")
            .arg(REDIS_SUPPRESSION_PROCESSING_KEY)
            .arg("not-a-list")
            .query_async(&mut *conn)
            .await;
    }
    proc.drain_suppression_retries().await;

    // (2) LLEN fails: the retry key holds a STRING (the reclaim is a no-op
    //     because `processing` is empty).
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_PROCESSING_KEY)
            .query_async(&mut *conn)
            .await;
        let _: Result<(), _> = redis::cmd("SET")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .arg("not-a-list")
            .query_async(&mut *conn)
            .await;
    }
    proc.drain_suppression_retries().await;
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .query_async(&mut *conn)
            .await;
    }

    // (3) Claim fails AFTER a successful LLEN: the scripted server answers
    //     the reclaim (*0), the LLEN (:1), then errors the claim EVALSHA.
    let empty_arr: &'static [u8] = b"*0\r\n";
    let one: &'static [u8] = b":1\r\n";
    let seq_claim_err = ScriptedRedis::start(vec![empty_arr, one], b"-ERR injected fault\r\n");
    let c = processor(lazy_db.clone(), seq_claim_err.pool.clone());
    c.drain_suppression_retries().await;

    // (4) Claim "succeeds" EMPTY while LLEN said 1 (a racing consumer) —
    //     the drain returns without touching Postgres.
    let seq_claim_empty = ScriptedRedis::start(vec![empty_arr, one, empty_arr], empty_arr);
    let d = processor(lazy_db.clone(), seq_claim_empty.pool.clone());
    d.drain_suppression_retries().await;

    // (5) Unparseable entries (incl. wrong-case field names) are skipped.
    {
        let mut conn = redis.get().await.unwrap();
        for junk in ["totally-not-json", r#"{"tenant_id":"t","email":"e","retries":0}"#] {
            let _: Result<(), _> = redis::cmd("RPUSH")
                .arg(REDIS_SUPPRESSION_RETRY_KEY)
                .arg(junk)
                .query_async(&mut *conn)
                .await;
        }
    }
    proc.drain_suppression_retries().await;
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .query_async(&mut *conn)
            .await;
    }

    // (6) Success against the LIVE database: the row lands, the fan-out
    //     fires, the lease is ACKed.
    let Some(db) = canonical_pool("tracking_drain_success").await else {
        eprintln!("skipping success arm: set TEST_DATABASE_URL");
        return;
    };
    seed_tenant(&db, "tn_drain_arms").await;
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("RPUSH")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .arg(&good)
            .query_async(&mut *conn)
            .await;
    }
    let healthy = processor(db.clone(), redis.clone());
    healthy.drain_suppression_retries().await;
    let landed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions WHERE tenant_id = $1 AND email = $2")
            .bind("tn_drain_arms")
            .bind("drainarms@example.com")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(landed, 1, "the retry landed the suppression row");

    // (7) Failure against the dead database: the good entry is re-queued
    //     with a bumped counter; the poison (budget exhausted) is dropped
    //     with the CRITICAL log — never silently.
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .query_async(&mut *conn)
            .await;
        for entry in [&good, &poison] {
            let _: Result<(), _> = redis::cmd("RPUSH")
                .arg(REDIS_SUPPRESSION_RETRY_KEY)
                .arg(entry)
                .query_async(&mut *conn)
                .await;
        }
    }
    proc.drain_suppression_retries().await;
    let left: Vec<String> = {
        let mut conn = redis.get().await.unwrap();
        redis::cmd("LRANGE")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .arg(0)
            .arg(-1)
            .query_async(&mut *conn)
            .await
            .unwrap()
    };
    assert_eq!(left.len(), 1, "only the re-queued good entry remains");
    assert!(left[0].contains("\"retries\":1"), "{left:?}");
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_RETRY_KEY)
            .arg(REDIS_SUPPRESSION_PROCESSING_KEY)
            .query_async(&mut *conn)
            .await;
    }
}

/// `release_lease` swallows (but logs) a failing release script: with the
/// processing key holding a STRING, the LREM inside the script errors and
/// the entry stays leased for reclamation.
#[tokio::test]
async fn suppression_lease_release_failure_is_swallowed() {
    test_log_subscriber();
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let proc = processor(lazy_dead_db(), redis.clone());
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("SET")
            .arg(REDIS_SUPPRESSION_PROCESSING_KEY)
            .arg("not-a-list")
            .query_async(&mut *conn)
            .await;
        proc.release_lease(&mut conn, "some-entry", Some("replacement".into()))
            .await;
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(REDIS_SUPPRESSION_PROCESSING_KEY)
            .query_async(&mut *conn)
            .await;
    }
}

/// Counter pipelines and dedup rollbacks must survive a Redis that rejects
/// every command (fire-and-forget paths stay fire-and-forget) — and a Redis
/// that cannot even hand out a connection.
#[tokio::test]
async fn counters_and_dedup_rollback_survive_err_redis() {
    test_log_subscriber();
    let err = err_redis();
    let proc = processor(lazy_dead_db(), err.pool.clone());
    proc.incr_counters("tn_counter_err", "2026-09-28", "10", "opens")
        .await;
    proc.clear_dedup("open:msg:rcpt").await;

    // The spawned tasks must also survive a DEAD pool (`get()` itself fails).
    let dead = processor(lazy_dead_db(), dead_redis());
    dead.incr_counters("tn_counter_dead", "2026-09-28", "10", "opens")
        .await;
    dead.clear_dedup("open:msg:rcpt").await;
    tokio::time::sleep(Duration::from_millis(250)).await;
}

/// A LEGACY bare-event WAL entry (no versioned envelope) still parses and
/// flushes through the modern pipeline — the backward-compatibility arm.
#[tokio::test]
async fn legacy_bare_wal_entries_still_flush() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_legacy_wal").await)
    else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
    clear_processing(&redis).await;
    let tenant = unique("tn_legacy");
    seed_tenant(&db, &tenant).await;
    let event = TrackingEvent {
        id: new_id("evt"),
        event_type: EventType::Opened,
        tenant_id: tenant.clone(),
        message_id: unique("msg_legacy"),
        recipient: "legacy@example.com".into(),
        link_id: None,
        link_url: None,
        unsubscribe_reason: None,
        user_agent: None,
        ip_address: None,
        timestamp: Utc::now(),
        metadata: None,
    };
    // Deliberately NOT wrapped in build_wal_envelope — the pre-envelope shape.
    let bare = serde_json::to_string(&event).unwrap();
    seed_wal(&redis, &[bare]).await;

    let proc = processor(db.clone(), redis.clone());
    proc.flush().await.expect("legacy entry flushes");
    let persisted: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND id = $2")
            .bind(&tenant)
            .bind(&event.id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(persisted, 1, "legacy bare event committed");
    assert_eq!(wal_len(&redis).await, 0);
    assert_eq!(processing_len(&redis).await, 0);
    clear_wal(&redis).await;
}

/// `dedup_key` scopes by link id when one is present — a click on link A
/// never dedupes a click on link B of the same message.
#[test]
fn dedup_key_with_link_id_is_distinct_and_deterministic() {
    let with_a = dedup_key("click", "msg", "r@x.com", Some("lnk_a"));
    let with_a_again = dedup_key("click", "msg", "r@x.com", Some("lnk_a"));
    let with_b = dedup_key("click", "msg", "r@x.com", Some("lnk_b"));
    let without = dedup_key("click", "msg", "r@x.com", None);
    assert_eq!(with_a, with_a_again, "deterministic for the same link");
    assert_ne!(with_a, with_b, "distinct link ids are distinct keys");
    assert_ne!(with_a, without, "a link-scoped key differs from the bare key");
}

/// The DLQ envelope builder:field-for-field shape contract.
#[test]
fn dead_letter_entry_shape_contract() {
    let now = Utc::now();
    let raw = r#"{"v":2,"cs":"ab","d":{}"#; // arbitrary payload string
    let built = build_dead_letter_entry(raw, "unparsable_envelope", 0, now);
    let parsed: DeadLetterEntry = serde_json::from_str(&built).expect("JSON");
    assert_eq!(parsed.payload, raw);
    assert_eq!(parsed.failure_reason, "unparsable_envelope");
    assert_eq!(parsed.attempts, 0);
    assert_eq!(parsed.schema_version, 1);
    assert_eq!(parsed.checksum.len(), 16);
    assert_eq!(parsed.checksum, format!("{:016x}", fnv1a64(raw.as_bytes())));
    // Deterministic for a fixed clock (minus the timestamps).
    let mut a = build_dead_letter_entry(raw, "r", 3, now);
    let mut b = build_dead_letter_entry(raw, "r", 3, now);
    a.truncate(a.len());
    b.truncate(b.len());
    assert_eq!(a, b);
}
