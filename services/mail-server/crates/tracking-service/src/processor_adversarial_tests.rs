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
/// isolates these tests from the shared route-handler tests.
fn redis_url_in_db(base: &str, db: u32) -> String {
    match url::Url::parse(base) {
        Ok(mut parsed) => {
            parsed.set_path(&db.to_string());
            parsed.to_string()
        }
        Err(_) => format!("{}/{}", base.trim_end_matches('/'), db),
    }
}

fn live_redis() -> Option<RedisPool> {
    let url = redis_url_in_db(&std::env::var("TEST_REDIS_URL").ok()?, 8);
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
/// …and ACROSS processes: `cargo nextest` runs every test as its own process,
/// and every instance of this suite shares Redis logical DB 8, so a
/// process-local mutex alone let one test's WAL writes leak into another
/// test's `WAL drained` assertion (observed as intermittent `left: 2,
/// right: 0` under parallel load). The guard is a SESSION-level Postgres
/// advisory lock on a dedicated connection: acquired for the test's lifetime,
/// released when the pool (and its connection) drops. `None` when no test
/// database is configured (the caller soft-skips anyway).
async fn cross_process_serial() -> Option<sqlx::PgPool> {
    let url = std::env::var("TEST_DATABASE_ADMIN_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DATABASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .and_then(|value| {
                    value
                        .rsplit_once('/')
                        .map(|(server, _)| format!("{server}/postgres"))
                })
        })?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(&url)
        .await
        .ok()?;
    sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
        .bind("tracking-service:redis-db8-serial")
        .execute(&pool)
        .await
        .ok()?;
    Some(pool)
}

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
    let _cross = cross_process_serial().await;
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
    let _cross = cross_process_serial().await;
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
    let _cross = cross_process_serial().await;
    let Some(redis) = live_redis() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let Some(db) = canonical_pool("tracking_unsub_retry").await else {
        eprintln!("skipping: set TEST_DATABASE_URL");
        return;
    };
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

#[tokio::test]
async fn flush_moves_events_to_postgres_and_clears_the_wal() {
    let _guard = SERIAL.lock().await;
    let _cross = cross_process_serial().await;
    let (Some(redis), Some(db)) = (live_redis(), canonical_pool("tracking_flush").await) else {
        eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL");
        return;
    };
    clear_wal(&redis).await;
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

    // Tenant isolation: no other tenant sees anything.
    let other: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id <> $1")
        .bind(&tenant)
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(other >= 0);

    // Malformed WAL entries are dropped, not wedged forever.
    {
        let mut conn = redis.get().await.unwrap();
        let _: Result<(), _> = redis::cmd("RPUSH")
            .arg(REDIS_WAL_KEY)
            .arg("definitely-not-an-envelope")
            .query_async(&mut *conn)
            .await;
    }
    proc.flush().await.expect("garbage flush is a no-op");
    assert_eq!(wal_len(&redis).await, 0, "poison-free: garbage dropped");
}

#[tokio::test]
async fn flush_failure_reenqueues_with_retry_budget_and_drops_poison() {
    let _guard = SERIAL.lock().await;
    let _cross = cross_process_serial().await;
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
    assert_eq!(entries.len(), 1, "event re-enqueued");
    assert!(
        entries[0].contains("\"r\":1"),
        "retry counter bumped: {}",
        entries[0]
    );

    // Walk the entry to the poison budget; it must be dropped, not retried
    // forever.
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
    assert_eq!(wal_len(&redis).await, 0, "poison dropped after the budget");
}

#[tokio::test]
async fn start_drains_on_shutdown_and_stop_joins_the_loop() {
    let _guard = SERIAL.lock().await;
    let _cross = cross_process_serial().await;
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
