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

#[tokio::test]
async fn flush_moves_events_to_postgres_and_clears_the_wal() {
    let _guard = SERIAL.lock().await;
    let _cross = crate::routes::test_support::redis_wal_serial().await;
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
    let ch_rows: Vec<(String, u64)> = live_clickhouse()
        .query("SELECT event_type, count() FROM events WHERE tenant_id = ? GROUP BY event_type")
        .bind(&tenant)
        .fetch_all()
        .await
        .expect("clickhouse ingest query");
    let by_type: std::collections::HashMap<String, u64> = ch_rows.into_iter().collect();
    assert_eq!(by_type.get("opened"), Some(&2));
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

/// `reenqueue_events` swallows a dead pool (the WAL keeps the entries —
/// nothing is lost by definition), drops poison entries with a warning, and
/// reports RPUSH failures (wrong-type key).
#[tokio::test]
async fn reenqueue_events_error_arms_are_swallowed_and_reported() {
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
    // (1) Dead pool: logs and returns without panicking.
    dead.reenqueue_events(&["{\"v\":2,\"cs\":\"ab\"}".into()])
        .await;

    // (2) Poison entry (retry budget exhausted) is dropped, not re-pushed.
    let proc = processor(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://offline@127.0.0.1:1/offline")
            .expect("lazy pool"),
        redis.clone(),
    );
    clear_wal(&redis).await;
    let envelope = build_wal_envelope(
        &serde_json::to_string(&wal_event("tn", "msg", EventType::Opened)).unwrap(),
    );
    let poison = bump_envelope_retries(
        &bump_envelope_retries(&bump_envelope_retries(&envelope).unwrap()).unwrap(),
    )
    .unwrap_or_else(|| envelope.clone());
    proc.reenqueue_events(&[poison]).await;

    // (3) RPUSH failure: the WAL key holds a STRING, so the pipeline fails.
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
    proc.reenqueue_events(&["{\"v\":2,\"cs\":\"ab\"}".into()])
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
/// poison (dropped), never a panic.
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
    let proc = processor(db.clone(), redis.clone());

    let mut unknown = build_wal_envelope(
        &serde_json::to_string(&wal_event("tn", "msg", EventType::Opened)).unwrap(),
    );
    unknown = unknown.replace("\"v\":2", "\"v\":99");
    let corrupt_legacy = "1:<not-json>:deadbeef";
    seed_wal(&redis, &[unknown, corrupt_legacy.into()]).await;
    proc.flush()
        .await
        .expect("poison is dropped, flush succeeds");
    assert_eq!(wal_len(&redis).await, 0, "both poison entries dropped");
}
