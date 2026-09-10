//! F83 canonical-schema tests for the compaction worker: provider/region are
//! DERIVED from validated event metadata (the canonical PostgreSQL events
//! table has no such columns), identity fields stay complete in the cold
//! copy, and retention/restart behave against the actual canonical schema.
//!
//! The compaction lock lives in Redis: each test starts an ephemeral
//! redis-server when available and skips otherwise (workspace convention).
//! Gated on `TEST_DATABASE_URL` for the database.

use analytics::compaction::CompactionWorker;
use analytics::config::CompactionConfig;
use sqlx::PgPool;

struct EphemeralRedis {
    port: u16,
    child: std::process::Child,
}

impl EphemeralRedis {
    fn start() -> Option<Self> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let child = std::process::Command::new("redis-server")
            .args([
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
                "--daemonize",
                "no",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let mut ready = false;
        for _ in 0..50 {
            if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                use std::io::{Read, Write};
                let _ = stream.write_all(b"PING\r\n");
                let mut buf = [0u8; 16];
                if let Ok(n) = stream.read(&mut buf) {
                    if &buf[..n.min(7)] == b"+PONG\r\n" {
                        ready = true;
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !ready {
            drop(child);
            return None;
        }
        Some(Self { port, child })
    }

    fn pool(&self) -> deadpool_redis::Pool {
        let cfg = deadpool_redis::Config::from_url(format!("redis://127.0.0.1:{}", self.port));
        cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool")
    }
}

impl Drop for EphemeralRedis {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn canonical_pool(db_suffix: &str) -> Option<PgPool> {
    match migrator::test_support::fresh_canonical_pool("analytics_f83", db_suffix).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn worker(pool: &PgPool, redis: &EphemeralRedis, storage: &std::path::Path) -> CompactionWorker {
    CompactionWorker::new(
        pool.clone(),
        redis.pool(),
        CompactionConfig {
            enabled: true,
            schedule_hour: 2,
            hot_retention_days: 1,
            cold_retention_days: 730,
            batch_size: 100,
        },
        storage.to_string_lossy().into_owned(),
    )
}

async fn seed_events(pool: &PgPool) {
    // Three events older than the 1-day hot window:
    //  * validated string metadata → provider/region derived;
    //  * numeric metadata provider → must NOT become the string "42";
    //  * NULL metadata → provider/region stay NULL.
    sqlx::query(
        r#"
        INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp, metadata, ip_address)
        VALUES
          ('f83-00000000-0000-0000-0000-000000000001', 'tenant_f83', 'msg-1', 'delivered', 'a@example.com',
           NOW() - INTERVAL '3 days', '{"provider": "ses", "region": "eu-west-1"}'::jsonb, '203.0.113.10'),
          ('f83-00000000-0000-0000-0000-000000000002', 'tenant_f83', 'msg-2', 'opened', 'b@example.com',
           NOW() - INTERVAL '3 days', '{"provider": 42}'::jsonb, NULL),
          ('f83-00000000-0000-0000-0000-000000000003', 'tenant_f83', 'msg-3', 'clicked', 'c@example.com',
           NOW() - INTERVAL '3 days', NULL, '198.51.100.7')
        "#,
    )
    .execute(pool)
    .await
    .expect("seed canonical events");
}

fn read_jsonl_lines(storage: &std::path::Path) -> Vec<serde_json::Value> {
    let mut lines = Vec::new();
    for entry in std::fs::read_dir(storage).expect("storage dir").flatten() {
        let tenant_dir = entry.path();
        if !tenant_dir.is_dir() {
            continue;
        }
        for year in std::fs::read_dir(&tenant_dir).unwrap().flatten() {
            for month in std::fs::read_dir(year.path()).unwrap().flatten() {
                for file in std::fs::read_dir(month.path()).unwrap().flatten() {
                    if file.path().extension().is_some_and(|e| e == "jsonl") {
                        let content = std::fs::read_to_string(file.path()).unwrap();
                        for line in content.lines() {
                            lines.push(serde_json::from_str(line).expect("jsonl line"));
                        }
                    }
                }
            }
        }
    }
    lines
}

/// Compaction against the canonical events schema: the batch SELECT must
/// succeed (no provider/region columns), the cold copy must carry the
/// derived provider/region from validated metadata only, and every identity
/// field must remain complete.
#[tokio::test]
async fn compaction_derives_provider_region_from_validated_metadata() {
    let Some(redis) = EphemeralRedis::start() else {
        eprintln!("skipping: redis-server not available");
        return;
    };
    let Some(pool) = canonical_pool("derive").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let storage = std::env::temp_dir().join(format!(
        "apexmail_f83_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    seed_events(&pool).await;

    let status = worker(&pool, &redis, &storage)
        .run()
        .await
        .expect("compaction against canonical schema");
    assert!(status.completed);
    assert_eq!(status.rows_migrated, 3);
    assert_eq!(status.rows_deleted, 3);

    // Hot rows are gone.
    let hot: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = 'tenant_f83'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(hot, 0);

    let cold = read_jsonl_lines(&storage);
    assert_eq!(cold.len(), 3, "one durable cold copy per event");

    let by_msg = |m: &str| {
        cold.iter()
            .find(|v| v["message_id"] == m)
            .unwrap_or_else(|| panic!("cold copy for {m}"))
            .clone()
    };

    let derived = by_msg("msg-1");
    assert_eq!(derived["provider"], "ses");
    assert_eq!(derived["region"], "eu-west-1");

    let numeric = by_msg("msg-2");
    assert!(
        numeric["provider"].is_null(),
        "a numeric metadata provider must not be stringified"
    );

    let null_meta = by_msg("msg-3");
    assert!(null_meta["provider"].is_null());
    assert!(null_meta["region"].is_null());

    // Identity and promised fields stay complete.
    for v in &cold {
        assert_eq!(v["tenant_id"], "tenant_f83");
        assert!(v["event_type"].is_string());
        assert!(v["recipient"].is_string());
        assert!(v["timestamp"].is_string());
        assert!(v["id"].is_string());
    }

    // GDPR: the client IP in the cold copy is masked, never the raw value.
    assert!(
        serde_json::to_string(&cold)
            .unwrap()
            .contains("203.0.113.0"),
        "IPv4 must be masked to /24"
    );
    assert!(
        !serde_json::to_string(&cold)
            .unwrap()
            .contains("203.0.113.10"),
        "raw IP must not survive"
    );

    // Restart: a second run finds nothing left and writes nothing new.
    let second = worker(&pool, &redis, &storage)
        .run()
        .await
        .expect("second compaction run (restart)");
    assert_eq!(second.rows_migrated, 0);
    assert_eq!(read_jsonl_lines(&storage).len(), 3, "no duplicates");

    std::fs::remove_dir_all(&storage).ok();
    pool.close().await;
}

/// Cold retention: month directories strictly older than the retention
/// cutoff are removed; current-month data survives.
#[tokio::test]
async fn cold_retention_removes_only_old_months() {
    let Some(redis) = EphemeralRedis::start() else {
        eprintln!("skipping: redis-server not available");
        return;
    };
    let Some(pool) = canonical_pool("retention").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let storage = std::env::temp_dir().join(format!(
        "apexmail_f83r_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let old = storage.join("tenant_old/2020/01");
    let recent = storage.join("tenant_new/2999/12");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::create_dir_all(&recent).unwrap();
    std::fs::write(old.join("events_1.jsonl"), b"{}\n").unwrap();
    std::fs::write(recent.join("events_1.jsonl"), b"{}\n").unwrap();

    let w = CompactionWorker::new(
        pool.clone(),
        redis.pool(),
        CompactionConfig {
            enabled: true,
            schedule_hour: 2,
            hot_retention_days: 1,
            cold_retention_days: 30,
            batch_size: 10,
        },
        storage.to_string_lossy().into_owned(),
    );
    w.run().await.expect("run applies cold retention");

    assert!(!old.exists(), "2020/01 is beyond the 30-day window");
    assert!(recent.exists(), "2999/12 is within the window");

    std::fs::remove_dir_all(&storage).ok();
    pool.close().await;
}
