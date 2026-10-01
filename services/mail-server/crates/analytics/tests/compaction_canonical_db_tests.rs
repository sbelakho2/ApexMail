//! F83 canonical-schema tests for the compaction worker: provider/region are
//! DERIVED from validated event metadata (the canonical PostgreSQL events
//! table has no such columns), identity fields stay complete in the cold
//! copy, and retention/restart behave against the actual canonical schema.
//!
//! The compaction lock lives in Redis: each test starts an ephemeral
//! redis-server when available and skips otherwise (workspace convention).
//! Gated on `TEST_DATABASE_URL` for the database.

use analytics::compaction::{
    commit_batch_to_ledger, compute_checksum, load_committed_batches, load_committed_event_ids,
    CommittedBatch, CompactionWorker,
};
use analytics::config::CompactionConfig;
use chrono::{Datelike, Duration, Utc};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sqlx::PgPool;
use std::collections::HashSet;

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
    // FINDING B:the dedup that makes this restart safe consults the LEDGER
    // (analytics_compaction_batches) — asserted in the ledger tests below —
    // not a rescan of the manifest tree.
    let second = worker(&pool, &redis, &storage)
        .run()
        .await
        .expect("second compaction run (restart)");
    assert_eq!(second.rows_migrated, 0);
    assert_eq!(read_jsonl_lines(&storage).len(), 3, "no duplicates");

    // FINDING A:the run committed one durable ledger batch for the three
    // migrated events (the commit point that preceded their deletion).
    let committed = load_committed_batches(&pool, "tenant_f83")
        .await
        .expect("ledger readable");
    assert_eq!(committed.len(), 1, "one committed batch row");
    assert_eq!(committed[0].event_count, 3);
    let ids_in_ledger: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM analytics_compaction_batch_event_ids WHERE tenant_id = 'tenant_f83'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(ids_in_ledger, 3, "one covered-id row per migrated event");

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

// ── FINDING A/B (migration 231): commit protocol + ledger-driven recovery ────

/// Seed events with an explicit Rust-side timestamp so tests can compute the
/// exact `{YYYY/MM}` directory compaction will use (same instant, no
/// wall-clock drift between the INSERT and the assertion).
async fn seed_events_at(
    pool: &PgPool,
    tenant: &str,
    ts: chrono::DateTime<Utc>,
    n: usize,
) -> Vec<String> {
    let mut ids = Vec::new();
    for i in 0..n {
        let id = format!("{tenant}-{i:012}-{}", uuid::Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp, metadata) \
             VALUES ($1, $2, $3, 'delivered', $4, $5, NULL)",
        )
        .bind(&id)
        .bind(tenant)
        .bind(format!("msg-{i}"))
        .bind("user@example.com")
        .bind(ts)
        .execute(pool)
        .await
        .expect("seed canonical event");
        ids.push(id);
    }
    ids
}

/// Simulate a committed-but-materialized batch:write the JSONL object to the
/// tenant tree, then insert the ledger rows through the REAL commit point
/// (`commit_batch_to_ledger`). Returns (batch_id, object path).
async fn materialize_committed_batch(
    pool: &PgPool,
    storage: &std::path::Path,
    tenant: &str,
    ts: chrono::DateTime<Utc>,
    ids: &[String],
) -> anyhow::Result<(uuid::Uuid, std::path::PathBuf)> {
    let batch_id = uuid::Uuid::new_v4();
    let dir = storage.join(tenant).join(ts.format("%Y/%m").to_string());
    std::fs::create_dir_all(&dir)?;
    let file = format!("events_{batch_id}.jsonl");
    let mut bytes = Vec::new();
    for id in ids {
        bytes
            .extend_from_slice(serde_json::to_string(&serde_json::json!({ "id": id }))?.as_bytes());
        bytes.push(b'\n');
    }
    std::fs::write(dir.join(&file), &bytes)?;
    commit_batch_to_ledger(
        pool,
        &CommittedBatch {
            batch_id,
            tenant_id: tenant.to_string(),
            year: ts.year(),
            month: ts.month() as i32,
            object_key: format!("{tenant}/{}/{file}", ts.format("%Y/%m")),
            manifest_key: format!(
                "{tenant}/{}/events_{batch_id}.manifest.json",
                ts.format("%Y/%m")
            ),
            event_count: ids.len() as i64,
            checksum: compute_checksum(&bytes),
            committed_at: Utc::now(),
        },
        ids.to_vec(),
    )
    .await?;
    Ok((batch_id, dir.join(file)))
}

/// The OLD (pre-FINDING-B) full manifest-tree scan, kept here as the
/// property-test oracle: coverage computed from the filesystem must equal
/// coverage computed from the ledger.
fn scan_manifest_ids_oracle(storage: &std::path::Path, tenant: &str) -> HashSet<String> {
    let mut ids = HashSet::new();
    let tenant_dir = storage.join(tenant);
    let Ok(years) = std::fs::read_dir(&tenant_dir) else {
        return ids;
    };
    for year in years.flatten() {
        let Ok(months) = std::fs::read_dir(year.path()) else {
            continue;
        };
        for month in months.flatten() {
            let Ok(files) = std::fs::read_dir(month.path()) else {
                continue;
            };
            for file in files.flatten() {
                let name = file.file_name().to_string_lossy().to_string();
                if !name.ends_with(".manifest.json") {
                    continue;
                }
                if let Ok(data) = std::fs::read(file.path()) {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&data) {
                        if let Some(list) = v["ids"].as_array() {
                            for id in list {
                                if let Some(s) = id.as_str() {
                                    ids.insert(s.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    ids
}

fn committed_object_path(storage: &std::path::Path, batch: &CommittedBatch) -> std::path::PathBuf {
    storage.join(&batch.object_key)
}

/// Migration 231 applies cleanly on the canonical chain (this whole file
/// bootstraps through the REAL migrator) and the ledger is usable as the
/// commit record: both tables, the recovery index, and the retention index
/// exist, and `committed_at` is durably defaulted.
#[tokio::test]
async fn migration_231_ledger_is_the_commit_record() {
    let Some(pool) = canonical_pool("m231").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    for rel in [
        "analytics_compaction_batches",
        "analytics_compaction_batch_event_ids",
        "idx_compaction_batches_tenant_committed",
        "idx_compaction_batches_year_month",
        "idx_compaction_event_ids_tenant_event",
    ] {
        let reg: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(rel)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(reg.is_some(), "migration 231 must create {rel}");
    }
    // DEFAULT NOW() commits a timestamp without the writer supplying one.
    let batch_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO analytics_compaction_batches \
         (batch_id, tenant_id, year, month, object_key, manifest_key, event_count, checksum) \
         VALUES ($1, 'tenant_m231', 2026, 9, 'k.jsonl', 'k.manifest.json', 0, 'x')",
    )
    .bind(batch_id)
    .execute(&pool)
    .await
    .unwrap();
    let committed_at: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT committed_at FROM analytics_compaction_batches WHERE batch_id = $1",
    )
    .bind(batch_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(committed_at.is_some(), "committed_at must default to now()");
    pool.close().await;
}

/// FINDING A:same-millisecond batches must get DISTINCT cold objects. With
/// the old wall-clock names, N batches written within one millisecond shared
/// one `events_{millis}.jsonl` and truncation destroyed all but the last.
/// batch_size=1 forces three consecutive batch writes back-to-back; each
/// must land in its own UUID-named object and its own committed ledger row.
#[tokio::test]
async fn same_millisecond_batches_get_distinct_cold_objects() {
    let Some(redis) = EphemeralRedis::start() else {
        eprintln!("skipping: redis-server not available");
        return;
    };
    let Some(pool) = canonical_pool("samems").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let storage = std::env::temp_dir().join(format!(
        "apexmail_f83ms_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let ts = Utc::now() - Duration::days(3);
    let ids = seed_events_at(&pool, "tenant_ms", ts, 3).await;

    let w = CompactionWorker::new(
        pool.clone(),
        redis.pool(),
        CompactionConfig {
            enabled: true,
            schedule_hour: 2,
            hot_retention_days: 1,
            cold_retention_days: 730,
            batch_size: 1,
        },
        storage.to_string_lossy().into_owned(),
    );
    let status = w.run().await.expect("compaction with batch_size=1");
    assert_eq!(status.rows_migrated, 3);
    assert_eq!(status.rows_deleted, 3);

    // One committed ledger row per batch, three covered ids.
    let committed = load_committed_batches(&pool, "tenant_ms").await.unwrap();
    assert_eq!(committed.len(), 3, "three batches = three commit rows");
    let distinct_objects: HashSet<String> =
        committed.iter().map(|b| b.object_key.clone()).collect();
    assert_eq!(
        distinct_objects.len(),
        3,
        "object keys must be distinct: {distinct_objects:?}"
    );
    for key in &distinct_objects {
        let name = key.rsplit('/').next().unwrap();
        assert!(
            name.starts_with("events_") && name.ends_with(".jsonl"),
            "{name}"
        );
        let middle = name
            .trim_start_matches("events_")
            .trim_end_matches(".jsonl");
        assert!(
            uuid::Uuid::parse_str(middle).is_ok(),
            "object identity must be a UUID, not wall-clock millis: {name}"
        );
    }

    // No truncation: each object holds exactly its own event, all 3 survive.
    let mut seen_ids = Vec::new();
    for batch in &committed {
        let bytes = std::fs::read(committed_object_path(&storage, batch))
            .unwrap_or_else(|e| panic!("object {} must exist: {e}", batch.object_key));
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "batch_size=1 → one line per object: {text}");
        let line: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        seen_ids.push(line["id"].as_str().unwrap().to_string());
        assert_eq!(
            compute_checksum(text.as_bytes()),
            batch.checksum,
            "ledger checksum must match the materialized bytes"
        );
    }
    seen_ids.sort();
    let mut expected = ids.clone();
    expected.sort();
    assert_eq!(
        seen_ids, expected,
        "every event must survive in exactly one object"
    );

    std::fs::remove_dir_all(&storage).ok();
    pool.close().await;
}

/// FINDING A kill window 1 — crash AFTER the object write, BEFORE the ledger
/// commit:an orphan object is left behind. It must be TOLERATED (never
/// swept mid-flight, never fatal) and the events must stay INTACT: the rerun
/// re-writes them under a fresh identity, commits the ledger, and only then
/// deletes the hot rows.
#[tokio::test]
async fn crash_after_object_write_before_commit_orphan_is_tolerated() {
    let Some(redis) = EphemeralRedis::start() else {
        eprintln!("skipping: redis-server not available");
        return;
    };
    let Some(pool) = canonical_pool("orphan").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let storage = std::env::temp_dir().join(format!(
        "apexmail_f83orph_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let ts = Utc::now() - Duration::days(3);
    let ids = seed_events_at(&pool, "tenant_orph", ts, 2).await;

    // The orphan: a complete object on disk with NO ledger row (crash in the
    // write→commit window). Same directory the rerun will write into.
    let dir = storage
        .join("tenant_orph")
        .join(ts.format("%Y/%m").to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let orphan = dir.join(format!("events_{}.jsonl", uuid::Uuid::new_v4()));
    std::fs::write(&orphan, b"{\"id\":\"orphan-crashed-write\"}\n").unwrap();

    let status = worker(&pool, &redis, &storage)
        .run()
        .await
        .expect("rerun after crash");
    assert_eq!(
        status.rows_migrated, 2,
        "orphan ids are not covered — they are re-written"
    );
    assert_eq!(
        status.rows_deleted, 2,
        "hot rows deleted only after the fresh commit"
    );

    // Events intact: every id is present in a COMMITTED object.
    let committed = load_committed_batches(&pool, "tenant_orph").await.unwrap();
    assert_eq!(committed.len(), 1);
    assert_eq!(committed[0].event_count, 2);
    let cold_bytes = std::fs::read(committed_object_path(&storage, &committed[0])).unwrap();
    let cold_text = String::from_utf8(cold_bytes).unwrap();
    for id in &ids {
        assert!(cold_text.contains(id), "committed object must carry {id}");
    }

    // The orphan is tolerated: still on disk, never swept, ages out with its
    // month directory under cold retention (documented residual duplicate).
    assert!(
        orphan.exists(),
        "orphan objects are tolerated, not destroyed"
    );

    // Another rerun: nothing left to do, ledger coverage is stable.
    let second = worker(&pool, &redis, &storage)
        .run()
        .await
        .expect("second rerun");
    assert_eq!(second.rows_migrated, 0);
    assert_eq!(
        load_committed_batches(&pool, "tenant_orph")
            .await
            .unwrap()
            .len(),
        1
    );

    std::fs::remove_dir_all(&storage).ok();
    pool.close().await;
}

/// FINDING A kill window 2 + FINDING B — crash AFTER the ledger commit,
/// BEFORE the hot DELETE. The rerun must consult the LEDGER (not the
/// filesystem): the covered ids are NOT re-written, and their hot rows are
/// deleted to finish the interrupted migration. The fixture deliberately has
/// NO manifest files at all — under the old manifest-scan dedup this rerun
/// would have re-written (duplicated) the batch.
#[tokio::test]
async fn crash_after_commit_before_delete_rerun_consults_ledger() {
    let Some(redis) = EphemeralRedis::start() else {
        eprintln!("skipping: redis-server not available");
        return;
    };
    let Some(pool) = canonical_pool("penddel").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let storage = std::env::temp_dir().join(format!(
        "apexmail_f83pend_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let ts = Utc::now() - Duration::days(3);
    let ids = seed_events_at(&pool, "tenant_pend", ts, 2).await;

    // Crash state: object written + ledger committed + manifest absent
    // (manifests are materialization only), events still in the hot table.
    let (_batch_id, object_path) =
        materialize_committed_batch(&pool, &storage, "tenant_pend", ts, &ids)
            .await
            .expect("simulate commit-before-delete crash");
    assert!(!object_path.to_string_lossy().contains(".manifest.json"));

    let status = worker(&pool, &redis, &storage)
        .run()
        .await
        .expect("rerun finishes the delete");
    assert_eq!(
        status.rows_migrated, 0,
        "covered ids must NOT be re-written (ledger consulted, not the filesystem)"
    );
    assert_eq!(
        status.rows_deleted, 2,
        "the interrupted DELETE is completed"
    );

    let hot: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id = 'tenant_pend'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(hot, 0);

    // Still exactly one committed batch, object untouched — no duplicates.
    let committed = load_committed_batches(&pool, "tenant_pend").await.unwrap();
    assert_eq!(committed.len(), 1);
    assert_eq!(committed[0].event_count, 2);
    let cold_text =
        std::fs::read_to_string(committed_object_path(&storage, &committed[0])).unwrap();
    for id in &ids {
        assert!(
            cold_text.contains(id),
            "cold copy must survive the delete: {id}"
        );
    }
    let total_objects = read_jsonl_lines(&storage).len();
    assert_eq!(total_objects, 2, "no duplicate cold rows for covered ids");

    std::fs::remove_dir_all(&storage).ok();
    pool.close().await;
}

/// FINDING B:ledger-driven id coverage must EQUAL the old full
/// manifest-tree scan (the removed load_manifested_ids recursion), on a
/// generated fixture tree — property test over seeded batches, shuffled
/// candidate sets, plus tenant isolation (a tenant's coverage never leaks
/// into another tenant's probe).
#[tokio::test]
async fn ledger_coverage_equals_old_full_manifest_scan_property() {
    let Some(pool) = canonical_pool("parity").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let storage = std::env::temp_dir().join(format!(
        "apexmail_f83par_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let ts = Utc::now() - Duration::days(3);
    let mut rng = StdRng::seed_from_u64(231202609);

    let mut first_tenant_ids: Vec<String> = Vec::new();
    for tenant in ["tenant_par1", "tenant_par2"] {
        let mut all_ids: Vec<String> = Vec::new();
        for _ in 0..8 {
            let n = rng.random_range(1..=12);
            let ids: Vec<String> = (0..n).map(|_| uuid::Uuid::new_v4().to_string()).collect();
            // Old-style manifest materialization (the oracle's input) + the
            // durable ledger commit (the new source of truth).
            let dir = storage.join(tenant).join(ts.format("%Y/%m").to_string());
            std::fs::create_dir_all(&dir).unwrap();
            let batch_id = uuid::Uuid::new_v4();
            let manifest = serde_json::json!({
                "file": format!("events_{batch_id}.jsonl"),
                "ids": ids,
            });
            std::fs::write(
                dir.join(format!("events_{batch_id}.manifest.json")),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            commit_batch_to_ledger(
                &pool,
                &CommittedBatch {
                    batch_id,
                    tenant_id: tenant.to_string(),
                    year: ts.year(),
                    month: ts.month() as i32,
                    object_key: format!("{tenant}/{}/events_{batch_id}.jsonl", ts.format("%Y/%m")),
                    manifest_key: format!(
                        "{tenant}/{}/events_{batch_id}.manifest.json",
                        ts.format("%Y/%m")
                    ),
                    event_count: n as i64,
                    checksum: compute_checksum(b""),
                    committed_at: Utc::now(),
                },
                ids.clone(),
            )
            .await
            .expect("ledger commit");
            all_ids.extend(ids);
        }

        // Candidates: every committed id plus guaranteed-absent ids,
        // deterministically shuffled.
        let absent: Vec<String> = (0..10).map(|_| uuid::Uuid::new_v4().to_string()).collect();
        let mut candidates = all_ids.clone();
        candidates.extend(absent.iter().cloned());
        for i in (1..candidates.len()).rev() {
            let j = rng.random_range(0..=i);
            candidates.swap(i, j);
        }

        let new_coverage = load_committed_event_ids(&pool, tenant, &candidates).await;
        let old_coverage = scan_manifest_ids_oracle(&storage, tenant);
        assert_eq!(
            new_coverage, old_coverage,
            "ledger coverage must equal the old full-scan coverage for {tenant}"
        );
        for a in &absent {
            assert!(
                !new_coverage.contains(a),
                "absent id {a} must not be covered"
            );
        }
        assert_eq!(new_coverage.len(), all_ids.len());
        if tenant == "tenant_par1" {
            first_tenant_ids = all_ids;
        }
    }

    // Tenant isolation:tenant_par1's committed ids are NEVER coverage for
    // tenant_par2 (the old scan keyed on the directory tree too, but the
    // ledger must enforce it explicitly).
    let leaked = load_committed_event_ids(&pool, "tenant_par2", &first_tenant_ids).await;
    assert!(
        leaked.is_empty(),
        "coverage must not leak across tenants: {leaked:?}"
    );

    std::fs::remove_dir_all(&storage).ok();
    pool.close().await;
}

/// FINDING A/B:the ledger ages out with the same `{YYYY/MM}` retention rule
/// as the on-disk month directories — a committed batch never outlives its
/// materialization, keeping the recovery lookup bounded by retention.
#[tokio::test]
async fn ledger_retention_tracks_cold_retention() {
    let Some(redis) = EphemeralRedis::start() else {
        eprintln!("skipping: redis-server not available");
        return;
    };
    let Some(pool) = canonical_pool("ledgret").await else {
        eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
        return;
    };
    let storage = std::env::temp_dir().join(format!(
        "apexmail_f83lr_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));

    // One batch dated 2020/01 (beyond a 30-day window), one dated 2999/12
    // (inside it); both committed through the real protocol.
    let old_id = uuid::Uuid::new_v4();
    let recent_id = uuid::Uuid::new_v4();
    commit_batch_to_ledger(
        &pool,
        &CommittedBatch {
            batch_id: old_id,
            tenant_id: "tenant_lr".into(),
            year: 2020,
            month: 1,
            object_key: "tenant_lr/2020/01/events_old.jsonl".into(),
            manifest_key: "tenant_lr/2020/01/events_old.manifest.json".into(),
            event_count: 1,
            checksum: "x".into(),
            committed_at: Utc::now(),
        },
        vec![uuid::Uuid::new_v4().to_string()],
    )
    .await
    .unwrap();
    commit_batch_to_ledger(
        &pool,
        &CommittedBatch {
            batch_id: recent_id,
            tenant_id: "tenant_lr".into(),
            year: 2999,
            month: 12,
            object_key: "tenant_lr/2999/12/events_recent.jsonl".into(),
            manifest_key: "tenant_lr/2999/12/events_recent.manifest.json".into(),
            event_count: 1,
            checksum: "x".into(),
            committed_at: Utc::now(),
        },
        vec![uuid::Uuid::new_v4().to_string()],
    )
    .await
    .unwrap();

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

    let old_gone: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM analytics_compaction_batches WHERE batch_id = $1")
            .bind(old_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        old_gone, 0,
        "ledger rows must age out with their month directory"
    );
    let old_ids: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM analytics_compaction_batch_event_ids WHERE batch_id = $1",
    )
    .bind(old_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(old_ids, 0, "covered ids must cascade with their batch");

    let recent_kept: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM analytics_compaction_batches WHERE batch_id = $1")
            .bind(recent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(recent_kept, 1, "in-window ledger rows survive");

    std::fs::remove_dir_all(&storage).ok();
    pool.close().await;
}
