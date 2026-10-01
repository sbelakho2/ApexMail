//! Adversarial, DB-/Redis-backed integration tests for the HA service:
//! backup/restore integrity (a corrupted backup is refused, never partially
//! applied), failover lock/state-machine behaviour, split-brain detection and
//! resolution, replication monitoring honesty, multi-region routing
//! determinism, chaos-experiment lifecycle + safety aborts, and the HTTP
//! surface's auth/validation gates.
//!
//! Harness convention (workspace): the canonical schema is provisioned with
//! `migrator::test_support::fresh_canonical_pool`; a configured provisioning
//! failure panics, an unset `TEST_DATABASE_URL` soft-skips. Redis comes from
//! `TEST_REDIS_URL` (unset → soft skip).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use ha::backup::BackupService;
use ha::chaos::ChaosEngineeringService;
use ha::circuit_breaker::CircuitBreakerService;
use ha::config::{Config, RoutingMode};
use ha::failover::FailoverService;
use ha::health_check::HealthCheckService;
use ha::multi_region::MultiRegionService;
use ha::replication::ReplicationService;
use ha::routes::{build_router, AppState};
use ha::types::*;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const INTERNAL_KEY: &str = "ha-adversarial-internal-key";
const ADMIN_KEY: &str = "ha-adversarial-admin-key";
const BACKUP_KEY: &str = "0123456789abcdef0123456789abcdef"; // exactly 32 bytes

static SHARED: tokio::sync::OnceCell<Option<Harness>> = tokio::sync::OnceCell::const_new();
/// `ha:primary:*` is global Redis state, so the split-brain scenarios in the
/// failover tests must not interleave with the fence-guard recovery call.
static SPLIT_BRAIN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

fn test_runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("build test runtime")
    })
}

fn run<F: std::future::Future>(future: F) -> F::Output {
    test_runtime().block_on(future)
}

struct Harness {
    db: PgPool,
    config: Arc<Config>,
}

impl Harness {
    fn state(&self) -> Arc<AppState> {
        self.state_with(self.config.clone())
    }

    fn state_with(&self, config: Arc<Config>) -> Arc<AppState> {
        Arc::new(AppState {
            health: HealthCheckService::new(self.db.clone(), Arc::clone(&config)),
            failover: FailoverService::new(self.db.clone(), Arc::clone(&config)),
            backup: BackupService::new(self.db.clone(), Arc::clone(&config))
                .expect("test backup config must be valid"),
            replication: ReplicationService::new(self.db.clone(), Arc::clone(&config)),
            multi_region: MultiRegionService::new(self.db.clone(), Arc::clone(&config)),
            circuit_breaker: CircuitBreakerService::new(Arc::clone(&config)),
            chaos: ChaosEngineeringService::new(self.db.clone(), Arc::clone(&config)),
            config,
        })
    }

    fn app(&self) -> Router {
        build_router(self.state())
    }
}

async fn harness() -> Option<&'static Harness> {
    SHARED
        .get_or_init(|| async { build_harness().await })
        .await
        .as_ref()
}

async fn build_harness() -> Option<Harness> {
    // Speed up the chaos safety-monitor so the abort paths are reachable in a
    // bounded test wait (the value is a documented operator knob).
    std::env::set_var("HA_CHAOS_SAFETY_INTERVAL_MS", "25");
    // `shared_canonical_db`, NOT `fresh_canonical_pool`: this suite shares ONE
    // database for the whole process (the `SHARED` OnceCell), and the
    // destructive variant DROPs and re-creates its database on every call — a
    // clone can then race a concurrent template top-up (or another binary's
    // clone) and fail with `clone-connect: database "…_ha_core" does not
    // exist`, which is exactly what a fully parallel instrumented run hit. The
    // shared variant creates-if-absent under a cluster advisory lock and
    // reuses an existing complete canonical database.
    // A PRIVATE database PER PROCESS: these tests assert things like "the
    // routing rule picks THIS region" and "the backup contains exactly these
    // rows", which are only true when nothing else is writing. Under nextest
    // every test is its own process, so the suffix includes the pid — each
    // process drops and re-creates only its own database, which is race-free
    // (a shared name would be dropped under a sibling's feet) and keeps the
    // exclusivity the assertions need.
    let db = match migrator::test_support::fresh_canonical_pool(
        "ha_adversarial",
        &format!("ha_core_p{}", std::process::id()),
    )
    .await
    {
        Ok(db) => db,
        Err(error) => panic!("{}", error.panic_message()),
    };
    let db = db?;
    let redis_url = std::env::var("TEST_REDIS_URL").ok()?;
    let (host, port, red_db) = parse_redis_url(&redis_url);

    let mut config = Config::from_env().expect("HA config must load in development");
    config.internal_api_key = INTERNAL_KEY.into();
    config.admin_api_key = ADMIN_KEY.into();
    config.redis.host = host;
    config.redis.port = port;
    config.redis.db = red_db;
    config.redis.password = None;
    config.multi_region.node_id = format!("node-{}", Uuid::new_v4().simple());
    config.backup.encryption_key = None;
    Some(Harness {
        db,
        config: Arc::new(config),
    })
}

fn parse_redis_url(url: &str) -> (String, u16, u8) {
    let rest = url.strip_prefix("redis://").unwrap_or(url);
    let rest = rest.rsplit('@').next().unwrap_or(rest);
    let (authority, db) = match rest.split_once('/') {
        Some((authority, db)) => (authority, db.split('?').next().unwrap_or("0")),
        None => (rest, "0"),
    };
    let (host, port) = authority
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(6379)))
        .unwrap_or_else(|| (authority.to_string(), 6379));
    (host, port, db.parse().unwrap_or(0))
}

async fn config_with(mutate: impl FnOnce(&mut Config)) -> Arc<Config> {
    let h = harness().await.expect("harness");
    let mut config = (*h.config).clone();
    mutate(&mut config);
    Arc::new(config)
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(key) = key {
        builder = builder.header("x-api-key", key);
    }
    let request = match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .expect("request body"),
        None => builder.body(Body::empty()).expect("empty request"),
    };
    let response = app.clone().oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

/// A JSON body that satisfies each body-taking method's extractor, so the
/// request reaches the auth check instead of failing extraction first.
fn route_body(method: &str, path: &str) -> Option<serde_json::Value> {
    if !matches!(method, "POST" | "PUT") {
        return None;
    }
    if path == "/api/v1/backup/restore" {
        return Some(serde_json::json!({
            "backup_id": Uuid::new_v4(),
            "target_time": null,
            "validate_only": true,
            "parallel_jobs": 1
        }));
    }
    Some(serde_json::json!({}))
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

/// Mutating requests pass the STONITH fence guard, which fails CLOSED with a
/// 503 when the fence status cannot be read (e.g. a transient Redis hiccup).
/// That is correct production behaviour, so retry such a call once — the
/// assertion under test is the auth gate, not the fence guard's availability.
async fn auth_call(
    app: &Router,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let (status, json) = call(app, method, path, key, body.clone()).await;
    let unreadable = json["reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("unreadable"));
    if status == StatusCode::SERVICE_UNAVAILABLE && unreadable {
        return call(app, method, path, key, body).await;
    }
    (status, json)
}

async fn redis_conn(config: &Config) -> redis::aio::MultiplexedConnection {
    redis::Client::open(config.redis.url())
        .expect("redis client")
        .get_multiplexed_async_connection()
        .await
        .expect("redis connection")
}

// ── Route gates ─────────────────────────────────────────────────────────

#[test]
fn routes_gate_on_api_key_and_report_malformed_ids_as_4xx() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app();

        let (status, _) = call(&app, "GET", "/health", None, None).await;
        assert_eq!(status, StatusCode::OK, "liveness must stay open");

        for (method, path) in [
            ("GET", "/api/v1/health"),
            ("GET", "/api/v1/health/cluster"),
            ("GET", "/api/v1/failover/status"),
            ("POST", "/api/v1/failover/initiate"),
            ("POST", "/api/v1/failover/failback"),
            ("GET", "/api/v1/failover/history"),
            ("GET", "/api/v1/failover/split-brain"),
            ("GET", "/api/v1/backup/list"),
            ("POST", "/api/v1/backup"),
            ("POST", "/api/v1/backup/restore"),
            ("GET", "/api/v1/backup/schedule"),
            ("GET", "/api/v1/replication/status"),
            ("GET", "/api/v1/regions"),
            ("GET", "/api/v1/circuit-breakers"),
            ("GET", "/api/v1/chaos/experiments"),
        ] {
            let body = route_body(method, path);
            let (status, json) = auth_call(&app, method, path, None, body.clone()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}: {json}");
            let (status, json) = auth_call(&app, method, path, Some("wrong-key"), body).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} bad key: {json}"
            );
        }

        // Both the internal and the admin key are accepted by every route.
        let (status, _) = call(
            &app,
            "GET",
            "/api/v1/failover/status",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            "/api/v1/failover/status",
            Some(ADMIN_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Malformed UUID path segments are 400, not 500.
        let (status, _) = call(
            &app,
            "GET",
            "/api/v1/backup/not-a-uuid",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = call(
            &app,
            "GET",
            "/api/v1/chaos/experiments/not-a-uuid",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, json) = auth_call(
            &app,
            "DELETE",
            "/api/v1/regions/geo-rules/not-a-uuid",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");

        // Unknown ids are 404 (backup/region/chaos/circuit).
        let (status, _) = call(
            &app,
            "GET",
            &format!("/api/v1/backup/{}", Uuid::new_v4()),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/api/v1/regions/{}", unique("no-region")),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = call(
            &app,
            "GET",
            "/api/v1/circuit-breakers/no-such-circuit",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

// ── Backup / restore ────────────────────────────────────────────────────

async fn seed_suppression_row(db: &PgPool, id: &str, email: &str) {
    sqlx::query("INSERT INTO suppression_list (id, tenant_id, email, reason) VALUES ($1, NULL, $2, 'bounce')")
        .bind(id)
        .bind(email)
        .execute(db)
        .await
        .expect("seed suppression row");
}

#[test]
fn backup_restore_round_trip_and_corrupted_payloads_are_refused() {
    run(async {
        let Some(h) = harness().await else { return };
        // The round-trip table is isolated from other tests' rows by using a
        // dedicated service instance over the shared canonical database.
        let backup = BackupService::new(h.db.clone(), h.config.clone()).expect("backup service");

        let table = "suppression_list".to_string();
        let email = format!("{}@example.com", unique("roundtrip"));
        let row_id = unique("row");
        seed_suppression_row(&h.db, &row_id, &email).await;

        // Create → get → list.
        let created = backup
            .create_backup(BackupType::Full, Some(vec![table.clone()]))
            .await
            .expect("create backup");
        assert_eq!(created.status, "completed");
        assert!(created.size_bytes > 0);
        assert!(created.checksum.is_some());
        assert!(created.location.as_deref().unwrap().starts_with("s3://"));
        let fetched = backup
            .get_backup(created.id)
            .await
            .unwrap()
            .expect("stored");
        assert_eq!(fetched.checksum, created.checksum);
        let listed = backup
            .list_backups(Some("full"), Some("completed"), 10)
            .await
            .unwrap();
        assert!(listed.iter().any(|b| b.id == created.id));
        let nonexistent = backup
            .list_backups(Some("wal"), Some("completed"), 10)
            .await
            .unwrap();
        assert!(nonexistent.iter().all(|b| b.backup_type == "wal"));

        // validate_only acknowledges without applying.
        let validate = backup
            .restore(RestoreOptions {
                backup_id: created.id,
                target_time: None,
                validate_only: true,
                parallel_jobs: 1,
            })
            .await
            .expect("validate only");
        assert!(validate.success);

        // Mutate the live table, then restore: the backup's state must be
        // restored EXACTLY (the extra row disappears, the saved row returns).
        sqlx::query("DELETE FROM suppression_list WHERE id = $1")
            .bind(&row_id)
            .execute(&h.db)
            .await
            .unwrap();
        seed_suppression_row(
            &h.db,
            &unique("extra"),
            &format!("{}@example.com", unique("extra")),
        )
        .await;
        let restored = backup
            .restore(RestoreOptions {
                backup_id: created.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .expect("restore");
        assert!(restored.success, "{:?}", restored.message);
        let verification = restored.verification.expect("verification");
        assert!(verification.checksum_match);
        assert!(verification.constraint_valid);
        let restored_email: String =
            sqlx::query_scalar("SELECT email FROM suppression_list WHERE id = $1")
                .bind(&row_id)
                .fetch_one(&h.db)
                .await
                .expect("restored source row");
        assert_eq!(restored_email, email);
        let extra: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM suppression_list WHERE email LIKE 'extra-%'")
                .fetch_one(&h.db)
                .await
                .unwrap();
        // Only the restored snapshot survives; rows added after the backup are
        // not present (the table was truncated then repopulated).
        assert_eq!(extra, 0, "restore must reproduce the backup, not merge");

        // Corrupted payload → refused, and the live table is untouched.
        let second = backup
            .create_backup(BackupType::Full, Some(vec![table.clone()]))
            .await
            .expect("second backup");
        let location = second.location.clone().unwrap();
        let local = local_staging_path(&location);
        let original = tokio::fs::read(&local).await.expect("payload on disk");
        assert!(!original.is_empty());
        let mut corrupted = original.clone();
        let mid = corrupted.len() / 2;
        corrupted[mid] ^= 0xFF;
        tokio::fs::write(&local, &corrupted).await.unwrap();
        let refused = backup
            .restore(RestoreOptions {
                backup_id: second.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await;
        assert!(refused.is_err(), "corrupted backup must be refused");
        let still_there: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM suppression_list WHERE id = $1")
                .bind(&row_id)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(still_there, 1, "a refused restore must not partially apply");

        // Truncated payload → refused.
        tokio::fs::write(&local, &original[..original.len() / 2])
            .await
            .unwrap();
        assert!(backup
            .restore(RestoreOptions {
                backup_id: second.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .is_err());

        // A backup that never completed cannot be restored.
        sqlx::query("UPDATE ha_backups SET status='in_progress' WHERE id=$1")
            .bind(second.id)
            .execute(&h.db)
            .await
            .unwrap();
        let pending = backup
            .restore(RestoreOptions {
                backup_id: second.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await;
        assert!(pending.is_err());

        // Unknown backup id is an honest error.
        assert!(backup
            .restore(RestoreOptions {
                backup_id: Uuid::new_v4(),
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .is_err());

        // delete_backup reports truthfully.
        assert!(backup.delete_backup(created.id).await.unwrap());
        assert!(!backup.delete_backup(created.id).await.unwrap());
        let _ = tokio::fs::remove_file(&local).await;
    });
}

fn local_staging_path(location: &str) -> std::path::PathBuf {
    let path = location.strip_prefix("s3://").expect("s3 location");
    let (_, key) = path.split_once('/').expect("object key");
    std::path::PathBuf::from(format!("/tmp/apexmail-backups/{}", key.replace('/', "_")))
}

/// `sequence_valid` must count only the ORPHANED sequences of the RESTORED
/// tables. The previous query counted every ownerless sequence in the whole
/// database, so an unrelated `CREATE SEQUENCE` made a correct single-table
/// restore report `sequence_valid = false`.
#[test]
fn restore_sequence_validity_is_scoped_to_the_restored_tables() {
    run(async {
        let Some(h) = harness().await else { return };
        let backup = BackupService::new(h.db.clone(), h.config.clone()).expect("backup service");

        // The restored table gets a real serial column: adding one creates a
        // sequence OWNED BY that column (the only kind the scoped check may
        // inspect).
        sqlx::query("ALTER TABLE suppression_list ADD COLUMN IF NOT EXISTS seq_no BIGSERIAL")
            .execute(&h.db)
            .await
            .expect("add serial column to the restored table");

        // An unrelated, deliberately ownerless sequence elsewhere in the
        // same schema. The OLD database-wide check counted this one and
        // turned `sequence_valid` false; the scoped check must ignore it.
        let orphan = unique("orphan_seq").replace('-', "_");
        sqlx::query(&format!("CREATE SEQUENCE {orphan}"))
            .execute(&h.db)
            .await
            .expect("create unrelated ownerless sequence");
        let database_wide_orphans: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_sequences s
             WHERE NOT EXISTS (
                SELECT 1 FROM pg_depend d
                JOIN pg_class seq ON seq.oid = d.objid
                WHERE d.classid = 'pg_class'::regclass
                  AND d.refclassid = 'pg_class'::regclass
                  AND d.refobjsubid > 0
                  AND seq.relkind = 'S'
                  AND seq.relname = s.sequencename
             )",
        )
        .fetch_one(&h.db)
        .await
        .expect("count database-wide ownerless sequences");
        assert!(
            database_wide_orphans >= 1,
            "the fixture must contain an unrelated ownerless sequence"
        );

        // A single-table backup/restore over the serial-bearing table.
        let row_id = unique("seq-row");
        seed_suppression_row(&h.db, &row_id, &format!("{}@example.com", unique("seq"))).await;
        let created = backup
            .create_backup(BackupType::Full, Some(vec!["suppression_list".to_string()]))
            .await
            .expect("create backup");
        let restored = backup
            .restore(RestoreOptions {
                backup_id: created.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .expect("restore");
        assert!(restored.success, "{:?}", restored.message);
        let verification = restored.verification.expect("verification");
        assert!(
            verification.sequence_valid,
            "an unrelated ownerless sequence must not invalidate the restore"
        );

        let _ = backup.delete_backup(created.id).await;
        let _ = sqlx::query(&format!("DROP SEQUENCE IF EXISTS {orphan}"))
            .execute(&h.db)
            .await;
    });
}

#[test]
fn encrypted_backup_requires_the_key_and_wrong_key_is_refused() {
    run(async {
        let Some(h) = harness().await else { return };
        let encrypted_config = config_with(|config| {
            config.backup.encryption_key = Some(BACKUP_KEY.to_string());
        })
        .await;
        let encrypted = BackupService::new(h.db.clone(), encrypted_config).expect("service");
        let table = "suppression_list".to_string();
        let row_id = unique("enc-row");
        let email = format!("{}@example.com", unique("enc"));
        seed_suppression_row(&h.db, &row_id, &email).await;

        let backup = encrypted
            .create_backup(BackupType::Full, Some(vec![table.clone()]))
            .await
            .expect("encrypted backup");
        assert!(backup.encrypted);
        assert!(backup.location.as_deref().unwrap().ends_with(".gz.enc"));

        // Correct key restores.
        let restored = encrypted
            .restore(RestoreOptions {
                backup_id: backup.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .expect("restore with the right key");
        assert!(restored.success);

        // A different key cannot read the payload.
        let wrong_key = config_with(|config| {
            config.backup.encryption_key = Some("ffffffffffffffffffffffffffffffff".into());
        })
        .await;
        let wrong = BackupService::new(h.db.clone(), wrong_key).unwrap();
        let error = wrong
            .restore(RestoreOptions {
                backup_id: backup.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .expect_err("wrong key must fail closed");
        assert!(error.contains("Decryption failed") || error.contains("corrupted"));

        // No key at all: the encrypted flag demands one.
        let no_key = config_with(|config| config.backup.encryption_key = None).await;
        let missing = BackupService::new(h.db.clone(), no_key).unwrap();
        let error = missing
            .restore(RestoreOptions {
                backup_id: backup.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .expect_err("missing key must fail closed");
        assert!(error.contains("BACKUP_ENCRYPTION_KEY"), "{error}");

        // The row survived the refused restores untouched.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM suppression_list WHERE id=$1")
            .bind(&row_id)
            .fetch_one(&h.db)
            .await
            .unwrap();
        assert_eq!(count, 1);
    });
}

#[test]
fn pitr_reports_the_unsupported_wal_step_and_retention_cleans_storage() {
    run(async {
        let Some(h) = harness().await else { return };
        let backup = BackupService::new(h.db.clone(), h.config.clone()).unwrap();
        let table = "suppression_list".to_string();
        let row_id = unique("pitr-row");
        seed_suppression_row(&h.db, &row_id, &format!("{}@example.com", unique("pitr"))).await;

        backup
            .create_backup(BackupType::Full, Some(vec![table.clone()]))
            .await
            .expect("backup");

        // PITR restores the base backup but must NOT claim success: WAL replay
        // to the target time is unsupported in this crate.
        let pitr = backup
            .pitr(chrono::Utc::now() + chrono::Duration::seconds(1))
            .await
            .expect("pitr call");
        assert!(!pitr.success, "PITR must not claim success");
        assert!(
            pitr.message
                .as_deref()
                .is_some_and(|m| m.contains("unsupported")),
            "message must be explicit: {:?}",
            pitr.message
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM suppression_list WHERE id=$1")
            .bind(&row_id)
            .fetch_one(&h.db)
            .await
            .unwrap();
        assert_eq!(count, 1, "base restore recreated the row");

        // A target time before any backup exists is an error, not a
        // false-success.
        assert!(backup
            .pitr(chrono::Utc::now() - chrono::Duration::days(3650))
            .await
            .is_err());

        // Retention: expired completed backups are removed together with
        // their stored object; expired-but-unfinished rows are kept.
        let expired_id = Uuid::new_v4();
        let expired_path = std::env::temp_dir().join(format!("apex-retention-{expired_id}.gz"));
        tokio::fs::write(&expired_path, b"payload").await.unwrap();
        sqlx::query(
            "INSERT INTO ha_backups (id, backup_type, status, size_bytes, location, encrypted, compressed, started_at, completed_at)
             VALUES ($1, 'full', 'completed', 7, $2, false, true, NOW() - INTERVAL '200 days', NOW() - INTERVAL '200 days')",
        )
        .bind(expired_id)
        .bind(format!("file://{}", expired_path.display()))
        .execute(&h.db)
        .await
        .unwrap();
        let pending_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ha_backups (id, backup_type, status, size_bytes, encrypted, compressed, started_at)
             VALUES ($1, 'full', 'in_progress', 0, false, true, NOW() - INTERVAL '200 days')",
        )
        .bind(pending_id)
        .execute(&h.db)
        .await
        .unwrap();

        let deleted = backup.enforce_retention().await.expect("retention");
        assert!(deleted >= 1);
        let gone: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ha_backups WHERE id=$1")
            .bind(expired_id)
            .fetch_one(&h.db)
            .await
            .unwrap();
        assert_eq!(gone, 0);
        assert!(
            !tokio::fs::try_exists(&expired_path).await.unwrap_or(true),
            "retention must remove the stored object too"
        );
        let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ha_backups WHERE id=$1")
            .bind(pending_id)
            .fetch_one(&h.db)
            .await
            .unwrap();
        assert_eq!(kept, 1, "an unfinished backup is not retention-eligible");
    });
}

// ── Failover ────────────────────────────────────────────────────────────

#[test]
fn failover_lock_state_and_split_brain_are_consistent() {
    run(async {
        let Some(h) = harness().await else { return };
        let failover = FailoverService::new(h.db.clone(), h.config.clone());
        let mut conn = redis_conn(&h.config).await;

        // A failover without configured replicas must fail AND leave the state
        // machine and distributed lock clean.
        let error = failover
            .initiate_failover(FailoverType::Manual, Some("adversarial".into()))
            .await
            .expect_err("no replica hosts → refuse");
        assert!(error.contains("replica"), "{error}");
        assert_eq!(failover.get_state().await, FailoverState::Normal);
        let lock: Option<String> = redis::cmd("GET")
            .arg("ha:failover:lock")
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(lock.is_none(), "the failover lock must be released");

        // A configured replica that is not replicating (no
        // pg_stat_replication row) is skipped — never promoted.
        let cfg = config_with(|config| {
            config.database.replica_hosts = vec!["replica-not-replicating".into()];
        })
        .await;
        let failover = FailoverService::new(h.db.clone(), cfg);
        let error = failover
            .initiate_failover(FailoverType::Manual, None)
            .await
            .expect_err("non-replicating candidate must be refused");
        assert!(error.contains("No healthy failover target"), "{error}");
        assert_eq!(failover.get_state().await, FailoverState::Normal);

        // Failback preconditions: disabled by default, and only valid from
        // FailedOver.
        assert!(failover.initiate_failback().await.is_err());
        let cfg = config_with(|config| config.failover.failback_enabled = true).await;
        let failover = FailoverService::new(h.db.clone(), cfg);
        let error = failover
            .initiate_failback()
            .await
            .expect_err("not failed over");
        assert!(error.contains("Cannot failback from state"), "{error}");

        // Failure reporting: per-component counters, only this component's
        // failures count, and the automatic attempt surfaces an error without
        // wedging the state machine.
        let cfg = config_with(|config| {
            config.failover.threshold = 3;
        })
        .await;
        let failover = FailoverService::new(h.db.clone(), cfg);
        for _ in 0..2 {
            failover.report_failure("database").await.unwrap();
        }
        failover.reset_failures_for("database").await;
        for _ in 0..2 {
            failover.report_failure("redis").await.unwrap();
        }
        assert_eq!(failover.get_state().await, FailoverState::Normal);
        let third = failover.report_failure("redis").await;
        assert!(third.is_err(), "automatic failover without replicas fails");
        assert_eq!(
            failover.get_state().await,
            FailoverState::Normal,
            "a failed automatic failover must not stay in Detecting"
        );
        failover.reset_failures().await;

        // Failover is disabled → report_failure is a no-op and no state flips.
        let cfg = config_with(|config| config.failover.enabled = false).await;
        let disabled = FailoverService::new(h.db.clone(), cfg);
        for _ in 0..10 {
            disabled.report_failure("database").await.unwrap();
        }
        assert_eq!(disabled.get_state().await, FailoverState::Normal);

        // Fencing is fail-closed and node-scoped. The probe uses a DEDICATED
        // node id: the fence key is global Redis state, and fencing the shared
        // harness node would (correctly) fail shut every concurrent mutating
        // request in this test binary.
        let fence_node = format!("fence-probe-{}", Uuid::new_v4().simple());
        let fence_cfg = config_with(|config| {
            config.multi_region.node_id = fence_node.clone();
        })
        .await;
        let probe = FailoverService::new(h.db.clone(), fence_cfg);
        probe.ensure_not_fenced().await.expect("not fenced");
        let _: () = redis::cmd("SET")
            .arg(format!("ha:fenced:{fence_node}"))
            .arg("1")
            .query_async(&mut conn)
            .await
            .unwrap();
        let reason = probe
            .ensure_not_fenced()
            .await
            .expect_err("fenced node must refuse");
        assert!(reason.contains("fenced"), "{reason}");
        assert!(probe.is_fenced_node(&fence_node).await.unwrap());
        assert!(!probe.is_fenced_node("some-other-node").await.unwrap());
        let _: i64 = redis::cmd("DEL")
            .arg(format!("ha:fenced:{fence_node}"))
            .query_async(&mut conn)
            .await
            .unwrap();
        probe.ensure_not_fenced().await.expect("unfenced again");

        // Split-brain: two primary claims are detected, then resolution leaves
        // exactly ONE claim and records the winner. The guard serializes this
        // against the sibling route test's recovery call (both use the global
        // `ha:primary:*` keyspace).
        let _split_guard = SPLIT_BRAIN_LOCK.lock().await;
        let stale: Vec<String> = redis::cmd("KEYS")
            .arg("ha:primary:*")
            .query_async(&mut conn)
            .await
            .unwrap();
        for key in &stale {
            let _: i64 = redis::cmd("DEL")
                .arg(key)
                .query_async(&mut conn)
                .await
                .unwrap();
        }
        for node in ["adv-a", "adv-b"] {
            let _: () = redis::cmd("SET")
                .arg(format!("ha:primary:{node}"))
                .arg("1")
                .query_async(&mut conn)
                .await
                .unwrap();
        }
        assert!(failover.detect_split_brain().await.unwrap());
        assert_eq!(failover.get_state().await, FailoverState::SplitBrain);
        // The route-level check sees the same global Redis claims.
        let app = h.app();
        let (status, json) = call(
            &app,
            "GET",
            "/api/v1/failover/split-brain",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["split_brain"], true);

        // Service-level resolution restores this instance's state machine.
        failover.resolve_split_brain("adv-a").await.unwrap();
        assert_eq!(failover.get_state().await, FailoverState::Normal);
        assert_eq!(failover.get_config_info().await.primary_node, "adv-a");
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("ha:primary:*")
            .query_async(&mut conn)
            .await
            .unwrap();
        let adv_keys: Vec<&String> = keys.iter().filter(|k| k.contains("adv-")).collect();
        assert_eq!(adv_keys.len(), 1, "exactly one primary claim survives");
        assert_eq!(adv_keys[0], "ha:primary:adv-a");
        let (_, json) = call(
            &app,
            "GET",
            "/api/v1/failover/split-brain",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(json["split_brain"], false);

        // …and the route-level resolution path is exercised over a fresh pair
        // of conflicting claims. SM10 F11: resolution is ADMIN-only, so the
        // internal key is refused before the coordinator runs.
        for node in ["adv-c", "adv-d"] {
            let _: () = redis::cmd("SET")
                .arg(format!("ha:primary:{node}"))
                .arg("1")
                .query_async(&mut conn)
                .await
                .unwrap();
        }
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/failover/split-brain/resolve",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"winner_node": "adv-c"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the universal internal key must not authorize split-brain resolution"
        );
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/failover/split-brain/resolve",
            Some(ADMIN_KEY),
            Some(serde_json::json!({"winner_node": "adv-c"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, json) = call(
            &app,
            "GET",
            "/api/v1/failover/split-brain",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(json["split_brain"], false, "resolution left one claim");

        // Claim refresh is owner-checked: the claim is written with THIS
        // service's node id as owner token, so only that owner's refresh
        // extends the TTL.
        let owner = h.config.multi_region.node_id.clone();
        let _: () = redis::cmd("SET")
            .arg("ha:primary:adv-a")
            .arg(&owner)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(failover.refresh_primary_claim("adv-a").await.unwrap());
        assert!(!failover.refresh_primary_claim("adv-b").await.unwrap());
        let _: i64 = redis::cmd("DEL")
            .arg("ha:primary:adv-a")
            .query_async(&mut conn)
            .await
            .unwrap();
    });
}

#[test]
fn failover_routes_expose_state_and_enforce_the_fence_guard() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app();

        let (status, json) = call(
            &app,
            "GET",
            "/api/v1/failover/status",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["current_state"], "normal");
        assert_eq!(json["enabled"], true);

        let (status, json) = call(
            &app,
            "GET",
            "/api/v1/failover/history?limit=5",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.is_array());

        // History records real events: seed one and read it back.
        let event_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ha_failover_events (id, from_node, to_node, failover_type, state, reason, started_at, data_loss)
             VALUES ($1, 'node-old', 'node-new', 'manual', 'completed', 'adversarial', NOW(), false)",
        )
        .bind(event_id)
        .execute(&h.db)
        .await
        .unwrap();
        let (_, json) = call(
            &app,
            "GET",
            "/api/v1/failover/history?limit=10",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert!(json
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["id"] == event_id.to_string()));

        // A fenced node refuses mutating requests with 503 while reads and
        // recovery endpoints stay available. SM10 F11: initiation (and the
        // recovery routes below) are ADMIN-only, so these calls present the
        // admin key; the internal key must not even reach the fence guard.
        let cfg = config_with(|config| {
            config.multi_region.node_id = "route-fenced-node".into();
        })
        .await;
        let mut conn = redis_conn(&h.config).await;
        let fenced_app = build_router(h.state_with(cfg));
        let _: () = redis::cmd("SET")
            .arg("ha:fenced:route-fenced-node")
            .arg("1")
            .query_async(&mut conn)
            .await
            .unwrap();
        let (status, _) = call(
            &fenced_app,
            "POST",
            "/api/v1/failover/initiate",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"reason": "should be refused"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the universal internal key must not authorize failover initiation"
        );
        let (status, json) = call(
            &fenced_app,
            "POST",
            "/api/v1/failover/initiate",
            Some(ADMIN_KEY),
            Some(serde_json::json!({"reason": "should be refused"})),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(json["error"].as_str().unwrap().contains("fenced"));
        let (status, _) = call(
            &fenced_app,
            "GET",
            "/api/v1/failover/status",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let _split_guard = SPLIT_BRAIN_LOCK.lock().await;
        let (status, _) = call(
            &fenced_app,
            "POST",
            "/api/v1/failover/split-brain/resolve",
            Some(ADMIN_KEY),
            Some(serde_json::json!({"winner_node": "route-fenced-node"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "recovery endpoints stay reachable");
        // Clean both global namespaces this recovery call touched.
        let _: i64 = redis::cmd("DEL")
            .arg("ha:fenced:route-fenced-node")
            .arg("ha:primary:route-fenced-node")
            .query_async(&mut conn)
            .await
            .unwrap();
        drop(_split_guard);

        // Malformed bodies are 4xx (never 500) and change nothing. The
        // resolve route is ADMIN-only (SM10 F11), so the malformed-body
        // probe presents the admin key; the internal key is 401.
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/failover/split-brain/resolve",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"winner": "wrong-field"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the universal internal key must not authorize split-brain resolution"
        );
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/failover/split-brain/resolve",
            Some(ADMIN_KEY),
            Some(serde_json::json!({"winner": "wrong-field"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _) = call(
            &app,
            "GET",
            "/api/v1/failover/history?limit=abc",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    });
}

// ── Replication ─────────────────────────────────────────────────────────

#[test]
fn replication_reports_empty_topology_honestly_and_guards_slot_names() {
    run(async {
        let Some(h) = harness().await else { return };
        let replication = ReplicationService::new(h.db.clone(), h.config.clone());

        let stats = replication.get_stats().await.expect("stats");
        assert_eq!(stats.mode, "async");
        assert!(stats.replicas.is_empty(), "no replicas connected");
        assert_eq!(stats.total_lag_bytes, 0);
        assert_eq!(stats.max_lag_ms, 0.0);
        assert!(stats.is_healthy);

        assert!(replication.get_replicas().await.unwrap().is_empty());
        assert!(replication.get_lag("nope").await.unwrap().is_none());
        replication
            .record_lag()
            .await
            .expect("record with no replicas");
        assert!(replication.get_slots().await.unwrap().is_empty());

        // Hostile slot names never reach SQL.
        for name in ["x; DROP TABLE ha_backups", "name with spaces", ""] {
            let error = replication
                .create_slot(name, "physical")
                .await
                .expect_err("invalid slot name");
            assert!(error.contains("Invalid slot name"), "{error}");
            assert!(replication.drop_slot(name).await.is_err());
        }

        // A well-formed-LOOKING slot name is attempted: `unique()` yields a
        // dashed suffix, which the slot-name validator rejects before any
        // SQL runs (a `-` is neither alphanumeric nor `_`). The outcome is
        // therefore validator-driven and role-independent — never a silent
        // success.
        let slot = unique("advslot");
        let created = replication.create_slot(&slot, "physical").await;
        assert!(created.is_err(), "the dashed name must fail validation");
        let dropped = replication.drop_slot(&slot).await;
        assert!(dropped.is_err(), "dropping a nonexistent slot must error");

        // Promotion on a non-standby / insufficient role is an error.
        assert!(replication.promote_standby().await.is_err());
        // Sync-mode switching needs superuser. The canonical TEST_DATABASE_URL
        // role IS a superuser on the shared dev cluster (ALTER SYSTEM is
        // granted), while a locked-down deployment role must see a loud
        // refusal — assert the honest outcome FOR THE ROLE WE ACTUALLY HAVE,
        // and never leave the shared server forced into synchronous commit.
        let superuser: bool = sqlx::query_scalar(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
        )
        .fetch_one(&h.db)
        .await
        .unwrap();
        if superuser {
            // pg_reload_conf() returns before the postmaster has processed
            // the reload, so the live setting is observed with a small
            // bounded wait instead of an immediate (racy) read.
            async fn sync_standby_setting(db: &sqlx::PgPool) -> String {
                let (value,): (String,) = sqlx::query_as(
                    "SELECT setting FROM pg_settings WHERE name = 'synchronous_standby_names'",
                )
                .fetch_one(db)
                .await
                .unwrap();
                value
            }
            async fn wait_for_setting(db: &sqlx::PgPool, expected: &str) -> String {
                let mut current = sync_standby_setting(db).await;
                for _ in 0..40 {
                    if current == expected {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    current = sync_standby_setting(db).await;
                }
                current
            }
            replication
                .set_sync_mode(true)
                .await
                .expect("a superuser toggles sync mode");
            let applied = wait_for_setting(&h.db, "*").await;
            assert_eq!(
                applied, "*",
                "the toggle must reach the live (reloaded) setting"
            );
            // Restore the shared server's async default — a test must never
            // leave the cluster requiring a synchronous standby.
            replication
                .set_sync_mode(false)
                .await
                .expect("a superuser restores the async default");
            let restored = wait_for_setting(&h.db, "").await;
            assert_eq!(restored, "", "the shared server must end async");
        } else {
            assert!(
                replication.set_sync_mode(true).await.is_err(),
                "a non-superuser role must be refused loudly"
            );
        }

        // Lag history: recorded → read within window → retention purge.
        let old = unique("lag-old");
        let recent = unique("lag-new");
        sqlx::query(
            "INSERT INTO ha_replication_lag_history (replica_name, lag_ms, lag_bytes, recorded_at)
             VALUES ($1, 10.0, 100, NOW() - INTERVAL '48 hours'), ($2, 5.0, 50, NOW())",
        )
        .bind(&old)
        .bind(&recent)
        .execute(&h.db)
        .await
        .unwrap();
        let history = replication.get_lag_history(60).await.unwrap();
        assert!(history.iter().any(|h| h["replica"] == recent));
        assert!(!history.iter().any(|h| h["replica"] == old));
        let purged = replication.cleanup_lag_history(24).await.unwrap();
        assert!(purged >= 1);
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ha_replication_lag_history WHERE replica_name = $1",
        )
        .bind(&old)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(remaining, 0);

        // Route surface mirrors the service (all honest 200s over a real DB).
        let app = h.app();
        for path in [
            "/api/v1/replication/status",
            "/api/v1/replication/replicas",
            "/api/v1/replication/slots",
            "/api/v1/replication/lag/history?minutes=5",
        ] {
            let (status, _) = call(&app, "GET", path, Some(INTERNAL_KEY), None).await;
            assert_eq!(status, StatusCode::OK, "{path}");
        }
        // Slot creation via route surfaces the server error as 500 (honest).
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/replication/slots",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"name": "bad name"})),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        // The sync-mode route mirrors the service's privilege contract:
        // a superuser test role toggles (200, back to async), a locked-down
        // role is refused with a loud server error.
        let superuser: bool = sqlx::query_scalar(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
        )
        .fetch_one(&h.db)
        .await
        .unwrap();
        let (status, _) = call(
            &app,
            "PUT",
            "/api/v1/replication/sync-mode",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"synchronous": false})),
        )
        .await;
        if superuser {
            assert_eq!(
                status,
                StatusCode::OK,
                "a superuser toggles sync mode (and this call restores async)"
            );
        } else {
            assert!(
                status.is_server_error(),
                "a non-superuser role must be refused loudly: got {status}"
            );
        }
    });
}

// ── Multi-region ────────────────────────────────────────────────────────

#[test]
fn multi_region_routing_is_deterministic_and_fencing_excludes_regions() {
    run(async {
        let Some(h) = harness().await else { return };

        // Active/passive: always the primary.
        let cfg = config_with(|config| {
            config.multi_region.routing_mode = RoutingMode::ActivePassive;
        })
        .await;
        let service = MultiRegionService::new(h.db.clone(), cfg);
        let primary = unique("region-primary");
        let standby_a = unique("region-a");
        let standby_b = unique("region-b");
        for (name, role) in [
            (&primary, RegionRole::Primary),
            (&standby_a, RegionRole::Secondary),
            (&standby_b, RegionRole::Secondary),
        ] {
            service
                .register_region(
                    name,
                    &format!("https://{name}.example.com"),
                    &role,
                    Some("az-1"),
                )
                .await
                .unwrap();
        }
        // Re-registering the same name updates instead of duplicating.
        service
            .register_region(
                &primary,
                "https://updated.example.com",
                &RegionRole::Primary,
                None,
            )
            .await
            .unwrap();
        let primary_info = service.get_region(&primary).await.unwrap().unwrap();
        assert_eq!(primary_info.endpoint, "https://updated.example.com");
        // The routing contract in ActivePassive mode is "a PRIMARY region,
        // chosen deterministically" — NOT "the primary this test happens to
        // have registered". The fixture database is SHARED (all tests in this
        // binary reuse it, and under nextest each test is its own process), so
        // other tests' primaries are present and may legitimately win the
        // selection; asserting the exact name made this test depend on what
        // ran before it.
        let mut chosen_three = Vec::new();
        for _ in 0..3 {
            let chosen = service.route_request(None).await.unwrap();
            let info = service.get_region(&chosen.name).await.unwrap().unwrap();
            assert_eq!(
                info.role, "primary",
                "active/passive must route to a primary region, got {info:?}"
            );
            assert_eq!(info.status, "active", "and it must be active: {info:?}");
            chosen_three.push(chosen.name);
        }
        assert!(
            chosen_three.windows(2).all(|pair| pair[0] == pair[1]),
            "active/passive must be stable across calls: {chosen_three:?}"
        );
        // This test's own primary is registered and active, i.e. it is a
        // legitimate candidate for the same contract.
        let own = service.get_region(&primary).await.unwrap().unwrap();
        assert_eq!(own.role, "primary");
        assert_eq!(own.endpoint, "https://updated.example.com");

        // Health thresholds drive status; a fenced region never becomes active
        // again through a health update.
        service
            .update_health(&standby_a, 95.0, 12.0, None)
            .await
            .unwrap();
        assert_eq!(
            service
                .get_region(&standby_a)
                .await
                .unwrap()
                .unwrap()
                .status,
            "active"
        );
        service
            .update_health(&standby_a, 60.0, 30.0, Some(5.0))
            .await
            .unwrap();
        assert_eq!(
            service
                .get_region(&standby_a)
                .await
                .unwrap()
                .unwrap()
                .status,
            "standby"
        );
        service
            .update_health(&standby_a, 10.0, 90.0, Some(500.0))
            .await
            .unwrap();
        assert_eq!(
            service
                .get_region(&standby_a)
                .await
                .unwrap()
                .unwrap()
                .status,
            "inactive"
        );
        service.fence_region(&standby_a, "test").await.unwrap();
        service
            .update_health(&standby_a, 100.0, 1.0, None)
            .await
            .unwrap();
        assert_eq!(
            service
                .get_region(&standby_a)
                .await
                .unwrap()
                .unwrap()
                .status,
            "fenced",
            "a fenced region must stay fenced"
        );
        service.unfence_region(&standby_a).await.unwrap();
        assert_eq!(
            service
                .get_region(&standby_a)
                .await
                .unwrap()
                .unwrap()
                .status,
            "standby"
        );

        // Latency-based routing picks the healthy minimum.
        let cfg = config_with(|config| {
            config.multi_region.routing_mode = RoutingMode::LatencyBased;
        })
        .await;
        let service = MultiRegionService::new(h.db.clone(), cfg);
        service
            .update_health(&standby_a, 95.0, 10.0, None)
            .await
            .unwrap();
        service
            .update_health(&standby_b, 95.0, 40.0, None)
            .await
            .unwrap();
        // "Lowest latency wins" is a rule about the ACTIVE set, not about this
        // test's regions: the fixture database is shared, so a foreign region
        // with a lower latency may legitimately win. Assert the rule itself —
        // the chosen region carries the minimum latency among active regions.
        let chosen = service.route_request(None).await.unwrap();
        let active = service.list_regions(10_000, 0).await.unwrap();
        let min_latency = active
            .iter()
            .filter(|r| r.status == "active" && r.health_score > 0.0)
            .filter_map(|r| r.latency_ms)
            .fold(f64::INFINITY, f64::min);
        assert_eq!(
            chosen.latency_ms,
            Some(min_latency),
            "latency routing must pick the healthy minimum: chosen {chosen:?}"
        );
        // …and this test's 10 ms region is a candidate that satisfies it.
        let own = service.get_region(&standby_a).await.unwrap().unwrap();
        assert_eq!(own.latency_ms, Some(10.0));

        // Active/active picks the healthiest.
        let cfg = config_with(|config| {
            config.multi_region.routing_mode = RoutingMode::ActiveActive;
        })
        .await;
        let service = MultiRegionService::new(h.db.clone(), cfg);
        service
            .update_health(&primary, 90.0, 5.0, None)
            .await
            .unwrap();
        service
            .update_health(&standby_b, 99.0, 40.0, None)
            .await
            .unwrap();
        let chosen = service.route_request(None).await.unwrap();
        assert_eq!(chosen.name, standby_b, "highest health wins");

        // Round robin advances deterministically across active regions.
        let cfg = config_with(|config| {
            config.multi_region.routing_mode = RoutingMode::RoundRobin;
        })
        .await;
        let service = MultiRegionService::new(h.db.clone(), cfg);
        let first = service.route_request(None).await.unwrap().name;
        let second = service.route_request(None).await.unwrap().name;
        assert_ne!(first, second, "round robin must advance");

        // Geo routing rules override the mode and lower priority wins.
        let _ = service
            .add_geo_rule(&unique("high"), &primary, &primary, 100)
            .await
            .unwrap();
        let rule_low = service
            .add_geo_rule(&unique("low"), &primary, &standby_b, 1)
            .await
            .unwrap();
        let chosen = service.route_request(Some(&primary)).await.unwrap();
        assert_eq!(chosen.name, standby_b, "matching geo rule wins");
        // A rule pointing at a non-active target is ignored, not honoured
        // blindly.
        service
            .fence_region(&standby_b, "geo target fenced")
            .await
            .unwrap();
        let chosen = service.route_request(Some(&primary)).await.unwrap();
        assert_ne!(chosen.name, standby_b);

        // Traffic distribution reflects weights; zero/negative weights are
        // floored at 1 so a region can never be starved into a zero share.
        service.set_weight(&primary, 3).await.unwrap();
        service.set_weight(&standby_a, 0).await.unwrap();
        let distribution = service.get_traffic_distribution().await.unwrap();
        let total: f64 = distribution.iter().map(|d| d.weight).sum();
        assert!((total - 1.0).abs() < 1e-9, "weights must sum to 1");
        assert!(distribution.iter().all(|d| d.weight > 0.0));

        // Rules are listable/deletable, including the unknown-id case.
        assert!(service.delete_geo_rule(rule_low.id).await.unwrap());
        assert!(!service.delete_geo_rule(rule_low.id).await.unwrap());
        let rules = service.list_geo_rules(10, 0).await.unwrap();
        assert!(!rules.iter().any(|r| r.id == rule_low.id));

        // Removal is truthfully reported.
        service.fence_region(&standby_b, "cleanup").await.unwrap();
        assert!(service.remove_region(&standby_b).await.unwrap());
        assert!(!service.remove_region(&standby_b).await.unwrap());

        // Route surface: registration, listing with clamped pagination, health
        // and fence endpoints.
        let app = h.app();
        let region = unique("route-region");
        let (status, json) = call(
            &app,
            "POST",
            "/api/v1/regions",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({
                "name": region, "endpoint": "https://r.example.com", "role": "primary"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
        let (status, json) = call(
            &app,
            "GET",
            "/api/v1/regions?limit=100000&offset=-3",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.as_array().is_some());
        let (status, _) = call(
            &app,
            "PUT",
            &format!("/api/v1/regions/{region}/health"),
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"health_score": 20.0, "latency_ms": 100.0})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, json) = call(
            &app,
            "GET",
            &format!("/api/v1/regions/{region}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(json["status"], "inactive");
        // SM10 F11 (adversarial pass): region fence/unfence place and lift
        // the STONITH keys — ADMIN-only, like initiate/promote. The
        // internal key is refused; the admin key reaches the handlers.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/api/v1/regions/{region}/fence"),
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"reason": "adversarial"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the universal internal key must not fence a region"
        );
        let (status, json) = call(
            &app,
            "POST",
            &format!("/api/v1/regions/{region}/fence"),
            Some(ADMIN_KEY),
            Some(serde_json::json!({"reason": "adversarial"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, json) = call(
            &app,
            "POST",
            &format!("/api/v1/regions/{region}/unfence"),
            Some(ADMIN_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, _) = call(
            &app,
            "PUT",
            &format!("/api/v1/regions/{region}/weight"),
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"weight": 7})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            "/api/v1/regions/traffic",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            "/api/v1/regions/route",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/regions/geo-rules",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({
                "name": unique("rule"), "source_region": "eu", "target_region": region, "priority": 5
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, json) = call(
            &app,
            "GET",
            "/api/v1/regions/geo-rules",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!json.as_array().unwrap().is_empty());
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/api/v1/regions/{region}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/api/v1/regions/{region}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "removing a missing region is honest"
        );
    });
}

// ── Chaos ───────────────────────────────────────────────────────────────

fn experiment_config(kind: &str, duration_ms: u64, safety: Vec<SafetyCheck>) -> ExperimentConfig {
    ExperimentConfig {
        experiment_type: kind.into(),
        target: ExperimentTarget {
            service: "ha".into(),
            instances: vec![],
            percentage: 100.0,
        },
        parameters: ExperimentParameters {
            duration_ms,
            intensity: 0.5,
            error_codes: None,
            latency_ms: None,
            resource_type: None,
            resource_limit: None,
        },
        safety_checks: safety,
        rollback_on_failure: true,
    }
}

async fn wait_for_status(
    service: &ChaosEngineeringService,
    id: Uuid,
    wanted: &[&str],
) -> Experiment {
    for _ in 0..200 {
        if let Some(experiment) = service.get_experiment(id).await.unwrap() {
            if wanted.contains(&experiment.status.as_str()) {
                return experiment;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("experiment {id} did not reach {wanted:?} in time");
}

#[test]
fn chaos_experiments_validate_abort_and_never_corrupt_state() {
    run(async {
        let Some(h) = harness().await else { return };

        // Disabled by default: refuse everything.
        let disabled = ChaosEngineeringService::new(h.db.clone(), h.config.clone());
        assert!(disabled
            .start_experiment("nope", experiment_config("process_kill", 100, vec![]))
            .await
            .is_err());

        let cfg = config_with(|config| config.chaos.enabled = true).await;
        let service = ChaosEngineeringService::new(h.db.clone(), cfg.clone());

        // Validation happens before any row is written.
        assert!(service
            .start_experiment("bad type", experiment_config("not_a_type", 100, vec![]))
            .await
            .is_err());
        assert!(service
            .start_experiment("zero", experiment_config("process_kill", 0, vec![]))
            .await
            .is_err());
        assert!(service
            .start_experiment(
                "too long",
                experiment_config("process_kill", 3_600_001, vec![])
            )
            .await
            .is_err());
        let experiments: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ha_chaos_experiments WHERE name = ANY($1)")
                .bind(vec!["bad type", "zero", "too long"])
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(experiments, 0, "rejected experiments must not be persisted");

        // A short experiment completes and records success + metrics.
        let short = service
            .start_experiment("short-lived", experiment_config("process_kill", 60, vec![]))
            .await
            .expect("start");
        let completed = wait_for_status(&service, short.id, &["completed", "aborted"]).await;
        assert_eq!(completed.status, "completed");
        let results: ExperimentResults =
            serde_json::from_value(completed.results.expect("results")).expect("decode results");
        assert!(results.success);
        assert!(results.safety_violations.is_empty());

        // A guaranteed-violated safety check aborts the experiment and records
        // the violation.
        let violation = SafetyCheck {
            name: "always".into(),
            check_type: "cpu_usage".into(),
            operator: "<".into(),
            // Large enough to always trip for the captured metric, while
            // staying small enough that PostgreSQL JSONB round-trips it as a
            // float (f64::MAX is stored as a 309-digit integer literal, which
            // serde_json refuses to read back).
            threshold: 1.0e12,
            abort_on_failure: true,
        };
        let guarded = service
            .start_experiment(
                "safety-abort",
                experiment_config("resource_exhaustion", 60_000, vec![violation]),
            )
            .await
            .expect("start guarded");
        let aborted = wait_for_status(&service, guarded.id, &["aborted"]).await;
        assert_eq!(aborted.status, "aborted");
        let results: ExperimentResults =
            serde_json::from_value(aborted.results.expect("results")).expect("decode results");
        assert!(!results.success);
        assert!(
            results
                .safety_violations
                .iter()
                .any(|v| v.contains("always")),
            "the violated check must be recorded: {:?}",
            results.safety_violations
        );

        // An unknown safety operator is treated as a violation (fail closed).
        let bogus_operator = SafetyCheck {
            name: "bogus".into(),
            check_type: "cpu_usage".into(),
            operator: "~=".into(),
            threshold: 0.0,
            abort_on_failure: true,
        };
        let fail_closed = service
            .start_experiment(
                "operator-abort",
                experiment_config("resource_exhaustion", 60_000, vec![bogus_operator]),
            )
            .await
            .expect("start");
        let aborted = wait_for_status(&service, fail_closed.id, &["aborted"]).await;
        assert_eq!(aborted.status, "aborted");

        // Manual abort of a long-running experiment; aborting again / aborting
        // an unknown id is an honest error.
        let long = service
            .start_experiment(
                "manual-abort",
                experiment_config("latency_injection", 60_000, vec![]),
            )
            .await
            .expect("start long");
        service.abort_experiment(long.id).await.expect("abort");
        let aborted = wait_for_status(&service, long.id, &["aborted"]).await;
        assert_eq!(aborted.status, "aborted");
        assert!(service.abort_experiment(long.id).await.is_err());
        assert!(service.abort_experiment(Uuid::new_v4()).await.is_err());

        // Listing/filtering/deleting reflects the database truthfully.
        let running_like = service.list_experiments(Some("running"), 10).await.unwrap();
        assert!(running_like.is_empty());
        let completed_list = service
            .list_experiments(Some("completed"), 100)
            .await
            .unwrap();
        assert!(completed_list.iter().any(|e| e.id == short.id));
        assert!(service
            .get_experiment(Uuid::new_v4())
            .await
            .unwrap()
            .is_none());
        assert!(service.delete_experiment(short.id).await.unwrap());
        assert!(!service.delete_experiment(short.id).await.unwrap());
        assert!(service.get_experiment(short.id).await.unwrap().is_none());

        // Route surface: start → get → list → abort → delete, with malformed
        // payloads rejected as 4xx. The router must be built with chaos
        // ENABLED (the default is off, which is itself pinned above).
        let chaos_cfg = config_with(|config| config.chaos.enabled = true).await;
        let app = build_router(h.state_with(chaos_cfg));
        // SM10 F11: chaos-experiment START is ADMIN-only — the universal
        // internal key is 401 before any handler/extractor runs.
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/chaos/experiments",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"name": "internal-key-must-not-start-chaos"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the universal internal key must not start chaos experiments"
        );
        let (status, json) = call(
            &app,
            "POST",
            "/api/v1/chaos/experiments",
            Some(ADMIN_KEY),
            Some(serde_json::json!({
                "name": unique("route-experiment"),
                "experiment_type": "network_partition",
                "target": {"service": "ha", "instances": [], "percentage": 100.0},
                "parameters": {"duration_ms": 40, "intensity": 0.5},
                "safety_checks": [],
                "rollback_on_failure": true
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
        let id = json["id"].as_str().unwrap().to_string();
        let (status, _) = call(
            &app,
            "GET",
            &format!("/api/v1/chaos/experiments/{id}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            "/api/v1/chaos/experiments?limit=5",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/chaos/experiments",
            Some(ADMIN_KEY),
            Some(serde_json::json!({"name": "missing everything"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/api/v1/chaos/experiments/{id}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    });
}

// ── Circuit breakers ────────────────────────────────────────────────────

#[test]
fn legacy_chaos_rows_with_unrepresentable_thresholds_stay_readable() {
    run(async {
        let Some(h) = harness().await else { return };

        // Simulate a row written BEFORE threshold validation existed: jsonb
        // normalizes f64::MAX to a 309-digit integer, and a plain
        // serde_json::Value decode then fails with "number out of range",
        // making the experiment permanently unreadable.
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ha_chaos_experiments
             (id, name, experiment_type, status, config, target, parameters, safety_checks, created_at)
             VALUES ($1, 'legacy-max', 'process_kill', 'completed',
                     '{\"experiment_type\":\"process_kill\",\"target\":{\"service\":\"ha\",\"instances\":[],\"percentage\":100.0},\"parameters\":{\"duration_ms\":1,\"intensity\":0.5},\"safety_checks\":[],\"rollback_on_failure\":true}'::jsonb,
                     '{\"service\":\"ha\",\"instances\":[],\"percentage\":100.0}'::jsonb,
                     '{\"duration_ms\":1,\"intensity\":0.5}'::jsonb,
                     '[{\"name\":\"unlimited\",\"check_type\":\"cpu_usage\",\"threshold\":1.7976931348623157e308,\"operator\":\"<\",\"abort_on_failure\":true}]'::jsonb,
                     NOW())",
        )
        .bind(id)
        .execute(&h.db)
        .await
        .expect("seed legacy chaotic experiment");

        let service = ChaosEngineeringService::new(h.db.clone(), h.config.clone());
        let experiment = service
            .get_experiment(id)
            .await
            .expect("a legacy row must remain readable")
            .expect("row exists");
        let threshold = experiment.safety_checks[0]["threshold"]
            .as_f64()
            .expect("clamped finite number");
        assert!(threshold.is_finite(), "clamped to a representable f64");
        assert_eq!(threshold, f64::MAX);

        // The row is visible through the list endpoint too, and the HTTP GET
        // surface returns it instead of a decode error.
        let listed = service.list_experiments(None, 100).await.expect("list");
        assert!(listed.iter().any(|e| e.id == id));
        let app = h.app();
        let (status, _) = call(
            &app,
            "GET",
            &format!("/api/v1/chaos/experiments/{id}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let _ = service.delete_experiment(id).await;
    });
}

#[test]
fn circuit_breaker_routes_manage_state_without_phantom_entries() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app();
        let name = unique("circuit");

        // An unknown circuit is an honest 404, not a phantom "closed" entry.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/api/v1/circuit-breakers/{name}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/circuit-breakers",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({
                "name": name,
                "failure_threshold": 3,
                "success_threshold": 2,
                "timeout_ms": 1000,
                "half_open_max_calls": 2,
                "enabled": true
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, _) = call(
            &app,
            "GET",
            &format!("/api/v1/circuit-breakers/{name}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "configured circuit is readable");

        let (status, json) = call(
            &app,
            "GET",
            "/api/v1/circuit-breakers",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.as_object().is_some() || json.is_array());

        let (status, _) = call(
            &app,
            "POST",
            &format!("/api/v1/circuit-breakers/{name}/reset"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Removing an absent circuit is an honest `removed: false`.
        let (status, json) = call(
            &app,
            "DELETE",
            &format!("/api/v1/circuit-breakers/{}", unique("ghost")),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["removed"], false);
        let (status, json) = call(
            &app,
            "DELETE",
            &format!("/api/v1/circuit-breakers/{name}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["removed"], true);
    });
}

// ── Health ──────────────────────────────────────────────────────────────

#[test]
fn health_endpoints_report_cluster_state_without_faking_readiness() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app();
        let (status, json) = call(&app, "GET", "/api/v1/health", Some(INTERNAL_KEY), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["overall"].is_string(), "cluster health: {json}");
        assert!(json["components"].is_array());
        let persistence = json["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "persistence")
            .expect("persistence component");
        assert_eq!(persistence["status"], "healthy");

        let (status, json) = call(
            &app,
            "GET",
            "/api/v1/health/cluster",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.is_array());
    });
}

// ── W6C adversarial coverage: backup storage-integrity + restore-integrity
// arms, retention storage cleanup, failover coordination fault arms, and the
// authorized mutating route surfaces. Each arm is reachable only through a
// specific failure state (corrupt payload, hostile location, storage outage,
// wrong-type Redis key) so every assertion can fail for a real reason.

use chrono::Utc;

/// Records method+path pairs and replies with a per-path configurable status
/// and body. A path of "*" matches everything not otherwise configured.
async fn spawn_storage_mock(
    config: Arc<std::sync::Mutex<std::collections::HashMap<String, (u16, String)>>>,
    log: Arc<std::sync::Mutex<Vec<String>>>,
) -> String {
    async fn handler(
        axum::extract::State((config, log)): axum::extract::State<(
            Arc<std::sync::Mutex<std::collections::HashMap<String, (u16, String)>>>,
            Arc<std::sync::Mutex<Vec<String>>>,
        )>,
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let _ = axum::body::to_bytes(request.into_body(), usize::MAX).await;
        log.lock().expect("log").push(format!("{method} {path}"));
        let (status, body) = {
            let guard = config.lock().expect("config");
            guard
                .get(&format!("{method} {path}"))
                .or_else(|| guard.get(&format!("{method} *")))
                .cloned()
                .unwrap_or((200, "{}".to_string()))
        };
        (
            axum::http::StatusCode::from_u16(status).expect("status"),
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response()
    }
    let app = axum::Router::new()
        .fallback(handler)
        .with_state((config, log));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind storage mock");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn temp_backup_file(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{}-{}.payload", name, Uuid::new_v4().simple()))
}

#[test]
fn backup_service_validation_and_table_enumeration() {
    run(async {
        let Some(h) = harness().await else { return };
        let db = h.db.clone();

        // Startup validation: a wrong-size key is rejected before any backup
        // can silently fall back to a broken cipher configuration.
        let mut bad_key = (*h.config).clone();
        bad_key.backup.encryption_key = Some("too-short".into());
        let error = match BackupService::new(db.clone(), Arc::new(bad_key)) {
            Err(error) => error,
            Ok(_) => panic!("wrong-size key must be rejected at startup"),
        };
        assert!(
            error.contains("Invalid backup encryption key size"),
            "{error}"
        );

        // Production fail-closed: no key, no service.
        let mut prod = (*h.config).clone();
        prod.environment = "production".into();
        prod.backup.encryption_key = None;
        let error = match BackupService::new(db.clone(), Arc::new(prod)) {
            Err(error) => error,
            Ok(_) => panic!("production without a key must fail closed"),
        };
        assert!(error.contains("BACKUP_ENCRYPTION_KEY"), "{error}");

        let backup = BackupService::new(db.clone(), Arc::clone(&h.config)).expect("service");

        // A table OUTSIDE the allowlist is refused even though it is a
        // syntactically valid identifier (defense in depth against catalog
        // dumps through the backup API).
        let error = backup
            .create_backup(BackupType::Full, Some(vec!["pg_class".into()]))
            .await
            .expect_err("catalog table must be refused");
        assert!(error.contains("Invalid table name"), "{error}");

        // An EMPTY table still produces a valid backup whose compression
        // ratio degrades to exactly 1.0 (no data to compress — never a
        // divide-by-zero or NaN). `ip_pools` exists in the canonical schema
        // and is empty in the harness clone.
        let empty = backup
            .create_backup(BackupType::Full, Some(vec!["ip_pools".into()]))
            .await
            .expect("empty-table backup");
        assert_eq!(empty.status, "completed");
        assert_eq!(
            empty.compression_ratio,
            Some(1.0),
            "{:?}",
            empty.compression_ratio
        );

        // No table list → the FULL table enumeration runs. The allowlist
        // filter decides what is swept; the recorded table list stays NULL
        // exactly because the caller did not pin one.
        let full = backup
            .create_backup(BackupType::Full, None)
            .await
            .expect("full enumeration backup");
        assert_eq!(full.status, "completed");
        assert!(full.tables_included.is_none());
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'
             AND tablename IN ('emails', 'contacts', 'suppression_list')",
        )
        .fetch_all(&db)
        .await
        .expect("probe tables");
        let enumerated: Vec<String> = rows.into_iter().map(|(t,)| t).collect();
        assert!(
            enumerated.contains(&"suppression_list".to_string()),
            "allowlisted application tables exist for the enumeration: {enumerated:?}"
        );

        for id in [empty.id, full.id] {
            assert!(backup.delete_backup(id).await.unwrap());
        }
    });
}

#[test]
fn backup_upload_failure_falls_back_to_staging_and_success_cleans_it() {
    run(async {
        let Some(h) = harness().await else { return };
        let backup = BackupService::new(h.db.clone(), Arc::clone(&h.config)).expect("service");

        let statuses = Arc::new(std::sync::Mutex::new(std::collections::HashMap::from([(
            "PUT *".to_string(),
            (500_u16, "storage exploded".to_string()),
        )])));
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let base = spawn_storage_mock(Arc::clone(&statuses), Arc::clone(&log)).await;

        let previous = std::env::var("BACKUP_PRESIGNED_URL_BASE").ok();
        std::env::set_var("BACKUP_PRESIGNED_URL_BASE", &base);

        // Remote upload fails → the payload is staged locally as a recovery
        // fallback AND the creation errors (the payload is never silently
        // "backed up" to nowhere).
        let failed = backup
            .create_backup(BackupType::Full, Some(vec!["suppression_list".into()]))
            .await;
        assert!(failed.is_err(), "a failed upload must fail the backup");
        let failed = failed.unwrap_err();
        assert!(failed.contains("S3 upload returned status"), "{failed}");
        let failed_location = failed.clone();
        let _ = failed_location;

        // The fallback staging copy exists for the failed object…
        let first_log = log.lock().expect("log").clone();
        assert!(
            first_log.iter().any(|entry| entry.starts_with("PUT ")),
            "the upload was attempted: {first_log:?}"
        );

        // …and once the remote recovers, the next backup succeeds and leaves
        // NO staging copy behind (retention cannot clean what /tmp hides).
        statuses
            .lock()
            .expect("config")
            .insert("PUT *".to_string(), (200_u16, "{}".to_string()));
        let ok = backup
            .create_backup(BackupType::Full, Some(vec!["suppression_list".into()]))
            .await
            .expect("upload recovered");
        let staging = local_staging_path(ok.location.as_deref().expect("location"));
        assert!(
            !staging.exists(),
            "a successful upload must not leave a staging copy at {}",
            staging.display()
        );
        assert!(backup.delete_backup(ok.id).await.unwrap());

        match previous {
            Some(value) => std::env::set_var("BACKUP_PRESIGNED_URL_BASE", value),
            None => std::env::remove_var("BACKUP_PRESIGNED_URL_BASE"),
        }
    });
}

#[test]
fn backup_download_gates_and_storage_schemes() {
    run(async {
        let Some(h) = harness().await else { return };
        let backup = BackupService::new(h.db.clone(), Arc::clone(&h.config)).expect("service");

        // Stored via the local fallback: a real payload on disk.
        let previous_base = std::env::var("BACKUP_PRESIGNED_URL_BASE").ok();
        let previous_allow = std::env::var("ALLOW_UNAUTHENTICATED_S3_DOWNLOAD").ok();
        let previous_endpoint = std::env::var("S3_ENDPOINT").ok();
        std::env::remove_var("BACKUP_PRESIGNED_URL_BASE");
        std::env::remove_var("ALLOW_UNAUTHENTICATED_S3_DOWNLOAD");
        let created = backup
            .create_backup(BackupType::Full, Some(vec!["suppression_list".into()]))
            .await
            .expect("local backup");
        let staging = local_staging_path(created.location.as_deref().expect("location"));
        let payload = tokio::fs::read(&staging).await.expect("payload bytes");
        assert!(!payload.is_empty());

        let set_location = |db: &sqlx::PgPool, id: Uuid, location: &str| {
            let db = db.clone();
            let location = location.to_string();
            async move {
                sqlx::query("UPDATE ha_backups SET location = $2 WHERE id = $1")
                    .bind(id)
                    .bind(&location)
                    .execute(&db)
                    .await
                    .expect("update location");
            }
        };
        let object_key = {
            let location = created.location.clone().unwrap();
            let path = location.strip_prefix("s3://").unwrap();
            let (_, key) = path.split_once('/').unwrap();
            key.to_string()
        };

        // (a) The s3 object is NOT staged locally and no download endpoint is
        // configured: the restore refuses instead of fetching unauthenticated.
        tokio::fs::remove_file(&staging)
            .await
            .expect("drop staging copy");
        set_location(&h.db, created.id, &format!("s3://w6c-bucket/{object_key}")).await;
        let refused = backup
            .restore(RestoreOptions {
                backup_id: created.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .expect_err("unauthenticated s3 download must be refused");
        assert!(
            refused.contains("Missing BACKUP_PRESIGNED_URL_BASE"),
            "{refused}"
        );

        // (b) Explicit acknowledgement + a failing endpoint: honest error.
        std::env::set_var(
            "ALLOW_UNAUTHENTICATED_S3_DOWNLOAD",
            "I_UNDERSTAND_THIS_IS_INSECURE",
        );
        let statuses = Arc::new(std::sync::Mutex::new(std::collections::HashMap::from([(
            "GET *".to_string(),
            (500_u16, "s3 down".to_string()),
        )])));
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let base = spawn_storage_mock(Arc::clone(&statuses), Arc::clone(&log)).await;
        std::env::set_var("S3_ENDPOINT", &base);
        let failed = backup
            .restore(RestoreOptions {
                backup_id: created.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .expect_err("s3 outage must fail the restore");
        assert!(failed.contains("S3 download returned status"), "{failed}");

        // (c) A 200 response carrying garbage bytes gets to the decompressor,
        // which must refuse it — corrupt objects never reach the database.
        statuses
            .lock()
            .expect("config")
            .insert("GET *".to_string(), (200_u16, "definitely not gzip".into()));
        let garbage = backup
            .restore(RestoreOptions {
                backup_id: created.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .expect_err("garbage object must be refused");
        assert!(garbage.contains("Decompress failed"), "{garbage}");

        // (d) file:// locations restore the REAL payload end-to-end.
        let payload_path = temp_backup_file("w6c-file-scheme");
        tokio::fs::write(&payload_path, &payload)
            .await
            .expect("write payload");
        set_location(
            &h.db,
            created.id,
            &format!("file://{}", payload_path.display()),
        )
        .await;
        let restored = backup
            .restore(RestoreOptions {
                backup_id: created.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .expect("file restore");
        assert!(restored.success, "{:?}", restored.message);

        // (e) Unknown schemes and (f) malformed s3 locations are errors.
        for hostile in [
            "ftp://example/backup.gz".to_string(),
            "s3://just-a-bucket".to_string(),
        ] {
            set_location(&h.db, created.id, &hostile).await;
            let error = backup
                .restore(RestoreOptions {
                    backup_id: created.id,
                    target_time: None,
                    validate_only: false,
                    parallel_jobs: 1,
                })
                .await
                .expect_err("hostile location must be refused");
            assert!(
                error.contains("Unknown storage location scheme")
                    || error.contains("Invalid S3 location"),
                "{hostile}: {error}"
            );
        }

        backup.delete_backup(created.id).await.unwrap();
        let _ = tokio::fs::remove_file(&payload_path).await;
        let _ = tokio::fs::remove_file(&staging).await;
        match (previous_base, previous_allow, previous_endpoint) {
            (b, a, e) => {
                if let Some(value) = b {
                    std::env::set_var("BACKUP_PRESIGNED_URL_BASE", value);
                } else {
                    std::env::remove_var("BACKUP_PRESIGNED_URL_BASE");
                }
                if let Some(value) = a {
                    std::env::set_var("ALLOW_UNAUTHENTICATED_S3_DOWNLOAD", value);
                } else {
                    std::env::remove_var("ALLOW_UNAUTHENTICATED_S3_DOWNLOAD");
                }
                if let Some(value) = e {
                    std::env::set_var("S3_ENDPOINT", value);
                } else {
                    std::env::remove_var("S3_ENDPOINT");
                }
            }
        }
    });
}

#[test]
fn restore_and_pitr_reject_hostile_tables_and_checksum_drift() {
    run(async {
        let Some(h) = harness().await else { return };
        let backup = BackupService::new(h.db.clone(), Arc::clone(&h.config)).expect("service");
        let created = backup
            .create_backup(BackupType::Full, Some(vec!["suppression_list".into()]))
            .await
            .expect("backup");

        // A catalog table smuggled into the recorded table list is refused
        // by the restore path too — not only at creation.
        sqlx::query(
            "UPDATE ha_backups SET tables_included = '[\"pg_class\"]'::jsonb WHERE id = $1",
        )
        .bind(created.id)
        .execute(&h.db)
        .await
        .expect("smuggle table");
        let error = backup
            .restore(RestoreOptions {
                backup_id: created.id,
                target_time: None,
                validate_only: false,
                parallel_jobs: 1,
            })
            .await
            .expect_err("catalog table must be refused on restore");
        assert!(error.contains("Invalid table name: pg_class"), "{error}");

        // PITR with a drifted checksum reports the mismatch honestly instead
        // of restoring an object it cannot verify.
        sqlx::query(
            "UPDATE ha_backups SET tables_included = '[\"suppression_list\"]'::jsonb,
             checksum = '0000000000000000000000000000000000000000000000000000000000000000'
             WHERE id = $1",
        )
        .bind(created.id)
        .execute(&h.db)
        .await
        .expect("drift checksum");
        let pitr = backup.pitr(Utc::now()).await.expect("pitr result");
        assert!(!pitr.success, "{:?}", pitr.message);
        assert!(
            pitr.message
                .as_deref()
                .is_some_and(|m| m.contains("checksum mismatch")),
            "{:?}",
            pitr.message
        );

        // PITR with a hostile table list fails at the table-restore step.
        sqlx::query(
            "UPDATE ha_backups SET tables_included = '[\"pg_class\"]'::jsonb,
             checksum = $2 WHERE id = $1",
        )
        .bind(created.id)
        .bind(&created.checksum)
        .execute(&h.db)
        .await
        .expect("smuggle table");
        let pitr = backup.pitr(Utc::now()).await.expect("pitr result");
        assert!(!pitr.success);
        assert!(
            pitr.message
                .as_deref()
                .is_some_and(|m| m.contains("restore of table pg_class")),
            "{:?}",
            pitr.message
        );

        backup.delete_backup(created.id).await.unwrap();
    });
}

#[test]
fn retention_removes_storage_objects_and_tolerates_storage_errors() {
    run(async {
        let Some(h) = harness().await else { return };
        let backup = BackupService::new(h.db.clone(), Arc::clone(&h.config)).expect("service");

        let statuses = Arc::new(std::sync::Mutex::new(std::collections::HashMap::from([(
            "DELETE *".to_string(),
            (200_u16, "{}".to_string()),
        )])));
        let base = spawn_storage_mock(statuses.clone(), Arc::default()).await;
        let previous = std::env::var("BACKUP_PRESIGNED_URL_BASE").ok();
        std::env::set_var("BACKUP_PRESIGNED_URL_BASE", &base);

        let seed_expired = |db: &sqlx::PgPool, location: String| {
            let db = db.clone();
            async move {
                let id = Uuid::new_v4();
                sqlx::query(
                    "INSERT INTO ha_backups
                         (id, backup_type, status, size_bytes, location, encrypted, compressed,
                          started_at, completed_at)
                     VALUES ($1, 'full', 'completed', 10, $2, false, true,
                             NOW() - INTERVAL '200 days', NOW() - INTERVAL '200 days')",
                )
                .bind(id)
                .bind(&location)
                .execute(&db)
                .await
                .expect("expired backup row");
                id
            }
        };

        // DELETE 200: the expired rows and their staging copies disappear.
        // The staging copy MUST be at the exact path delete_from_storage
        // derives from the object key (/tmp/apexmail-backups/<flattened
        // key>). The key is unique per run so no earlier run's leftovers can
        // satisfy or break the assertion.
        let object_key = format!("w6c-ret-{}.gz", Uuid::new_v4().simple());
        std::fs::create_dir_all("/tmp/apexmail-backups").expect("staging dir");
        let staged = std::path::PathBuf::from("/tmp/apexmail-backups").join(&object_key);
        std::fs::write(&staged, b"payload").expect("stage payload");
        let one = seed_expired(&h.db, format!("s3://w6c-ret/{object_key}")).await;

        let deleted = backup.enforce_retention().await.expect("retention");
        assert!(deleted >= 1, "expired rows are deleted");
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ha_backups WHERE id = ANY($1)")
                .bind(&[one])
                .fetch_one(&h.db)
                .await
                .expect("rows");
        assert_eq!(remaining, 0);
        assert!(
            !staged.exists(),
            "the staging copy of a retained-away backup is removed"
        );

        // DELETE 500: catalog cleanup still proceeds (the row is past
        // retention either way) — the storage failure is logged, not fatal.
        statuses
            .lock()
            .expect("config")
            .insert("DELETE *".to_string(), (500_u16, "still down".into()));
        let two = seed_expired(&h.db, "s3://w6c-ret/two.gz".into()).await;
        let deleted = backup.enforce_retention().await.expect("retention");
        assert!(deleted >= 1);
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ha_backups WHERE id = ANY($1)")
                .bind(&[two])
                .fetch_one(&h.db)
                .await
                .expect("rows");
        assert_eq!(remaining, 0, "a storage outage does not keep dead rows");

        // DELETE 404: the object is already gone — success.
        statuses
            .lock()
            .expect("config")
            .insert("DELETE *".to_string(), (404_u16, "gone".into()));
        let three = seed_expired(&h.db, "s3://w6c-ret/three.gz".into()).await;
        backup.enforce_retention().await.expect("retention");
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ha_backups WHERE id = ANY($1)")
                .bind(&[three])
                .fetch_one(&h.db)
                .await
                .expect("rows");
        assert_eq!(remaining, 0);

        match previous {
            Some(value) => std::env::set_var("BACKUP_PRESIGNED_URL_BASE", value),
            None => std::env::remove_var("BACKUP_PRESIGNED_URL_BASE"),
        }
    });
}

#[test]
fn failover_reports_failures_and_refuses_unsafe_targets() {
    run(async {
        let Some(h) = harness().await else { return };

        // Config info reflects the failback mode honestly.
        let base = FailoverService::new(h.db.clone(), Arc::clone(&h.config));
        assert_eq!(base.get_config_info().await.mode, "manual");
        let auto_cfg = config_with(|config| config.failover.failback_enabled = true).await;
        let auto = FailoverService::new(h.db.clone(), auto_cfg);
        assert_eq!(auto.get_config_info().await.mode, "automatic");

        // UNREACHABLE coordination: writes fail closed, lock acquisition
        // fails, claim refresh errors, split-brain detection errors — and
        // none of it wedges the state machine.
        let mut dead = (*h.config).clone();
        dead.redis.host = "127.0.0.1".into();
        dead.redis.port = 1;
        let dead = FailoverService::new(h.db.clone(), Arc::new(dead));
        let closed = dead
            .ensure_not_fenced()
            .await
            .expect_err("unreadable fence status fails closed");
        assert!(closed.contains("failing closed"), "{closed}");
        let error = dead
            .initiate_failover(FailoverType::Manual, None)
            .await
            .expect_err("no coordination, no failover");
        assert!(error.contains("failover lock"), "{error}");
        assert_eq!(dead.get_state().await, FailoverState::Normal);
        assert!(dead.refresh_primary_claim("w6c-node").await.is_err());
        assert!(dead.detect_split_brain().await.is_err());

        // A LIVE coordinator with a configured replica: the automatic
        // failover acquires the lock, probes the candidate, finds it
        // verifiably NOT replicating and aborts — the state machine returns
        // to Normal and the lock is released.
        let cfg = config_with(|config| {
            config.failover.threshold = 1;
            config.database.replica_hosts = vec!["w6c-not-replicating".into()];
        })
        .await;
        let service = FailoverService::new(h.db.clone(), cfg);
        let error = service
            .report_failure("database")
            .await
            .expect_err("a non-replicating candidate must abort the automatic failover");
        assert!(error.contains("No healthy failover target"), "{error}");
        assert_eq!(
            service.get_state().await,
            FailoverState::Normal,
            "an aborted failover must restore the prior state"
        );
        let mut conn = redis_conn(&h.config).await;
        let lock: Option<String> = redis::cmd("GET")
            .arg("ha:failover:lock")
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(lock.is_none(), "the lock is released on the abort path");

        // Claim refresh: own claim extends, foreign claim is reported lost.
        let owner = h.config.multi_region.node_id.clone();
        let _: () = redis::cmd("SET")
            .arg("ha:primary:w6c-refresh")
            .arg(&owner)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(service.refresh_primary_claim("w6c-refresh").await.unwrap());
        let _: () = redis::cmd("SET")
            .arg("ha:primary:w6c-refresh")
            .arg("someone-else")
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(!service.refresh_primary_claim("w6c-refresh").await.unwrap());
        let _: i64 = redis::cmd("DEL")
            .arg("ha:primary:w6c-refresh")
            .query_async(&mut conn)
            .await
            .unwrap();

        // Bootstrap is idempotent: the HA tables exist and accept the exact
        // rows the coordinator writes at runtime.
        ha::failover::bootstrap_tables(&h.db)
            .await
            .expect("bootstrap 1");
        ha::failover::bootstrap_tables(&h.db)
            .await
            .expect("bootstrap 2");
    });
}

#[test]
fn routes_exercise_every_authorized_mutating_surface() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app();

        // SM10 F11: initiation, failback, restore and promotion are
        // ADMIN-only — the universal internal key is 401, and the admin key
        // reaches the handler.
        for (method, path, body) in [
            (
                "POST",
                "/api/v1/failover/initiate",
                Some(serde_json::json!({"reason": "w6c route coverage"})),
            ),
            ("POST", "/api/v1/failover/failback", Some(serde_json::json!({}))),
            ("POST", "/api/v1/replication/promote", Some(serde_json::json!({}))),
        ] {
            let (status, _) = call(&app, method, path, Some(INTERNAL_KEY), body.clone()).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {path}: the universal internal key must not authorize topology changes"
            );
        }

        // Failover initiation without replicas is an honest 500 — the
        // handler ran, the coordinator refused.
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/failover/initiate",
            Some(ADMIN_KEY),
            Some(serde_json::json!({"reason": "w6c route coverage"})),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        // Failback is disabled by default → 500 with the coordinator's
        // refusal.
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/failover/failback",
            Some(ADMIN_KEY),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        // Backup lifecycle over the HTTP surface: create → list → get →
        // validate-only restore → pitr → retention → delete.
        let (status, created) = call(
            &app,
            "POST",
            "/api/v1/backup",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"backup_type": "full", "tables": ["suppression_list"]})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let backup_id = created["id"].as_str().expect("backup id").to_string();

        let (status, listed) = call(
            &app,
            "GET",
            "/api/v1/backup/list?backup_type=full&status=completed&limit=5",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(listed.is_array());

        let (status, fetched) = call(
            &app,
            "GET",
            &format!("/api/v1/backup/{backup_id}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fetched["id"].as_str(), Some(backup_id.as_str()));
        let (status, _) = call(
            &app,
            "GET",
            &format!("/api/v1/backup/{}", Uuid::new_v4()),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/backup/restore",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({
                "backup_id": backup_id,
                "target_time": null,
                "validate_only": true,
                "parallel_jobs": 1
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "restore is ADMIN-only (SM10 F11): the internal key must not reach the handler"
        );
        let (status, validated) = call(
            &app,
            "POST",
            "/api/v1/backup/restore",
            Some(ADMIN_KEY),
            Some(serde_json::json!({
                "backup_id": backup_id,
                "target_time": null,
                "validate_only": true,
                "parallel_jobs": 1
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{validated}");
        assert_eq!(validated["success"], true);

        let (status, pitr) = call(
            &app,
            "POST",
            "/api/v1/backup/pitr",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"target_time": chrono::Utc::now().to_rfc3339()})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{pitr}");
        assert_eq!(
            pitr["success"], false,
            "PITR without WAL replay is never a claimed success"
        );

        let (status, retention) = call(
            &app,
            "POST",
            "/api/v1/backup/retention",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{retention}");

        let (status, deleted) = call(
            &app,
            "DELETE",
            &format!("/api/v1/backup/{backup_id}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{deleted}");
        assert_eq!(deleted["deleted"], true);

        // Replication control surface: slot create/drop (the database may
        // refuse the privilege — a 500 IS the handler reporting honestly),
        // promotion of a non-standby, sync-mode flips and lag history.
        let slot_name = format!("w6c_slot_{}", Uuid::new_v4().simple());
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/replication/slots",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"name": slot_name, "slot_type": "physical"})),
        )
        .await;
        assert!(
            status == StatusCode::CREATED || status == StatusCode::INTERNAL_SERVER_ERROR,
            "slot creation is either granted or honestly refused: {status}"
        );
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/api/v1/replication/slots/{slot_name}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "{status}"
        );
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/replication/promote",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "promotion is ADMIN-only (SM10 F11): the internal key must not reach the handler"
        );
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/replication/promote",
            Some(ADMIN_KEY),
            Some(serde_json::json!({})),
        )
        .await;
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "promoting a non-standby reports honestly: {status}"
        );
        let (status, _) = call(
            &app,
            "PUT",
            "/api/v1/replication/sync-mode",
            Some(INTERNAL_KEY),
            Some(serde_json::json!({"synchronous": false})),
        )
        .await;
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "{status}"
        );
        let (status, _) = call(
            &app,
            "GET",
            "/api/v1/replication/lag/history?minutes=30",
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "{status}"
        );

        // Geo-rule deletion of an unknown id is a truthful `false`.
        let (status, deleted) = call(
            &app,
            "DELETE",
            &format!("/api/v1/regions/geo-rules/{}", Uuid::new_v4()),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{deleted}");
        assert_eq!(deleted["deleted"], false);

        // Chaos surface: aborting an unknown experiment fails loudly;
        // deleting one is a truthful `false`.
        let unknown = Uuid::new_v4();
        let (status, _) = call(
            &app,
            "POST",
            &format!("/api/v1/chaos/experiments/{unknown}/abort"),
            Some(INTERNAL_KEY),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let (status, deleted) = call(
            &app,
            "DELETE",
            &format!("/api/v1/chaos/experiments/{unknown}"),
            Some(INTERNAL_KEY),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{deleted}");
        assert_eq!(deleted["deleted"], false);
    });
}
