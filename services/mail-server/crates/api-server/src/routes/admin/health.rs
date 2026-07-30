//! System health monitoring with automated alerting.
//!
//! Provides:
//! - GET  /v1/admin/health/status  — live composite health score (0–100)
//! - GET  /v1/admin/health/history — last 7 days of hourly snapshots
//! - Background task that checks every 60 s, stores scores, and inserts alerts.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use deadpool_redis::Pool as RedisPool;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};
use tokio::sync::Notify;
use tokio::time::{interval, MissedTickBehavior};
use tracing;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

const HEALTH_CHECK_INTERVAL_SECS: u64 = 60;
const HISTORY_RETENTION_DAYS: i64 = 7;
const QUEUE_DEPTH_WARNING: i64 = 10_000;
const OLDEST_JOB_AGE_CRITICAL_SECS: i64 = 3_600;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthStatusResponse {
    pub overall_score: f64,
    pub components: HealthComponents,
    pub alerts_last_hour: i64,
    pub checked_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthComponents {
    pub database: ComponentHealth,
    pub redis: ComponentHealth,
    pub email_queue: ComponentHealth,
    pub mta: ComponentHealth,
    pub disk: ComponentHealth,
    pub memory: ComponentHealth,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentHealth {
    pub score: f64,
    pub status: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthHistoryResponse {
    pub entries: Vec<HealthHistoryEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthHistoryEntry {
    pub overall_score: f64,
    pub checked_at: String,
    pub components: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthHistoryQuery {
    #[serde(default = "default_history_hours")]
    pub hours: i64,
}

fn default_history_hours() -> i64 {
    24
}

pub struct HealthMonitorState {
    db: PgPool,
    redis: RedisPool,
    shutdown: Arc<Notify>,
    pub started: AtomicBool,
}

impl HealthMonitorState {
    pub fn new(db: PgPool, redis: RedisPool) -> Self {
        Self {
            db,
            redis,
            shutdown: Arc::new(Notify::new()),
            started: AtomicBool::new(false),
        }
    }

    pub fn start(self: Arc<Self>) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }

        let monitor = self.clone();
        tokio::spawn(async move {
            monitor.run_loop().await;
        });
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    async fn run_loop(&self) {
        let mut ticker =
            interval(tokio::time::Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tracing::info!(
            interval_secs = HEALTH_CHECK_INTERVAL_SECS,
            "health monitor started"
        );

        // Run immediately on start
        self.check_and_record().await;

        loop {
            tokio::select! {
                _ = self.shutdown.notified() => {
                    tracing::info!("health monitor shutting down");
                    return;
                }
                _ = ticker.tick() => {
                    self.check_and_record().await;
                }
            }
        }
    }

    async fn check_and_record(&self) {
        let now = Utc::now();
        match compute_health_scores(&self.db, &self.redis).await {
            Ok(result) => {
                if let Err(e) = self
                    .store_snapshot(&result, now)
                    .await
                {
                    tracing::error!(error = %e, "failed to store health snapshot");
                }
                self.evaluate_alerts(&result, now).await;
            }
            Err(e) => {
                tracing::error!(error = %e, "health check failed");
                self.insert_db_failure_alert(now).await;
            }
        }
    }

    async fn store_snapshot(
        &self,
        result: &HealthCheckResult,
        now: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let components = serde_json::to_value(&result.components).unwrap_or_default();
        sqlx::query(
            "INSERT INTO health_check_history
             (overall_score, db_score, redis_score, queue_score, mta_score, disk_score, memory_score, details, checked_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(result.overall_score)
        .bind(result.db_score)
        .bind(result.redis_score)
        .bind(result.queue_score)
        .bind(result.mta_score)
        .bind(result.disk_score)
        .bind(result.memory_score)
        .bind(&components)
        .bind(now)
        .execute(&self.db)
        .await?;

        // Purge entries older than 7 days
        let cutoff = now - Duration::days(HISTORY_RETENTION_DAYS);
        let _ = sqlx::query("DELETE FROM health_check_history WHERE checked_at < $1")
            .bind(cutoff)
            .execute(&self.db)
            .await;

        Ok(())
    }

    async fn evaluate_alerts(&self, result: &HealthCheckResult, now: DateTime<Utc>) {
        if result.overall_score < 50.0 {
            let _ = self
                .insert_alert(
                    "health_score",
                    "critical",
                    &format!(
                        "System health critical: overall score {:.1}/100",
                        result.overall_score
                    ),
                    now,
                )
                .await;
        } else if result.overall_score < 70.0 {
            let _ = self
                .insert_alert(
                    "health_score",
                    "warning",
                    &format!(
                        "System health warning: overall score {:.1}/100",
                        result.overall_score
                    ),
                    now,
                )
                .await;
        }

        if result.queue_depth > QUEUE_DEPTH_WARNING {
            let _ = self
                .insert_alert(
                    "queue_depth",
                    "warning",
                    &format!(
                        "Email queue depth {} exceeds threshold {}",
                        result.queue_depth, QUEUE_DEPTH_WARNING
                    ),
                    now,
                )
                .await;
        }

        if let Some(age_secs) = result.oldest_job_age_secs {
            if age_secs > OLDEST_JOB_AGE_CRITICAL_SECS {
                let _ = self
                    .insert_alert(
                        "queue_stall",
                        "critical",
                        &format!(
                            "Oldest pending job is {}s old (>{}s threshold)",
                            age_secs, OLDEST_JOB_AGE_CRITICAL_SECS
                        ),
                        now,
                    )
                    .await;
            }
        }
    }

    async fn insert_db_failure_alert(&self, now: DateTime<Utc>) {
        let _ = self
            .insert_alert(
                "db_failure",
                "critical",
                "Database connection failure during health check",
                now,
            )
            .await;
    }

    async fn insert_alert(
        &self,
        alert_type: &str,
        severity: &str,
        message: &str,
        created_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO system_alerts (alert_type, severity, message, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(alert_type)
        .bind(severity)
        .bind(message)
        .bind(created_at)
        .execute(&self.db)
        .await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct HealthCheckResult {
    overall_score: f64,
    db_score: f64,
    redis_score: f64,
    queue_score: f64,
    mta_score: f64,
    disk_score: f64,
    memory_score: f64,
    components: HealthComponents,
    queue_depth: i64,
    oldest_job_age_secs: Option<i64>,
}

async fn compute_health_scores(
    db: &PgPool,
    redis: &RedisPool,
) -> Result<HealthCheckResult, anyhow::Error> {
    let (db_score, db_details) = check_database(db).await;
    let (redis_score, redis_details) = check_redis(redis).await;
    let (queue_score, queue_details, queue_depth, oldest_job_age) = check_email_queue(db).await;
    let (mta_score, mta_details) = check_mta().await;
    let (disk_score, disk_details) = check_disk();
    let (memory_score, memory_details) = check_memory();

    let overall_score =
        (db_score * 0.30) + (redis_score * 0.15) + (queue_score * 0.25) + (mta_score * 0.10)
            + (disk_score * 0.10) + (memory_score * 0.10);

    let components = HealthComponents {
        database: ComponentHealth {
            score: db_score,
            status: score_status(db_score),
            details: db_details,
        },
        redis: ComponentHealth {
            score: redis_score,
            status: score_status(redis_score),
            details: redis_details,
        },
        email_queue: ComponentHealth {
            score: queue_score,
            status: score_status(queue_score),
            details: queue_details,
        },
        mta: ComponentHealth {
            score: mta_score,
            status: score_status(mta_score),
            details: mta_details,
        },
        disk: ComponentHealth {
            score: disk_score,
            status: score_status(disk_score),
            details: disk_details,
        },
        memory: ComponentHealth {
            score: memory_score,
            status: score_status(memory_score),
            details: memory_details,
        },
    };

    Ok(HealthCheckResult {
        overall_score,
        db_score,
        redis_score,
        queue_score,
        mta_score,
        disk_score,
        memory_score,
        components,
        queue_depth,
        oldest_job_age_secs: oldest_job_age,
    })
}

fn score_status(score: f64) -> String {
    if score >= 80.0 {
        "healthy".into()
    } else if score >= 50.0 {
        "degraded".into()
    } else {
        "critical".into()
    }
}

async fn check_database(db: &PgPool) -> (f64, serde_json::Value) {
    let start = tokio::time::Instant::now();
    let connected = sqlx::query("SELECT 1").fetch_one(db).await.is_ok();
    let latency_ms = start.elapsed().as_millis() as f64;

    let pool_size: i32 = db.size() as i32;
    let idle: i32 = db.num_idle() as i32;
    let used = pool_size - idle;

    let score = if !connected {
        0.0
    } else if latency_ms < 10.0 {
        100.0
    } else if latency_ms < 50.0 {
        80.0
    } else if latency_ms < 200.0 {
        60.0
    } else {
        30.0
    };

    (
        score,
        serde_json::json!({
            "connected": connected,
            "latencyMs": latency_ms,
            "poolSize": pool_size,
            "activeConnections": used,
            "idleConnections": idle,
        }),
    )
}

async fn check_redis(redis: &RedisPool) -> (f64, serde_json::Value) {
    let result: Result<(f64, serde_json::Value), anyhow::Error> = async {
        let mut conn = redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let start = tokio::time::Instant::now();
        let ping: String = deadpool_redis::redis::cmd("PING")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let latency_ms = start.elapsed().as_millis() as f64;

        let info: String = deadpool_redis::redis::cmd("INFO")
            .arg("memory")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let used_memory = info
            .lines()
            .find(|l| l.starts_with("used_memory:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(0);

        let connected = ping == "PONG";
        let score = if !connected {
            0.0
        } else if latency_ms < 5.0 {
            100.0
        } else if latency_ms < 20.0 {
            80.0
        } else {
            50.0
        };

        Ok((
            score,
            serde_json::json!({
                "connected": connected,
                "latencyMs": latency_ms,
                "usedMemoryBytes": used_memory,
            }),
        ))
    }
    .await;

    match result {
        Ok((score, details)) => (score, details),
        Err(e) => (
            0.0,
            serde_json::json!({
                "connected": false,
                "error": e.to_string(),
            }),
        ),
    }
}

async fn check_email_queue(
    db: &PgPool,
) -> (f64, serde_json::Value, i64, Option<i64>) {
    let result = sqlx::query_as::<_, (i64, Option<i64>)>(
        "SELECT
            COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0) as depth,
            COALESCE(
                (SELECT EXTRACT(EPOCH FROM NOW() - MIN(created_at))::bigint
                 FROM email_queue WHERE status = 'pending'),
                0
            ) as oldest_age_secs
         FROM email_queue",
    )
    .fetch_one(db)
    .await;

    match result {
        Ok((depth, oldest)) => {
            let score = if depth == 0 {
                100.0
            } else if depth < 1_000 {
                90.0
            } else if depth < 5_000 {
                70.0
            } else if depth < QUEUE_DEPTH_WARNING {
                50.0
            } else {
                20.0
            };

            (
                score,
                serde_json::json!({
                    "depth": depth,
                    "oldestPendingAgeSecs": oldest,
                }),
                depth,
                oldest,
            )
        }
        Err(e) => (
            0.0,
            serde_json::json!({
                "error": e.to_string(),
            }),
            0,
            None,
        ),
    }
}

async fn check_mta() -> (f64, serde_json::Value) {
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect("127.0.0.1:25"),
    )
    .await;

    match result {
        Ok(Ok(mut stream)) => {
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 512];
            let connected = tokio::time::timeout(
                tokio::time::Duration::from_secs(3),
                stream.read(&mut buf),
            )
            .await
            .is_ok_and(|r| r.is_ok_and(|n| n > 0));

            if connected {
                let banner = String::from_utf8_lossy(&buf)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                (
                    100.0,
                    serde_json::json!({
                        "reachable": true,
                        "banner": banner.trim(),
                    }),
                )
            } else {
                (
                    50.0,
                    serde_json::json!({
                        "reachable": true,
                        "banner": null,
                    }),
                )
            }
        }
        _ => (
            0.0,
            serde_json::json!({
                "reachable": false,
            }),
        ),
    }
}

fn check_disk() -> (f64, serde_json::Value) {
    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| ".".into());
    let data_path = std::path::Path::new(&data_dir);

    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut best_total: u64 = 0;
    let mut best_free: u64 = 0;
    let mut best_path = String::new();

    for disk in disks.list() {
        let mp = disk.mount_point();
        if data_path.starts_with(mp) && mp.as_os_str().len() >= best_path.len() {
            best_total = disk.total_space();
            best_free = disk.available_space();
            best_path = mp.to_string_lossy().to_string();
        }
    }

    if best_total > 0 {
        let used_pct = if best_total > 0 {
            ((best_total - best_free) as f64 / best_total as f64) * 100.0
        } else {
            0.0
        };

        let score = if used_pct < 60.0 {
            100.0
        } else if used_pct < 80.0 {
            70.0
        } else if used_pct < 90.0 {
            40.0
        } else {
            10.0
        };

        (
            score,
            serde_json::json!({
                "path": data_dir,
                "mountPoint": best_path,
                "totalBytes": best_total,
                "freeBytes": best_free,
                "usedPercent": (used_pct * 100.0).round() / 100.0,
            }),
        )
    } else {
        (
            0.0,
            serde_json::json!({ "error": format!("cannot determine disk usage for {data_dir}") }),
        )
    }
}

fn check_memory() -> (f64, serde_json::Value) {
    let sys = System::new_with_specifics(
        RefreshKind::nothing().with_memory(MemoryRefreshKind::everything()),
    );

    let total_kb = sys.total_memory();
    let used_kb = sys.used_memory();
    let free_kb = sys.free_memory();
    let available_kb = sys.available_memory();

    let used_pct = if total_kb > 0 {
        (used_kb as f64 / total_kb as f64) * 100.0
    } else {
        0.0
    };

    let score = if used_pct < 60.0 {
        100.0
    } else if used_pct < 80.0 {
        70.0
    } else if used_pct < 95.0 {
        40.0
    } else {
        10.0
    };

    (
        score,
        serde_json::json!({
            "totalKb": total_kb,
            "usedKb": used_kb,
            "freeKb": free_kb,
            "availableKb": available_kb,
            "usedPercent": (used_pct * 100.0).round() / 100.0,
        }),
    )
}

// ─── Route handlers ─────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(health_status))
        .route("/history", get(health_history))
}

async fn health_status(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<HealthStatusResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let result = compute_health_scores(&state.db, &state.redis)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let now = Utc::now();

    let alerts_last_hour = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM system_alerts
         WHERE alert_type LIKE 'health_%' OR alert_type IN ('queue_depth', 'queue_stall', 'db_failure')
           AND created_at > $1",
    )
    .bind(now - Duration::hours(1))
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    Ok(Json(HealthStatusResponse {
        overall_score: result.overall_score,
        components: result.components,
        alerts_last_hour,
        checked_at: now.to_rfc3339(),
    }))
}

async fn health_history(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<HealthHistoryQuery>,
) -> Result<Json<HealthHistoryResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let hours = params.hours.clamp(1, 168); // 7 days max
    let cutoff = Utc::now() - Duration::hours(hours);

    let rows = sqlx::query_as::<_, (f64, DateTime<Utc>, serde_json::Value)>(
        "SELECT overall_score, checked_at, details
         FROM health_check_history
         WHERE checked_at > $1
         ORDER BY checked_at ASC",
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await?;

    let entries: Vec<HealthHistoryEntry> = rows
        .into_iter()
        .map(|(score, ts, details)| HealthHistoryEntry {
            overall_score: score,
            checked_at: ts.to_rfc3339(),
            components: details,
        })
        .collect();

    Ok(Json(HealthHistoryResponse { entries }))
}
