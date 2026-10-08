//! Control-plane job controls — the operator surface for the canonical
//! `queue_jobs` store (`queue-provider`'s schema).
//!
//! Dogfood 2026-10-08 F13: `/jobs` and `/infrastructure/queues` carried no
//! retry/purge/drain controls and no endpoint backed them — an operator
//! could see a dead-letter pile but not act on it. This module implements the
//! two controls that match the queue's OWN semantics:
//!
//! * **retry** — a `dead_letter` (or terminal `failed`) job is re-queued:
//!   status `pending`, attempts reset to 0, schedule/error/lease cleared.
//!   ONLY terminal states are retryable; a `pending` job is already
//!   scheduled, a `completed` job is history, and a `processing` job is
//!   owned by a worker's lease — resetting it would race the owner whose
//!   completion paths are lease-fenced (`queue-provider` migration 103).
//!
//! * **cancel** — a `pending` job (nothing has claimed it) is deleted, the
//!   same row-level delete `PostgresQueueProvider::purge` performs for
//!   terminal rows. `processing` jobs are refused (in flight), `completed`
//!   jobs are refused (history), and `dead_letter` jobs are refused with a
//!   pointer to retry/purge — cancellation is not a substitute for either.
//!
//! Both mutations are actor-attributed in `audit_logs`
//! (`control_plane.job.retried` / `control_plane.job.cancelled`), matching
//! the operator lifecycle surface.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, require_system_tenant, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_jobs))
        .route("/:id/retry", post(retry_job_endpoint))
        .route("/:id/cancel", post(cancel_job_endpoint))
}

/// Statuses a retry may re-queue: the terminal failure states. `failed` is
/// the schema's terminal failure status (queue-provider's `fail()` either
/// re-queues to `pending` or dead-letters, so rows here are legacy/manual).
const RETRYABLE_STATUSES: &[&str] = &["dead_letter", "failed"];
/// Statuses a cancel may delete: unclaimed work only.
const CANCELLABLE_STATUSES: &[&str] = &["pending"];

#[derive(Debug, Serialize, FromRow)]
pub struct JobRow {
    pub id: String,
    pub queue: String,
    pub status: String,
    pub attempts: i32,
    pub max_attempts: i32,
    pub error_message: Option<String>,
    pub scheduled_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub failed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobListQuery {
    /// Exact queue-name filter (`?queue=emails`).
    pub queue: Option<String>,
    /// Exact status filter; validated against the schema's status CHECK.
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobListResponse {
    pub jobs: Vec<JobRow>,
    pub limit: i64,
    pub offset: i64,
}

const JOB_COLUMNS: &str = "id::text AS id, COALESCE(queue, 'default') AS queue, status, \
     attempts, max_attempts, error_message, scheduled_at, started_at, completed_at, \
     failed_at, updated_at";

async fn list_jobs(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<JobListQuery>,
) -> Result<Json<JobListResponse>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    if let Some(status) = query.status.as_deref() {
        if !matches!(
            status,
            "pending" | "processing" | "completed" | "failed" | "dead_letter"
        ) {
            return Err(ApiError::Validation(vec![format!(
                "invalid status: {status} (allowed: pending, processing, completed, failed, dead_letter)"
            )]));
        }
    }
    let limit = query.limit.clamp(1, 200);
    let offset = query.offset.max(0);

    // Filters are optional predicates over the SAME parameterized query;
    // nothing is interpolated.
    let rows = sqlx::query_as::<_, JobRow>(&format!(
        "SELECT {JOB_COLUMNS} FROM queue_jobs \
         WHERE ($1::text IS NULL OR COALESCE(queue, 'default') = $1) \
           AND ($2::text IS NULL OR status = $2) \
         ORDER BY updated_at DESC, id \
         LIMIT $3 OFFSET $4"
    ))
    .bind(query.queue.as_deref())
    .bind(query.status.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|error| {
        tracing::error!(error = %error, "job list query failed");
        ApiError::Internal("Failed to list jobs".into())
    })?;

    Ok(Json(JobListResponse {
        jobs: rows,
        limit,
        offset,
    }))
}

/// Actor-attributed audit entry for a job control mutation.
pub(crate) async fn log_job_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    job_id: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "queue_job",
        Some(job_id),
        metadata,
        None,
        None,
    )
    .await;
}

/// Re-queue a terminal job exactly as `queue-provider`'s recovery paths do:
/// `pending`, attempts 0, schedule now, every terminal marker and the lease
/// cleared. The UPDATE itself is the state guard, so two concurrent retries
/// have exactly one effect (the loser matches zero rows).
pub(crate) async fn retry_job(state: &AppState, id: Uuid) -> Result<JobRow, ApiError> {
    let row = sqlx::query_as::<_, JobRow>(&format!(
        "UPDATE queue_jobs \
         SET status = 'pending', attempts = 0, scheduled_at = NOW(), started_at = NULL, \
             completed_at = NULL, failed_at = NULL, error_message = NULL, lease_token = NULL, \
             updated_at = NOW() \
         WHERE id = $1 AND status = ANY($2) \
         RETURNING {JOB_COLUMNS}"
    ))
    .bind(id)
    .bind(RETRYABLE_STATUSES)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| {
        tracing::error!(job_id = %id, error = %error, "job retry failed");
        ApiError::Internal("Failed to retry job".into())
    })?;

    row.ok_or_else(|| {
        ApiError::Conflict(
            "only dead-lettered (or failed) jobs can be retried; pending jobs are already \
             scheduled, completed jobs are history, and processing jobs are in flight under a \
             worker lease"
                .into(),
        )
    })
}

/// Delete an unclaimed (`pending`) job — the row-level analogue of the
/// queue provider's terminal-row purge. Refuses in-flight and terminal jobs
/// by name (the UPDATE..WHERE status guard is the concurrency fence).
pub(crate) async fn cancel_job(state: &AppState, id: Uuid) -> Result<JobRow, ApiError> {
    let row = sqlx::query_as::<_, JobRow>(&format!(
        "DELETE FROM queue_jobs WHERE id = $1 AND status = ANY($2) RETURNING {JOB_COLUMNS}"
    ))
    .bind(id)
    .bind(CANCELLABLE_STATUSES)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| {
        tracing::error!(job_id = %id, error = %error, "job cancel failed");
        ApiError::Internal("Failed to cancel job".into())
    })?;

    row.ok_or_else(|| {
        ApiError::Conflict(
            "only pending (unclaimed) jobs can be cancelled; processing jobs are in flight \
             under a worker lease, completed jobs are history, and dead-lettered jobs are \
             retried or purged"
                .into(),
        )
    })
}

/// [`retry_job`] plus its actor-attributed audit entry — the shared core of
/// the JSON endpoint and the zero-JS CP form handler.
pub(crate) async fn retry_job_audited(
    state: &AppState,
    auth: &AuthUser,
    id: Uuid,
) -> Result<JobRow, ApiError> {
    let job = retry_job(state, id).await?;
    log_job_audit(
        state,
        auth,
        "control_plane.job.retried",
        &id.to_string(),
        serde_json::json!({ "queue": job.queue, "status": job.status }),
    )
    .await;
    tracing::info!(job_id = %id, queue = %job.queue, "Operator re-queued a job");
    Ok(job)
}

/// [`cancel_job`] plus its actor-attributed audit entry.
pub(crate) async fn cancel_job_audited(
    state: &AppState,
    auth: &AuthUser,
    id: Uuid,
) -> Result<JobRow, ApiError> {
    let job = cancel_job(state, id).await?;
    log_job_audit(
        state,
        auth,
        "control_plane.job.cancelled",
        &id.to_string(),
        serde_json::json!({ "queue": job.queue }),
    )
    .await;
    tracing::info!(job_id = %id, queue = %job.queue, "Operator cancelled a pending job");
    Ok(job)
}

fn parse_job_id(raw: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw).map_err(|_| ApiError::Validation(vec!["job id must be a UUID".into()]))
}

async fn retry_job_endpoint(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<JobRow>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    let id = parse_job_id(&id)?;
    Ok(Json(retry_job_audited(&state, &auth, id).await?))
}

async fn cancel_job_endpoint(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<JobRow>), ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    let id = parse_job_id(&id)?;
    Ok((
        StatusCode::OK,
        Json(cancel_job_audited(&state, &auth, id).await?),
    ))
}

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;
    use uuid::Uuid;

    use crate::app::test_support::adv::AdvEnv;

    /// Seed one queue_jobs row in the requested state, with a unique queue
    /// name so assertions scope to this test on the shared `_api` database.
    async fn seed_job(
        pool: &sqlx::PgPool,
        queue: &str,
        status: &str,
        attempts: i32,
        max_attempts: i32,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO queue_jobs (id, tenant_id, queue, payload, status, attempts, max_attempts,
                                     scheduled_at, started_at, error_message, created_at, updated_at)
             VALUES ($1, $2, $3, '{}'::jsonb, $4, $5, $6,
                     NOW(), CASE WHEN $4 = 'processing' THEN NOW() ELSE NULL END,
                     CASE WHEN $4 IN ('failed', 'dead_letter') THEN 'probe failure' ELSE NULL END,
                     NOW(), NOW())",
        )
        .bind(id)
        .bind(Uuid::new_v4())
        .bind(queue)
        .bind(status)
        .bind(attempts)
        .bind(max_attempts)
        .execute(pool)
        .await
        .expect("seed queue job");
        id
    }

    async fn job_status(pool: &sqlx::PgPool, id: Uuid) -> Option<String> {
        sqlx::query_scalar("SELECT status FROM queue_jobs WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .expect("status lookup")
    }

    #[tokio::test]
    async fn retry_requeues_terminal_jobs_and_refuses_in_flight_and_completed() {
        let Some(pool) = crate::test_db::canonical_pool("jobs_retry").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let tag = Uuid::new_v4().simple().to_string();

        let dead = seed_job(&pool, &format!("jobs-ctl-dl-{tag}"), "dead_letter", 5, 3).await;
        let in_flight = seed_job(&pool, &format!("jobs-ctl-proc-{tag}"), "processing", 1, 3).await;
        let completed = seed_job(&pool, &format!("jobs-ctl-done-{tag}"), "completed", 1, 3).await;
        let pending = seed_job(&pool, &format!("jobs-ctl-pend-{tag}"), "pending", 0, 3).await;

        // Dead-letter → re-queued with a clean slate.
        let (status, body) = env.post(&format!("/v1/admin/jobs/{dead}/retry"), "").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "pending");
        assert_eq!(body["attempts"], 0);
        let (db_status, attempts, error): (String, i32, Option<String>) =
            sqlx::query_as("SELECT status, attempts, error_message FROM queue_jobs WHERE id = $1")
                .bind(dead)
                .fetch_one(&pool)
                .await
                .expect("row");
        assert_eq!(db_status, "pending");
        assert_eq!(attempts, 0, "retry resets the attempt counter");
        assert!(error.is_none(), "retry clears the terminal error");
        let audit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'control_plane.job.retried' AND resource_id = $1",
        )
        .bind(dead.to_string())
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(audit, 1, "the retry must be actor-attributed");

        // Every other state is refused BY NAME, with the row untouched.
        for (id, expected) in [
            (in_flight, "processing"),
            (completed, "completed"),
            (pending, "pending"),
        ] {
            let (status, body) = env.post(&format!("/v1/admin/jobs/{id}/retry"), "").await;
            assert_eq!(status, StatusCode::CONFLICT, "{id}: {body}");
            assert!(
                body["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("only dead-lettered"),
                "{body}"
            );
            assert_eq!(
                job_status(&pool, id).await.as_deref(),
                Some(expected),
                "a refused retry must not mutate the row"
            );
        }

        // Unknown id: same named refusal, nothing created.
        let (status, _) = env
            .post(&format!("/v1/admin/jobs/{}/retry", Uuid::new_v4()), "")
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        // Malformed id is a validation refusal, not a 500.
        let (status, _) = env.post("/v1/admin/jobs/not-a-uuid/retry", "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cancel_deletes_pending_jobs_and_refuses_in_flight_and_terminal() {
        let Some(pool) = crate::test_db::canonical_pool("jobs_cancel").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let tag = Uuid::new_v4().simple().to_string();

        let pending = seed_job(&pool, &format!("jobs-ctl-p-{tag}"), "pending", 0, 3).await;
        let (status, body) = env
            .post(&format!("/v1/admin/jobs/{pending}/cancel"), "")
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "pending");
        assert!(
            job_status(&pool, pending).await.is_none(),
            "the cancelled job row is deleted"
        );
        let audit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'control_plane.job.cancelled' AND resource_id = $1",
        )
        .bind(pending.to_string())
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(audit, 1, "the cancel must be actor-attributed");

        let in_flight = seed_job(&pool, &format!("jobs-ctl-i-{tag}"), "processing", 1, 3).await;
        let dead = seed_job(&pool, &format!("jobs-ctl-d-{tag}"), "dead_letter", 3, 3).await;
        let completed = seed_job(&pool, &format!("jobs-ctl-c-{tag}"), "completed", 1, 3).await;
        for (id, expected) in [
            (in_flight, "processing"),
            (dead, "dead_letter"),
            (completed, "completed"),
        ] {
            let (status, body) = env.post(&format!("/v1/admin/jobs/{id}/cancel"), "").await;
            assert_eq!(status, StatusCode::CONFLICT, "{id}: {body}");
            assert!(
                body["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("only pending"),
                "{body}"
            );
            assert_eq!(
                job_status(&pool, id).await.as_deref(),
                Some(expected),
                "a refused cancel must not delete the row"
            );
        }
    }

    #[tokio::test]
    async fn job_list_filters_by_queue_and_status_and_refuses_bad_status() {
        let Some(pool) = crate::test_db::canonical_pool("jobs_list").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let tag = Uuid::new_v4().simple().to_string();
        let queue = format!("jobs-ctl-list-{tag}");
        let pending = seed_job(&pool, &queue, "pending", 0, 3).await;
        let dead = seed_job(&pool, &queue, "dead_letter", 3, 3).await;

        let (status, body) = env
            .get(&format!("/v1/admin/jobs?queue={queue}&status=pending"))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let jobs = body["jobs"].as_array().expect("jobs array");
        assert_eq!(jobs.len(), 1, "{body}");
        assert_eq!(jobs[0]["id"], pending.to_string());

        let (status, body) = env.get(&format!("/v1/admin/jobs?queue={queue}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["jobs"].as_array().map(Vec::len), Some(2));
        assert!(body["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|job| job["id"] == dead.to_string()));

        // An out-of-vocabulary status is a validation refusal, never a
        // silently empty list.
        let (status, _) = env.get("/v1/admin/jobs?status=cancelled").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn job_controls_require_system_tenant_and_wildcard_scope() {
        let Some(pool) = crate::test_db::canonical_pool("jobs_gates").await else {
            return;
        };
        // A system-tenant key WITHOUT the wildcard: the scope gate refuses.
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["analytics:read"]).await;
        let scoped = AdvEnv::over(pool.clone(), key).await;
        let id = seed_job(
            &pool,
            &format!("jobs-ctl-gate-{}", Uuid::new_v4().simple()),
            "pending",
            0,
            3,
        )
        .await;
        for uri in [
            "/v1/admin/jobs".to_string(),
            format!("/v1/admin/jobs/{id}/retry"),
            format!("/v1/admin/jobs/{id}/cancel"),
        ] {
            let method = if uri == "/v1/admin/jobs" {
                "GET"
            } else {
                "POST"
            };
            let (status, body) = if method == "GET" {
                scoped.get(&uri).await
            } else {
                scoped.post(&uri, "").await
            };
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        }
        assert!(
            job_status(&pool, id).await.is_some(),
            "a refused control must leave the job alone"
        );

        // A non-system (customer) wildcard key: the system-tenant gate refuses.
        let tenant_id = apexmail_lib::id::generate_id("advt", 20);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'job control probe', $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant_id)
        .bind(format!("slug-{tenant_id}"))
        .execute(&pool)
        .await
        .expect("seed tenant");
        let key = crate::app::test_support::seed_api_key_for(&pool, &tenant_id, &["*"]).await;
        let customer = AdvEnv::over(pool, key).await;
        let (status, _) = customer.get("/v1/admin/jobs").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
